package importer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// The interactive import wizard (import-paths ADR § Entry modes; spellings spec
// § 3 wizard interaction states). The wizard is an AUTHORING FRONTEND for the
// mapping template: it walks the source and the target mapping interactively,
// records every choice into a Template, and then runs BuildProjectPlan — the
// exact path replay uses. Byte-identity between a wizard session and an
// equivalent flag/replay run (where the choices coincide) is therefore
// structural, not tested-in: both reach the one planner.
//
// The engine is I/O-agnostic. Terminal reads and writes go through a Prompter;
// source reads and the server presence read are injected callbacks the CLI
// supplies. Nothing here contacts a network or a terminal directly, so the whole
// nine-state walk is testable with a scripted prompter.

// Prompter is the wizard's terminal surface. Confirm/Choose/Line read one answer;
// Notice prints an informational line and reads nothing. Every method may return
// an error (EOF on a closed stdin, a broken pipe) which aborts the session.
type Prompter interface {
	Notice(msg string)
	Confirm(question string, def bool) (bool, error)
	Choose(question string, options []string, def int) (int, error)
	Line(question, def string) (string, error)
}

// Selector is the connector-shaped source slice the wizard gathers for one read.
// It mirrors the flag-mode selectors so the CLI can drive Run/RunLive from it.
type Selector struct {
	Live      bool
	File      string
	Namespace string
	Name      string
	Context   string
	Mount     string
	Path      string
	KVVersion int
	EnvSlug   string
}

// SourceRead is one connector read the host performed for the wizard.
type SourceRead struct {
	Result     Result
	FileDigest string
	EnvSlug    string
}

// NamedEnv is one existing target environment the actor may read.
type NamedEnv struct {
	ID   string
	Name string
}

// WizardHost is the impure surface the CLI supplies: the terminal, the source
// reader, the environment list, and the server presence read. The engine calls
// these; it never opens a file, a socket or a terminal itself.
type WizardHost interface {
	Prompter
	// ReadSource performs one connector read for a gathered selector.
	ReadSource(source string, sel Selector) (SourceRead, error)
	// ExistingEnvironments lists the environments the actor can read (read(E)).
	ExistingEnvironments() ([]NamedEnv, error)
	// Presence reads server presence for one existing environment, minting an
	// occurrence per candidate.
	Presence(envID string, candidates []PlannedCandidate) (ServerState, error)
}

// wizardEnv is one target environment the session gathered: its identity, the
// source read mapped onto it, and (for existing environments) the presence read.
type wizardEnv struct {
	ref    string // env id (existing) or env name (created)
	name   string
	create bool
	read   SourceRead
	state  ServerState // empty for a created environment
}

// Wizard runs the whole interactive session and returns the authored project
// plan, or an error (a refusal the human could not resolve, or an aborted
// session). The project is the resolved target the CLI supplies; it must
// pre-exist (import never creates a project). The definitions revision the
// manifest records is captured from the presence reads (it is project-scoped, so
// every environment reports the same one) and is informational only.
func Wizard(host WizardHost, project string) (*ProjectPlan, error) {
	source, err := wizardSource(host)
	if err != nil {
		return nil, err
	}

	// ONE source read, fanned across the target environments (import-paths ADR
	// § The two-phase invariant: keys/types/classifications are project-scoped,
	// "only presence varies by environment"). Reading one slice and mapping it
	// onto several targets is what makes the session faithfully replayable — the
	// template records one scope, and a replay re-reads that one source and fans
	// it the same way.
	sel, err := wizardSelector(host, source)
	if err != nil {
		return nil, err
	}
	read, err := host.ReadSource(source, sel)
	if err != nil {
		return nil, err
	}
	if read.Result.DecodedBytes > MaxSessionDecodedBytes {
		return nil, failure(source, CodeBound, "",
			"the source read totals %d decoded bytes, exceeding the %d-byte wizard-session aggregate cap",
			read.Result.DecodedBytes, MaxSessionDecodedBytes)
	}

	existing, err := host.ExistingEnvironments()
	if err != nil {
		return nil, err
	}

	envs, err := wizardEnvironments(host, source, existing, read)
	if err != nil {
		return nil, err
	}
	if len(envs) == 0 {
		return nil, failure(source, CodeMalformed, "", "the session mapped no target environment")
	}

	tmpl := &Template{}
	// Renames are structural — no server contact.
	valuesByKey, _, err := wizardRenames(host, source, envs, tmpl)
	if err != nil {
		return nil, err
	}
	// A first presence read (with the default classification/type intent) learns
	// what the project already declares, so classification and type review can
	// skip those keys and record the EXISTING declaration as the reviewed consent.
	declared, err := wizardDeclaredSet(host, source, envs)
	if err != nil {
		return nil, err
	}
	if err := wizardClassType(host, valuesByKey, declared, tmpl); err != nil {
		return nil, err
	}
	// The second presence read carries the FINAL classification/type intent, so
	// each undeclared key's occurrence token binds the declaration the bundle
	// will actually apply — a first-read token minted before a downgrade or an
	// accepted type suggestion would be stale the moment phase 2 checked it.
	definitionsRevision, err := wizardPresence(host, source, envs, tmpl)
	if err != nil {
		return nil, err
	}
	if err := wizardCollisions(host, envs, tmpl); err != nil {
		return nil, err
	}
	if err := wizardTrim(host, envs, tmpl); err != nil {
		return nil, err
	}

	in := ProjectPlanInput{
		Source: source, Project: project, DefinitionsRevision: definitionsRevision,
		Template: tmpl,
	}
	for _, e := range envs {
		env := EnvInput{
			Records: e.read.Result.Records, Skipped: e.read.Result.Skipped,
			Scope: e.read.Result.Scope, FileDigest: e.read.FileDigest, EnvSlug: e.read.EnvSlug,
			SourceIdentity: e.read.Result.Identity, Keys: e.state.Keys,
		}
		if e.create {
			env.Create = true
			env.EnvName = e.name
		} else {
			env.EnvID = e.ref
			env.EnvName = e.name
		}
		in.Envs = append(in.Envs, env)
	}
	return BuildProjectPlan(in)
}

// wizardSource is state 1: source select. Live/file mode and the credential
// presence check ride on the connector selectors gathered per environment.
func wizardSource(host WizardHost) (string, error) {
	sources := Sources()
	i, err := host.Choose("Which source are you importing from?", sources, 0)
	if err != nil {
		return "", err
	}
	return sources[i], nil
}

// wizardEnvironments is state 3: the human maps the one source read onto one or
// more target environments — existing ones, or ones the session will create,
// declared up front. Every environment shares the same source read; only
// presence varies.
func wizardEnvironments(host WizardHost, source string, existing []NamedEnv, read SourceRead) ([]wizardEnv, error) {
	options := make([]string, 0, len(existing)+1)
	existingNames := map[string]bool{}
	for _, e := range existing {
		options = append(options, e.Name)
		existingNames[e.Name] = true
	}
	options = append(options, "+ create a new environment")

	claimed := map[string]bool{}
	var envs []wizardEnv
	for {
		add := true
		if len(envs) > 0 {
			var err error
			add, err = host.Confirm("Map another target environment?", false)
			if err != nil {
				return nil, err
			}
			if !add {
				break
			}
		}
		env, err := wizardOneEnvironment(host, source, existing, options, existingNames, claimed)
		if err != nil {
			return nil, err
		}
		env.read = read
		envs = append(envs, env)
	}
	return envs, nil
}

func wizardOneEnvironment(host WizardHost, source string, existing []NamedEnv, options []string,
	existingNames, claimed map[string]bool) (wizardEnv, error) {
	choice, err := host.Choose("Target environment:", options, 0)
	if err != nil {
		return wizardEnv{}, err
	}
	if choice == len(existing) {
		name, err := host.Line("New environment name:", "")
		if err != nil {
			return wizardEnv{}, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return wizardEnv{}, failure(source, CodeMalformed, "", "a created environment needs a name")
		}
		// A created environment must not collide with one that already exists —
		// import never modifies an environment, so `create <existing>` is a
		// contradiction, not a target — nor with one already mapped this session.
		if existingNames[name] {
			return wizardEnv{}, failure(source, CodeMalformed, "",
				"environment %s already exists; map it as an existing target rather than creating it", quoteName(name))
		}
		if claimed[name] {
			return wizardEnv{}, failure(source, CodeMalformed, "",
				"environment %s is already mapped this session", quoteName(name))
		}
		claimed[name] = true
		return wizardEnv{ref: name, name: name, create: true}, nil
	}
	e := existing[choice]
	if claimed[e.ID] {
		return wizardEnv{}, failure(source, CodeMalformed, "",
			"environment %s is already mapped this session", quoteName(e.Name))
	}
	claimed[e.ID] = true
	return wizardEnv{ref: e.ID, name: e.Name}, nil
}

// wizardSelector is state 2: the connector selectors for one source slice,
// bounded per the ops catalogue by the connector itself on read.
func wizardSelector(host WizardHost, source string) (Selector, error) {
	var sel Selector
	live := false
	if source == k8sSource || source == vaultSource {
		var err error
		live, err = host.Confirm("Read live through the ambient client configuration?", false)
		if err != nil {
			return Selector{}, err
		}
	}
	sel.Live = live
	if !live {
		file, err := host.Line("Export file path:", "")
		if err != nil {
			return Selector{}, err
		}
		sel.File = strings.TrimSpace(file)
		if source == infisicalSource {
			slug, err := host.Line("Source environment slug (Infisical):", "")
			if err != nil {
				return Selector{}, err
			}
			sel.EnvSlug = strings.TrimSpace(slug)
		}
		return sel, nil
	}
	switch source {
	case k8sSource:
		ns, err := host.Line("Kubernetes namespace:", "")
		if err != nil {
			return Selector{}, err
		}
		sel.Namespace = strings.TrimSpace(ns)
		name, err := host.Line("One Secret name (blank for all in the namespace):", "")
		if err != nil {
			return Selector{}, err
		}
		sel.Name = strings.TrimSpace(name)
	case vaultSource:
		mount, err := host.Line("Vault/OpenBao KV mount:", "")
		if err != nil {
			return Selector{}, err
		}
		sel.Mount = strings.TrimSpace(mount)
		path, err := host.Line("Path prefix (blank for the mount root):", "")
		if err != nil {
			return Selector{}, err
		}
		sel.Path = strings.TrimSpace(path)
	}
	return sel, nil
}

// wizardRenames is states 4/5's rename half: every source name is surfaced, an
// unmappable one is prompted for an explicit rename, and the choices are written
// into the template. Renames are project-wide — a source name maps to one target
// across the session. It returns each target key's values (across environments,
// for the type suggestion) and the manual-rename map (for folder computation).
func wizardRenames(host WizardHost, source string, envs []wizardEnv, tmpl *Template) (
	map[string][]string, map[string]string, error) {
	renames := map[string]TransformKind{} // source name -> transform, for template rows
	manual := map[string]string{}
	targetOf := map[string]string{} // source name -> target
	valuesByKey := map[string][]string{}
	for i := range envs {
		for _, rec := range envs[i].read.Result.Records {
			if _, done := targetOf[rec.SourceName]; done {
				valuesByKey[targetOf[rec.SourceName]] = append(valuesByKey[targetOf[rec.SourceName]], rec.Value)
				continue
			}
			target, wasValid, err := TransformName(rec.SourceName)
			if err != nil {
				// A hard-stop name: the transform cannot resolve it, so the human
				// must name it explicitly (ADR § Renames).
				host.Notice(fmt.Sprintf("%s cannot be mapped automatically.", quoteName(rec.SourceName)))
				entered, lerr := host.Line("Rename it to:", "")
				if lerr != nil {
					return nil, nil, lerr
				}
				entered = strings.TrimSpace(entered)
				if err := schema.CheckKeyName(entered); err != nil {
					return nil, nil, failure(source, CodeUnmappableName, quoteName(rec.SourceName),
						"the entered name %s is not a canonical key", quoteName(entered))
				}
				target = entered
				manual[rec.SourceName] = entered
				renames[rec.SourceName] = TransformManual
			} else if !wasValid {
				host.Notice(fmt.Sprintf("rename: %s -> %s", quoteName(rec.SourceName), quoteName(target)))
				edit, err := host.Confirm("Edit this rename?", false)
				if err != nil {
					return nil, nil, err
				}
				if edit {
					entered, err := host.Line("Rename it to:", target)
					if err != nil {
						return nil, nil, err
					}
					entered = strings.TrimSpace(entered)
					if err := schema.CheckKeyName(entered); err != nil {
						return nil, nil, failure(source, CodeUnmappableName, quoteName(rec.SourceName),
							"the entered name %s is not a canonical key", quoteName(entered))
					}
					target = entered
					manual[rec.SourceName] = entered
					renames[rec.SourceName] = TransformManual
				} else {
					renames[rec.SourceName] = TransformAuto
				}
			}
			targetOf[rec.SourceName] = target
			valuesByKey[target] = append(valuesByKey[target], rec.Value)
		}
	}
	for from, kind := range renames {
		if kind == TransformManual {
			tmpl.Renames = append(tmpl.Renames, Rename{From: from, To: manual[from], Transform: TransformManual})
		} else {
			tmpl.Renames = append(tmpl.Renames, Rename{From: from, To: targetOf[from], Transform: TransformAuto})
		}
	}
	sort.Slice(tmpl.Renames, func(i, j int) bool { return tmpl.Renames[i].From < tmpl.Renames[j].From })
	return valuesByKey, manual, nil
}

// wizardDeclaredSet performs the first presence read (default declaration
// intent) purely to learn what the project already declares. Declared keys are
// project-scoped, so one existing environment answers for the whole project;
// its tokens are not kept — the second read carries the final intent. A session
// with only created environments reads nothing (the project declares nothing an
// import would collide with, or the collision surfaces at plan time).
func wizardDeclaredSet(host WizardHost, source string, envs []wizardEnv) (map[string]KeyState, error) {
	declared := map[string]KeyState{}
	var ref string
	var records []Record
	for i := range envs {
		if !envs[i].create {
			ref = envs[i].ref
			records = envs[i].read.Result.Records
			break
		}
	}
	if ref == "" {
		return declared, nil
	}
	candidates, err := PlannedCandidates(PlanInput{Source: source, Records: records})
	if err != nil {
		return nil, err
	}
	state, err := host.Presence(ref, candidates)
	if err != nil {
		return nil, err
	}
	for _, k := range state.Keys {
		if k.Declared {
			declared[k.Name] = k
		}
	}
	return declared, nil
}

// wizardClassType is state 5's classification and typing half. For a key the
// project does NOT already declare it prompts: classification (secret default,
// explicit per-key downgrades) and a deterministic type suggestion (across the
// key's values, applied only on accept). For a key it DOES already declare, it
// records the EXISTING classification and type as the reviewed consent — the
// escape hatch the ADR means by "resolved by hand" — but only when they diverge
// from the uniform secret/string default, so a default-declared key stays
// byte-identical to a flag run (which records nothing for it).
func wizardClassType(host WizardHost, valuesByKey map[string][]string, declared map[string]KeyState,
	tmpl *Template) error {
	keys := make([]string, 0, len(valuesByKey))
	for k := range valuesByKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if existing, ok := declared[key]; ok {
			host.Notice(fmt.Sprintf("%s is already declared (%s %s); keeping the existing declaration.",
				quoteName(key), existing.Classification, existing.Type))
			// Record the existing classification/type as the reviewed consent, but
			// only where the uniform secret/string default would otherwise make the
			// planner refuse — so a default-declared key stays byte-identical to a
			// flag run. A non-declarable existing type (an any_of the imported
			// string does not satisfy) is left unrecorded on purpose: the planner
			// refuses it, which is the human's to resolve.
			if existing.Classification != "" && existing.Classification != string(schema.Secret) {
				tmpl.Classifications = append(tmpl.Classifications,
					ClassificationChoice{Key: key, Class: existing.Classification})
			}
			if existing.Type != "" && !compatibleImportedType(existing.Type, schema.TypeString) &&
				isDeclarableType(existing.Type) {
				tmpl.Types = append(tmpl.Types, TypeChoice{Key: key, Type: existing.Type, Accepted: true})
			}
			continue
		}
		class, downgraded, err := wizardClassification(host, key)
		if err != nil {
			return err
		}
		tmpl.Classifications = append(tmpl.Classifications,
			ClassificationChoice{Key: key, Class: class, Downgraded: downgraded})

		typ, err := wizardType(host, key, valuesByKey[key])
		if err != nil {
			return err
		}
		tmpl.Types = append(tmpl.Types, TypeChoice{Key: key, Type: string(typ), Accepted: true})
	}
	return nil
}

// wizardClassification is state 5's classification half: secret by default,
// downgrade to config an explicit per-key act (hints suggest, never apply).
func wizardClassification(host WizardHost, key string) (string, bool, error) {
	if hint := classificationHint(key); hint != "" {
		host.Notice(fmt.Sprintf("%s looks like it may be config (%s); it still defaults to secret.",
			quoteName(key), hint))
	}
	down, err := host.Confirm(fmt.Sprintf("Downgrade %s from secret to config?", quoteName(key)), false)
	if err != nil {
		return "", false, err
	}
	if down {
		return string(schema.Config), true, nil
	}
	return string(schema.Secret), false, nil
}

// wizardType is state 5's typing half: a deterministic suggestion across all
// environments' values, applied only on accept; the floor is string.
func wizardType(host WizardHost, key string, values []string) (schema.Type, error) {
	suggested := SuggestType(values)
	if suggested == schema.TypeString {
		return schema.TypeString, nil
	}
	accept, err := host.Confirm(fmt.Sprintf("Declare %s as %s?", quoteName(key), suggested), true)
	if err != nil {
		return "", err
	}
	if accept {
		return suggested, nil
	}
	return schema.TypeString, nil
}

// wizardPresence performs the per-environment presence read now that the target
// names, classifications and types are settled. Created environments have no
// presence read.
func wizardPresence(host WizardHost, source string, envs []wizardEnv, tmpl *Template) (int64, error) {
	var revision int64
	haveRevision := false
	for i := range envs {
		if envs[i].create {
			continue
		}
		candidates, err := PlannedCandidates(PlanInput{
			Source: source, Records: envs[i].read.Result.Records, Template: tmpl,
		})
		if err != nil {
			return 0, err
		}
		state, err := host.Presence(envs[i].ref, candidates)
		if err != nil {
			return 0, err
		}
		// Every environment's read must observe the SAME project catalogue
		// revision. A definitions change committed mid-session would make the
		// occurrence tokens across environments describe different catalogue
		// states — an incoherent manifest. Refuse it; the human re-runs.
		if haveRevision && state.DefinitionsRevision != revision {
			return 0, failure(source, CodeIncompatible, "",
				"the project's definitions revision changed during the session (%d then %d); "+
					"re-run the import so every environment is reviewed against one catalogue",
				revision, state.DefinitionsRevision)
		}
		revision = state.DefinitionsRevision
		haveRevision = true
		envs[i].state = state
	}
	return revision, nil
}

// wizardCollisions is state 7: per environment, each key already `set` is shown
// and overwrite is opt-in per key (skip by default). The enumerated selection is
// recorded in the template.
func wizardCollisions(host WizardHost, envs []wizardEnv, tmpl *Template) error {
	for i := range envs {
		e := envs[i]
		if e.create {
			continue
		}
		setKeys := map[string]bool{}
		for _, k := range e.state.Keys {
			if k.Set {
				setKeys[k.Name] = true
			}
		}
		if len(setKeys) == 0 {
			continue
		}
		names := make([]string, 0, len(setKeys))
		for n := range setKeys {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			ok, err := host.Confirm(fmt.Sprintf("%s is already set in %s; overwrite it?",
				quoteName(name), quoteName(e.name)), false)
			if err != nil {
				return err
			}
			if ok {
				tmpl.Overwrites = append(tmpl.Overwrites, KeyEnvironment{Key: name, Environment: e.ref})
			}
		}
	}
	return nil
}

// wizardTrim is state 8: a value the write-time trim would alter is refused
// unless acknowledged; the wizard asks per (key, environment) and records the
// acknowledgement in the template.
func wizardTrim(host WizardHost, envs []wizardEnv, tmpl *Template) error {
	manual := map[string]string{}
	for _, r := range tmpl.Renames {
		if r.Transform == TransformManual {
			manual[r.From] = r.To
		}
	}
	for i := range envs {
		e := envs[i]
		for _, rec := range e.read.Result.Records {
			if schema.Normalize(rec.Value) == rec.Value {
				continue
			}
			target, _, err := targetName(rec.SourceName, manual)
			if err != nil {
				return err
			}
			ack, err := host.Confirm(fmt.Sprintf(
				"%s in %s has surrounding whitespace the store would trim; import the trimmed value?",
				quoteName(target), quoteName(e.name)), false)
			if err != nil {
				return err
			}
			if !ack {
				return failure(e.read.Result.Identity, CodeTrim, quoteName(target),
					"the value would be altered by the write-time trim and was not acknowledged; fix it at the source")
			}
			tmpl.TrimAcknowledgements = append(tmpl.TrimAcknowledgements,
				KeyEnvironment{Key: target, Environment: e.ref})
		}
	}
	return nil
}

// classificationHint returns a short reason a key name looks like config, or "".
// Hints suggest a downgrade; they never apply one (ADR § Classification).
func classificationHint(key string) string {
	for _, suffix := range []string{"_URL", "_HOST", "_PORT", "_PATH", "_DIR", "_ADDR"} {
		if strings.HasSuffix(key, suffix) {
			return "name ends " + suffix
		}
	}
	if strings.Contains(key, "LOG_LEVEL") || strings.HasSuffix(key, "_ENV") {
		return "name pattern"
	}
	return ""
}
