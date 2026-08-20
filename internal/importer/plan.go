package importer

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// Phase 1's whole decision surface: rename, collide, classify, type, bucket,
// preflight, and author. It runs against the SERVER STATE phase 1 read
// (declared keys, per-environment presence, and the server-minted occurrence
// token per (key, environment)) and it authors artifacts and stops. There is no
// flag that turns two-phase off.

// KeyState is one key's phase-1 observation: what the project declares about
// it, whether it is `set` in the target environment, and the server-minted
// occurrence token naming that exact resolved state.
//
// It covers keys the project does NOT declare as well, because an import
// proposes those and phase 2 must still be able to check they did not move. For
// them Declared is false, the declaration fields are empty, and the token
// binds the intended undeclared-to-declared transition under the same scoped
// key — so every row in a run manifest is server-minted, with no
// client-authored gaps for an edited manifest to hide in.
type KeyState struct {
	Name           string
	ID             string
	Declared       bool
	Classification string
	// Type is the key catalogue's canonical textual type expression: a
	// primitive, or any_of(branch|branch). It is empty only for an undeclared
	// key.
	Type string
	// Set is the two-state presence the flat model leaves: `set` or `absent`.
	// There is no third state to carry.
	Set bool
	// Token is the server-minted opaque occurrence token for
	// (this key, this environment). Opaque to this package by construction: it
	// is copied into the manifest and never interpreted.
	Token string
}

// PlannedCandidate is the declaration intent phase 1 sends to the presence
// endpoint. The server binds these exact fields into an undeclared token; they
// are the same classification and primitive the emitted bundle line declares.
type PlannedCandidate struct {
	Name           string
	Classification string
	Type           string
}

// ServerState is everything phase 1 read from the server for ONE target
// environment. Phase 1 never requires `reveal`, never compares values and never
// writes — this struct is the whole of what it learned.
type ServerState struct {
	Project             string
	Environment         string
	DefinitionsRevision int64
	// Keys covers every key the project declares PLUS every candidate name the
	// run asked about, so a plan can mint a manifest row for each.
	Keys []KeyState
}

// PlanInput is one phase-1 run's material.
type PlanInput struct {
	Source string
	// Records and Skipped are the connector's output, already bounded.
	Records []Record
	Skipped []string
	// Scope is the connector's own source selector (k8s `{namespace, names[]}`),
	// merged with the framework's file digest and env slug into the template.
	Scope Scope
	// FileDigest and EnvSlug identify file sources. SourceIdentity is the
	// non-secret provider origin/context supplied by a live connector.
	FileDigest     string
	EnvSlug        string
	SourceIdentity string
	State          ServerState
	// Template is the replayed template, or nil in flag mode. Replay is where
	// manual renames, classification downgrades, richer types, enumerated
	// overwrites and trim acknowledgements come from — flag mode has none of
	// them by construction.
	Template *Template
}

// Plan is phase 1's result: the four artifacts plus everything the run must
// surface to the human before they review.
type Plan struct {
	Template Template
	Manifest Manifest
	Bundle   definitions.Bundle
	Values   ValuesFile

	// Renames is every source-name → target-name mapping. Nothing is renamed
	// invisibly, so this is printed in full.
	Renames []Rename
	// NearMisses are advisory: an imported name one edit from a declared one.
	NearMisses []NearMiss
	// HasValues reports whether the run writes anything at all. A run that
	// skipped every key emits no values file — an empty one is an artifact
	// phase 2 refuses by construction.
	HasValues bool
	// New and Set are the two collision buckets the flat-model ADR leaves.
	// Set is skipped by default and listed BY NAME.
	New []string
	Set []string
	// Overwritten names the `set` keys an enumerated --overwrite selection
	// admitted. Consent binds to the reviewed occurrence through the manifest.
	Overwritten []string
	// SkippedBySource are entries a connector deliberately did not import
	// (for example Infisical personal overrides or deleted Vault versions),
	// listed by name.
	SkippedBySource []string
	// PlaintextHints names keys whose source leaf was stored in plaintext. A
	// HINT: zero downgrades are performed from it.
	PlaintextHints []string
	// AlreadyDeclared names keys the project already declares COMPATIBLY. They
	// are not re-declared — an additive bundle may not modify a declaration it
	// was not computed against — and the existing declaration is what applies.
	// An INCOMPATIBLE existing declaration is not listed here; it is a refusal.
	AlreadyDeclared []string
}

// PlannedNames is the rename half of the plan, run on its own.
//
// It exists because phase 1 has a chicken-and-egg: the server mints an
// occurrence token per (key, environment) INCLUDING for keys it does not
// declare yet, and it cannot do that without knowing which names the run will
// propose — while the names come from a transform that happens client-side.
// So the transform runs first, its output is what the presence read asks
// about, and BuildPlan runs the same pass again over the answer. One function,
// called twice, rather than two that have to agree.
func PlannedNames(in PlanInput) ([]string, error) {
	candidates, err := PlannedCandidates(in)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.Name)
	}
	return names, nil
}

// PlannedCandidates performs the pre-presence half of planning. Keeping the
// declaration choice here and in BuildPlan behind desiredDeclaration prevents
// the token intent from drifting from the bundle it binds.
func PlannedCandidates(in PlanInput) ([]PlannedCandidate, error) {
	rows, _, err := mapRecords(in.Source, in.Records, in.Template)
	if err != nil {
		return nil, err
	}
	classChoice, _ := templateClassifications(in.Template)
	typeChoice, err := templateTypes(in.Template)
	if err != nil {
		return nil, err
	}
	out := make([]PlannedCandidate, 0, len(rows))
	for _, row := range rows {
		class, typ, _ := desiredDeclaration(row.target, classChoice, typeChoice)
		out = append(out, PlannedCandidate{
			Name: row.target, Classification: class, Type: string(typ),
		})
	}
	return out, nil
}

// mappedRecord is one source record bound to the target key it maps onto.
type mappedRecord struct {
	record Record
	target string
}

// mapRecords runs the rename transform and the post-transform collision check
// over every record, and returns the mapping plus the renames to surface.
//
// It collects EVERY offender before refusing. "Refusal is per-key, not
// per-import" is not satisfied by a message that happens to name one key: a
// two-hundred-key migration with four unmappable names must be four fixes in
// one edit, not four runs.
func mapRecords(source string, records []Record, template *Template) ([]mappedRecord, []Rename, error) {
	manual := map[string]string{}
	if template != nil {
		for _, r := range template.Renames {
			if r.Transform == TransformManual {
				manual[r.From] = r.To
			}
		}
	}
	var (
		rows       []mappedRecord
		renames    []Rename
		unmappable []string
		collisions []string
	)
	origin := map[string]string{} // target name -> source path that claimed it
	for _, rec := range records {
		sourcePath := recordPath(rec)
		target, transform, err := targetName(rec.SourceName, manual)
		if err != nil {
			unmappable = append(unmappable, sourcePath)
			continue
		}
		if target != rec.SourceName {
			renames = append(renames, Rename{From: rec.SourceName, To: target, Transform: transform})
		}
		// Post-transform collision is a HARD ERROR. No suffix-numbering, no
		// last-wins: two source keys landing on one target name is a decision
		// the human makes in the template, not one the tool makes silently.
		if prior, taken := origin[target]; taken {
			collisions = append(collisions,
				fmt.Sprintf("%s and %s both map onto %s", prior, sourcePath, quoteName(target)))
			continue
		}
		origin[target] = sourcePath
		rows = append(rows, mappedRecord{record: rec, target: target})
	}
	if len(unmappable) > 0 {
		slices.Sort(unmappable)
		return nil, nil, failure(source, CodeUnmappableName, "",
			"%d source name(s) fall outside the documented transform; name each one explicitly in the "+
				"mapping template's `renames`: %s", len(unmappable), strings.Join(unmappable, ", "))
	}
	if len(collisions) > 0 {
		slices.Sort(collisions)
		return nil, nil, failure(source, CodeNameCollision, "",
			"%d post-transform collision(s); resolve each with an explicit rename in the mapping template: %s",
			len(collisions), strings.Join(collisions, "; "))
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].target < rows[j].target })
	sort.SliceStable(renames, func(i, j int) bool { return renames[i].From < renames[j].From })
	return rows, renames, nil
}

// BuildPlan runs the phase-1 decision surface for a single (project,
// environment) — flag mode and single-environment replay. It is a thin wrapper
// over BuildProjectPlan with exactly one target environment, so a flag/replay
// run and a single-environment wizard session author byte-identical artifacts:
// there is one planner, reached two ways.
func BuildPlan(in PlanInput) (*Plan, error) {
	if in.State.Project == "" || in.State.Environment == "" {
		return nil, failure("import", CodeMalformed, "",
			"a phase-1 plan targets exactly one (project, environment)")
	}
	project, err := BuildProjectPlan(ProjectPlanInput{
		Source:              in.Source,
		Project:             in.State.Project,
		DefinitionsRevision: in.State.DefinitionsRevision,
		Template:            in.Template,
		Envs: []EnvInput{{
			Records: in.Records, Skipped: in.Skipped, Scope: in.Scope,
			FileDigest: in.FileDigest, EnvSlug: in.EnvSlug, SourceIdentity: in.SourceIdentity,
			EnvID: in.State.Environment, Keys: in.State.Keys,
		}},
	})
	if err != nil {
		return nil, err
	}
	return project.single(), nil
}

// EnvInput is one target environment's phase-1 material inside a session. A
// created environment carries no server-read Keys (it does not exist yet) and
// is addressed by EnvName; an existing environment is addressed by EnvID and
// carries the presence read the server returned for it.
type EnvInput struct {
	Records        []Record
	Skipped        []string
	Scope          Scope
	FileDigest     string
	EnvSlug        string
	SourceIdentity string
	// EnvID is the server-owned id of an existing target environment. Empty for
	// a created environment.
	EnvID string
	// EnvName is the environment's portable name. Required for a created
	// environment (which has no id yet); optional otherwise.
	EnvName string
	// Create marks an environment the session will create at phase 2 through the
	// bundle's `create environment` line. Created environments are tokenless by
	// construction: no presence read happened, so no occurrence is bound and the
	// manifest names them without an id (docs/handoff/112-import-wizard.md).
	Create bool
	// Keys is the per-environment presence read. Empty for a created environment.
	Keys []KeyState
}

// ProjectPlanInput is one phase-1 session's whole material: one source, one
// project, and one or more target environments. Keys, types and classifications
// are project-scoped and reconciled to one canonical identity per key across the
// fan-out; only presence — the buckets and the values written — varies by
// environment (import-paths ADR § The two-phase invariant).
type ProjectPlanInput struct {
	Source              string
	Project             string
	DefinitionsRevision int64
	Template            *Template
	Envs                []EnvInput
}

// EnvPlan is one environment's slice of a project plan: its buckets and its
// values file.
type EnvPlan struct {
	EnvID   string
	EnvName string
	Create  bool
	// New and Set are the two collision buckets the flat-model ADR leaves, for
	// this environment. Set is skipped by default and listed by name.
	New []string
	Set []string
	// Overwritten names the `set` keys an enumerated overwrite selection admitted
	// in this environment.
	Overwritten []string
	Values      ValuesFile
	// HasValues reports whether this environment's values file carries anything.
	HasValues bool
}

// ProjectPlan is a whole session's result: the four artifact families, with one
// project-wide bundle and manifest and one values file per environment that
// writes anything.
type ProjectPlan struct {
	Template Template
	Manifest Manifest
	Bundle   definitions.Bundle
	Envs     []EnvPlan

	Renames         []Rename
	NearMisses      []NearMiss
	SkippedBySource []string
	PlaintextHints  []string
	AlreadyDeclared []string
}

// single collapses a one-environment project plan into the legacy single-env
// Plan the flag/replay CLI and the conformance harness consume. The artifact
// bytes are the project plan's own, so a single-environment wizard session and
// a flag run produce identical Template, Bundle and Manifest.
func (p *ProjectPlan) single() *Plan {
	env := p.Envs[0]
	return &Plan{
		Template: p.Template, Manifest: p.Manifest, Bundle: p.Bundle,
		Values: env.Values, HasValues: env.HasValues,
		Renames: p.Renames, NearMisses: p.NearMisses,
		New: env.New, Set: env.Set, Overwritten: env.Overwritten,
		SkippedBySource: p.SkippedBySource, PlaintextHints: p.PlaintextHints,
		AlreadyDeclared: p.AlreadyDeclared,
	}
}

// keyDecision is the project-scoped, per-key reconciled decision: one identity,
// classification, type and folder, canonical across every environment the key
// appears in.
type keyDecision struct {
	target       string
	class        string
	declType     schema.Type
	typeSupplied bool
	downgraded   bool
	folder       string
	declared     bool // an existing compatible declaration governs; not re-declared
}

// BuildProjectPlan runs the whole phase-1 decision surface across one or more
// target environments. Keys, classifications and types are decided once,
// project-wide, and reconciled to one canonical identity per key; each key's
// folder must agree across every environment it appears in. Buckets, values,
// occurrences and source versions are then decided per environment.
func BuildProjectPlan(in ProjectPlanInput) (*ProjectPlan, error) {
	if in.Source == "" {
		return nil, failure("import", CodeMalformed, "", "a phase-1 plan names no source")
	}
	if in.Project == "" {
		return nil, failure("import", CodeMalformed, "",
			"a phase-1 plan targets exactly one (project, environment)")
	}
	if len(in.Envs) == 0 {
		return nil, failure(in.Source, CodeMalformed, "",
			"a phase-1 plan targets at least one environment")
	}
	for i := range in.Envs {
		e := &in.Envs[i]
		if e.Create && e.EnvName == "" {
			return nil, failure(in.Source, CodeMalformed, "",
				"a created environment is named, not id'd")
		}
		if !e.Create && e.EnvID == "" {
			return nil, failure(in.Source, CodeMalformed, "",
				"a phase-1 plan targets exactly one (project, environment)")
		}
	}

	classChoice, downgraded := templateClassifications(in.Template)
	typeChoice, err := templateTypes(in.Template)
	if err != nil {
		return nil, err
	}
	recordedFolders, err := templateFolders(in.Template)
	if err != nil {
		return nil, err
	}

	// Per-environment name mapping, and the project-wide declared-key set. A key
	// is declared for the project if any environment's read reports it declared;
	// the declaration is project-scoped, so the fields agree across environments.
	declaredNames := map[string]bool{}
	declaredState := map[string]KeyState{}
	envRows := make([][]mappedRecord, len(in.Envs))
	var renames []Rename
	renameSeen := map[string]bool{}
	for i, e := range in.Envs {
		rows, envRenames, err := mapRecords(in.Source, e.Records, in.Template)
		if err != nil {
			return nil, err
		}
		envRows[i] = rows
		for _, r := range envRenames {
			if !renameSeen[r.From] {
				renameSeen[r.From] = true
				renames = append(renames, r)
			}
		}
		for _, k := range e.Keys {
			if k.Declared {
				declaredNames[k.Name] = true
				declaredState[k.Name] = k
			}
		}
	}
	sort.SliceStable(renames, func(i, j int) bool { return renames[i].From < renames[j].From })

	// The project pass: one reconciled decision per key, in sorted target order.
	// Folder is computed per environment (root-collapse is a per-source fact) and
	// must reconcile to one value — the bundle carries one folder_path per key.
	decisions, order, folders, plaintextHints, err := reconcileKeys(in, envRows, recordedFolders,
		classChoice, downgraded, typeChoice, declaredState)
	if err != nil {
		return nil, err
	}

	plan := &ProjectPlan{
		SkippedBySource: mergeSkipped(in.Envs),
		Renames:         renames,
		PlaintextHints:  plaintextHints,
	}
	plan.Bundle = definitions.Bundle{
		FormatVersion: definitions.FormatVersion,
		Environments:  []definitions.Environment{},
		KeyGroups:     []definitions.KeyGroup{},
		Keys:          []definitions.Key{},
	}

	var importedNames []string
	for _, target := range order {
		d := decisions[target]
		importedNames = append(importedNames, target)
		if d.declared {
			plan.AlreadyDeclared = append(plan.AlreadyDeclared, target)
		} else {
			rule := schema.Rule{Type: d.declType}
			plan.Bundle.Keys = append(plan.Bundle.Keys, definitions.Key{
				Name:           target,
				FolderPath:     d.folder,
				Classification: d.class,
				Declaration:    schema.Declaration{Rule: &rule},
				RequiredIn:     definitions.Presence{Mode: string(schema.PresenceNone), Environments: []string{}},
				ForbiddenIn:    definitions.Presence{Mode: string(schema.PresenceNone), Environments: []string{}},
			})
		}
		plan.Template.Classifications = append(plan.Template.Classifications,
			ClassificationChoice{Key: target, Class: d.class, Downgraded: d.downgraded})
		// For an already-declared key, absence of a template type row means the
		// existing declaration governs; recording the default `string` would
		// fabricate consent the template author never supplied.
		if !d.declared || d.typeSupplied {
			plan.Template.Types = append(plan.Template.Types,
				TypeChoice{Key: target, Type: string(d.declType), Accepted: true})
		}
	}

	sortedDeclared := make([]string, 0, len(declaredNames))
	for name := range declaredNames {
		sortedDeclared = append(sortedDeclared, name)
	}
	slices.Sort(sortedDeclared)
	plan.NearMisses = NearMisses(importedNames, sortedDeclared)

	// The per-environment pass: buckets, values, occurrences and trim preflight.
	var trimOffenders []string
	trimSeen := map[string]bool{}
	for i := range in.Envs {
		e := in.Envs[i]
		envPlan, err := planEnvironment(in, e, envRows[i], decisions, &trimOffenders, trimSeen)
		if err != nil {
			return nil, err
		}
		plan.Envs = append(plan.Envs, envPlan)
	}
	if len(trimOffenders) > 0 {
		slices.Sort(trimOffenders)
		return nil, failure(in.Source, CodeTrim, "",
			"the write-time trim would alter %d value(s); acknowledge each key in the mapping template's "+
				"`trim_acknowledgements`, or fix the values at the source: %s",
			len(trimOffenders), strings.Join(trimOffenders, ", "))
	}

	plan.Template = buildTemplate(in, plan.Template, plan.Renames, folders, plan.Envs)

	encoded, err := Encode(plan.Template)
	if err != nil {
		return nil, err
	}
	plan.Manifest, err = buildManifest(in, encoded, envRows, decisions)
	if err != nil {
		return nil, err
	}
	// Created environments are explicit, reviewable bundle lines (ADR § Targeting
	// and hierarchy creation): `definitions apply` creates them. Deduped and
	// sorted so the bundle is byte-stable.
	seenEnv := map[string]bool{}
	var created []string
	for _, e := range in.Envs {
		if e.Create && !seenEnv[e.EnvName] {
			seenEnv[e.EnvName] = true
			created = append(created, e.EnvName)
		}
	}
	slices.Sort(created)
	for _, name := range created {
		plan.Bundle.Environments = append(plan.Bundle.Environments, definitions.Environment{Name: name})
	}
	plan.Bundle, err = definitions.Normalize(plan.Bundle)
	if err != nil {
		return nil, fmt.Errorf("import: normalizing definitions bundle: %w", err)
	}
	return plan, nil
}

// reconcileKeys makes the project-scoped, per-key decision across every
// environment. It returns the decisions keyed by target, the sorted target
// order, the folder rows for the template, the plaintext hints, or a refusal —
// an existing declaration this import disagrees with, or a key whose folder
// differs between environments (two environments proposing one key under two
// folders is the reconciliation conflict the wizard resolves interactively and
// flag mode cannot reach, since flag mode has one environment).
func reconcileKeys(in ProjectPlanInput, envRows [][]mappedRecord, recordedFolders map[string]string,
	classChoice map[string]string, downgraded map[string]bool, typeChoice map[string]schema.Type,
	declaredState map[string]KeyState) (map[string]keyDecision, []string, map[string]string, []string, error) {
	decisions := map[string]keyDecision{}
	var order []string
	folders := map[string]string{}
	folderOf := map[string]string{} // target key -> reconciled folder
	plaintextSeen := map[string]bool{}
	var plaintextHints []string
	var incompatible []string
	var folderConflicts []string

	for i, rows := range envRows {
		rootCollapse := in.Source == k8sSource && singleSourceFolder(in.Envs[i].Records)
		for _, row := range rows {
			rec, target := row.record, row.target
			sourcePath := recordPath(rec)

			sourceFolder := strings.Join(rec.Folder, "/")
			targetFolder, ok := recordedFolders[sourceFolder]
			if !ok {
				if len(recordedFolders) > 0 {
					return nil, nil, nil, nil, failure(in.Source, CodeMalformed, sourcePath,
						"the mapping template records no folder for source path %s; a replay against a source with "+
							"folders the template never saw is a different mapping, not the same one",
						quoteName(sourceFolder))
				}
				var err error
				if targetFolder, err = targetFolderPath(rec.Folder, rootCollapse); err != nil {
					return nil, nil, nil, nil, err
				}
			}
			if prior, seen := folderOf[target]; seen && prior != targetFolder {
				folderConflicts = append(folderConflicts, fmt.Sprintf(
					"%s maps onto folder %s and %s in different environments",
					quoteName(target), quoteName(prior), quoteName(targetFolder)))
				continue
			}
			folderOf[target] = targetFolder
			folders[sourceFolder] = targetFolder

			if rec.PlaintextHint && !plaintextSeen[target] {
				plaintextSeen[target] = true
				plaintextHints = append(plaintextHints, target)
			}

			if _, done := decisions[target]; done {
				continue
			}
			class, declType, typeSupplied := desiredDeclaration(target, classChoice, typeChoice)
			existing, isDeclared := declaredState[target]
			declared := false
			if isDeclared {
				switch {
				case existing.Classification != class:
					incompatible = append(incompatible, fmt.Sprintf(
						"%s is declared `%s` but this import would declare `%s`",
						quoteName(target), existing.Classification, class))
					continue
				case !compatibleImportedType(existing.Type, declType):
					incompatible = append(incompatible, fmt.Sprintf(
						"%s is declared type `%s` but this import would declare `%s`",
						quoteName(target), existing.Type, declType))
					continue
				}
				declared = true
			}
			decisions[target] = keyDecision{
				target: target, class: class, declType: declType, typeSupplied: typeSupplied,
				downgraded: downgraded[target], folder: targetFolder, declared: declared,
			}
			order = append(order, target)
		}
	}
	// A key seen first under a conflicting folder still has its decision folder
	// from the first environment; the conflict list forces a refusal regardless,
	// so a stale folder in a discarded decision never reaches an artifact.
	if len(incompatible) > 0 {
		slices.Sort(incompatible)
		return nil, nil, nil, nil, failure(in.Source, CodeIncompatible, "",
			"%d key(s) already carry a declaration this import disagrees with; import never modifies a "+
				"declaration, so resolve each by declaring the existing classification and type for that key "+
				"in the mapping template, or by reclassifying the key first: %s",
			len(incompatible), strings.Join(incompatible, "; "))
	}
	if len(folderConflicts) > 0 {
		slices.Sort(folderConflicts)
		return nil, nil, nil, nil, failure(in.Source, CodeIncompatible, "",
			"%d key(s) reconcile to different folders across environments; one bundle declares one folder per "+
				"key, so resolve each with an explicit folder in the mapping template: %s",
			len(folderConflicts), strings.Join(folderConflicts, "; "))
	}
	slices.Sort(order)
	return decisions, order, folders, plaintextHints, nil
}

// planEnvironment decides one environment's buckets and values. Trim offenders
// are collected project-wide (deduped by key) so the refusal names them once.
func planEnvironment(in ProjectPlanInput, e EnvInput, rows []mappedRecord, decisions map[string]keyDecision,
	trimOffenders *[]string, trimSeen map[string]bool) (EnvPlan, error) {
	envID := e.EnvID
	envRef := envID
	if e.Create {
		envRef = e.EnvName
	}
	overwrite := templateOverwrites(in.Template, envRef)
	trimAck := templateTrimAcks(in.Template, envRef)

	state := make(map[string]KeyState, len(e.Keys))
	for _, k := range e.Keys {
		state[k.Name] = k
	}

	envPlan := EnvPlan{EnvID: envID, EnvName: e.EnvName, Create: e.Create}
	envPlan.Values = ValuesFile{
		FormatVersion: FormatVersion,
		Project:       in.Project,
	}
	// A created environment has no id at phase 1, so its values file carries the
	// name; `values import` resolves it after `definitions apply`.
	if e.Create {
		envPlan.Values.EnvironmentName = e.EnvName
	} else {
		envPlan.Values.Environment = envID
	}
	for _, row := range rows {
		rec, target := row.record, row.target
		if _, planned := decisions[target]; !planned {
			// The key was dropped in reconciliation (a folder conflict), which is
			// already a refusal; never reachable on the success path.
			continue
		}
		if schema.Normalize(rec.Value) != rec.Value && !trimAck[target] {
			if !trimSeen[target] {
				trimSeen[target] = true
				*trimOffenders = append(*trimOffenders, quoteName(target))
			}
			continue
		}
		// A created environment has no prior state: every key is absent, so it is
		// `new` and there is nothing to overwrite.
		existing := state[target]
		switch {
		case existing.Set && !overwrite[target]:
			envPlan.Set = append(envPlan.Set, target)
			continue
		case existing.Set:
			envPlan.Set = append(envPlan.Set, target)
			envPlan.Overwritten = append(envPlan.Overwritten, target)
		default:
			envPlan.New = append(envPlan.New, target)
		}
		envPlan.Values.Entries = append(envPlan.Values.Entries, ValuesEntry{Key: target, Value: rec.Value})
	}
	envPlan.HasValues = len(envPlan.Values.Entries) > 0
	return envPlan, nil
}

// buildTemplate assembles the mapping template. Flag mode records its effective
// template identically to a wizard session, so a flag-mode run is replayable
// without ceremony.
func buildTemplate(in ProjectPlanInput, tmpl Template, renames []Rename, folders map[string]string,
	envs []EnvPlan) Template {
	tmpl.FormatVersion = FormatVersion
	tmpl.ConnectorContractVersion = ConnectorContractVersion
	tmpl.Source = in.Source
	tmpl.Project = in.Project
	// The scope is one connector read's shape. A single-environment session (flag
	// mode, single-env replay, or a one-target wizard) records the read it made;
	// a multi-environment session records the first environment's read as the
	// representative scope, with per-environment source slices carried on the
	// environment rows.
	first := in.Envs[0]
	tmpl.Scope = first.Scope
	tmpl.Scope.FileDigest = first.FileDigest
	if first.EnvSlug != "" {
		tmpl.Scope.EnvSlug = first.EnvSlug
	}
	tmpl.Environments = nil
	for _, e := range in.Envs {
		target := e.EnvID
		if e.Create {
			target = e.EnvName
		}
		tmpl.Environments = append(tmpl.Environments, EnvironmentMapping{
			Source: sourceEnvironment(e.EnvSlug),
			Target: target,
			Create: e.Create,
		})
	}
	tmpl.Folders = folderRows(folders)
	if tmpl.Renames == nil {
		tmpl.Renames = renames
	}
	// Overwrites and trim acknowledgements are per (key, environment). The
	// overwrite rows record what was actually admitted this run; the trim rows
	// re-state the input template's acknowledgements for the environment they
	// applied to. Grouped by environment (input order), sorted by key within.
	tmpl.Overwrites = nil
	tmpl.TrimAcknowledgements = nil
	for i, e := range in.Envs {
		envRef := e.EnvID
		if e.Create {
			envRef = e.EnvName
		}
		for _, name := range envs[i].Overwritten {
			tmpl.Overwrites = append(tmpl.Overwrites, KeyEnvironment{Key: name, Environment: envRef})
		}
		acks := make([]string, 0)
		for name := range templateTrimAcks(in.Template, envRef) {
			acks = append(acks, name)
		}
		slices.Sort(acks)
		for _, name := range acks {
			tmpl.TrimAcknowledgements = append(tmpl.TrimAcknowledgements,
				KeyEnvironment{Key: name, Environment: envRef})
		}
	}
	emptySlices(&tmpl)
	return tmpl
}

// buildManifest assembles the run manifest: the bound record of the run and the
// phase-2 precondition. Every key a run touches in an existing environment gets
// a server-minted occurrence row — including skipped ones, so a later overwrite
// re-run reviews the same occurrences it was shown. Created environments are
// tokenless: they contribute no occurrence rows and are named without an id.
func buildManifest(in ProjectPlanInput, encodedTemplate []byte, envRows [][]mappedRecord,
	decisions map[string]keyDecision) (Manifest, error) {
	first := in.Envs[0]
	m := Manifest{
		FormatVersion:            FormatVersion,
		ConnectorContractVersion: ConnectorContractVersion,
		Template:                 TemplateReference{Digest: Digest(encodedTemplate)},
		SourceIdentity:           SourceIdentity{Kind: in.Source, Context: sourceContext(first)},
		Target:                   Target{Project: in.Project},
		DefinitionsRevision:      in.DefinitionsRevision,
		PhaseCompletion:          PhaseCompletion{Authored: true, Applied: false, Imported: map[string]bool{}},
	}
	keyID := map[string]*string{}
	var keyOrder []string
	var missing []string
	for i, e := range in.Envs {
		envRef := e.EnvID
		if e.Create {
			// Created environments are named, not id'd, and sit in a distinct
			// field: they are tokenless (no presence read happened), so they
			// contribute no occurrence row and are outside the precondition.
			envRef = e.EnvName
			m.Target.CreatedEnvironments = append(m.Target.CreatedEnvironments, e.EnvName)
		} else {
			m.Target.Environments = append(m.Target.Environments, e.EnvID)
		}
		m.PhaseCompletion.Imported[envRef] = false
		state := make(map[string]KeyState, len(e.Keys))
		for _, k := range e.Keys {
			state[k.Name] = k
		}
		for _, row := range envRows[i] {
			key := row.target
			if _, planned := decisions[key]; !planned {
				continue
			}
			if _, seen := keyID[key]; !seen {
				keyOrder = append(keyOrder, key)
				keyID[key] = nil
			}
			if e.Create {
				// Tokenless by construction: no presence read, so no occurrence.
				continue
			}
			observed, ok := state[key]
			if !ok {
				missing = append(missing, quoteName(key))
				continue
			}
			if observed.Declared {
				id := observed.ID
				keyID[key] = &id
			}
			m.Occurrences = append(m.Occurrences, ManifestOccurrence{
				Key: key, Environment: e.EnvID, Token: observed.Token,
			})
			if row.record.Version != "" {
				m.SourceVersions = append(m.SourceVersions, SourceVersion{
					Key: key, Environment: e.EnvID, Version: row.record.Version,
				})
			}
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return Manifest{}, failure(in.Source, CodeMalformed, "",
			"the presence read returned no occurrence for %d planned key(s): %s — phase 1 must ask about "+
				"every key it plans", len(missing), strings.Join(missing, ", "))
	}
	for _, key := range keyOrder {
		m.Target.Keys = append(m.Target.Keys, TargetKey{Name: key, ID: keyID[key]})
	}
	m.Target.Environments = nonNil(m.Target.Environments)
	m.SourceVersions = nonNil(m.SourceVersions)
	m.Occurrences = nonNil(m.Occurrences)
	return m, nil
}

// mergeSkipped unions the per-environment source-skip lists, deduped and sorted.
func mergeSkipped(envs []EnvInput) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range envs {
		for _, name := range e.Skipped {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

func sourceContext(e EnvInput) string {
	if e.SourceIdentity != "" {
		return e.SourceIdentity
	}
	return e.FileDigest
}

func desiredDeclaration(target string, classChoice map[string]string,
	typeChoice map[string]schema.Type) (string, schema.Type, bool) {
	class := string(schema.Secret)
	if chosen := classChoice[target]; chosen != "" {
		class = chosen
	}
	typ, supplied := typeChoice[target]
	if !supplied {
		typ = schema.TypeString
	}
	return class, typ, supplied
}

// compatibleImportedType applies the phase-1 compatibility rule to the key
// catalogue's canonical textual expression. The imported primitive must equal
// the declaration or be one branch of its any_of union.
func compatibleImportedType(declared string, imported schema.Type) bool {
	if declared == string(imported) {
		return true
	}
	const prefix = "any_of("
	if !strings.HasPrefix(declared, prefix) || !strings.HasSuffix(declared, ")") {
		return false
	}
	for _, branch := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(declared, prefix), ")"), "|") {
		if branch == string(imported) {
			return true
		}
	}
	return false
}

// targetName applies the template's manual rename if there is one, else the
// documented transform.
func targetName(source string, manual map[string]string) (string, TransformKind, error) {
	if to, ok := manual[source]; ok {
		if err := schema.CheckKeyName(to); err != nil {
			return "", "", failure("import", CodeUnmappableName, quoteName(source),
				"the template renames it to %s, which the canonical grammar refuses", quoteName(to))
		}
		return to, TransformManual, nil
	}
	target, _, err := TransformName(source)
	if err != nil {
		return "", "", err
	}
	return target, TransformAuto, nil
}

// targetFolderPath maps a source folder chain onto a Hikyo folder path. The
// single-container case takes the environment root.
//
// Segments are NOT transformed: a folder is display grouping, and its namespace
// grammar (no control characters, no `.`/`..`, no edge whitespace) is a
// different grammar from the key one. A segment the folder grammar cannot hold
// is a hard stop for the same reason an unmappable key name is.
func targetFolderPath(folder []string, single bool) (string, error) {
	if single || len(folder) == 0 {
		return "", nil
	}
	for _, seg := range folder {
		switch {
		case seg == "", seg == ".", seg == "..":
			return "", failure("import", CodeUnmappableName, quoteName(strings.Join(folder, "/")),
				"a folder path segment is empty or reserved")
		case strings.TrimSpace(seg) != seg:
			return "", failure("import", CodeUnmappableName, quoteName(strings.Join(folder, "/")),
				"a folder path segment has leading or trailing whitespace")
		case strings.ContainsAny(seg, "/"):
			return "", failure("import", CodeUnmappableName, quoteName(strings.Join(folder, "/")),
				"a folder path segment contains a separator")
		}
	}
	return strings.Join(folder, "/"), nil
}

// singleSourceFolder reports whether every record sits under one source
// container — the case where a folder named after that container groups nothing.
func singleSourceFolder(records []Record) bool {
	seen := map[string]bool{}
	for _, r := range records {
		seen[strings.Join(r.Folder, "/")] = true
		if len(seen) > 1 {
			return false
		}
	}
	return len(seen) == 1
}

func folderRows(m map[string]string) []FolderMapping {
	out := make([]FolderMapping, 0, len(m))
	for source, target := range m {
		out = append(out, FolderMapping{SourcePath: source, TargetPath: target})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourcePath < out[j].SourcePath })
	return out
}

func sourceEnvironment(slug string) *string {
	if slug == "" {
		return nil
	}
	s := slug
	return &s
}

func templateOverwrites(t *Template, env string) map[string]bool {
	out := map[string]bool{}
	if t == nil {
		return out
	}
	for _, o := range t.Overwrites {
		if o.Environment == env {
			out[o.Key] = true
		}
	}
	return out
}

func templateTrimAcks(t *Template, env string) map[string]bool {
	out := map[string]bool{}
	if t == nil {
		return out
	}
	for _, a := range t.TrimAcknowledgements {
		if a.Environment == env {
			out[a.Key] = true
		}
	}
	return out
}

func templateClassifications(t *Template) (map[string]string, map[string]bool) {
	class := map[string]string{}
	down := map[string]bool{}
	if t == nil {
		return class, down
	}
	for _, c := range t.Classifications {
		class[c.Key] = c.Class
		down[c.Key] = c.Downgraded
	}
	return class, down
}

// templateTypes reads the template's per-key type declarations.
//
// `accepted: false` is REFUSED rather than ignored. The field records that a
// human accepted a suggestion, and the wizard writes it; a row that says the
// type was never accepted and yet declares one is malformed intent, and
// applying it anyway would make the flag decorative — the same
// "appears to enforce something and does not" failure the declaration
// vocabulary refuses everywhere.
func templateTypes(t *Template) (map[string]schema.Type, error) {
	out := map[string]schema.Type{}
	if t == nil {
		return out, nil
	}
	var unaccepted []string
	for _, ty := range t.Types {
		if !ty.Accepted {
			unaccepted = append(unaccepted, quoteName(ty.Key))
			continue
		}
		out[ty.Key] = schema.Type(ty.Type)
	}
	if len(unaccepted) > 0 {
		slices.Sort(unaccepted)
		return nil, failure("import", CodeMalformed, "mapping.json",
			"%d type declaration(s) carry `accepted: false`, which records that nobody accepted them; "+
				"remove the row or set it true: %s", len(unaccepted), strings.Join(unaccepted, ", "))
	}
	return out, nil
}

// templateFolders reads the template's recorded folder choices. A replay honors
// them rather than recomputing: the template is the record of every CHOICE, and
// a folder mapping recomputed behind the operator's back is a choice the
// artifact claims to have recorded and did not.
func templateFolders(t *Template) (map[string]string, error) {
	out := map[string]string{}
	if t == nil {
		return out, nil
	}
	for _, f := range t.Folders {
		if prior, dup := out[f.SourcePath]; dup && prior != f.TargetPath {
			return nil, failure("import", CodeMalformed, "mapping.json",
				"source path %s is mapped onto two different folders", quoteName(f.SourcePath))
		}
		out[f.SourcePath] = f.TargetPath
	}
	return out, nil
}

// emptySlices makes every list member non-nil before serialization, through the
// one shared helper.
func emptySlices(t *Template) {
	t.Environments = nonNil(t.Environments)
	t.Folders = nonNil(t.Folders)
	t.Renames = nonNil(t.Renames)
	t.Classifications = nonNil(t.Classifications)
	t.Types = nonNil(t.Types)
	t.Overwrites = nonNil(t.Overwrites)
	t.TrimAcknowledgements = nonNil(t.TrimAcknowledgements)
	t.Scope.Names = nonNil(t.Scope.Names)
}

// PlaintextWarning is the phrase every phase-1 run ends with. The source-of-
// truth ADR requires the source-still-on-disk warning; the import-paths ADR extends
// it to the emitted values files, which sit there until `values import`
// completes and the human deletes them.
func PlaintextWarning(sourcePath string, valuesFiles []string) string {
	paths := make([]string, 0, len(valuesFiles)+1)
	if sourcePath != "" {
		paths = append(paths, sourcePath)
	}
	paths = append(paths, valuesFiles...)
	if len(paths) == 0 {
		return "no import plaintext artifact remains on disk"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "plaintext is still on disk: %s", strings.Join(paths, ", "))
	b.WriteString("\ndelete them once `hikyo values import` has completed.")
	return b.String()
}
