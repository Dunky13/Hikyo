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
	rows, _, err := mapRecords(in)
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
func mapRecords(in PlanInput) ([]mappedRecord, []Rename, error) {
	manual := map[string]string{}
	if in.Template != nil {
		for _, r := range in.Template.Renames {
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
	for _, rec := range in.Records {
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
		return nil, nil, failure(in.Source, CodeUnmappableName, "",
			"%d source name(s) fall outside the documented transform; name each one explicitly in the "+
				"mapping template's `renames`: %s", len(unmappable), strings.Join(unmappable, ", "))
	}
	if len(collisions) > 0 {
		slices.Sort(collisions)
		return nil, nil, failure(in.Source, CodeNameCollision, "",
			"%d post-transform collision(s); resolve each with an explicit rename in the mapping template: %s",
			len(collisions), strings.Join(collisions, "; "))
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].target < rows[j].target })
	sort.SliceStable(renames, func(i, j int) bool { return renames[i].From < renames[j].From })
	return rows, renames, nil
}

// BuildPlan runs the whole phase-1 decision surface.
func BuildPlan(in PlanInput) (*Plan, error) {
	if in.State.Project == "" || in.State.Environment == "" {
		return nil, failure("import", CodeMalformed, "",
			"a phase-1 plan targets exactly one (project, environment)")
	}
	state := make(map[string]KeyState, len(in.State.Keys))
	declaredNames := make([]string, 0, len(in.State.Keys))
	for _, k := range in.State.Keys {
		state[k.Name] = k
		if k.Declared {
			declaredNames = append(declaredNames, k.Name)
		}
	}
	slices.Sort(declaredNames)

	rows, renames, err := mapRecords(in)
	if err != nil {
		return nil, err
	}
	plan := &Plan{SkippedBySource: append([]string{}, in.Skipped...), Renames: renames}

	// One Secret -> one folder named after the Secret; a SINGLE-Secret import
	// may target the environment root. That provision is the K8S ROW's and no
	// other: a SOPS file's top-level map and an Infisical `secretPath` are
	// folder structure the source states outright, and collapsing them because
	// this particular export happened to have one branch would silently flatten
	// a tree the operator will grow tomorrow.
	rootCollapse := in.Source == k8sSource && singleSourceFolder(in.Records)

	overwrite := templateOverwrites(in.Template, in.State.Environment)
	trimAck := templateTrimAcks(in.Template, in.State.Environment)
	classChoice, downgraded := templateClassifications(in.Template)
	typeChoice, err := templateTypes(in.Template)
	if err != nil {
		return nil, err
	}
	recordedFolders, err := templateFolders(in.Template)
	if err != nil {
		return nil, err
	}

	var (
		importedNames []string
		folders       = map[string]string{}
		trimOffenders []string
		incompatible  []string
	)
	plan.Values = ValuesFile{
		FormatVersion: FormatVersion,
		Project:       in.State.Project,
		Environment:   in.State.Environment,
	}
	plan.Bundle = definitions.Bundle{
		FormatVersion: definitions.FormatVersion,
		Environments:  []definitions.Environment{},
		KeyGroups:     []definitions.KeyGroup{},
		Keys:          []definitions.Key{},
	}

	for _, row := range rows {
		rec, target := row.record, row.target
		sourcePath := recordPath(rec)
		importedNames = append(importedNames, target)
		if rec.PlaintextHint {
			plan.PlaintextHints = append(plan.PlaintextHints, target)
		}

		// Write-time trim preflight. The schema layer trims edge whitespace on
		// write, so a certificate with a trailing newline or a padded token
		// would import CHANGED, silently. Every offender is collected; the
		// refusal names them all, so one template edit acknowledges the lot.
		if schema.Normalize(rec.Value) != rec.Value && !trimAck[target] {
			trimOffenders = append(trimOffenders, quoteName(target))
			continue
		}

		// Folder mapping. A source path maps onto a folder chain; the k8s
		// single-container case takes the environment root. A replayed template
		// that RECORDED a folder choice wins — the template is the record of
		// every choice, and silently recomputing one makes it a suggestion.
		sourceFolder := strings.Join(rec.Folder, "/")
		targetFolder, ok := recordedFolders[sourceFolder]
		if !ok {
			if len(recordedFolders) > 0 {
				return nil, failure(in.Source, CodeMalformed, sourcePath,
					"the mapping template records no folder for source path %s; a replay against a source with "+
						"folders the template never saw is a different mapping, not the same one",
					quoteName(sourceFolder))
			}
			if targetFolder, err = targetFolderPath(rec.Folder, rootCollapse); err != nil {
				return nil, err
			}
		}
		folders[sourceFolder] = targetFolder

		// Classification and type.
		//
		// EVERY IMPORTED KEY DEFAULTS `secret`, from every source. The only
		// thing that can move it is an explicit per-key template downgrade.
		class, declType, typeSupplied := desiredDeclaration(target, classChoice, typeChoice)
		wasDowngraded := downgraded[target]

		// An EXISTING declaration is not modified — an additive bundle may not —
		// so a declaration that disagrees with what this import would declare is
		// a conflict the human resolves, not one the importer absorbs. Refusing
		// here rather than at phase 2 is the same refusal one command earlier,
		// and it closes the case where a secret-store value lands quietly under
		// a `config` declaration that every plain-`read` holder can see.
		//
		// The escape hatch is the template line itself: a template that declares
		// `config` for this key IS the reviewed, recorded, committable consent
		// the ADR means by "resolved by hand".
		existing, isDeclared := state[target]
		if isDeclared && existing.Declared {
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
			plan.AlreadyDeclared = append(plan.AlreadyDeclared, target)
		} else {
			rule := schema.Rule{Type: declType}
			plan.Bundle.Keys = append(plan.Bundle.Keys, definitions.Key{
				Name:           target,
				FolderPath:     targetFolder,
				Classification: class,
				Declaration:    schema.Declaration{Rule: &rule},
				RequiredIn: definitions.Presence{
					Mode:         string(schema.PresenceNone),
					Environments: []string{},
				},
				ForbiddenIn: definitions.Presence{
					Mode:         string(schema.PresenceNone),
					Environments: []string{},
				},
			})
		}

		plan.Template.Classifications = append(plan.Template.Classifications,
			ClassificationChoice{Key: target, Class: class, Downgraded: wasDowngraded})
		// For an already-declared key, absence of a template type row means the
		// existing declaration governs. Recording the default `string` here
		// would fabricate consent the template author never supplied.
		if !isDeclared || !existing.Declared || typeSupplied {
			plan.Template.Types = append(plan.Template.Types,
				TypeChoice{Key: target, Type: string(declType), Accepted: true})
		}

		// Bucketing on the target environment's state. Two buckets, because
		// local state IS resolved state once inheritance is gone.
		switch {
		case existing.Set && !overwrite[target]:
			// `set`: skipped by default, listed by name. Skip-by-default is
			// what makes a re-run naturally idempotent.
			plan.Set = append(plan.Set, target)
			continue
		case existing.Set:
			plan.Set = append(plan.Set, target)
			plan.Overwritten = append(plan.Overwritten, target)
		default:
			plan.New = append(plan.New, target)
		}
		plan.Values.Entries = append(plan.Values.Entries, ValuesEntry{Key: target, Value: rec.Value})
	}

	if len(trimOffenders) > 0 {
		slices.Sort(trimOffenders)
		return nil, failure(in.Source, CodeTrim, "",
			"the write-time trim would alter %d value(s); acknowledge each key in the mapping template's "+
				"`trim_acknowledgements`, or fix the values at the source: %s",
			len(trimOffenders), strings.Join(trimOffenders, ", "))
	}
	if len(incompatible) > 0 {
		slices.Sort(incompatible)
		return nil, failure(in.Source, CodeIncompatible, "",
			"%d key(s) already carry a declaration this import disagrees with; import never modifies a "+
				"declaration, so resolve each by declaring the existing classification and type for that key "+
				"in the mapping template, or by reclassifying the key first: %s",
			len(incompatible), strings.Join(incompatible, "; "))
	}

	plan.NearMisses = NearMisses(importedNames, declaredNames)

	// The template: flag mode records its effective template identically to a
	// wizard session, so a flag-mode run is replayable without ceremony.
	plan.Template.FormatVersion = FormatVersion
	plan.Template.ConnectorContractVersion = ConnectorContractVersion
	plan.Template.Source = in.Source
	plan.Template.Project = in.State.Project
	// The connector states its own scope shape (k8s reports the namespace and
	// the Secret names it parsed); the framework stamps the file digest and the
	// slice slug, which are its facts and not the connector's.
	plan.Template.Scope = in.Scope
	plan.Template.Scope.FileDigest = in.FileDigest
	if in.EnvSlug != "" {
		plan.Template.Scope.EnvSlug = in.EnvSlug
	}
	plan.Template.Environments = []EnvironmentMapping{{
		Source: sourceEnvironment(in.EnvSlug),
		Target: in.State.Environment,
		// Import never creates the environment in flag mode: the target is
		// addressed by id and must already resolve for the presence read to
		// have happened at all.
		Create: false,
	}}
	plan.Template.Folders = folderRows(folders)
	if plan.Template.Renames == nil {
		plan.Template.Renames = plan.Renames
	}
	for _, name := range plan.Overwritten {
		plan.Template.Overwrites = append(plan.Template.Overwrites,
			KeyEnvironment{Key: name, Environment: in.State.Environment})
	}
	for name := range trimAck {
		plan.Template.TrimAcknowledgements = append(plan.Template.TrimAcknowledgements,
			KeyEnvironment{Key: name, Environment: in.State.Environment})
	}
	sort.Slice(plan.Template.TrimAcknowledgements, func(i, j int) bool {
		return plan.Template.TrimAcknowledgements[i].Key < plan.Template.TrimAcknowledgements[j].Key
	})
	emptySlices(&plan.Template)

	encoded, err := Encode(plan.Template)
	if err != nil {
		return nil, err
	}

	// The manifest: the bound record of THIS run, and the phase-2 precondition.
	// It carries the occurrence token for every key the run touches — including
	// the ones it skipped, so a later `--overwrite` re-run reviews the same
	// occurrences it was shown.
	plan.Manifest = Manifest{
		FormatVersion:            FormatVersion,
		ConnectorContractVersion: ConnectorContractVersion,
		Template:                 TemplateReference{Digest: Digest(encoded)},
		SourceIdentity:           SourceIdentity{Kind: in.Source, Context: sourceIdentity(in)},
		Target: Target{
			Project:      in.State.Project,
			Environments: []string{in.State.Environment},
		},
		DefinitionsRevision: in.State.DefinitionsRevision,
		PhaseCompletion: PhaseCompletion{
			Authored: true,
			Applied:  false,
			Imported: map[string]bool{in.State.Environment: false},
		},
	}
	// EVERY planned key gets a manifest row, declared or not. A key the project
	// does not declare yet is exactly the key an import is about to create, and
	// leaving it tokenless would leave the one row phase 2 cannot check —
	// the row an edited manifest would choose to forge.
	var missing []string
	for _, row := range rows {
		key := row.target
		observed, ok := state[key]
		if !ok {
			missing = append(missing, quoteName(key))
			continue
		}
		var id *string
		if observed.Declared {
			keyID := observed.ID
			id = &keyID
		}
		plan.Manifest.Occurrences = append(plan.Manifest.Occurrences, ManifestOccurrence{
			Key: key, Environment: in.State.Environment, Token: observed.Token,
		})
		plan.Manifest.Target.Keys = append(plan.Manifest.Target.Keys, TargetKey{Name: key, ID: id})
		if row.record.Version != "" {
			plan.Manifest.SourceVersions = append(plan.Manifest.SourceVersions, SourceVersion{
				Key: key, Environment: in.State.Environment, Version: row.record.Version,
			})
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, failure(in.Source, CodeMalformed, "",
			"the presence read returned no occurrence for %d planned key(s): %s — phase 1 must ask about "+
				"every key it plans", len(missing), strings.Join(missing, ", "))
	}
	plan.Manifest.SourceVersions = nonNil(plan.Manifest.SourceVersions)
	plan.Manifest.Occurrences = nonNil(plan.Manifest.Occurrences)
	plan.Bundle, err = definitions.Normalize(plan.Bundle)
	if err != nil {
		return nil, fmt.Errorf("import: normalizing definitions bundle: %w", err)
	}
	// A run that writes nothing emits NO values file. An empty one is an
	// artifact its own phase 2 refuses ("the values file holds no entries"),
	// which would end every idempotent re-run in a refusal for having correctly
	// done nothing.
	if len(plan.Values.Entries) > 0 {
		plan.HasValues = true
	}
	return plan, nil
}

func sourceIdentity(in PlanInput) string {
	if in.SourceIdentity != "" {
		return in.SourceIdentity
	}
	return in.FileDigest
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
