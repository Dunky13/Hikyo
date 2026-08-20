package importer

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// TestValidNamesArePreservedByteForByte is the rename rule's sharp half: a
// transform applied to an already-valid name IS a silent rename, so a valid
// name never enters the transform at all.
func TestValidNamesArePreservedByteForByte(t *testing.T) {
	for _, name := range []string{"DB_URL", "_PRIVATE", "A", "X9", "A__B", "_0"} {
		got, valid, err := TransformName(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !valid {
			t.Errorf("%s was reported invalid; it matches the canonical grammar", name)
		}
		if got != name {
			t.Errorf("%s was rewritten to %s", name, got)
		}
	}
}

func TestDocumentedTransform(t *testing.T) {
	cases := map[string]string{
		"db-host":     "DB_HOST",
		"db.host":     "DB_HOST",
		"api/key":     "API_KEY",
		`api\key`:     "API_KEY",
		"lowercase":   "LOWERCASE",
		"9lives":      "_9LIVES",
		"mixed-Case.": "MIXED_CASE_",
	}
	for source, want := range cases {
		got, valid, err := TransformName(source)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if valid {
			t.Errorf("%s was reported already valid", source)
		}
		if got != want {
			t.Errorf("%s -> %s, want %s", source, got, want)
		}
		if err := schema.CheckKeyName(got); err != nil {
			t.Errorf("%s produced %s, which the grammar refuses: %v", source, got, err)
		}
	}
}

// TestHardStopNamesRequireAnExplicitRename: the transform covers the common
// classes ONLY. Anything else stops the run rather than guessing.
func TestHardStopNamesRequireAnExplicitRename(t *testing.T) {
	for _, name := range []string{"has space", "a=b", "café", "a:b", "a+b", ""} {
		_, _, err := TransformName(name)
		wantCode(t, err, CodeUnmappableName)
		if !strings.Contains(err.Error(), "mapping template") && name != "" {
			t.Errorf("%q: the refusal does not point at the template: %v", name, err)
		}
	}
}

func TestNearMissAdvisory(t *testing.T) {
	got := NearMisses([]string{"DB_PASWORD", "DB_PASSWORD", "TOTALLY_OTHER"},
		[]string{"DB_PASSWORD", "API_KEY"})
	if len(got) != 1 || got[0].Imported != "DB_PASWORD" || got[0].Declared != "DB_PASSWORD" {
		t.Fatalf("near misses = %+v, want the one-edit typo only", got)
	}
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

// declaredKey is the fixture spelling for a key the project already declares.
func declaredKey(name, class string, set bool, token string) KeyState {
	return KeyState{
		Name: name, ID: "key_" + name, Declared: true, Classification: class,
		Type: string(schema.TypeString), Set: set, Token: token,
	}
}

func state(keys ...KeyState) ServerState {
	return ServerState{
		Project: "prj_1", Environment: "env_prod", DefinitionsRevision: 7, Keys: keys,
	}
}

// planFrom mirrors what the CLI does: transform names, ask the server about
// every candidate (here: a stub that mints a per-name token for anything the
// fixture state does not declare), then plan.
func planFrom(t *testing.T, fixture string, st ServerState, tmpl *Template) (*Plan, error) {
	t.Helper()
	res, err := run(t, k8sSource, fixture, "")
	if err != nil {
		t.Fatal(err)
	}
	in := PlanInput{
		Source: k8sSource, Records: res.Records, Skipped: res.Skipped,
		Scope: res.Scope, FileDigest: "sha256:fixture", State: st, Template: tmpl,
	}
	candidates, err := PlannedNames(in)
	if err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	for _, k := range st.Keys {
		declared[k.Name] = true
	}
	for _, name := range candidates {
		if !declared[name] {
			in.State.Keys = append(in.State.Keys, KeyState{Name: name, Token: "v1:undeclared-" + name})
		}
	}
	return BuildPlan(in)
}

// envFrom reads a k8s fixture and mints a per-name undeclared token for anything
// the fixture state does not declare, mirroring the CLI's presence read for one
// environment. Undeclared tokens are salted with the environment id so the two
// environments' occurrences are distinguishable, as the server's scoped tokens
// are.
func envFrom(t *testing.T, fixture, envID string, keys []KeyState, tmpl *Template) EnvInput {
	t.Helper()
	res, err := run(t, k8sSource, fixture, "")
	if err != nil {
		t.Fatal(err)
	}
	in := PlanInput{Source: k8sSource, Records: res.Records, Template: tmpl}
	candidates, err := PlannedNames(in)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, k := range keys {
		declared[k.Name] = true
	}
	state := append([]KeyState{}, keys...)
	for _, name := range candidates {
		if !declared[name] {
			state = append(state, KeyState{Name: name, Token: "v1:undeclared-" + envID + "-" + name})
		}
	}
	return EnvInput{
		Records: res.Records, Skipped: res.Skipped, Scope: res.Scope,
		FileDigest: "sha256:fixture", EnvID: envID, Keys: state,
	}
}

// TestProjectPlanFansOutAcrossEnvironments: one source, two existing target
// environments, one project-wide bundle, and per-environment buckets that differ
// only by presence.
func TestProjectPlanFansOutAcrossEnvironments(t *testing.T) {
	prod := envFrom(t, "k8s-multi.yaml", "env_prod",
		[]KeyState{declaredKey("DB_PASSWORD", "secret", true, "v1:tok-prod")}, nil)
	staging := envFrom(t, "k8s-multi.yaml", "env_staging",
		[]KeyState{declaredKey("DB_PASSWORD", "secret", false, "v1:tok-staging")}, nil)
	plan, err := BuildProjectPlan(ProjectPlanInput{
		Source: k8sSource, Project: "prj_1", DefinitionsRevision: 7,
		Envs: []EnvInput{prod, staging},
	})
	if err != nil {
		t.Fatal(err)
	}

	// One project-wide bundle: the three undeclared keys declared once each;
	// DB_PASSWORD is already declared in both environments and not re-declared.
	if len(plan.Bundle.Keys) != 3 {
		t.Fatalf("bundle keys = %d, want one project-wide declaration per undeclared key", len(plan.Bundle.Keys))
	}
	if strings.Join(plan.AlreadyDeclared, ",") != "DB_PASSWORD" {
		t.Errorf("already declared = %v, want DB_PASSWORD once project-wide", plan.AlreadyDeclared)
	}

	// Presence varies by environment: DB_PASSWORD is set in prod (skipped) and
	// absent in staging (imported).
	if len(plan.Envs) != 2 {
		t.Fatalf("env plans = %d", len(plan.Envs))
	}
	byEnv := map[string]EnvPlan{}
	for _, e := range plan.Envs {
		byEnv[e.EnvID] = e
	}
	if strings.Join(byEnv["env_prod"].Set, ",") != "DB_PASSWORD" {
		t.Errorf("prod set = %v, want DB_PASSWORD skipped", byEnv["env_prod"].Set)
	}
	for _, e := range byEnv["env_prod"].Values.Entries {
		if e.Key == "DB_PASSWORD" {
			t.Error("prod imported a set key without overwrite consent")
		}
	}
	stagingHasPassword := false
	for _, e := range byEnv["env_staging"].Values.Entries {
		if e.Key == "DB_PASSWORD" {
			stagingHasPassword = true
		}
	}
	if !stagingHasPassword {
		t.Error("staging (absent) did not import DB_PASSWORD")
	}

	// One manifest naming both environments, with occurrences per (key, env).
	if len(plan.Manifest.Target.Environments) != 2 {
		t.Errorf("manifest environments = %v", plan.Manifest.Target.Environments)
	}
	perEnv := map[string]int{}
	for _, o := range plan.Manifest.Occurrences {
		perEnv[o.Environment]++
	}
	if perEnv["env_prod"] != 4 || perEnv["env_staging"] != 4 {
		t.Errorf("occurrence counts = %v, want 4 per environment", perEnv)
	}

	// The template records both environment rows.
	if len(plan.Template.Environments) != 2 {
		t.Errorf("template environments = %+v", plan.Template.Environments)
	}
}

// TestProjectPlanRefusesFolderConflict: a key that reconciles to two different
// folders across environments cannot be declared once (the bundle carries one
// folder_path per key), so the run refuses. Multi-folder records defeat the k8s
// single-Secret root collapse, so the folders are the ones the records name.
func TestProjectPlanRefusesFolderConflict(t *testing.T) {
	env := func(id, dbFolder string) EnvInput {
		return EnvInput{
			EnvID: id,
			Records: []Record{
				{Folder: []string{dbFolder}, SourceName: "DB_HOST", Value: "h", Type: schema.TypeString},
				{Folder: []string{"api"}, SourceName: "API_KEY", Value: "k", Type: schema.TypeString},
			},
		}
	}
	_, err := BuildProjectPlan(ProjectPlanInput{
		Source: k8sSource, Project: "prj_1", DefinitionsRevision: 7,
		Envs: []EnvInput{env("env_a", "db"), env("env_b", "database")},
	})
	wantCode(t, err, CodeIncompatible)
	if !strings.Contains(err.Error(), "folder") {
		t.Errorf("refusal does not name the folder conflict: %v", err)
	}
}

// TestBucketsAreNewAndSetOnly pins the flat-model amendment: two buckets, and a
// `set` key is skipped by default and listed by name.
func TestBucketsAreNewAndSetOnly(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(
		declaredKey("DB_PASSWORD", "secret", true, "v1:tok-a"),
		declaredKey("API_KEY", "secret", false, "v1:tok-b"),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Set, ",") != "DB_PASSWORD" {
		t.Errorf("set bucket = %v, want [DB_PASSWORD] skipped by name", plan.Set)
	}
	if strings.Join(plan.New, ",") != "API_KEY,DB_HOST,DB_PORT" {
		t.Errorf("new bucket = %v", plan.New)
	}
	// Skip-by-default: the skipped key contributes no value entry, which is
	// what makes a re-run idempotent.
	for _, e := range plan.Values.Entries {
		if e.Key == "DB_PASSWORD" {
			t.Error("a `set` key reached the values file without an explicit overwrite")
		}
	}
	// The occurrence token of every DECLARED key rides in the manifest,
	// including the one the run skipped: a later --overwrite must review the
	// same occurrence it was shown.
	tokens := map[string]string{}
	for _, o := range plan.Manifest.Occurrences {
		tokens[o.Key] = o.Token
	}
	if tokens["DB_PASSWORD"] != "v1:tok-a" || tokens["API_KEY"] != "v1:tok-b" {
		t.Errorf("occurrences = %+v", plan.Manifest.Occurrences)
	}
	if plan.Manifest.DefinitionsRevision != 7 {
		t.Errorf("definitions revision = %d, want the one phase 1 observed", plan.Manifest.DefinitionsRevision)
	}
}

func TestOverwriteIsOptInAndEnumerated(t *testing.T) {
	tmpl := &Template{Overwrites: []KeyEnvironment{{Key: "DB_PASSWORD", Environment: "env_prod"}}}
	plan, err := planFrom(t, "k8s-multi.yaml", state(
		declaredKey("DB_PASSWORD", "secret", true, "v1:tok-a"),
	), tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Overwritten, ",") != "DB_PASSWORD" {
		t.Fatalf("overwritten = %v", plan.Overwritten)
	}
	found := false
	for _, e := range plan.Values.Entries {
		if e.Key == "DB_PASSWORD" {
			found = true
		}
	}
	if !found {
		t.Error("the enumerated overwrite did not reach the values file")
	}
	// The choice is recorded in the effective template either way.
	if len(plan.Template.Overwrites) != 1 {
		t.Errorf("template overwrites = %+v", plan.Template.Overwrites)
	}
}

// TestEveryImportedKeyDefaultsSecret: from every source, no exceptions, and no
// downgrade without an explicit template act.
func TestEveryImportedKeyDefaultsSecret(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range plan.Bundle.Keys {
		if k.Classification != string(schema.Secret) {
			t.Errorf("%s declared %s; every imported key defaults secret", k.Name, k.Classification)
		}
		if k.Declaration.Rule == nil || k.Declaration.Rule.Type != schema.TypeString {
			t.Errorf("%s: flag mode declares every value `string`", k.Name)
		}
	}
	for _, c := range plan.Template.Classifications {
		if c.Downgraded {
			t.Errorf("%s recorded as downgraded; flag mode performs zero downgrades", c.Key)
		}
	}
}

func TestBundleIsCanonicalAdditiveAndApplicable(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := definitions.Encode(plan.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"project"`)) {
		t.Fatalf("canonical definitions bundle carries importer project field:\n%s", raw)
	}

	bundle, err := definitions.Parse(raw)
	if err != nil {
		t.Fatalf("importer bundle does not parse through definitions.Parse: %v\n%s", err, raw)
	}
	if !bundle.Additive() || len(bundle.Environments) != 0 || len(bundle.KeyGroups) != 0 {
		t.Fatalf("bundle is not project-wide additive: %+v", bundle)
	}
	for _, key := range bundle.Keys {
		if key.ID != "" || key.Description != "" || key.Deprecated || key.DeprecationNote != "" || key.Group != "" {
			t.Errorf("key %s carries non-additive identity or metadata: %+v", key.Name, key)
		}
		for field, presence := range map[string]definitions.Presence{
			"required_in": key.RequiredIn, "forbidden_in": key.ForbiddenIn,
		} {
			if presence.Mode != string(schema.PresenceNone) || len(presence.Environments) != 0 {
				t.Errorf("key %s %s = %+v, want mode none with [] environments", key.Name, field, presence)
			}
		}
	}

	resolution, err := definitions.Resolve(bundle, definitions.CurrentState{})
	if err != nil {
		t.Fatalf("canonical importer bundle is not applicable additively: %v", err)
	}
	if !resolution.Additive || len(resolution.KeyCreates) != len(bundle.Keys) {
		t.Fatalf("additive resolution = %+v, want %d key creates", resolution, len(bundle.Keys))
	}
}

func TestTemplateDowngradeAndTypesAreRecorded(t *testing.T) {
	tmpl := &Template{
		Classifications: []ClassificationChoice{{Key: "DB_PORT", Class: "config", Downgraded: true}},
		Types:           []TypeChoice{{Key: "DB_PORT", Type: "integer", Accepted: true}},
	}
	plan, err := planFrom(t, "k8s-multi.yaml", state(), tmpl)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range plan.Bundle.Keys {
		if k.Name != "DB_PORT" {
			continue
		}
		if k.Classification != "config" {
			t.Errorf("DB_PORT classification = %s, want the template's downgrade", k.Classification)
		}
		if k.Declaration.Rule.Type != schema.TypeInteger {
			t.Errorf("DB_PORT type = %s, want the template's declaration", k.Declaration.Rule.Type)
		}
	}
	for _, c := range plan.Template.Classifications {
		if c.Key == "DB_PORT" && !c.Downgraded {
			t.Error("the downgrade was not recorded in the effective template")
		}
	}
}

// TestRenamesAreSurfacedAndRecorded: nothing is renamed invisibly.
func TestRenamesAreSurfacedAndRecorded(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Renames) != 1 || plan.Renames[0].From != "db-host" || plan.Renames[0].To != "DB_HOST" {
		t.Fatalf("renames = %+v, want db-host -> DB_HOST only", plan.Renames)
	}
	if plan.Renames[0].Transform != TransformAuto {
		t.Errorf("transform = %s, want auto", plan.Renames[0].Transform)
	}
	if len(plan.Template.Renames) != 1 {
		t.Errorf("the rename was not recorded in the template: %+v", plan.Template.Renames)
	}
}

func TestPostTransformCollisionIsAHardError(t *testing.T) {
	_, err := planFrom(t, "k8s-collision.yaml", state(), nil)
	wantCode(t, err, CodeNameCollision)
	if !strings.Contains(err.Error(), "DB_HOST") {
		t.Errorf("the refusal does not name the target key: %v", err)
	}
}

func TestUnmappableNameStopsTheRun(t *testing.T) {
	_, err := planFrom(t, "k8s-unmappable.yaml", state(), nil)
	wantCode(t, err, CodeUnmappableName)
}

// TestRefusalsNameEveryOffenderNotJustTheFirst: "refusal is per key, not per
// import" is only true if the message names every offending key. A refusal that
// stops at the first turns one edit into N runs.
func TestRefusalsNameEveryOffenderNotJustTheFirst(t *testing.T) {
	_, err := planFrom(t, "k8s-many-unmappable.yaml", state(), nil)
	wantCode(t, err, CodeUnmappableName)
	for _, name := range []string{"has space", "a=b", "caf"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name %q: %v", name, err)
		}
	}

	_, err = planFrom(t, "k8s-many-trim.yaml", state(), nil)
	wantCode(t, err, CodeTrim)
	for _, name := range []string{"CERT_A", "CERT_B"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the trim refusal does not name %q: %v", name, err)
		}
	}

	res, err := run(t, k8sSource, "k8s-many-binary.yaml", "")
	if err == nil {
		t.Fatalf("binary values were accepted: %+v", res)
	}
	wantCode(t, err, CodeBinaryValue)
	for _, name := range []string{"BLOB_A", "BLOB_B"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the binary refusal does not name %q: %v", name, err)
		}
	}
}

// TestIncompatibleExistingDeclarationIsRefusedByName: import never modifies a
// declaration, so one it disagrees with is a conflict the human resolves — not
// a warning the run steps past on its way to writing a secret into a `config`
// key that every plain-`read` holder can see.
func TestIncompatibleExistingDeclarationIsRefusedByName(t *testing.T) {
	_, err := planFrom(t, "k8s-single.yaml", state(
		declaredKey("ALPHA", "config", false, "v1:t"),
	), nil)
	wantCode(t, err, CodeIncompatible)
	if !strings.Contains(err.Error(), "ALPHA") || !strings.Contains(err.Error(), "config") {
		t.Errorf("the refusal must name the key and the conflict: %v", err)
	}

	// The escape hatch is the template line: declaring `config` for that key IS
	// the reviewed, recorded, committable consent.
	plan, err := planFrom(t, "k8s-single.yaml", state(
		declaredKey("ALPHA", "config", false, "v1:t"),
	), &Template{Classifications: []ClassificationChoice{{Key: "ALPHA", Class: "config", Downgraded: true}}})
	if err != nil {
		t.Fatalf("an explicit template downgrade did not resolve the conflict: %v", err)
	}
	if strings.Join(plan.AlreadyDeclared, ",") != "ALPHA" {
		t.Errorf("already-declared = %v", plan.AlreadyDeclared)
	}
	for _, k := range plan.Bundle.Keys {
		if k.Name == "ALPHA" {
			t.Error("an already-declared key was re-declared")
		}
	}

	// Type incompatibility is refused on the same terms.
	mismatch := state(declaredKey("ALPHA", "secret", false, "v1:t"))
	mismatch.Keys[0].Type = string(schema.TypeInteger)
	_, err = planFrom(t, "k8s-single.yaml", mismatch, nil)
	wantCode(t, err, CodeIncompatible)
	if !strings.Contains(err.Error(), "integer") {
		t.Errorf("the refusal does not name the declared type: %v", err)
	}

	// An any_of declaration is compatible only when the effective imported
	// primitive is one of its branches.
	withoutString := state(declaredKey("ALPHA", "secret", false, "v1:t"))
	withoutString.Keys[0].Type = "any_of(integer|boolean)"
	_, err = planFrom(t, "k8s-single.yaml", withoutString, nil)
	wantCode(t, err, CodeIncompatible)

	withString := state(declaredKey("ALPHA", "secret", false, "v1:t"))
	withString.Keys[0].Type = "any_of(integer|string)"
	plan, err = planFrom(t, "k8s-single.yaml", withString, nil)
	if err != nil {
		t.Fatalf("an any_of declaration with a string branch was refused: %v", err)
	}
	for _, typ := range plan.Template.Types {
		if typ.Key == "ALPHA" {
			t.Errorf("an already-declared key fabricated a template type row: %+v", plan.Template.Types)
		}
	}

	// A supplied matching type is explicit template consent and is retained.
	matching := state(declaredKey("ALPHA", "secret", false, "v1:t"))
	matching.Keys[0].Type = string(schema.TypeInteger)
	plan, err = planFrom(t, "k8s-single.yaml", matching, &Template{
		Types: []TypeChoice{{Key: "ALPHA", Type: "integer", Accepted: true}},
	})
	if err != nil {
		t.Fatalf("a template-supplied matching type was refused: %v", err)
	}
	foundMatching := false
	for _, typ := range plan.Template.Types {
		if typ.Key == "ALPHA" && typ.Type == "integer" {
			foundMatching = true
		}
	}
	if !foundMatching {
		t.Errorf("matching template type was not retained: %+v", plan.Template.Types)
	}
}

// TestRootCollapseIsTheK8sProvisionOnly: "a single-Secret import may target the
// environment root" is the K8s row's. A SOPS or Infisical export states its
// folder structure outright and must keep it.
func TestRootCollapseIsTheK8sProvisionOnly(t *testing.T) {
	withAgeIdentity(t)
	res, err := run(t, sopsSource, "sops-single-folder.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	in := PlanInput{Source: sopsSource, Records: res.Records, Scope: res.Scope, State: state()}
	names, err := PlannedNames(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		in.State.Keys = append(in.State.Keys, KeyState{Name: name, Token: "v1:u-" + name})
	}
	plan, err := BuildPlan(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range plan.Bundle.Keys {
		if k.FolderPath != "only" {
			t.Errorf("%s landed at %q; a SOPS map level is folder structure the source stated", k.Name, k.FolderPath)
		}
	}
}

// TestTemplateFolderChoicesAreHonouredOnReplay: the template is the record of
// every CHOICE. Recomputing one behind the operator's back makes it a
// suggestion.
func TestTemplateFolderChoicesAreHonouredOnReplay(t *testing.T) {
	tmpl := &Template{Folders: []FolderMapping{
		{SourcePath: "app-db", TargetPath: "databases/primary"},
		{SourcePath: "app-api", TargetPath: "services/api"},
	}}
	plan, err := planFrom(t, "k8s-multi.yaml", state(), tmpl)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, k := range plan.Bundle.Keys {
		got[k.Name] = k.FolderPath
	}
	if got["DB_HOST"] != "databases/primary" || got["API_KEY"] != "services/api" {
		t.Fatalf("recorded folder choices were recomputed: %v", got)
	}

	// A source path the template never saw is a different mapping, loudly.
	partial := &Template{Folders: []FolderMapping{{SourcePath: "app-db", TargetPath: "databases/primary"}}}
	_, err = planFrom(t, "k8s-multi.yaml", state(), partial)
	wantCode(t, err, CodeMalformed)
	if !strings.Contains(err.Error(), "app-api") {
		t.Errorf("the refusal does not name the unmapped source path: %v", err)
	}
}

// TestUnacceptedTypeRowIsRefused: `accepted: false` records that nobody
// accepted the suggestion. Applying it anyway makes the flag decorative.
func TestUnacceptedTypeRowIsRefused(t *testing.T) {
	_, err := planFrom(t, "k8s-single.yaml", state(),
		&Template{Types: []TypeChoice{{Key: "ALPHA", Type: "integer", Accepted: false}}})
	wantCode(t, err, CodeMalformed)
	if !strings.Contains(err.Error(), "ALPHA") || !strings.Contains(err.Error(), "accepted") {
		t.Errorf("the refusal must name the key and the flag: %v", err)
	}
}

// TestEveryPlannedKeyGetsAManifestRow: the undeclared keys are exactly the ones
// an import creates, and a manifest row without a server-minted token is the
// one row an edited manifest could forge freely.
func TestEveryPlannedKeyGetsAManifestRow(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(
		declaredKey("DB_PASSWORD", "secret", true, "v1:tok-a"),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	for _, o := range plan.Manifest.Occurrences {
		tokens[o.Key] = o.Token
	}
	for _, name := range []string{"API_KEY", "DB_HOST", "DB_PASSWORD", "DB_PORT"} {
		if tokens[name] == "" {
			t.Errorf("%s carries no occurrence token", name)
		}
	}
	// An undeclared key's manifest row carries a null id, which is a different
	// fact from an empty one.
	for _, k := range plan.Manifest.Target.Keys {
		if k.Name == "API_KEY" && k.ID != nil {
			t.Errorf("an undeclared key carries a key id: %v", *k.ID)
		}
		if k.Name == "DB_PASSWORD" && k.ID == nil {
			t.Error("a declared key carries no key id")
		}
	}
}

// TestAllSkippedRunEmitsNoValuesFile: an empty values file is an artifact phase
// 2 refuses by construction, so an idempotent re-run would end in a refusal for
// having correctly done nothing.
func TestAllSkippedRunEmitsNoValuesFile(t *testing.T) {
	plan, err := planFrom(t, "k8s-single.yaml", state(
		declaredKey("ALPHA", "secret", true, "v1:a"),
		declaredKey("BETA", "secret", true, "v1:b"),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HasValues {
		t.Fatal("a run that wrote nothing claims a values file")
	}
	if len(plan.Values.Entries) != 0 {
		t.Fatalf("entries = %v", plan.Values.Entries)
	}
}

// TestK8sScopeIsNamespaceAndNames pins the spellings spec's connector-shaped
// scope: k8s records {namespace, names[]}, not a bare file digest.
func TestK8sScopeIsNamespaceAndNames(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Template.Scope.Namespace != "prod" {
		t.Errorf("namespace = %q, want the one parsed off the manifests", plan.Template.Scope.Namespace)
	}
	if strings.Join(plan.Template.Scope.Names, ",") != "app-api,app-db" {
		t.Errorf("names = %v", plan.Template.Scope.Names)
	}
	if plan.Template.Scope.FileDigest == "" {
		t.Error("the framework's file digest was dropped")
	}
}

// TestTrimPreflightRefusesByNameUnlessAcknowledged: a value the write-time trim
// would alter would import CHANGED, silently.
func TestTrimPreflightRefusesByNameUnlessAcknowledged(t *testing.T) {
	_, err := planFrom(t, "k8s-trim.yaml", state(), nil)
	wantCode(t, err, CodeTrim)
	if !strings.Contains(err.Error(), "CERT") || !strings.Contains(err.Error(), "trim_acknowledgements") {
		t.Errorf("the refusal must name the key and the acknowledgement: %v", err)
	}

	ack := &Template{TrimAcknowledgements: []KeyEnvironment{{Key: "CERT", Environment: "env_prod"}}}
	plan, err := planFrom(t, "k8s-trim.yaml", state(), ack)
	if err != nil {
		t.Fatalf("an acknowledged trim must proceed: %v", err)
	}
	if len(plan.Template.TrimAcknowledgements) != 1 {
		t.Error("the acknowledgement was not recorded in the effective template")
	}
}

// TestSingleSecretMayTargetTheEnvironmentRoot pins the K8s folder rule's
// second half.
func TestSingleSecretMayTargetTheEnvironmentRoot(t *testing.T) {
	plan, err := planFrom(t, "k8s-single.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range plan.Bundle.Keys {
		if k.FolderPath != "" {
			t.Errorf("%s landed in folder %q; a single-Secret import targets the root", k.Name, k.FolderPath)
		}
	}
	plan, err = planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, k := range plan.Bundle.Keys {
		seen[k.Name] = k.FolderPath
	}
	if seen["API_KEY"] != "app-api" || seen["DB_HOST"] != "app-db" {
		t.Errorf("folder mapping = %v; one Secret maps onto one folder named after it", seen)
	}
}

func TestExistingDeclarationIsNotRedeclared(t *testing.T) {
	plan, err := planFrom(t, "k8s-single.yaml", state(
		declaredKey("ALPHA", "secret", false, "v1:t"),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range plan.Bundle.Keys {
		if k.Name == "ALPHA" {
			t.Error("an already-declared key was re-declared; an additive bundle may not modify one")
		}
	}
	if strings.Join(plan.AlreadyDeclared, ",") != "ALPHA" {
		t.Errorf("already-declared = %v", plan.AlreadyDeclared)
	}
}

// TestArtifactsRoundTripStrictly: the template and manifest serializations are
// the spec's, and an unknown field rejects loudly NAMING A VERSION MISMATCH.
func TestArtifactsRoundTripStrictly(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(plan.Template)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseTemplate(raw)
	if err != nil {
		t.Fatalf("the template does not round-trip: %v", err)
	}
	again, err := Encode(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(again) {
		t.Errorf("the template is not byte-stable across a round trip:\n%s\n---\n%s", raw, again)
	}

	rawManifest, err := Encode(plan.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(rawManifest); err != nil {
		t.Fatalf("the manifest does not round-trip: %v", err)
	}
	plan.Manifest.Target.Environments[0] = ""
	emptyTarget, err := Encode(plan.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseManifest(emptyTarget)
	wantCode(t, err, CodeMalformed)

	// A field this build does not know is a field a different build wrote.
	polluted := strings.Replace(string(raw), `"source":`, `"unknown_choice": true,
  "source":`, 1)
	_, err = ParseTemplate([]byte(polluted))
	wantCode(t, err, CodeVersion)
	if !strings.Contains(err.Error(), "version mismatch") {
		t.Errorf("the refusal must name a version mismatch: %v", err)
	}

	bumped := strings.Replace(string(raw), `"format_version": 1`, `"format_version": 2`, 1)
	_, err = ParseTemplate([]byte(bumped))
	wantCode(t, err, CodeVersion)
}

func TestArtifactsRejectTrailingDocumentsAndDuplicateMembers(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(plan.Manifest)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseManifest(append(raw, []byte(`{"format_version":1}`)...))
	wantCode(t, err, CodeMalformed)
	if !strings.Contains(err.Error(), "trailing content") {
		t.Fatalf("trailing-value refusal does not name trailing content: %v", err)
	}

	duplicate := strings.Replace(string(raw), `"target": {`, `"target": {},
  "target": {`, 1)
	_, err = ParseManifest([]byte(duplicate))
	wantCode(t, err, CodeDuplicateKey)
	if !strings.Contains(err.Error(), `"target"`) {
		t.Fatalf("duplicate-member refusal does not name target: %v", err)
	}

	caseVariant := strings.Replace(string(raw), `"source_identity": {`, `"SOURCE_IDENTITY": {},
  "source_identity": {`, 1)
	_, err = ParseManifest([]byte(caseVariant))
	wantCode(t, err, CodeDuplicateKey)
	if !strings.Contains(strings.ToLower(err.Error()), `"source_identity"`) {
		t.Fatalf("case-variant duplicate refusal does not name source_identity: %v", err)
	}
}

func TestTemplateRequiresEveryTargetEnvironment(t *testing.T) {
	plan, err := planFrom(t, "k8s-multi.yaml", state(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan.Template.Environments[0].Target = ""
	raw, err := Encode(plan.Template)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseTemplate(raw)
	wantCode(t, err, CodeMalformed)
	if !strings.Contains(err.Error(), "target environment") {
		t.Fatalf("empty-target refusal does not name target environment: %v", err)
	}
}

func TestValuesFileIsStrict(t *testing.T) {
	good := ValuesFile{
		FormatVersion: FormatVersion, Project: "prj_1", Environment: "env_prod",
		Entries: []ValuesEntry{{Key: "A", Value: "1"}},
	}
	raw, err := Encode(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseValuesFile(raw); err != nil {
		t.Fatal(err)
	}
	dup := `{"format_version":1,"project":"p","environment":"e","entries":[{"key":"A","value":"1"},{"key":"A","value":"2"}]}`
	_, err = ParseValuesFile([]byte(dup))
	wantCode(t, err, CodeDuplicateKey)

	good.Project = ""
	raw, err = Encode(good)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseValuesFile(raw)
	wantCode(t, err, CodeMalformed)
}

func TestPlaintextWarningNamesEveryFileStillOnDisk(t *testing.T) {
	got := PlaintextWarning("/tmp/secrets.yaml", []string{"/out/values-env_prod.json"})
	for _, want := range []string{"/tmp/secrets.yaml", "/out/values-env_prod.json", "values import"} {
		if !strings.Contains(got, want) {
			t.Errorf("the warning does not name %q: %s", want, got)
		}
	}
}

func TestPlaintextWarningForLiveModeNamesOnlyAuthoredValues(t *testing.T) {
	got := PlaintextWarning("", []string{"/out/values-env_prod.json"})
	if strings.Contains(got, "source") || !strings.Contains(got, "/out/values-env_prod.json") {
		t.Fatalf("live warning = %q", got)
	}
	if got := PlaintextWarning("", nil); got != "no import plaintext artifact remains on disk" {
		t.Fatalf("empty live warning = %q", got)
	}
}

// TestTemplateManualRenameIsTheHardStopEscapeHatch: every unmappable-name
// refusal points at the template's `renames`, so the template had better be
// able to resolve one. This pins that promise.
func TestTemplateManualRenameIsTheHardStopEscapeHatch(t *testing.T) {
	if _, err := planFrom(t, "k8s-unmappable.yaml", state(), nil); err == nil {
		t.Fatal("flag mode accepted an unmappable name")
	}

	tmpl := &Template{Renames: []Rename{{From: "has space", To: "HAS_SPACE", Transform: TransformManual}}}
	plan, err := planFrom(t, "k8s-unmappable.yaml", state(), tmpl)
	if err != nil {
		t.Fatalf("an explicit rename did not resolve the hard stop: %v", err)
	}
	if strings.Join(plan.New, ",") != "HAS_SPACE" {
		t.Fatalf("new = %v, want the explicitly renamed key", plan.New)
	}
	if len(plan.Renames) != 1 || plan.Renames[0].Transform != TransformManual {
		t.Fatalf("the manual rename was not surfaced as manual: %+v", plan.Renames)
	}

	// A manual rename to a name the canonical grammar refuses is still a hard
	// stop: the template chooses the name, it does not suspend the grammar.
	bad := &Template{Renames: []Rename{{From: "has space", To: "has space", Transform: TransformManual}}}
	_, err = planFrom(t, "k8s-unmappable.yaml", state(), bad)
	wantCode(t, err, CodeUnmappableName)
}
