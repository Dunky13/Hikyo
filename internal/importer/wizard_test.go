package importer

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
)

// scriptHost is a scripted WizardHost: it answers prompts by matching a
// substring of the question, so a test states its intent ("decline every
// downgrade") without tracking prompt order.
type scriptHost struct {
	t        *testing.T
	source   string
	reads    []SourceRead
	readAt   int
	envs     []NamedEnv
	presence func(envID string, cands []PlannedCandidate) ServerState

	confirm map[string]bool
	choose  map[string]int
	line    map[string]string
	notices []string
}

func (h *scriptHost) Notice(msg string) { h.notices = append(h.notices, msg) }

func (h *scriptHost) Confirm(q string, def bool) (bool, error) {
	for sub, v := range h.confirm {
		if strings.Contains(q, sub) {
			return v, nil
		}
	}
	h.t.Fatalf("unscripted Confirm: %q", q)
	return false, nil
}

func (h *scriptHost) Choose(q string, options []string, def int) (int, error) {
	for sub, v := range h.choose {
		if strings.Contains(q, sub) {
			return v, nil
		}
	}
	h.t.Fatalf("unscripted Choose: %q %v", q, options)
	return 0, nil
}

func (h *scriptHost) Line(q, def string) (string, error) {
	for sub, v := range h.line {
		if strings.Contains(q, sub) {
			return v, nil
		}
	}
	h.t.Fatalf("unscripted Line: %q", q)
	return "", nil
}

func (h *scriptHost) ReadSource(source string, sel Selector) (SourceRead, error) {
	r := h.reads[h.readAt]
	h.readAt++
	return r, nil
}

func (h *scriptHost) ExistingEnvironments() ([]NamedEnv, error) { return h.envs, nil }

func (h *scriptHost) Presence(envID string, cands []PlannedCandidate) (ServerState, error) {
	return h.presence(envID, cands), nil
}

// undeclaredState mints an undeclared token per candidate, mirroring the server
// presence read for a project that declares nothing yet.
func undeclaredState(envID string, cands []PlannedCandidate) ServerState {
	st := ServerState{Environment: envID, DefinitionsRevision: 7}
	for _, c := range cands {
		st.Keys = append(st.Keys, KeyState{Name: c.Name, Token: "v1:undeclared-" + c.Name})
	}
	return st
}

// TestWizardSingleEnvMatchesFlagRun is acceptance criterion 1: a wizard session
// whose choices coincide with a flag run authors byte-identical artifacts. It is
// structural — both reach BuildProjectPlan — and this test pins it.
func TestWizardSingleEnvMatchesFlagRun(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:fixture"

	// Flag run: nil template, every default.
	flagState := ServerState{Project: "prj_1", Environment: "env_prod", DefinitionsRevision: 7}
	flagIn := PlanInput{Source: k8sSource, Records: res.Records, Skipped: res.Skipped,
		Scope: res.Scope, FileDigest: digest, State: flagState}
	cands, err := PlannedNames(flagIn)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range cands {
		flagIn.State.Keys = append(flagIn.State.Keys, KeyState{Name: name, Token: "v1:undeclared-" + name})
	}
	flag, err := BuildPlan(flagIn)
	if err != nil {
		t.Fatal(err)
	}

	// Wizard run: same read, coinciding choices — decline every downgrade and
	// every type suggestion (flag mode declares string), never edit a rename.
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{{Result: res, FileDigest: digest}},
		envs:  []NamedEnv{{ID: "env_prod", Name: "prod"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			return undeclaredState(envID, c)
		},
		confirm: map[string]bool{
			"Read live":       false,
			"Map another":     false,
			"Edit this":       false,
			"Downgrade":       false,
			"Declare":         false,
			"overwrite":       false,
			"import the trim": false,
		},
		choose: map[string]int{"source": 1, "Target environment": 0},
		line:   map[string]string{"Export file path": "export.yaml"},
	}
	wiz, err := Wizard(host, "prj_1")
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}

	assertSameBytes(t, "template", mustEncode(t, flag.Template), mustEncode(t, wiz.Template))
	assertSameBytes(t, "manifest", mustEncode(t, flag.Manifest), mustEncode(t, wiz.Manifest))
	assertSameBytes(t, "values", mustEncode(t, flag.Values), mustEncode(t, wiz.Envs[0].Values))
	fb, _ := definitions.Encode(flag.Bundle)
	wb, _ := definitions.Encode(wiz.Bundle)
	assertSameBytes(t, "bundle", fb, wb)
}

func mustEncode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertSameBytes(t *testing.T, what string, want, got []byte) {
	t.Helper()
	if string(want) != string(got) {
		t.Errorf("%s bytes differ.\n--- flag ---\n%s\n--- wizard ---\n%s", what, want, got)
	}
}

// TestWizardFansOutAcrossEnvironments: the wizard maps one source onto two
// existing environments, one bundle, presence differing per environment.
func TestWizardFansOutAcrossEnvironments(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{
			{Result: res, FileDigest: "sha256:a"},
			{Result: res, FileDigest: "sha256:b"},
		},
		envs: []NamedEnv{{ID: "env_prod", Name: "prod"}, {ID: "env_staging", Name: "staging"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			st := undeclaredState(envID, c)
			if envID == "env_prod" {
				// DB_PASSWORD already set in prod; skipped by default there.
				for i := range st.Keys {
					if st.Keys[i].Name == "DB_PASSWORD" {
						st.Keys[i] = declaredKey("DB_PASSWORD", "secret", true, "v1:tok-prod")
					}
				}
			}
			return st
		},
		confirm: map[string]bool{
			"Read live": false, "Edit this": false, "Downgrade": false,
			"Declare": false, "overwrite": false, "import the trim": false,
			"Map another": true, // add the second environment, then stop
		},
		choose: map[string]int{"source": 1, "Target environment": 0},
		line:   map[string]string{"Export file path": "export.yaml"},
	}
	// "Map another" true would loop forever; flip it after the first extra env by
	// tracking calls. Simpler: answer true once, then false.
	host.confirm["Map another"] = true
	callHost := &mapAnotherOnce{scriptHost: host}

	wiz, err := Wizard(callHost, "prj_1")
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if len(wiz.Envs) != 2 {
		t.Fatalf("env plans = %d, want 2", len(wiz.Envs))
	}
	if len(wiz.Manifest.Target.Environments) != 2 {
		t.Errorf("manifest environments = %v", wiz.Manifest.Target.Environments)
	}
	byEnv := map[string]EnvPlan{}
	for _, e := range wiz.Envs {
		byEnv[e.EnvID] = e
	}
	if strings.Join(byEnv["env_prod"].Set, ",") != "DB_PASSWORD" {
		t.Errorf("prod set = %v, want DB_PASSWORD skipped", byEnv["env_prod"].Set)
	}
}

// TestWizardCreatesEnvironment: a session that creates its target environment
// declares it up front, emits a `create environment` bundle line, and authors a
// tokenless, name-addressed values file and manifest for it.
func TestWizardCreatesEnvironment(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	presenceCalled := false
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{{Result: res, FileDigest: "sha256:a"}},
		envs:  []NamedEnv{{ID: "env_prod", Name: "prod"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			presenceCalled = true
			return undeclaredState(envID, c)
		},
		confirm: map[string]bool{
			"Read live": false, "Map another": false, "Edit this": false,
			"Downgrade": false, "Declare": false, "overwrite": false, "import the trim": false,
		},
		// index 1 is "+ create a new environment" (existing has one entry at 0).
		choose: map[string]int{"source": 1, "Target environment": 1},
		line:   map[string]string{"Export file path": "export.yaml", "New environment name": "staging"},
	}
	wiz, err := Wizard(host, "prj_1")
	if err != nil {
		t.Fatalf("wizard: %v", err)
	}
	if presenceCalled {
		t.Error("a created environment triggered a presence read; it has no state to read")
	}

	// The bundle carries the create-environment line.
	foundEnv := false
	for _, e := range wiz.Bundle.Environments {
		if e.Name == "staging" {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Errorf("bundle environments = %+v, want a `staging` create line", wiz.Bundle.Environments)
	}

	// The manifest names it under created_environments, with no occurrence rows.
	if strings.Join(wiz.Manifest.Target.CreatedEnvironments, ",") != "staging" {
		t.Errorf("created environments = %v", wiz.Manifest.Target.CreatedEnvironments)
	}
	if len(wiz.Manifest.Occurrences) != 0 {
		t.Errorf("a created environment minted %d occurrences; it is tokenless", len(wiz.Manifest.Occurrences))
	}

	// The values file is name-addressed, not id-addressed.
	if wiz.Envs[0].Values.EnvironmentName != "staging" || wiz.Envs[0].Values.Environment != "" {
		t.Errorf("values file = %+v, want name-addressed", wiz.Envs[0].Values)
	}
	encoded := string(mustEncode(t, wiz.Envs[0].Values))
	if !strings.Contains(encoded, `"environment_name": "staging"`) || strings.Contains(encoded, `"environment":`) {
		t.Errorf("values serialization does not carry the name alone:\n%s", encoded)
	}
}

// TestWizardSkipsAlreadyDeclaredKeys: a key the project already declares is
// discovered by the first presence read and skipped in classification/type
// review, so accepting a type suggestion cannot propose a declaration that
// conflicts with the existing one. DB_PORT is declared `string`; its value
// "5432" would suggest `integer`, and accepting that against the existing
// `string` used to be a spurious incompatible refusal.
func TestWizardSkipsAlreadyDeclaredKeys(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{{Result: res, FileDigest: "sha256:a"}},
		envs:  []NamedEnv{{ID: "env_prod", Name: "prod"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			st := undeclaredState(envID, c)
			for i := range st.Keys {
				if st.Keys[i].Name == "DB_PORT" {
					st.Keys[i] = declaredKey("DB_PORT", "secret", false, "v1:tok-port")
				}
			}
			return st
		},
		confirm: map[string]bool{
			"Read live": false, "Map another": false, "Edit this": false,
			"Downgrade": false, "overwrite": false, "import the trim": false,
			"Declare": true, // accept every type suggestion
		},
		choose: map[string]int{"source": 1, "Target environment": 0},
		line:   map[string]string{"Export file path": "export.yaml"},
	}
	wiz, err := Wizard(host, "prj_1")
	if err != nil {
		t.Fatalf("wizard refused an already-declared key with a divergent suggestion: %v", err)
	}
	for _, ty := range wiz.Template.Types {
		if ty.Key == "DB_PORT" {
			t.Errorf("recorded a type row for the already-declared DB_PORT: %+v", ty)
		}
	}
	found := false
	for _, k := range wiz.AlreadyDeclared {
		if k == "DB_PORT" {
			found = true
		}
	}
	if !found {
		t.Errorf("DB_PORT not reported already declared: %v", wiz.AlreadyDeclared)
	}
}

// TestWizardRecordsExistingNonDefaultDeclaration: a key already declared with a
// non-default classification (config) is recorded as the reviewed consent, so
// the planner treats it as already-declared instead of refusing it against the
// uniform secret default.
func TestWizardRecordsExistingNonDefaultDeclaration(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{{Result: res, FileDigest: "sha256:a"}},
		envs:  []NamedEnv{{ID: "env_prod", Name: "prod"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			st := undeclaredState(envID, c)
			for i := range st.Keys {
				if st.Keys[i].Name == "DB_HOST" {
					st.Keys[i] = declaredKey("DB_HOST", "config", false, "v1:tok-host")
				}
			}
			return st
		},
		confirm: map[string]bool{
			"Read live": false, "Map another": false, "Edit this": false,
			"Downgrade": false, "Declare": false, "overwrite": false, "import the trim": false,
		},
		choose: map[string]int{"source": 1, "Target environment": 0},
		line:   map[string]string{"Export file path": "export.yaml"},
	}
	wiz, err := Wizard(host, "prj_1")
	if err != nil {
		t.Fatalf("wizard refused a key declared config against the secret default: %v", err)
	}
	found := false
	for _, c := range wiz.Template.Classifications {
		if c.Key == "DB_HOST" && c.Class == "config" {
			found = true
		}
	}
	if !found {
		t.Errorf("existing config declaration not recorded as consent: %+v", wiz.Template.Classifications)
	}
	if !contains(wiz.AlreadyDeclared, "DB_HOST") {
		t.Errorf("DB_HOST not reported already declared: %v", wiz.AlreadyDeclared)
	}
}

// TestWizardRefusesRevisionDivergence: if the project's definitions revision
// changes between two environments' presence reads, the manifest would bind
// tokens against two catalogue states — refused.
func TestWizardRefusesRevisionDivergence(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{{Result: res, FileDigest: "sha256:a"}},
		envs:  []NamedEnv{{ID: "env_prod", Name: "prod"}, {ID: "env_staging", Name: "staging"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			st := undeclaredState(envID, c)
			if envID == "env_staging" {
				st.DefinitionsRevision = 8 // prod read 7; a change landed mid-session
			}
			return st
		},
		confirm: map[string]bool{
			"Read live": false, "Edit this": false, "Downgrade": false,
			"Declare": false, "overwrite": false, "import the trim": false,
		},
		choose: map[string]int{"source": 1, "Target environment": 0},
		line:   map[string]string{"Export file path": "export.yaml"},
	}
	callHost := &mapAnotherOnce{scriptHost: host}
	_, err = Wizard(callHost, "prj_1")
	wantCode(t, err, CodeIncompatible)
	if !strings.Contains(err.Error(), "revision") {
		t.Errorf("refusal does not name the revision change: %v", err)
	}
}

// TestWizardRefusesCreatingExistingEnvironment: choosing "create" and naming an
// environment that already exists is a contradiction (import never modifies an
// environment), refused rather than emitting a `create <existing>` bundle line.
func TestWizardRefusesCreatingExistingEnvironment(t *testing.T) {
	res, err := run(t, k8sSource, "k8s-multi.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	host := &scriptHost{
		t: t, source: k8sSource,
		reads: []SourceRead{{Result: res, FileDigest: "sha256:a"}},
		envs:  []NamedEnv{{ID: "env_prod", Name: "prod"}},
		presence: func(envID string, c []PlannedCandidate) ServerState {
			return undeclaredState(envID, c)
		},
		confirm: map[string]bool{"Read live": false, "Map another": false},
		choose:  map[string]int{"source": 1, "Target environment": 1}, // the "+ create" option
		line:    map[string]string{"Export file path": "export.yaml", "New environment name": "prod"},
	}
	_, err = Wizard(host, "prj_1")
	wantCode(t, err, CodeMalformed)
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("refusal does not explain the collision: %v", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// mapAnotherOnce answers the "Map another?" confirm true exactly once, so the
// fan-out loop adds a second environment and then terminates, and picks a fresh
// existing environment on each "Target environment" choice.
type mapAnotherOnce struct {
	*scriptHost
	asked   bool
	envPick int
}

func (m *mapAnotherOnce) Confirm(q string, def bool) (bool, error) {
	if strings.Contains(q, "Map another") {
		if m.asked {
			return false, nil
		}
		m.asked = true
		return true, nil
	}
	return m.scriptHost.Confirm(q, def)
}

func (m *mapAnotherOnce) Choose(q string, options []string, def int) (int, error) {
	if strings.Contains(q, "Target environment") {
		pick := m.envPick
		m.envPick++
		return pick, nil
	}
	return m.scriptHost.Choose(q, options, def)
}
