package cli_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// Golden snapshots (api-cli-surface ADR § The CLI is a frozen surface too).
//
// From the first stable release, within the major: no verb or flag is removed
// or repurposed, `-o json` shapes are additive-only, exit-code meanings are
// stable, and `--format` values are never removed. Enforced by committed
// fixtures whose diff is reviewed like a spec change.
//
// Human-oriented `table` output is explicitly NOT frozen and is deliberately
// absent from these fixtures — scripts that parse tables instead of `-o json`
// are outside the promise, and snapshotting table output here would quietly
// extend the promise to cover it.

var update = flag.Bool("update", false, "rewrite the golden fixtures")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing fixture %s (run `go test ./internal/cli -update` and review the diff): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s drifted from its committed fixture.\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func testIO(t *testing.T, env map[string]string) (cli.IO, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	state := t.TempDir()
	work := t.TempDir()
	var stdout, stderr bytes.Buffer
	get := func(k string) string {
		if v, ok := env[k]; ok {
			return v
		}
		if k == "HIKYO_STATE_DIR" {
			return state
		}
		return ""
	}
	return cli.IO{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Env:     cli.Env{Getenv: get},
		Workdir: work,
	}, &stdout, &stderr
}

func TestHelpOutputIsFrozen(t *testing.T) {
	var buf bytes.Buffer
	cli.Usage(&buf)
	golden(t, "help.txt", buf.Bytes())
}

func TestExitCodeMatrix(t *testing.T) {
	// The scenario matrix the ops spec calls for: a fixed set of invocations
	// with their committed exit codes. Scripts branch on codes, so a code
	// changing under an unchanged invocation is a breaking change.
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, cli.ExitUsage},
		{"unknown verb", []string{"teleport"}, cli.ExitUsage},
		{"unknown context subverb", []string{"context", "warp"}, cli.ExitUsage},
		{"context show without a name", []string{"context", "show"}, cli.ExitUsage},
		{"context show unknown name", []string{"context", "show", "nope"}, cli.ExitNotFound},
		{"context delete unknown trust entry", []string{"context", "delete", "--instance", "nope"}, cli.ExitNotFound},
		{"login without a target", []string{"login", "--local"}, cli.ExitUsage},
		{"login without --local refuses by name", []string{"login", "https://hikyo.example"}, cli.ExitRefused},
		{"device flow refuses by name", []string{"login", "https://hikyo.example", "--device"}, cli.ExitRefused},
		{"login against an unestablished reference", []string{"login", "--local", "--as", "u", "unknown-ref"}, cli.ExitRefused},
		{"unknown output format", []string{"context", "list", "-o", "yaml"}, cli.ExitUsage},
		{"org without a subverb", []string{"org"}, cli.ExitUsage},
		{"org list with no session", []string{"org", "list", "--instance", "unknown-ref"}, cli.ExitRefused},
		{"account without the subverb", []string{"account"}, cli.ExitUsage},
		// The hierarchy families (#48). Each refuses on its own terms before
		// reaching a server, so the matrix pins the usage boundary of every new
		// verb family rather than only the one that happens to be shortest.
		{"project without a subverb", []string{"project"}, cli.ExitUsage},
		{"unknown project subverb", []string{"project", "warp"}, cli.ExitUsage},
		{"env without a subverb", []string{"env"}, cli.ExitUsage},
		{"unknown env subverb", []string{"env", "warp"}, cli.ExitUsage},
		{"folder without a subverb", []string{"folder"}, cli.ExitUsage},
		{"unknown folder subverb", []string{"folder", "warp"}, cli.ExitUsage},
		{"project list with no session", []string{"project", "list", "--instance", "unknown-ref", "--org", "org_x"}, cli.ExitRefused},
		{"env list without a resolved project", []string{"env", "list", "--instance", "unknown-ref"}, cli.ExitRefused},
		// Syntax is decided BEFORE target resolution and session lookup, so a
		// malformed invocation answers 2 regardless of login state. Each of these
		// names an unestablished instance deliberately: were validation still
		// running after resolution, they would answer 4 instead.
		{"folder create without a path", []string{"folder", "create", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"folder show without a folder", []string{"folder", "show", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"env rename without a name", []string{"env", "rename", "env_x", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"env reorder without an order", []string{"env", "reorder", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"extra positional is not silently dropped", []string{"folder", "delete", "fld_x", "typo", "--instance", "unknown-ref"}, cli.ExitUsage},
		// The verbs that address NO object reject a positional too — one stray
		// word per family, so a missing guard in any of the four shows up here.
		{"stray positional on folder list", []string{"folder", "list", "stray", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"stray positional on project create", []string{"project", "create", "stray", "--name", "p", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"stray positional on env list", []string{"env", "list", "stray", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"stray positional on org list", []string{"org", "list", "stray", "--instance", "unknown-ref"}, cli.ExitUsage},
		// org gets the same syntax-before-authentication ordering as the rest.
		{"unknown org subverb", []string{"org", "warp"}, cli.ExitUsage},
		{"org create without a name", []string{"org", "create", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"org rename without a name", []string{"org", "rename", "org_x", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"org positional contradicting --org", []string{"org", "show", "org_a", "--org", "org_b", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"positional contradicting its selector flag", []string{"project", "show", "prj_a", "--project", "prj_b", "--instance", "unknown-ref"}, cli.ExitUsage},
		// Project deletion refuses BEFORE reaching a server when the confirmation
		// naming the project is absent — the permission model's locked row for an
		// irreversible, key-shredding operation. Refused (4), not usage: the
		// taxonomy spells a declined ceremony 4.
		{"project delete without a confirmation", []string{"project", "delete", "prj_x", "--org", "org_x", "--instance", "unknown-ref"}, cli.ExitRefused},
		{"passkey enrol refuses by name", []string{"account", "passkey", "enrol"}, cli.ExitRefused},
		// The key catalogue (#49). Same syntax-before-authentication ordering:
		// every one of these names an unestablished instance, so an answer of 4
		// instead of 2 would mean validation had moved after resolution.
		{"key without a subverb", []string{"key"}, cli.ExitUsage},
		{"unknown key subverb", []string{"key", "warp"}, cli.ExitUsage},
		{"key group without a subverb", []string{"key", "group"}, cli.ExitUsage},
		{"unknown key group subverb", []string{"key", "group", "warp"}, cli.ExitUsage},
		{"key create without a name", []string{"key", "create", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key create without a classification", []string{"key", "create", "--name", "A", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key create without a declaration", []string{"key", "create", "--name", "A", "--classification", "config", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key show without a key", []string{"key", "show", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key declare without a declaration", []string{"key", "declare", "key_x", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key reclassify without a classification", []string{"key", "reclassify", "key_x", "--instance", "unknown-ref"}, cli.ExitUsage},
		// A malformed declaration is a client-side syntax error, refused before
		// a request is spent to be told the same thing.
		{"key create with a malformed declaration", []string{"key", "create", "--name", "A", "--classification", "config", "--declaration", "{oops", "--instance", "unknown-ref"}, cli.ExitUsage},
		// A member the declaration vocabulary does not have is REFUSED, never
		// dropped: a silently discarded `patern` would send a valid declaration
		// with the constraint the operator wrote missing, and the server's
		// additionalProperties would never see the typo because it never left
		// this process.
		{"key create with an unknown declaration member", []string{"key", "create", "--name", "A", "--classification", "config", "--declaration", `{"rule":{"type":"string"},"rules":{}}`, "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key create with a misspelled rule constraint", []string{"key", "create", "--name", "A", "--classification", "config", "--declaration", `{"rule":{"type":"string","patern":"^A"}}`, "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key declare with trailing content after the declaration", []string{"key", "declare", "key_x", "--declaration", `{"rule":{"type":"string"}} {"rule":{"type":"integer"}}`, "--instance", "unknown-ref"}, cli.ExitUsage},
		// An impossible presence spelling is likewise caught client-side.
		{"key declare with an empty environment id", []string{"key", "declare", "key_x", "--declaration", "{}", "--required-in", "env_a,,env_b", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"stray positional on key list", []string{"key", "list", "stray", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"extra positional on key delete", []string{"key", "delete", "key_x", "typo", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"stray positional on key group list", []string{"key", "group", "list", "stray", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"key list with no session", []string{"key", "list", "--instance", "unknown-ref", "--org", "org_x", "--project", "prj_x"}, cli.ExitRefused},
		// The import path (#68). Its usage boundary is pinned like every other
		// verb family's, and the first case is the one the ADR states outright:
		// `import` with no source arguments and no terminal is a HARD ERROR,
		// never a hung prompt. testIO injects no OpenTerminal, so these run in
		// exactly that state.
		{"import without a source or a mapping", []string{"import"}, cli.ExitUsage},
		{"import with both a source and a mapping", []string{"import", "--from", "k8s", "--mapping", "m.json"}, cli.ExitUsage},
		{"import without an export file", []string{"import", "--from", "k8s", "--project", "prj_x", "--environment", "env_x"}, cli.ExitUsage},
		{"import with an unserved source", []string{"import", "--from", "vault", "--file", "x.yaml"}, cli.ExitUsage},
		{"import without an explicit project", []string{"import", "--from", "k8s", "--environment", "env_x", "--file", "x.yaml"}, cli.ExitRefused},
		{"import without an explicit environment", []string{"import", "--from", "k8s", "--project", "prj_x", "--file", "x.yaml"}, cli.ExitRefused},
		{"import with a missing export file", []string{"import", "--from", "k8s", "--project", "prj_x", "--environment", "env_x", "--file", "nope.yaml"}, cli.ExitUsage},
		{"stray positional on import", []string{"import", "--from", "k8s", "--file", "x.yaml", "stray"}, cli.ExitUsage},
		{"values import without a file", []string{"values", "import", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"values import with a missing file", []string{"values", "import", "--file", "nope.json", "--instance", "unknown-ref"}, cli.ExitUsage},
		{"stray positional on values import", []string{"values", "import", "stray", "--instance", "unknown-ref"}, cli.ExitUsage},
		// A replay takes its target from the artifact it replays; a flag that
		// would override it is refused rather than silently ignored, which is
		// what keeps the template a record rather than a suggestion.
		{"replay with an overriding project", []string{"import", "--mapping", "m.json", "--file", "x.yaml", "--project", "prj_x"}, cli.ExitUsage},
		{"replay with an overriding environment", []string{"import", "--mapping", "m.json", "--file", "x.yaml", "--environment", "env_x"}, cli.ExitUsage},
		{"values import with an unknown output format", []string{"values", "import", "--file", "v.json", "-o", "yaml", "--instance", "unknown-ref"}, cli.ExitUsage},
	}
	var report strings.Builder
	for _, tc := range cases {
		ios, _, _ := testIO(t, nil)
		got := cli.Run(t.Context(), ios, tc.args)
		report.WriteString(strings.Join(append([]string{"hikyo"}, tc.args...), " "))
		report.WriteString(" -> ")
		report.WriteString(exitName(got))
		report.WriteString("\n")
		if got != tc.want {
			t.Errorf("%s: exit %d (%s), want %d (%s)", tc.name, got, exitName(got), tc.want, exitName(tc.want))
		}
	}
	golden(t, "exit-codes.txt", []byte(report.String()))
}

func exitName(code int) string {
	switch code {
	case cli.ExitOK:
		return "0 ok"
	case cli.ExitInternal:
		return "1 internal"
	case cli.ExitUsage:
		return "2 usage"
	case cli.ExitAuth:
		return "3 authentication"
	case cli.ExitRefused:
		return "4 refused"
	case cli.ExitNotFound:
		return "5 not found"
	case cli.ExitUnavailable:
		return "6 unavailable"
	default:
		return "unknown"
	}
}

func TestContextJSONShapeIsFrozen(t *testing.T) {
	// `-o json` shapes are part of the promise. The fixture is the machine
	// contract; adding a field to it is additive and fine, removing or
	// renaming one is not.
	ios, stdout, _ := testIO(t, nil)
	if code := cli.Run(t.Context(), ios, []string{"context", "list", "-o", "json"}); code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	golden(t, "context-list-empty.json", stdout.Bytes())
}

func TestAnUnestablishedReferenceIsRefusedNotPrompted(t *testing.T) {
	// The rule with teeth: a pin file or a context may NAME an instance, and
	// if the reference is not in the local trust store the CLI refuses and
	// names the missing provisioning step. It never prompts-to-trust
	// mid-command and never sends a credential toward the origin.
	ios, _, stderr := testIO(t, nil)
	code := cli.Run(t.Context(), ios, []string{"login", "--local", "--as", "admin", "malicious-ref"})
	if code != cli.ExitRefused {
		t.Fatalf("exit %d, want %d", code, cli.ExitRefused)
	}
	msg := stderr.String()
	for _, want := range []string{"not in the local trust store", "--trust-file", "HIKYO_TRUST_BUNDLE"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q:\n%s", want, msg)
		}
	}
}

func TestPinFileCanDirectButNeverIntroducesAnOrigin(t *testing.T) {
	// A hostile pin-file edit is bounded to retargeting WITHIN origins this
	// box already trusts. It cannot name an origin at all — the schema has no
	// field for one — and a reference it names that is not established is a
	// refusal, so the credential-exfiltration variant is closed by
	// construction rather than by vigilance.
	ios, _, stderr := testIO(t, nil)
	work := ios.Workdir
	pin := `{"instance":"attacker-controlled","org":"o","project":"p","env":"e"}`
	if err := os.WriteFile(filepath.Join(work, cli.PinFileName), []byte(pin), 0o644); err != nil {
		t.Fatal(err)
	}
	code := cli.Run(t.Context(), ios, []string{"org", "list"})
	if code != cli.ExitRefused {
		t.Fatalf("exit %d, want %d — a pin file reached an unestablished instance", code, cli.ExitRefused)
	}
	if !strings.Contains(stderr.String(), "not in the local trust store") {
		t.Errorf("unexpected refusal:\n%s", stderr.String())
	}
	// And the pin file schema itself has no origin field: a struct field is
	// the only way one could be introduced, and there is none.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(`{"origin":"https://attacker.example"}`), &parsed); err != nil {
		t.Fatal(err)
	}
	var typed cli.PinFile
	if err := json.Unmarshal([]byte(`{"origin":"https://attacker.example"}`), &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Instance != "" {
		t.Error("a pin file introduced an instance through an origin member")
	}
}

func TestCanonicalOriginRefusesWhatIsNotAnOrigin(t *testing.T) {
	for _, bad := range []string{
		"https://hikyo.example/some/path",
		"https://user:pass@hikyo.example",
		"ftp://hikyo.example",
		"https://",
		"https://hikyo.example?a=1",
	} {
		if _, err := cli.CanonicalOrigin(bad); err == nil {
			t.Errorf("%q was accepted as an origin", bad)
		}
	}
	got, err := cli.CanonicalOrigin("HTTPS://Hikyo.Example:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://hikyo.example:8443" {
		t.Fatalf("canonical origin %q", got)
	}
}

func TestTargetResolutionPrecedence(t *testing.T) {
	// Per dimension, first hit wins: flags, then environment, then the pin
	// file, then the named context. Overriding ONE dimension is legitimate
	// exactly because the others re-resolve within the same chain.
	ios, _, _ := testIO(t, map[string]string{"HIKYO_PROJECT": "from-env"})
	if err := os.WriteFile(filepath.Join(ios.Workdir, cli.PinFileName),
		[]byte(`{"instance":"pinned","org":"pinned-org","project":"pinned-project","env":"pinned-env"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := cli.NewState(ios.Env)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := cli.Resolve(st, ios.Env, cli.Flags{Env: "from-flag"}, ios.Workdir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[cli.Dimension]struct {
		value  string
		source cli.Source
	}{
		cli.DimEnv:      {"from-flag", cli.SourceFlag},
		cli.DimProject:  {"from-env", cli.SourceEnv},
		cli.DimOrg:      {"pinned-org", cli.SourcePinFile},
		cli.DimInstance: {"pinned", cli.SourcePinFile},
	}
	for dim, w := range want {
		if got := resolved.Get(dim); got != w.value {
			t.Errorf("%s = %q, want %q", dim, got, w.value)
		}
		if got := resolved.Sources[dim]; got != w.source {
			t.Errorf("%s came from %q, want %q", dim, got, w.source)
		}
	}
}

func TestMissingDimensionIsAHardErrorNamingWhereItLooked(t *testing.T) {
	// Ambiguity is a hard error, never a default: no dimension is ever
	// silently assumed.
	ios, _, _ := testIO(t, nil)
	st, err := cli.NewState(ios.Env)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := cli.Resolve(st, ios.Env, cli.Flags{}, ios.Workdir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolved.Require(cli.DimOrg)
	if err == nil {
		t.Fatal("a missing dimension resolved to something")
	}
	for _, want := range []string{"--org", "HIKYO_ORG", cli.PinFileName, "context"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say it looked at %q: %v", want, err)
		}
	}
}

func TestThereIsNoPersistentActiveContext(t *testing.T) {
	// `context use` was the sticky global the model prohibits, and its absence
	// is a property worth asserting: one forgotten `use` before a disclosure
	// verb is the wrong-environment export this design exists to prevent.
	ios, _, stderr := testIO(t, nil)
	if code := cli.Run(t.Context(), ios, []string{"context", "use", "prod"}); code != cli.ExitUsage {
		t.Fatalf("`context use` exists (exit %d)", code)
	}
	if !strings.Contains(stderr.String(), "create, list, show or delete") {
		t.Errorf("unexpected message:\n%s", stderr.String())
	}
	var help bytes.Buffer
	cli.Usage(&help)
	if strings.Contains(help.String(), "context use") {
		t.Error("help advertises `context use`")
	}
}

// TestHierarchyJSONShapesAreFrozen byte-pins the `-o json` document the CLI
// emits for each hierarchy entity.
//
// `-o json` schemas are part of the frozen surface (api-cli-surface ADR: they
// are additive-only within the major, and scripts branch on them); human `table`
// output explicitly is not. So the fixture is the JSON, rendered from a fixed
// payload through the CLI's own renderer — no server, no clock, no ids from a
// generator, which is what makes a byte comparison meaningful. A removed or
// renamed member is a red diff here; an added one is a reviewed diff.
func TestHierarchyJSONShapesAreFrozen(t *testing.T) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, tc := range []struct {
		fixture string
		payload any
	}{
		{"org-json.json", apigen.OrgList{
			Items: []apigen.Org{{
				Id: "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11", Name: "acme",
				Active: true, CreatedAt: stamp,
			}},
			Count: 1,
		}},
		{"project-json.json", apigen.ProjectList{
			Items: []apigen.Project{{
				Id:    "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f22",
				OrgId: "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11",
				Name:  "checkout", CreatedAt: stamp,
			}},
			Count: 1,
		}},
		{"environment-json.json", apigen.EnvironmentList{
			Items: []apigen.Environment{{
				Id:        "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f33",
				OrgId:     "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11",
				ProjectId: "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f22",
				Name:      "prod", DisplayOrder: 0, CreatedAt: stamp,
			}},
			Count: 1,
		}},
		// The key catalogue (#49). The declaration and the presence rules are
		// inside the pinned document: a rule an operator cannot read back is a
		// rule they cannot review, and a member quietly dropped from either is
		// exactly what this fixture exists to catch.
		{"key-json.json", apigen.KeyList{
			Items: []apigen.Key{{
				Id:              "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55",
				OrgId:           "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11",
				ProjectId:       "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f22",
				Name:            "DATABASE_URL",
				FolderPath:      "services/api",
				Classification:  "secret",
				Description:     "primary datastore",
				Deprecated:      false,
				DeprecationNote: "",
				Declaration: apigen.KeyDeclaration{Rule: &apigen.KeyRule{
					Type: "url", Schemes: &[]string{"postgres"},
				}},
				Presence: apigen.KeyPresenceRules{
					RequiredIn:  apigen.KeyPresence{Mode: "all"},
					ForbiddenIn: apigen.KeyPresence{Mode: "none"},
				},
				GroupId:   "kgr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f66",
				CreatedAt: stamp,
			}},
			Count:          1,
			SchemaRevision: 7,
		}},
		{"key-group-json.json", apigen.KeyGroupList{
			Items: []apigen.KeyGroup{{
				Id:        "kgr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f66",
				OrgId:     "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11",
				ProjectId: "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f22",
				Name:      "database",
				Members:   []string{"DATABASE_URL", "DATABASE_USER"},
				Inert:     false,
				CreatedAt: stamp,
			}},
			Count: 1,
		}},
		// The flat value model (#50). The pinned document is where "presence is
		// two-state" stops being prose: `set` is a boolean, `revealed` says
		// whether `value` is there at all, and there is no third state and no
		// `masked` member to drop later without noticing.
		{"value-json.json", apigen.ValueList{
			Items: []apigen.ValueCell{
				{
					KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55", Name: "DATABASE_URL",
					Classification: "secret", Set: true, Revealed: false,
					UpdatedAt: &stamp, UpdatedBy: strptr("usr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f77"),
				},
				{
					KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f56", Name: "LOG_LEVEL",
					Classification: "config", Set: true, Revealed: true, Value: strptr("info"),
					UpdatedAt: &stamp, UpdatedBy: strptr("usr_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f77"),
				},
				{
					KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f57", Name: "FEATURE_FLAG",
					Classification: "config", Set: false, Revealed: false,
				},
			},
			Count: 3,
		}},
		{"value-diff-json.json", apigen.ValueDiff{
			LeftEnvironmentId:  "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f33",
			RightEnvironmentId: "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f34",
			Items: []apigen.ValueDiffRow{
				{
					KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f56", Name: "LOG_LEVEL",
					Classification: "config",
					Left: apigen.ValueCell{
						KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f56", Name: "LOG_LEVEL",
						Classification: "config", Set: true, Revealed: true, Value: strptr("debug"),
					},
					Right: apigen.ValueCell{
						KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f56", Name: "LOG_LEVEL",
						Classification: "config", Set: true, Revealed: true, Value: strptr("info"),
					},
					Equal: boolptr(false),
				},
				{
					// Both sides set, neither readable: `equal` is ABSENT, not
					// false. Whether two secrets match is itself material.
					KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55", Name: "DATABASE_URL",
					Classification: "secret",
					Left: apigen.ValueCell{
						KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55", Name: "DATABASE_URL",
						Classification: "secret", Set: true,
					},
					Right: apigen.ValueCell{
						KeyId: "key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55", Name: "DATABASE_URL",
						Classification: "secret", Set: true,
					},
				},
			},
		}},
		{"folder-json.json", apigen.FolderList{
			Items: []apigen.Folder{{
				Id:        "fld_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f44",
				OrgId:     "org_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f11",
				ProjectId: "prj_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f22",
				Path:      "services/api", CreatedAt: stamp,
			}},
			Count: 1,
		}},
		// The import path (#68). Two shapes worth freezing: phase 1's
		// occurrence list, whose `token` is opaque to every client and whose
		// `set` is the whole two-state presence model; and phase 2's result,
		// where `skipped` is a LIST OF NAMES rather than a count — a skipped key
		// the operator expected to land is a fact they must be told by name.
		{"value-occurrences-json.json", apigen.ValueOccurrenceList{
			EnvironmentId:       "env_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f33",
			DefinitionsRevision: 7,
			Items: []apigen.ValueOccurrence{
				{
					KeyId: strptr("key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f55"), Name: "DATABASE_URL",
					Declared: true, Classification: classptr("secret"),
					DeclaredType: strptr("string"), Set: true,
					Token: "v1:sBn6Q0m2Yy1a9m0nGm9nX0cD4rQ7pS2tU5vW8xY1zA0",
				},
				{
					KeyId: strptr("key_0193f0b4-1f2a-7c31-9c1e-2a4b6d8e0f57"), Name: "FEATURE_FLAG",
					Declared: true, Classification: classptr("config"),
					DeclaredType: strptr("boolean"), Set: false,
					Token: "v1:Tq3Lm7Nn2Pp9Rr4Ss6Uu8Vv0Ww1Xx3Yy5Zz7Aa9Bb2",
				},
				// A candidate the project does not declare yet: `declared` is
				// false, there is no key id and no classification to report, and
				// the token names exactly that state. It is the row an import
				// creates, and it is server-minted like every other.
				{
					Name: "NEW_FROM_IMPORT", Declared: false, Set: false,
					Token: "v1:Cc4Dd6Ee8Ff0Gg2Hh4Ii6Jj8Kk0Ll2Mm4Nn6Oo8Pp0",
				},
			},
		}},
		{"value-import-json.json", apigen.ImportValuesResult{
			Imported: []string{"DATABASE_URL", "FEATURE_FLAG"},
			Skipped:  []string{"API_KEY"},
		}},
	} {
		var out bytes.Buffer
		if err := cli.Render(&out, cli.FormatJSON, cli.Table{JSON: tc.payload}); err != nil {
			t.Fatalf("%s: %v", tc.fixture, err)
		}
		golden(t, tc.fixture, out.Bytes())
	}
}

func strptr(s string) *string { return &s }

func classptr(c apigen.KeyClassification) *apigen.KeyClassification { return &c }
func boolptr(b bool) *bool                                          { return &b }
