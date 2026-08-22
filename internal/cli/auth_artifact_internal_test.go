package cli

import (
	"bytes"
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestVerbAuthKindsCoverEveryVerb(t *testing.T) {
	topLevels := map[string]bool{}
	for operation, kinds := range operationAuthKinds {
		topLevels[topLevelOperation(operation)] = true
		if kinds == 0 {
			t.Errorf("%s has no allowed authentication kind", operation)
		}
	}
	declared := slices.Sorted(maps.Keys(topLevels))
	if !slices.Equal(declared, Verbs) {
		t.Fatalf("auth-kind top-level verbs = %v, want %v", declared, Verbs)
	}

	for _, test := range []struct {
		operation AuthOperation
		kind      AuthKind
		want      bool
	}{
		{operation: "logout", kind: AuthKindHumanSession, want: true},
		{operation: "logout", kind: AuthKindMachineCredential, want: false},
		{operation: "adapter sync", kind: AuthKindMachineCredential, want: false},
		{operation: "definitions export", kind: AuthKindMachineCredential, want: false},
		{operation: "definitions apply", kind: AuthKindMachineCredential, want: true},
		{operation: "key list", kind: AuthKindMachineCredential, want: false},
		{operation: "key update", kind: AuthKindMachineCredential, want: true},
		{operation: "values get", kind: AuthKindMachineCredential, want: false},
		{operation: "values export", kind: AuthKindMachineCredential, want: true},
		{operation: "compose render", kind: AuthKindMachineCredential, want: true},
		{operation: "compose render", kind: AuthKindHumanSession, want: false},
		{operation: "run", kind: AuthKindHumanSession, want: true},
		{operation: "run", kind: AuthKindMachineCredential, want: true},
	} {
		t.Run(string(test.operation)+"/"+string(test.kind), func(t *testing.T) {
			if got := operationAuthKinds[test.operation].Allows(test.kind); got != test.want {
				t.Fatalf("Allows(%s) = %t, want %t", test.kind, got, test.want)
			}
		})
	}
}

func TestAuthenticatedTargetReturnsExplicitMachineCredential(t *testing.T) {
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: "http://127.0.0.1:1234"}); err != nil {
		t.Fatal(err)
	}
	ios := IO{Env: Env{
		StateD: stateDir,
		Getenv: func(key string) string {
			if key == "HIKYO_TOKEN" {
				return "hik_1_machine-secret"
			}
			return ""
		},
	}, Stderr: &bytes.Buffer{}}

	_, artifact, _, err := authenticatedTarget(st, ios, commonFlags{
		Flags: Flags{Instance: "local"}, operation: "definitions apply",
	})
	if err != nil {
		t.Fatal(err)
	}
	machine, ok := artifact.(MachineCredential)
	if !ok {
		t.Fatalf("artifact type = %T, want MachineCredential", artifact)
	}
	if machine.Origin != "http://127.0.0.1:1234" || machine.CredentialRef != CredentialRefEnvironment {
		t.Fatalf("machine artifact = %+v", machine)
	}
	if strings.Contains(machine.CredentialRef.String(), "machine-secret") {
		t.Fatal("machine artifact contains credential plaintext")
	}
}

func TestDualEligibleOperationRequiresExplicitAuthChoice(t *testing.T) {
	st, ios := authTargetFixture(t)
	_, _, _, err := authenticatedTarget(st, ios, commonFlags{
		Flags: Flags{Instance: "local"}, operation: "values export",
	})
	if err == nil || !strings.Contains(err.Error(), "both a stored human session and a machine credential") || !strings.Contains(err.Error(), "--auth=human") {
		t.Fatalf("error = %v, want explicit artifact-choice refusal", err)
	}
}

func TestExplicitHumanChoiceDoesNotReadMachineCredential(t *testing.T) {
	st, ios := authTargetFixture(t)
	_, artifact, _, err := authenticatedTarget(st, ios, commonFlags{
		Flags: Flags{Instance: "local"}, operation: "values export", Auth: "human",
		TokenFile: filepath.Join(t.TempDir(), "missing-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := artifact.(HumanSession); !ok {
		t.Fatalf("artifact type = %T, want HumanSession", artifact)
	}
}

func TestHumanOnlyOperationIgnoresIneligibleAmbientMachineCredential(t *testing.T) {
	st, ios := authTargetFixture(t)
	_, artifact, _, err := authenticatedTarget(st, ios, commonFlags{
		Flags: Flags{Instance: "local"}, operation: "whoami",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := artifact.(HumanSession); !ok {
		t.Fatalf("artifact type = %T, want HumanSession", artifact)
	}
}

func authTargetFixture(t *testing.T) (*State, IO) {
	t.Helper()
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	const origin = "http://127.0.0.1:1234"
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: origin}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSession(SessionArtifact{
		Instance: "local", Origin: origin, Token: "hik_1_human-secret", SessionID: "ses_1",
		Principal: "usr_1", ExpiresAt: "2030-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	ios := IO{Env: Env{
		StateD: stateDir,
		Getenv: func(key string) string {
			if key == "HIKYO_TOKEN" {
				return "hik_1_machine-secret"
			}
			return ""
		},
	}, Stderr: &bytes.Buffer{}}
	return st, ios
}

func TestHumanOnlyVerbRefusesMachineCredentialBeforeNetwork(t *testing.T) {
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	ios := IO{
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr, Workdir: t.TempDir(),
		Env: Env{StateD: stateDir, Getenv: func(key string) string {
			if key == "HIKYO_STATE_DIR" {
				return stateDir
			}
			if key == "HIKYO_TOKEN" {
				return "hik_1_machine-secret"
			}
			return ""
		}},
	}
	if code := Run(context.Background(), ios, []string{"logout", "--instance", "local"}); code != ExitRefused {
		t.Fatalf("exit = %d, want %d; stderr=%s", code, ExitRefused, stderr.String())
	}
	if !strings.Contains(stderr.String(), "logout requires a human session") {
		t.Fatalf("refusal = %q", stderr.String())
	}
}

func TestAdapterReauthRefusesMachineCredentialBeforeNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	st := &State{dir: stateDir}
	if err := st.Trust().Put(TrustEntry{Name: "local", Origin: server.URL}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	ios := IO{
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr, Workdir: t.TempDir(),
		Env: Env{StateD: stateDir, Getenv: func(key string) string {
			if key == "HIKYO_STATE_DIR" {
				return stateDir
			}
			if key == "HIKYO_TOKEN" {
				return "hik_1_machine-secret"
			}
			return ""
		}},
	}
	args := []string{"adapter", "sync", "--target", "target_1", "--instance", "local", "--org", "org_1", "--project", "project_1"}
	if code := Run(context.Background(), ios, args); code != ExitRefused {
		t.Fatalf("exit = %d, want %d; stderr=%s", code, ExitRefused, stderr.String())
	}
	if requests != 0 {
		t.Fatalf("network requests = %d, want 0", requests)
	}
	if !strings.Contains(stderr.String(), "hikyo adapter sync requires a human session") {
		t.Fatalf("refusal = %q", stderr.String())
	}
}

func TestSessionsReadLegacyFixture(t *testing.T) {
	stateDir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "sessions-legacy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "sessions.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sessions, err := (&State{dir: stateDir}).Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if got := sessions["local"]; got.Instance != "local" || got.Token != "hik_1_legacy" || got.Principal != "usr_legacy" {
		t.Fatalf("legacy session = %+v", got)
	}
}

func TestSessionsRefuseFutureVersionActionably(t *testing.T) {
	stateDir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("testdata", "sessions-future.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "sessions.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = (&State{dir: stateDir}).Sessions()
	if err == nil || !strings.Contains(err.Error(), "state version 2") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("error = %v, want actionable version refusal", err)
	}
}
