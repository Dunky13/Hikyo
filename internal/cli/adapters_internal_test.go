package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

func TestAdapterCredentialSourcesNeverNeedArgv(t *testing.T) {
	ios := IO{Stdin: strings.NewReader("stdin-token\n"), ReadPassword: func(prompt string) (string, error) {
		if prompt == "" {
			t.Fatal("terminal prompt was empty")
		}
		return "tty-token", nil
	}}
	got, err := (adapterCredentialSource{}).read(ios)
	if err != nil || string(got) != "tty-token" {
		t.Fatalf("tty=%q %v", got, err)
	}
	got, err = (adapterCredentialSource{stdin: true}).read(ios)
	if err != nil || string(got) != "stdin-token" {
		t.Fatalf("stdin=%q %v", got, err)
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = (adapterCredentialSource{file: path}).read(ios)
	if err != nil || string(got) != "file-token" {
		t.Fatalf("file=%q %v", got, err)
	}
	if _, err = (adapterCredentialSource{stdin: true, file: path}).read(ios); err == nil {
		t.Fatal("ambiguous sources accepted")
	}
}

func TestAdapterMoveResumeBodiesAreExplicitAndCredentialIsWriteOnly(t *testing.T) {
	originBody := resumeAdapterOriginBody("https://next.example", []byte("pending-token"))
	raw, err := json.Marshal(originBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"credential":"pending-token","origin":"https://next.example"}` {
		t.Fatalf("origin resume body=%s", raw)
	}
	if strings.Contains(string(raw), "keep_remote") {
		t.Fatalf("resume body changed initial move policy: %s", raw)
	}

	targetBody := resumeAdapterTargetBody("tgt_019c1234-1234-7123-8123-123456789abc", apigen.AdapterTargetInput{
		EnvironmentId:   "env_019c1234-1234-7123-8123-123456789abc",
		DestinationKind: "repository", DestinationOwner: "team", DestinationName: "repo",
		NamePrefix: "PROD_", KeyIds: []apigen.ID{"key_019c1234-1234-7123-8123-123456789abc"},
	})
	raw, err = json.Marshal(targetBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"target_id":"tgt_`, `"environment_id":"env_`, `"destination_name":"repo"`, `"key_ids":["key_`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("target resume body missing %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "credential") || strings.Contains(string(raw), "expected_generation") {
		t.Fatalf("target resume body crossed union branch: %s", raw)
	}
}

func TestAdapterMoveOutputEnumeratesPendingRouteJobsAndOrphansWithoutCredential(t *testing.T) {
	move := apigen.AdapterMove{
		Id:            "mov_019c1234-1234-7123-8123-123456789abc",
		AdapterId:     "adp_019c1234-1234-7123-8123-123456789abc",
		State:         "scrubbing",
		Kind:          "origin",
		PendingOrigin: "https://new-forgejo.example",
		Targets: []apigen.AdapterMoveTarget{{
			TargetId:         "atg_019c1234-1234-7123-8123-123456789abc",
			DestinationOwner: "team",
			DestinationName:  "repo",
			OrphanedNames:    []string{"PROD_OLD"},
			Jobs: []apigen.AdapterMoveJob{{
				Id:    "ajb_019c1234-1234-7123-8123-123456789abc",
				Kind:  "scrub",
				State: "running",
			}},
		}},
	}
	var out bytes.Buffer
	if err := Render(&out, FormatTable, adapterMoveTable(move)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{string(move.Id), move.PendingOrigin, "team/repo", "PROD_OLD", "scrub"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("move output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(strings.ToLower(out.String()), "credential") {
		t.Fatalf("move output exposed a credential surface:\n%s", out.String())
	}
}

func TestAdapterTargetMutationOutputFollowsServiceResult(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "updated",
			response: `{"id":"tgt_one","adapter_id":"adp_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"app","destination_id":42,"name_prefix":"PROD_","generation":2,"state":"active","sync_status":"converging","failure_names":[]}`,
			want:     "converging",
		},
		{
			name:     "move started",
			response: `{"id":"mov_one","adapter_id":"adp_one","kind":"target","state":"scrubbing","keep_remote":false,"pending_origin":"","targets":[{"target_id":"tgt_one","environment_id":"env_one","destination_kind":"repository","destination_owner":"team","destination_name":"next","visibility":"","selected_repository_ids":[],"name_prefix":"PROD_","key_ids":["key_one"],"jobs":[],"orphaned_names":[]}],"created_at":"2026-08-17T00:00:00Z"}`,
			want:     "mov_one",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := renderAdapterTargetMutation(&out, FormatTable, []byte(tt.response)); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("output = %q, want %q", out.String(), tt.want)
			}
		})
	}
}

func TestAdapterShowIncludesTargetStatusRevisionAndFailures(t *testing.T) {
	revision := int64(42)
	adapter := apigen.Adapter{Id: "adp_one", Origin: "https://forgejo.example", Targets: []apigen.AdapterTarget{{
		Id: "tgt_one", EnvironmentId: "env_one", DestinationOwner: "team", DestinationName: "app",
		SyncStatus: "failed", ConvergedRevision: &revision, FailureNames: []string{"secret:TOKEN"},
		Conflicts: []apigen.AdapterConflictArtifact{{Id: "acf_one", Entries: []apigen.AdapterConflictEntry{{Surface: "variable", EffectiveName: "PROD_MODE"}}}},
	}}}
	var out bytes.Buffer
	if err := Render(&out, FormatTable, adapterDetailTable(adapter)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"adp_one", "tgt_one", "failed", "42", "secret:TOKEN", "variable:PROD_MODE"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("adapter show missing %q:\n%s", want, out.String())
		}
	}
}

func TestAdapterHelpAndParserExposeNoCredentialValueFlag(t *testing.T) {
	var help bytes.Buffer
	Usage(&help)
	if strings.Contains(help.String(), "--value ") || strings.Contains(help.String(), "--credential ") {
		t.Fatalf("credential argv surface in help:\n%s", help.String())
	}
	var stderr bytes.Buffer
	code := Run(t.Context(), IO{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr, Env: Env{Getenv: func(string) string { return "" }}}, []string{"adapter", "credential", "set", "--adapter", "adp_x", "--value", "secret"})
	if code != ExitUsage {
		t.Fatalf("--value exit=%d stderr=%q", code, stderr.String())
	}
}

func TestAdapterCancelMoveRequiresOnlyExplicitMove(t *testing.T) {
	for _, args := range [][]string{
		{"adapter", "update", "adp_x", "--cancel-move"},
		{"adapter", "update", "adp_x", "--cancel-move", "--move", "mov_x", "--origin", "https://wrong.example"},
	} {
		var stderr bytes.Buffer
		stateDir := t.TempDir()
		code := Run(t.Context(), IO{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr, Env: Env{Getenv: func(name string) string {
			if name == "HIKYO_STATE_DIR" {
				return stateDir
			}
			return ""
		}}}, args)
		if code != ExitUsage || !strings.Contains(stderr.String(), "--cancel-move") {
			t.Fatalf("args=%v exit=%d stderr=%q", args, code, stderr.String())
		}
	}
}
