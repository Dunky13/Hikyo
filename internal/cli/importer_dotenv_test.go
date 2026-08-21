package cli_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// A strict import server: it declares LOG_LEVEL and DATABASE_URL and rejects any
// other key by name, exactly as the closed schema requires.
func strictImportHandler(t *testing.T) http.Handler {
	t.Helper()
	declared := map[string]bool{"LOG_LEVEL": true, "DATABASE_URL": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/values/import") {
			http.NotFound(w, r)
			return
		}
		var req apigen.ImportValuesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode import body: %v", err)
		}
		var imported []string
		for _, e := range req.Entries {
			if !declared[string(e.Key)] {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"error":{"code":"undeclared_key","message":"key ` + string(e.Key) + ` is not declared in this project"}}`))
				return
			}
			imported = append(imported, string(e.Key))
		}
		_ = json.NewEncoder(w).Encode(apigen.ImportValuesResult{Imported: imported})
	})
}

func TestValuesImportFromDotenvStagesDeclaredKeys(t *testing.T) {
	ios, stdout, stderr := definitionsTestIO(t, strictImportHandler(t))
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("LOG_LEVEL=info\nDATABASE_URL=\"postgres://x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := cli.Run(t.Context(), ios, []string{
		"values", "import", "--from-dotenv", path,
		"--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70",
	})
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "LOG_LEVEL") {
		t.Errorf("import table missing the imported key:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "still plaintext on disk") {
		t.Errorf("missing the plaintext-on-disk warning: %s", stderr.String())
	}
}

func TestValuesImportFromDotenvRejectsUndeclaredByName(t *testing.T) {
	ios, _, stderr := definitionsTestIO(t, strictImportHandler(t))
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("LOG_LEVEL=info\nTYPOO_KEY=oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := cli.Run(t.Context(), ios, []string{
		"values", "import", "--from-dotenv", path,
		"--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70",
	})
	if code == cli.ExitOK {
		t.Fatal("an undeclared key was accepted — the closed schema was conceded")
	}
	if !strings.Contains(stderr.String(), "TYPOO_KEY") {
		t.Errorf("the rejection does not name the undeclared key: %s", stderr.String())
	}
}

func TestValuesImportDotenvAndFileAreMutuallyExclusive(t *testing.T) {
	ios, _, _ := testIO(t, nil)
	code := cli.Run(t.Context(), ios, []string{
		"values", "import", "--from-dotenv", "a.env", "--file", "v.json", "--instance", "unknown-ref",
	})
	if code != cli.ExitUsage {
		t.Fatalf("exit %d, want usage", code)
	}
}
