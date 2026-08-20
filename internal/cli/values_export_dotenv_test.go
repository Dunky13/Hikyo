package cli_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/cli"
)

func exportHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/values/export") {
			http.NotFound(w, r)
			return
		}
		var req apigen.ExportValuesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode export body: %v", err)
		}
		reveal := req.Reveal != nil && *req.Reveal
		info := "info"
		secret := "s3cr3t"
		items := []apigen.ExportedValue{
			{Name: "LOG_LEVEL", Classification: "config", Value: &info},
		}
		// The secret cell carries plaintext only when the export revealed it; masked
		// otherwise (Value nil), exactly as the server behaves.
		if reveal {
			items = append(items, apigen.ExportedValue{Name: "API_KEY", Classification: "secret", Value: &secret})
		} else {
			items = append(items, apigen.ExportedValue{Name: "API_KEY", Classification: "secret"})
		}
		_ = json.NewEncoder(w).Encode(apigen.ExportedValues{Items: items})
	})
}

func TestValuesExportDotenvMasksSecretsWithoutReveal(t *testing.T) {
	ios, stdout, stderr := definitionsTestIO(t, exportHandler(t))
	code := cli.Run(t.Context(), ios, []string{
		"values", "export", "--format", "dotenv",
		"--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70",
	})
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if got := stdout.String(); got != "LOG_LEVEL=info\n" {
		t.Fatalf("dotenv export = %q, want only the config line", got)
	}
	if !strings.Contains(stderr.String(), "omitted 1 secret") {
		t.Errorf("missing the omitted-secret count: %s", stderr.String())
	}
}

func TestValuesExportDotenvIncludesSecretsWithReveal(t *testing.T) {
	ios, stdout, stderr := definitionsTestIO(t, exportHandler(t))
	code := cli.Run(t.Context(), ios, []string{
		"values", "export", "--format", "dotenv", "--reveal", "--dangerously-print",
		"--instance", "local", "--org", "org_70", "--project", "prj_70", "--env", "env_70",
	})
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "LOG_LEVEL=info") || !strings.Contains(out, "API_KEY=s3cr3t") {
		t.Fatalf("revealed dotenv export missing lines:\n%s", out)
	}
	if strings.Contains(stderr.String(), "omitted") {
		t.Errorf("reported an omission when everything was revealed: %s", stderr.String())
	}
}
