package adapter

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestValidateManifestRefusesLossyForgejoNamesAndValues(t *testing.T) {
	tests := []struct {
		name string
		row  ManifestEntry
	}{
		{"lowercase", ManifestEntry{CanonicalName: "Database_URL", Classification: SecretClassification, Value: "x"}},
		{"leading digit", ManifestEntry{CanonicalName: "1_TOKEN", Classification: SecretClassification, Value: "x"}},
		{"reserved prefix", ManifestEntry{CanonicalName: "FORGEJO_TOKEN", Classification: SecretClassification, Value: "x"}},
		{"variable CI", ManifestEntry{CanonicalName: "CI", Classification: ConfigClassification, Value: "x"}},
		{"carriage return", ManifestEntry{CanonicalName: "TOKEN", Classification: SecretClassification, Value: "a\r\nb"}},
		{"prefixed sentinel", ManifestEntry{CanonicalName: SentinelName, Classification: SecretClassification, Value: "x"}},
		{"too long", ManifestEntry{CanonicalName: strings.Repeat("A", 124), Classification: SecretClassification, Value: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := ""
			if tt.name == "prefixed sentinel" || tt.name == "too long" {
				prefix = "PROD_"
			}
			if err := ValidateManifest(prefix, []ManifestEntry{tt.row}); err == nil || !strings.Contains(err.Error(), tt.row.CanonicalName) {
				t.Fatalf("ValidateManifest() = %v, want named refusal", err)
			}
		})
	}

	if err := ValidateManifest("PROD_", []ManifestEntry{
		{KeyID: "key_1", CanonicalName: "CI", Classification: ConfigClassification, Value: "on"},
		{KeyID: "key_2", CanonicalName: "TOKEN", Classification: SecretClassification, Value: "x"},
	}); err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
}

func TestWorkflowUsesCanonicalNamesAtRuntime(t *testing.T) {
	got, err := Workflow("PROD_", []ManifestEntry{
		{CanonicalName: "DATABASE_URL", Classification: SecretClassification},
		{CanonicalName: "LOG_LEVEL", Classification: ConfigClassification},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "env:\n  DATABASE_URL: ${{ secrets.PROD_DATABASE_URL }}\n  LOG_LEVEL: ${{ vars.PROD_LOG_LEVEL }}\n"
	if got != want {
		t.Fatalf("Workflow() =\n%s\nwant:\n%s", got, want)
	}
}

func TestGitHubWorkflowAllowsForeignPrefixesAndCIWhileBanningGitHub(t *testing.T) {
	entries := []ManifestEntry{
		{CanonicalName: "FORGEJO_TOKEN", Classification: SecretClassification},
		{CanonicalName: "GITEA_URL", Classification: ConfigClassification},
		{CanonicalName: "CI", Classification: ConfigClassification},
	}
	workflow, err := WorkflowForProvider("github-actions", "", entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"FORGEJO_TOKEN", "GITEA_URL", "CI"} {
		if !strings.Contains(workflow, name+":") {
			t.Fatalf("workflow omitted GitHub-valid name %q:\n%s", name, workflow)
		}
	}
	if _, err := WorkflowForProvider("github-actions", "", []ManifestEntry{{CanonicalName: "GITHUB_TOKEN", Classification: SecretClassification}}); err == nil {
		t.Fatal("GitHub workflow accepted GITHUB_ reserved prefix")
	}
}

func TestGitHubManifestRefusesUnrepresentableNonUTF8ByName(t *testing.T) {
	err := ValidateGitHubActionsManifest("", []ManifestEntry{{CanonicalName: "BINARY", Classification: SecretClassification, Value: string([]byte{0xff, 0xfe})}}, true)
	if err == nil || !strings.Contains(err.Error(), "BINARY") || !strings.Contains(err.Error(), "non-UTF-8") {
		t.Fatalf("ValidateGitHubActionsManifest() = %v, want named byte-exactness refusal", err)
	}
}

func TestModuleSeamHasExactlyFourOperations(t *testing.T) {
	typeOf := reflect.TypeOf((*Module)(nil)).Elem()
	got := make([]string, 0, typeOf.NumMethod())
	for i := range typeOf.NumMethod() {
		got = append(got, typeOf.Method(i).Name)
	}
	want := []string{"Plan", "Sync", "TestConnection", "ValidateConfig"}
	if !slices.Equal(got, want) {
		t.Fatalf("Module operations = %v, want exactly %v", got, want)
	}
	var _ Module = stubModule{}
}

type stubModule struct{}

func (stubModule) ValidateConfig(Config) error { return nil }
func (stubModule) TestConnection(context.Context, ConnectionRequest) (Connection, error) {
	return Connection{}, nil
}
func (stubModule) Plan(context.Context, PlanRequest) (Plan, error) { return Plan{}, nil }
func (stubModule) Sync(context.Context, SyncRequest, Journal) (SyncResult, error) {
	return SyncResult{}, nil
}
