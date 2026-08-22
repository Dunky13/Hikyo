package compose

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func renderValue(value string) *string { return &value }

func TestBuildRenderPlanLiveOfflineEquivalence(t *testing.T) {
	targets := []RenderTarget{
		{Name: "api", KeyIDs: []string{"key_url", "key_mode"}},
		{Name: "worker", KeyIDs: []string{"key_mode"}},
	}
	rows := []RenderSourceRow{
		{KeyID: "key_url", Name: "DATABASE_URL", Classification: "secret", Value: renderValue("postgres://db")},
		{KeyID: "key_mode", Name: "APP_MODE", Classification: "config", Value: renderValue("production")},
	}

	live, err := BuildRenderPlan(RenderInput{
		Projection: RenderProjectionFull,
		AbsentKeys: AbsentKeyRefuseNotDelivered,
		Targets:    targets,
		Rows:       rows,
	})
	if err != nil {
		t.Fatal(err)
	}
	offline, err := BuildRenderPlan(RenderInput{
		Projection: RenderProjectionFull,
		AbsentKeys: AbsentKeyRefuseNotInSnapshot,
		Targets:    targets,
		Rows:       append([]RenderSourceRow(nil), rows...),
	})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(live, offline) {
		t.Fatalf("equivalent live/offline plans differ:\n live: %#v\noffline: %#v", live, offline)
	}
}

func TestBuildRenderPlanGolden(t *testing.T) {
	plan, err := BuildRenderPlan(RenderInput{
		Projection: RenderProjectionConfigOnly,
		AbsentKeys: AbsentKeySkip,
		Targets: []RenderTarget{
			{Name: "api", KeyIDs: []string{"key_url", "key_unset", "key_projected", "key_path"}},
			{Name: "worker", KeyIDs: []string{"key_bad_name", "key_multiline"}},
		},
		Rows: []RenderSourceRow{
			{KeyID: "key_url", Name: "DATABASE_URL", Classification: "config", Value: renderValue("postgres://db")},
			{KeyID: "key_unset", Name: "OPTIONAL", Classification: "config"},
			{KeyID: "key_path", Name: "PATH", Classification: "config", Value: renderValue("/srv/bin")},
			{KeyID: "key_bad_name", Name: "BAD-NAME", Classification: "config", Value: renderValue("x")},
			{KeyID: "key_multiline", Name: "MULTILINE", Classification: "config", Value: renderValue("a\nb")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/renderplan/config-only.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("render plan golden mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestBuildRenderPlanModelsFullProjectionRefusals(t *testing.T) {
	plan, err := BuildRenderPlan(RenderInput{
		Projection: RenderProjectionFull,
		AbsentKeys: AbsentKeyRefuseNotDelivered,
		Targets: []RenderTarget{{
			Name: "api", KeyIDs: []string{"key_missing", "key_secret"},
		}},
		Rows: []RenderSourceRow{{
			KeyID: "key_secret", Name: "DB_PASSWORD", Classification: "secret", UnrevealedSecret: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []RenderRefusal{
		{Target: "api", Key: "key_missing", Kind: RenderRefusalKeyNotDelivered},
		{Target: "api", Key: "DB_PASSWORD", Kind: RenderRefusalSecretUnrevealed},
	}
	if !reflect.DeepEqual(plan.Refusals, want) {
		t.Fatalf("refusals = %#v, want %#v", plan.Refusals, want)
	}
}
