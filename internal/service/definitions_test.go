package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestSanitizeDefinitionsProvenance(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"empty", "", true},
		{"printable label", "refs/heads/main@abc123", true},
		{"control", "main\nsecret", false},
		{"too long", strings.Repeat("x ", MaxProvenanceBytes), false},
		{"bearer shaped", strings.Repeat("a", 32), false},
		{"embedded bearer shaped", "build:" + strings.Repeat("a", 32) + ":label", false},
		{"hikyo token grammar short body", "merged by hik_1_ci_" + strings.Repeat("a9", 8), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sanitizeProvenance("commit", tc.value)
			if tc.valid && (err != nil || got != tc.value) {
				t.Fatalf("sanitize = %q, %v; want unchanged", got, err)
			}
			if !tc.valid && !errors.Is(err, domain.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestValidateFinalDefinitionsNamesAndCaps(t *testing.T) {
	keys := make([]definitions.Key, schema.MaxKeysPerProject+1)
	for i := range keys {
		keys[i].Name = fmt.Sprintf("KEY_%d", i)
	}
	environments := make([]string, MaxEnvironmentsPerProject+1)
	for i := range environments {
		environments[i] = fmt.Sprintf("environment-%d", i)
	}
	groups := make([]string, schema.MaxKeyGroupsPerProject+1)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%d", i)
	}
	tests := []struct {
		name string
		cur  definitions.CurrentState
		res  definitions.Resolution
		want error
		text string
	}{
		{"key grammar", definitions.CurrentState{}, definitions.Resolution{KeyCreates: []definitions.Key{{Name: "lowercase"}}}, domain.ErrInvalid, "lowercase"},
		{"environment grammar", definitions.CurrentState{}, definitions.Resolution{EnvCreates: []string{" padded "}}, domain.ErrInvalid, "padded"},
		{"group grammar", definitions.CurrentState{}, definitions.Resolution{GroupCreates: []string{" padded "}}, domain.ErrInvalid, "padded"},
		{"key cap", definitions.CurrentState{}, definitions.Resolution{KeyCreates: keys}, domain.ErrLimitExceeded, "keys"},
		{"environment cap", definitions.CurrentState{}, definitions.Resolution{EnvCreates: environments}, domain.ErrLimitExceeded, "environments"},
		{"group cap", definitions.CurrentState{}, definitions.Resolution{GroupCreates: groups}, domain.ErrLimitExceeded, "key groups"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateFinalDefinitions(test.cur, test.res)
			if !errors.Is(err, test.want) || !strings.Contains(err.Error(), test.text) {
				t.Fatalf("validation = %v, want %v naming %q", err, test.want, test.text)
			}
		})
	}
}

func TestDefinitionsPlanViewKeepsPlanTimeProtectedNames(t *testing.T) {
	expires := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	plan := store.DefinitionsPlan{
		ID: "dpl_test", Digest: "digest", BaseSchemaRevision: 12, ExpiresAt: expires,
		ProtectedEnvs: `[{"id":"env_b","name":"production"},{"id":"env_a","name":"acceptance"}]`,
		Diff:          `{"environments":{"creates":[],"updates":[],"renames":[],"deletes":[]},"key_groups":{"creates":[],"updates":[],"renames":[],"deletes":[]},"keys":{"creates":[],"updates":[],"renames":[],"deletes":[]},"key_deletions":[],"env_deletions":[],"reveal_required":[]}`,
	}
	got, err := planViewOf(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.ProtectedEnvironments, ",") != "acceptance,production" {
		t.Fatalf("protected names = %v", got.ProtectedEnvironments)
	}
	if got.CurrentRevision != 12 || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("plan-time pins changed: revision=%d expires=%s", got.CurrentRevision, got.ExpiresAt)
	}

	plan.ProtectedEnvs = `["legacy-id-only"]`
	if _, err := planViewOf(plan); err == nil {
		t.Fatal("legacy/corrupt protected pin unexpectedly decoded")
	}
}

func TestDefinitionsRevisionPinsSeparateTopologyFromValueDrift(t *testing.T) {
	pinned := map[string]int64{"env_a": 2, "env_b": 4}
	if !sameRevisionKeys(pinned, map[string]int64{"env_a": 7, "env_b": 4}) {
		t.Fatal("value revision movement was mistaken for topology drift")
	}
	if sameRevisionKeys(pinned, map[string]int64{"env_a": 2, "env_c": 4}) {
		t.Fatal("environment replacement did not trip topology pin")
	}
	if id, changed := changedRevision(pinned, map[string]int64{"env_a": 3, "env_b": 9}); !changed || id != "env_a" {
		t.Fatalf("first stable changed revision = %q, %v; want env_a, true", id, changed)
	}
}
