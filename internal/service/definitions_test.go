package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
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
