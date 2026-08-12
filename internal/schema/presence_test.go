package schema_test

import (
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/schema"
)

// Presence conflicts that are statically decidable are rejected at
// declaration, not discovered at publish (schema-model ADR § Presence).

func TestPresenceConflicts(t *testing.T) {
	all := schema.Presence{Mode: schema.PresenceAll}
	none := schema.Presence{Mode: schema.PresenceNone}
	env := func(ids ...string) schema.Presence {
		return schema.Presence{Mode: schema.PresenceExplicit, Environments: ids}
	}

	cases := []struct {
		name                string
		required, forbidden schema.Presence
		conflict            bool
	}{
		{"both none", none, none, false},
		{"required all, forbidden none", all, none, false},
		{"required all, forbidden all", all, all, true},
		{"required all, forbidden explicit", all, env("env_a"), true},
		{"required explicit, forbidden all", env("env_a"), all, true},
		{"disjoint explicit sets", env("env_a"), env("env_b"), false},
		{"overlapping explicit sets", env("env_a", "env_b"), env("env_b"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := schema.CheckPresence(tc.required, tc.forbidden)
			if tc.conflict != (err != nil) {
				t.Fatalf("CheckPresence = %v, want conflict=%v", err, tc.conflict)
			}
			if tc.conflict && !strings.Contains(err.Error(), "forbidden") {
				t.Fatalf("conflict refusal %q does not name the rules", err)
			}
		})
	}
}

func TestPresenceWellFormedness(t *testing.T) {
	for _, bad := range []schema.Presence{
		{Mode: "sometimes"},
		{Mode: schema.PresenceAll, Environments: []string{"env_a"}},
		{Mode: schema.PresenceNone, Environments: []string{"env_a"}},
		{Mode: schema.PresenceExplicit},
		{Mode: schema.PresenceExplicit, Environments: []string{"env_a", "env_a"}},
	} {
		if err := schema.CheckPresence(bad, schema.Presence{Mode: schema.PresenceNone}); err == nil {
			t.Fatalf("CheckPresence accepted %+v", bad)
		}
	}
}

// A group's all-or-none presence is broken statically when one member is
// required where another is forbidden, so that pair is refused at declaration.
func TestGroupPresenceConflict(t *testing.T) {
	a := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceAll},
		Forbidden: schema.Presence{Mode: schema.PresenceNone},
	}
	b := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceNone},
		Forbidden: schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{"env_a"}},
	}
	if err := schema.CheckGroupPresence(a, b); err == nil {
		t.Fatal("a member required everywhere beside one forbidden in env_a is not all-or-none")
	}
	clean := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{"env_a"}},
		Forbidden: schema.Presence{Mode: schema.PresenceNone},
	}
	if err := schema.CheckGroupPresence(clean, clean); err != nil {
		t.Fatalf("identical presence rules conflict: %v", err)
	}
}
