package definitions

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

func curKey(id, name, class string) CurrentKey {
	return CurrentKey{
		ID: id, Name: name, Classification: class,
		Declaration: stringRule(),
		Required:    schema.Presence{Mode: schema.PresenceNone},
		Forbidden:   schema.Presence{Mode: schema.PresenceNone},
	}
}

func bKey(id, name, class string) Key {
	return Key{
		ID: id, Name: name, Classification: class, Declaration: stringRule(),
		RequiredIn:  Presence{Mode: "none", Environments: []string{}},
		ForbiddenIn: Presence{Mode: "none", Environments: []string{}},
	}
}

// ADR worked example: id-1 named A, bundle holds {id-1, name B} plus a bare
// {name A}. id-1 binds and becomes B; the bare A finds no unbound identity and
// is a create.
func TestResolveIDFirstThenBareCreate(t *testing.T) {
	cur := CurrentState{SchemaRevision: 5, Keys: []CurrentKey{curKey("id-1", "A", "config")}}
	b := Bundle{
		FormatVersion: FormatVersion, BaseRevision: rev(5),
		Environments: []Environment{}, KeyGroups: []KeyGroup{},
		Keys: []Key{bKey("id-1", "B", "config"), bKey("", "A", "config")},
	}
	b, _ = Normalize(b)
	res, err := Resolve(b, cur)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.KeyCreates) != 1 || res.KeyCreates[0].Name != "A" {
		t.Fatalf("bare A must be a create, got creates %+v", res.KeyCreates)
	}
	if len(res.KeyUpdates) != 1 || res.KeyUpdates[0].ID != "id-1" || !res.KeyUpdates[0].Renamed {
		t.Fatalf("id-1 must rename to B, got updates %+v", res.KeyUpdates)
	}
	if len(res.KeyDeletes) != 0 {
		t.Fatalf("nothing deleted, got %+v", res.KeyDeletes)
	}
}

// Swap: A->B and B->A, both id-bearing, resolves without collision.
func TestResolveSwapRename(t *testing.T) {
	cur := CurrentState{SchemaRevision: 3, Keys: []CurrentKey{
		curKey("id-a", "A", "config"), curKey("id-b", "B", "config"),
	}}
	b := Bundle{
		FormatVersion: FormatVersion, BaseRevision: rev(3),
		Environments: []Environment{}, KeyGroups: []KeyGroup{},
		Keys: []Key{bKey("id-a", "B", "config"), bKey("id-b", "A", "config")},
	}
	b, _ = Normalize(b)
	res, err := Resolve(b, cur)
	if err != nil {
		t.Fatalf("swap must resolve: %v", err)
	}
	if len(res.KeyUpdates) != 2 || len(res.KeyCreates) != 0 || len(res.KeyDeletes) != 0 {
		t.Fatalf("swap = two renames, no create/delete: %+v", res)
	}
}

func TestResolveStaleIDIsHardError(t *testing.T) {
	cur := CurrentState{SchemaRevision: 1, Keys: []CurrentKey{curKey("id-1", "A", "config")}}
	b := Bundle{
		FormatVersion: FormatVersion, BaseRevision: rev(1),
		Environments: []Environment{}, KeyGroups: []KeyGroup{},
		Keys: []Key{bKey("id-ghost", "A", "config")},
	}
	b, _ = Normalize(b)
	_, err := Resolve(b, cur)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "stale file") {
		t.Fatalf("stale id must be a hard error: %v", err)
	}
}

func TestResolveDuplicateFinalNameNamesBoth(t *testing.T) {
	cur := CurrentState{SchemaRevision: 1, Keys: []CurrentKey{
		curKey("id-1", "A", "config"), curKey("id-2", "B", "config"),
	}}
	b := Bundle{
		FormatVersion: FormatVersion, BaseRevision: rev(1),
		Environments: []Environment{}, KeyGroups: []KeyGroup{},
		Keys: []Key{bKey("id-1", "SAME", "config"), bKey("id-2", "SAME", "config")},
	}
	b, _ = Normalize(b)
	_, err := Resolve(b, cur)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "SAME") {
		t.Fatalf("duplicate final name must name it: %v", err)
	}
}

// A portable bundle (no ids, no base) applied to its own project matches by name
// at step 3 rather than duplicating.
func TestResolvePortableMatchesByName(t *testing.T) {
	cur := CurrentState{SchemaRevision: 7, Keys: []CurrentKey{
		curKey("id-1", "A", "config"), curKey("id-2", "B", "config"),
	}}
	b := Bundle{
		FormatVersion: FormatVersion, // no base -> additive/portable
		Environments:  []Environment{}, KeyGroups: []KeyGroup{},
		Keys: []Key{bKey("", "A", "config"), bKey("", "B", "config")},
	}
	b, _ = Normalize(b)
	res, err := Resolve(b, cur)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.KeyCreates) != 0 {
		t.Fatalf("portable re-apply must not duplicate: %+v", res.KeyCreates)
	}
}

func TestResolveAdditiveModificationRefused(t *testing.T) {
	cur := CurrentState{SchemaRevision: 1, Keys: []CurrentKey{
		{ID: "id-1", Name: "A", Classification: "config",
			Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
			Required:    schema.Presence{Mode: schema.PresenceNone}, Forbidden: schema.Presence{Mode: schema.PresenceNone}},
	}}
	// Same name, different declaration -> modification.
	mod := bKey("", "A", "config")
	mod.Declaration = schema.Declaration{Rule: &schema.Rule{Type: schema.TypeInteger}}
	b := Bundle{FormatVersion: FormatVersion, Environments: []Environment{}, KeyGroups: []KeyGroup{}, Keys: []Key{mod}}
	b, _ = Normalize(b)
	_, err := Resolve(b, cur)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "additive bundle may not modify") {
		t.Fatalf("additive modification must be refused naming the key: %v", err)
	}
}

func TestResolveDeletionByAbsence(t *testing.T) {
	cur := CurrentState{SchemaRevision: 4, Keys: []CurrentKey{
		curKey("id-1", "KEEP", "config"), curKey("id-2", "DROP", "secret"),
	}}
	b := Bundle{
		FormatVersion: FormatVersion, BaseRevision: rev(4),
		Environments: []Environment{}, KeyGroups: []KeyGroup{},
		Keys: []Key{bKey("id-1", "KEEP", "config")},
	}
	b, _ = Normalize(b)
	res, err := Resolve(b, cur)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.KeyDeletes) != 1 || res.KeyDeletes[0].Name != "DROP" {
		t.Fatalf("absent key must be a deletion: %+v", res.KeyDeletes)
	}
	if !res.DeletionsPresent() {
		t.Fatal("DeletionsPresent must be true")
	}
}

func TestResolveRevealOnSecretRuleChange(t *testing.T) {
	cur := CurrentState{SchemaRevision: 2, Keys: []CurrentKey{{
		ID: "id-1", Name: "TOKEN", Classification: "secret",
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Required:    schema.Presence{Mode: schema.PresenceNone}, Forbidden: schema.Presence{Mode: schema.PresenceNone},
	}}}
	changed := bKey("id-1", "TOKEN", "secret")
	changed.Declaration = schema.Declaration{Rule: &schema.Rule{Type: schema.TypeInteger}}
	b := Bundle{FormatVersion: FormatVersion, BaseRevision: rev(2), Environments: []Environment{}, KeyGroups: []KeyGroup{}, Keys: []Key{changed}}
	b, _ = Normalize(b)
	res, err := Resolve(b, cur)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RevealKeys) != 1 || res.RevealKeys[0] != "TOKEN" {
		t.Fatalf("secret rule change must require reveal: %+v", res.RevealKeys)
	}
}

func TestResolveDanglingPresenceRejected(t *testing.T) {
	cur := CurrentState{SchemaRevision: 1}
	k := bKey("", "A", "config")
	k.RequiredIn = Presence{Mode: "explicit", Environments: []string{"ghost"}}
	b := Bundle{FormatVersion: FormatVersion, Environments: []Environment{}, KeyGroups: []KeyGroup{}, Keys: []Key{k}}
	b, _ = Normalize(b)
	_, err := Resolve(b, cur)
	if !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("dangling presence env must be rejected naming it: %v", err)
	}
}

func TestClassifyDrift(t *testing.T) {
	cur := CurrentState{SchemaRevision: 10, Keys: []CurrentKey{curKey("id-1", "A", "config")}}
	equalBundle := func(base int64, keys ...Key) Bundle {
		b := Bundle{FormatVersion: FormatVersion, BaseRevision: rev(base), Environments: []Environment{}, KeyGroups: []KeyGroup{}, Keys: keys}
		b, _ = Normalize(b)
		return b
	}
	cases := []struct {
		name string
		b    Bundle
		want DriftState
	}{
		{"equal", equalBundle(10, bKey("id-1", "A", "config")), DriftEqual},
		{"file_ahead", equalBundle(10, bKey("id-1", "A", "config"), bKey("", "NEW", "config")), DriftFileAhead},
		{"db_ahead", equalBundle(8, bKey("id-1", "A", "config")), DriftDBAhead},
		{"diverged", equalBundle(8, bKey("id-1", "A", "config"), bKey("", "NEW", "config")), DriftDiverged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Classify(tc.b, cur)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("drift = %s, want %s", got, tc.want)
			}
		})
	}

	// base ahead of current -> impossible/foreign bundle.
	foreign := equalBundle(99, bKey("id-1", "A", "config"))
	if _, err := Classify(foreign, cur); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("base ahead must be ErrInvalid: %v", err)
	}
}
