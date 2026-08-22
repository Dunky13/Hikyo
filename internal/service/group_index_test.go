package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestGroupIndexStaticPresencePermutations(t *testing.T) {
	prodRequired := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{"env_prod"}},
		Forbidden: schema.Presence{Mode: schema.PresenceNone},
	}
	prodForbidden := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceNone},
		Forbidden: schema.Presence{Mode: schema.PresenceExplicit, Environments: []string{"env_prod"}},
	}
	defaultPresence := schema.DefaultPresenceRules()

	tests := []struct {
		name      string
		groupID   string
		selfID    string
		self      schema.PresenceRules
		wantError bool
		wantName  string
	}{
		{name: "required conflicts with forbidden sibling", groupID: "group_database", selfID: "key_password", self: prodRequired, wantError: true, wantName: "DB_USER"},
		{name: "forbidden conflicts with required sibling", groupID: "group_database", selfID: "key_user", self: prodForbidden, wantError: true, wantName: "DB_PASSWORD"},
		{name: "same forbidden rule is compatible", groupID: "group_database", selfID: "key_password", self: prodForbidden},
		{name: "different group is ignored", groupID: "group_cache", selfID: "key_cache", self: prodRequired},
		{name: "ungrouped is a no-op", selfID: "key_password", self: prodRequired},
		{name: "default presence is compatible", groupID: "group_database", selfID: "key_password", self: defaultPresence},
	}

	index, err := newGroupIndex([]store.CatalogueKey{
		{ID: "key_user", Name: "DB_USER", GroupID: "group_database", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceExplicit)},
		{ID: "key_password", Name: "DB_PASSWORD", GroupID: "group_database", RequiredMode: string(schema.PresenceExplicit), ForbiddenMode: string(schema.PresenceNone)},
		{ID: "key_cache", Name: "CACHE_URL", GroupID: "group_cache", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceNone)},
	}, []store.KeyPresence{
		{KeyID: "key_user", EnvironmentID: "env_prod", Rule: store.PresenceRuleForbidden},
		{KeyID: "key_password", EnvironmentID: "env_prod", Rule: store.PresenceRuleRequired},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := index.validateStaticMembership(tc.groupID, tc.selfID, tc.self)
			if got := err != nil; got != tc.wantError {
				t.Fatalf("validateStaticMembership() error = %v, wantError %t", err, tc.wantError)
			}
			if tc.wantName != "" && (err == nil || !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), tc.wantName)) {
				t.Fatalf("validateStaticMembership() = %v, want ErrInvalid naming %q", err, tc.wantName)
			}
		})
	}
}

func TestGroupIndexResolvedEnvironmentPermutations(t *testing.T) {
	keys := []store.CatalogueKey{
		{ID: "key_user", Name: "DB_USER", GroupID: "group_database", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceNone), Declaration: `{"rule":{"type":"string"}}`, Classification: string(schema.Config)},
		{ID: "key_password", Name: "DB_PASSWORD", GroupID: "group_database", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceNone), Declaration: `{"rule":{"type":"string"}}`, Classification: string(schema.Config)},
		{ID: "key_cache", Name: "CACHE_URL", GroupID: "", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceNone), Declaration: `{"rule":{"type":"string"}}`, Classification: string(schema.Config)},
	}
	index, err := newGroupIndex(keys, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		envID     string
		set       map[string]bool
		wantError bool
	}{
		{name: "all absent", envID: "env_dev", set: map[string]bool{}},
		{name: "all set", envID: "env_dev", set: map[string]bool{"key_user": true, "key_password": true}},
		{name: "first member only", envID: "env_dev", set: map[string]bool{"key_user": true}, wantError: true},
		{name: "second member only", envID: "env_prod", set: map[string]bool{"key_password": true}, wantError: true},
		{name: "ungrouped value does not affect closure", envID: "env_prod", set: map[string]bool{"key_cache": true}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cells := make([]resolvedCell, 0, len(keys))
			for _, key := range keys {
				cells = append(cells, resolvedCell{key: key, set: tc.set[key.ID], value: "value"})
			}
			err := index.validateResolvedPublish(cells, tc.envID)
			if got := err != nil; got != tc.wantError {
				t.Fatalf("validateResolvedPublish() error = %v, wantError %t", err, tc.wantError)
			}
			if tc.wantError && (!errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "group_database") || !strings.Contains(err.Error(), tc.envID)) {
				t.Fatalf("validateResolvedPublish() = %v, want group/environment detail", err)
			}
		})
	}
}

func TestGroupIndexBuildScansEachInputRowOnce(t *testing.T) {
	keys := []store.CatalogueKey{
		{ID: "key_a", GroupID: "group_a", RequiredMode: string(schema.PresenceExplicit), ForbiddenMode: string(schema.PresenceNone)},
		{ID: "key_b", GroupID: "group_a", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceExplicit)},
		{ID: "key_c", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceNone)},
	}
	presence := []store.KeyPresence{
		{KeyID: "key_a", EnvironmentID: "env_dev", Rule: store.PresenceRuleRequired},
		{KeyID: "key_a", EnvironmentID: "env_prod", Rule: store.PresenceRuleRequired},
		{KeyID: "key_b", EnvironmentID: "env_prod", Rule: store.PresenceRuleForbidden},
	}
	var keyScans, presenceScans int
	index, err := buildGroupIndex(keys, presence, func(kind groupIndexInputKind) {
		switch kind {
		case groupIndexCatalogueInput:
			keyScans++
		case groupIndexPresenceInput:
			presenceScans++
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	if keyScans != len(keys) || presenceScans != len(presence) {
		t.Fatalf("build scans = keys %d/%d, presence %d/%d; want each input row once", keyScans, len(keys), presenceScans, len(presence))
	}
	rules, err := index.presenceFor("key_a")
	if err != nil {
		t.Fatal(err)
	}
	if got := rules.Required.Environments; len(got) != 2 {
		t.Fatalf("indexed explicit presence = %v, want both environments", got)
	}
}

func TestGroupIndexRefusesBrokenInputRelationships(t *testing.T) {
	keys := []store.CatalogueKey{{ID: "key_a"}}
	if _, err := newGroupIndex(keys, []store.KeyPresence{{KeyID: "key_missing", EnvironmentID: "env_prod", Rule: store.PresenceRuleRequired}}); err == nil {
		t.Fatal("presence row for an unknown key was silently dropped")
	}
	if _, err := newGroupIndex(append(keys, keys[0]), nil); err == nil {
		t.Fatal("duplicate catalogue key was silently collapsed")
	}
	index, err := newGroupIndex(keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := index.presenceFor("key_missing"); err == nil {
		t.Fatal("unknown key presence silently became zero-value rules")
	}
}

func TestGroupIndexPhaseReadsCatalogueAndPresenceOnce(t *testing.T) {
	cat := &countingGroupIndexCatalogue{
		keys: []store.CatalogueKey{{ID: "key_a", RequiredMode: string(schema.PresenceNone), ForbiddenMode: string(schema.PresenceNone)}},
	}
	phase := &groupIndexPhase{}
	first, err := phase.snapshot(t.Context(), cat, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := phase.snapshot(t.Context(), cat, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("one validation phase returned two different group snapshots")
	}
	if cat.listCalls != 1 || cat.presenceCalls != 1 {
		t.Fatalf("catalogue reads = List %d, ListPresence %d; want one each", cat.listCalls, cat.presenceCalls)
	}
}

func TestGroupMembershipIndexDoesNotReadPresence(t *testing.T) {
	cat := &countingGroupIndexCatalogue{
		keys: []store.CatalogueKey{{ID: "key_a", GroupID: "group_a"}},
	}
	index, err := loadGroupMembershipIndex(t.Context(), cat, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.members("group_a")) != 1 {
		t.Fatal("membership-only snapshot omitted the grouped key")
	}
	if cat.listCalls != 1 || cat.presenceCalls != 0 {
		t.Fatalf("catalogue reads = List %d, ListPresence %d; want membership-only 1/0", cat.listCalls, cat.presenceCalls)
	}
}

type countingGroupIndexCatalogue struct {
	keys          []store.CatalogueKey
	presence      []store.KeyPresence
	listCalls     int
	presenceCalls int
}

func (c *countingGroupIndexCatalogue) Get(context.Context, authz.Proof, string) (store.CatalogueKey, error) {
	return store.CatalogueKey{}, errors.New("unexpected Get")
}
func (c *countingGroupIndexCatalogue) List(context.Context, authz.Proof) ([]store.CatalogueKey, error) {
	c.listCalls++
	return c.keys, nil
}
func (c *countingGroupIndexCatalogue) Count(context.Context, authz.Proof) (int64, error) {
	return 0, errors.New("unexpected Count")
}
func (c *countingGroupIndexCatalogue) AdapterPins(context.Context, authz.Proof, string) ([]store.AdapterPin, error) {
	return nil, errors.New("unexpected AdapterPins")
}
func (c *countingGroupIndexCatalogue) GetGroup(context.Context, authz.Proof, string) (store.CatalogueGroup, error) {
	return store.CatalogueGroup{}, errors.New("unexpected GetGroup")
}
func (c *countingGroupIndexCatalogue) ListGroups(context.Context, authz.Proof) ([]store.CatalogueGroup, error) {
	return nil, errors.New("unexpected ListGroups")
}
func (c *countingGroupIndexCatalogue) CountGroups(context.Context, authz.Proof) (int64, error) {
	return 0, errors.New("unexpected CountGroups")
}
func (c *countingGroupIndexCatalogue) ListPresence(context.Context, authz.Proof) ([]store.KeyPresence, error) {
	c.presenceCalls++
	return c.presence, nil
}
func (c *countingGroupIndexCatalogue) SchemaRevision(context.Context, authz.Proof) (int64, error) {
	return 0, errors.New("unexpected SchemaRevision")
}

var _ store.CatalogueReader = (*countingGroupIndexCatalogue)(nil)
