package service

import (
	"context"
	"fmt"
	"slices"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

type groupIndexInputKind uint8

const (
	groupIndexCatalogueInput groupIndexInputKind = iota
	groupIndexPresenceInput
)

type groupEnvironment struct {
	groupID       string
	environmentID string
}

// groupIndex is one immutable catalogue/presence snapshot. It belongs to one
// transaction-local validation phase: callers rebuild it after catalogue or
// membership writes instead of carrying a mutable cache across phases.
type groupIndex struct {
	keys           []store.CatalogueKey
	keyByID        map[string]store.CatalogueKey
	membersByGroup map[string][]store.CatalogueKey
	presenceByKey  map[string]schema.PresenceRules
}

// groupIndexPhase loads one immutable snapshot lazily after the first
// environment authorization, then shares it across that validation phase.
// A catalogue mutation starts a new phase by constructing a new value.
type groupIndexPhase struct {
	index *groupIndex
}

func (p *groupIndexPhase) snapshot(ctx context.Context, catalogue store.CatalogueReader, proof authz.Proof) (*groupIndex, error) {
	if p.index != nil {
		return p.index, nil
	}
	index, err := loadGroupIndex(ctx, catalogue, proof)
	if err != nil {
		return nil, err
	}
	p.index = index
	return index, nil
}

func newGroupIndex(keys []store.CatalogueKey, presence []store.KeyPresence) (*groupIndex, error) {
	return buildGroupIndex(keys, presence, nil)
}

// buildGroupIndex has an observation seam only for the required linear-scan
// invariant test. Production passes nil through newGroupIndex.
func buildGroupIndex(keys []store.CatalogueKey, presence []store.KeyPresence, observed func(groupIndexInputKind)) (*groupIndex, error) {
	index := &groupIndex{
		keys:           slices.Clone(keys),
		keyByID:        make(map[string]store.CatalogueKey, len(keys)),
		membersByGroup: make(map[string][]store.CatalogueKey),
		presenceByKey:  make(map[string]schema.PresenceRules, len(keys)),
	}
	for _, key := range index.keys {
		if observed != nil {
			observed(groupIndexCatalogueInput)
		}
		if _, exists := index.keyByID[key.ID]; exists {
			return nil, fmt.Errorf("service: group index: duplicate catalogue key %s", key.ID)
		}
		index.keyByID[key.ID] = key
		if key.GroupID != "" {
			index.membersByGroup[key.GroupID] = append(index.membersByGroup[key.GroupID], key)
		}
		index.presenceByKey[key.ID] = schema.PresenceRules{
			Required:  schema.Presence{Mode: schema.PresenceMode(key.RequiredMode)},
			Forbidden: schema.Presence{Mode: schema.PresenceMode(key.ForbiddenMode)},
		}
	}
	for _, row := range presence {
		if observed != nil {
			observed(groupIndexPresenceInput)
		}
		rules, exists := index.presenceByKey[row.KeyID]
		if !exists {
			return nil, fmt.Errorf("service: group index: presence row names unknown key %s", row.KeyID)
		}
		switch {
		case row.Rule == store.PresenceRuleRequired && rules.Required.Mode == schema.PresenceExplicit:
			rules.Required.Environments = append(rules.Required.Environments, row.EnvironmentID)
		case row.Rule == store.PresenceRuleForbidden && rules.Forbidden.Mode == schema.PresenceExplicit:
			rules.Forbidden.Environments = append(rules.Forbidden.Environments, row.EnvironmentID)
		}
		index.presenceByKey[row.KeyID] = rules
	}
	return index, nil
}

func loadGroupIndex(ctx context.Context, catalogue store.CatalogueReader, proof authz.Proof) (*groupIndex, error) {
	keys, err := catalogue.List(ctx, proof)
	if err != nil {
		return nil, err
	}
	presence, err := catalogue.ListPresence(ctx, proof)
	if err != nil {
		return nil, err
	}
	return newGroupIndex(keys, presence)
}

// loadGroupMembershipIndex is for closure-only phases such as restore impact
// preview. Those proofs can read catalogue membership but do not validate
// environment presence; requiring ListPresence there would widen their store
// operation set for data the phase never consumes.
func loadGroupMembershipIndex(ctx context.Context, catalogue store.CatalogueReader, proof authz.Proof) (*groupIndex, error) {
	keys, err := catalogue.List(ctx, proof)
	if err != nil {
		return nil, err
	}
	return newGroupIndex(keys, nil)
}

func (i *groupIndex) catalogueKeys() []store.CatalogueKey {
	return i.keys
}

func (i *groupIndex) key(id string) (store.CatalogueKey, bool) {
	key, ok := i.keyByID[id]
	return key, ok
}

func (i *groupIndex) members(groupID string) []store.CatalogueKey {
	return i.membersByGroup[groupID]
}

func (i *groupIndex) presenceFor(keyID string) (schema.PresenceRules, error) {
	rules, exists := i.presenceByKey[keyID]
	if !exists {
		return schema.PresenceRules{}, fmt.Errorf("service: group index: key %s is not indexed", keyID)
	}
	return rules, nil
}

// validateStaticMembership is declaration-time authority for the statically
// decidable required/forbidden conflict between members of one group.
func (i *groupIndex) validateStaticMembership(groupID, selfID string, self schema.PresenceRules) error {
	if groupID == "" {
		return nil
	}
	for _, member := range i.members(groupID) {
		if member.ID == selfID {
			continue
		}
		other, err := i.presenceFor(member.ID)
		if err != nil {
			return err
		}
		if err := schema.CheckGroupPresence(self, other); err != nil {
			return fmt.Errorf("%w: %s (with key %q)", domain.ErrInvalid, err, member.Name)
		}
	}
	return nil
}

// validateResolvedPublish is publish-time authority over resolved values. It
// keeps per-key presence/value refusals in catalogue order, then evaluates each
// (group, environment) bucket for all-or-none presence.
func (i *groupIndex) validateResolvedPublish(cells []resolvedCell, envID string) error {
	groups := make(map[groupEnvironment][]resolvedCell)
	for _, cell := range cells {
		rules, err := i.presenceFor(cell.key.ID)
		if err != nil {
			return err
		}
		switch {
		case rules.Required.Covers(envID) && !cell.set:
			// mvp-boundary C2: required_in absent vetoes by key and env.
			return invalidDetail("key %q is `required_in` environment %s and resolves to absent: publish is vetoed",
				cell.key.Name, envID)
		case rules.Forbidden.Covers(envID) && cell.set:
			return invalidDetail("key %q is `forbidden_in` environment %s and resolves to set: publish is vetoed",
				cell.key.Name, envID)
		}
		if cell.set {
			if err := validateValue(cell.key, cell.value); err != nil {
				return err
			}
		}
		if cell.key.GroupID != "" {
			bucket := groupEnvironment{groupID: cell.key.GroupID, environmentID: envID}
			groups[bucket] = append(groups[bucket], cell)
		}
	}
	for bucket, members := range groups {
		set, absent := []string{}, []string{}
		for _, member := range members {
			if member.set {
				set = append(set, member.key.Name)
			} else {
				absent = append(absent, member.key.Name)
			}
		}
		if len(set) > 0 && len(absent) > 0 {
			slices.Sort(set)
			slices.Sort(absent)
			return invalidDetail("key group %s resolves partially in environment %s: set %v, absent %v: a group's presence is all-or-none",
				bucket.groupID, bucket.environmentID, set, absent)
		}
	}
	return nil
}
