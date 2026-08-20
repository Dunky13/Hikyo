package definitions

import (
	"fmt"
	"sort"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// Rename records an identity whose name moves. Ref names an identity by id and
// its current name.
type Rename struct {
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
}

type Ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// KeyUpdate is a bound key whose desired state differs from the database. It
// carries the desired form (presence and group still by name, resolved to ids
// by apply once the final topology exists) and the change flags the plan and
// the reveal gate read.
type KeyUpdate struct {
	ID                 string
	PrevName           string
	Desired            Key
	Renamed            bool
	MetaChanged        bool
	DeclChanged        bool
	Reclassified       bool
	GroupChanged       bool
	PresenceChanged    bool
	PrevClassification string
	PrevDeclaration    schema.Declaration
}

// Resolution is the executable diff: the exact set of store operations apply
// runs, plus the reveal-requiring keys the preview names. Environment and group
// topology ops resolve first at apply, then key ops resolve their group name
// and presence environment names against the final topology. Nothing here has
// executed — Resolve is pure.
type Resolution struct {
	Additive bool

	EnvCreates []string
	EnvRenames []Rename
	EnvDeletes []Ref

	GroupCreates []string
	GroupRenames []Rename
	GroupDeletes []Ref

	KeyCreates []Key
	KeyUpdates []KeyUpdate
	KeyDeletes []Ref

	RevealKeys []string
}

// Resolve diffs a normalized bundle against current state, applying the ADR's
// matching algorithm to environments, key groups, and keys independently and
// composing the result. It enforces the structural invariants that do not need
// the store: dangling presence/group references, additive-modification refusal,
// and the identity/name uniqueness the matcher guards. Value-dependent
// declaration and store-backed invariants (secret literal keywords, live pins,
// live occurrences) are enforced by the service at apply against the shared
// helpers.
func Resolve(b Bundle, cur CurrentState) (Resolution, error) {
	return resolve(b, cur, true)
}

// resolve is Resolve with a strictness switch. When strict, an additive bundle
// modifying an existing key is refused (the apply/plan path); when not, the
// modification is recorded as an update so drift classification can observe the
// difference without refusing (the diagnostic `check` path).
func resolve(b Bundle, cur CurrentState, strict bool) (Resolution, error) {
	additive := b.Additive()

	envMatch, err := matchEntities("environment", envEntities(b.Environments), envEntities(cur.Environments), additive)
	if err != nil {
		return Resolution{}, err
	}
	groupMatch, err := matchEntities("key group", groupEntities(b.KeyGroups), groupEntities(cur.KeyGroups), additive)
	if err != nil {
		return Resolution{}, err
	}
	keyMatch, err := matchEntities("key", bundleKeyEntities(b.Keys), currentKeyEntities(cur.Keys), additive)
	if err != nil {
		return Resolution{}, err
	}

	res := Resolution{Additive: additive}

	// Reference tables the key diff resolves identities through.
	bundleEnvNames := make(map[string]struct{}, len(b.Environments))
	envIdentityByName := make(map[string]string, len(b.Environments))
	for i, e := range b.Environments {
		bundleEnvNames[e.Name] = struct{}{}
		if envMatch.bound(i) {
			envIdentityByName[e.Name] = envMatch.boundDBID[i]
		} else {
			envIdentityByName[e.Name] = "new:" + e.Name
		}
	}
	bundleGroupNames := make(map[string]struct{}, len(b.KeyGroups))
	groupIdentityByName := make(map[string]string, len(b.KeyGroups))
	for i, g := range b.KeyGroups {
		bundleGroupNames[g.Name] = struct{}{}
		if groupMatch.bound(i) {
			groupIdentityByName[g.Name] = groupMatch.boundDBID[i]
		} else {
			groupIdentityByName[g.Name] = "new:" + g.Name
		}
	}
	curEnvName := make(map[string]string, len(cur.Environments)) // id -> name (unused but symmetric)
	for _, e := range cur.Environments {
		curEnvName[e.ID] = e.Name
	}
	curKeyByID := make(map[string]CurrentKey, len(cur.Keys))
	for _, k := range cur.Keys {
		curKeyByID[k.ID] = k
	}

	// Environments.
	for i, e := range b.Environments {
		if envMatch.bound(i) {
			from := entityName(cur.Environments, envMatch.boundDBID[i])
			if from != e.Name {
				res.EnvRenames = append(res.EnvRenames, Rename{ID: envMatch.boundDBID[i], From: from, To: e.Name})
			}
			continue
		}
		res.EnvCreates = append(res.EnvCreates, e.Name)
	}
	res.EnvDeletes = refsFor(cur.Environments, envMatch.deletes)

	// Key groups.
	for i, g := range b.KeyGroups {
		if groupMatch.bound(i) {
			from := entityName(groupEntities(cur.KeyGroups), groupMatch.boundDBID[i])
			if from != g.Name {
				res.GroupRenames = append(res.GroupRenames, Rename{ID: groupMatch.boundDBID[i], From: from, To: g.Name})
			}
			continue
		}
		res.GroupCreates = append(res.GroupCreates, g.Name)
	}
	res.GroupDeletes = refsForGroups(cur.KeyGroups, groupMatch.deletes)

	// Keys.
	for i, k := range b.Keys {
		if err := validateKeyReferences(k, bundleEnvNames, bundleGroupNames); err != nil {
			return Resolution{}, err
		}
		if !keyMatch.bound(i) {
			res.KeyCreates = append(res.KeyCreates, k)
			continue
		}
		before := curKeyByID[keyMatch.boundDBID[i]]
		upd := diffKey(before, k, envIdentityByName, groupIdentityByName)
		if !upd.changed() {
			continue
		}
		if additive && strict {
			return Resolution{}, &AdditiveModificationError{
				Key: k.Name,
				detail: fmt.Sprintf(
					"additive bundle may not modify existing key %q; export first to obtain a desired-state base", k.Name),
			}
		}
		res.KeyUpdates = append(res.KeyUpdates, upd)
		if upd.needsReveal() {
			res.RevealKeys = append(res.RevealKeys, k.Name)
		}
	}
	res.KeyDeletes = refsForKeys(cur.Keys, keyMatch.deletes)
	sort.Strings(res.RevealKeys)

	return res, nil
}

// diffKey computes the change flags for a bound key. Group and presence are
// compared in identity space so a rename of an environment or group is not
// mistaken for a membership change.
func diffKey(before CurrentKey, desired Key, envIdentity, groupIdentity map[string]string) KeyUpdate {
	upd := KeyUpdate{
		ID:                 before.ID,
		PrevName:           before.Name,
		Desired:            desired,
		PrevClassification: before.Classification,
		PrevDeclaration:    before.Declaration,
	}
	upd.Renamed = before.Name != desired.Name
	upd.MetaChanged = before.FolderPath != desired.FolderPath ||
		before.Description != desired.Description ||
		before.Deprecated != desired.Deprecated ||
		before.DeprecationNote != desired.DeprecationNote
	upd.Reclassified = before.Classification != desired.Classification
	upd.DeclChanged = schema.ValueDependentChange(before.Declaration, desired.Declaration)

	desiredGroup := ""
	if desired.Group != "" {
		desiredGroup = groupIdentity[desired.Group]
	}
	curGroup := ""
	if before.GroupID != "" {
		curGroup = before.GroupID
	}
	upd.GroupChanged = desiredGroup != curGroup

	upd.PresenceChanged = presenceChanged(before.Required, desired.RequiredIn, envIdentity) ||
		presenceChanged(before.Forbidden, desired.ForbiddenIn, envIdentity)
	return upd
}

func (u KeyUpdate) changed() bool {
	return u.Renamed || u.MetaChanged || u.DeclChanged || u.Reclassified || u.GroupChanged || u.PresenceChanged
}

// needsReveal mirrors the two locked reveal gates: a value-dependent rule change
// on a currently-secret key (schema ADR), and declassification secret→config
// (reclassification ceremony). Presence-driven reveal — an environment begins
// delivering a secret the publisher did not supply — is enforced by the publish
// pipeline itself at apply, not previewed here.
func (u KeyUpdate) needsReveal() bool {
	wasSecret := u.PrevClassification == string(schema.Secret)
	declRuleChange := wasSecret && u.DeclChanged
	declassify := wasSecret && u.Desired.Classification == string(schema.Config)
	return declRuleChange || declassify
}

// presenceChanged compares a current presence rule (environment ids) against a
// desired one (environment names) in identity space.
func presenceChanged(before schema.Presence, desired Presence, envIdentity map[string]string) bool {
	if string(before.Mode) != desired.Mode {
		return true
	}
	if schema.PresenceMode(desired.Mode) != schema.PresenceExplicit {
		return false
	}
	beforeSet := make(map[string]struct{}, len(before.Environments))
	for _, id := range before.Environments {
		beforeSet[id] = struct{}{}
	}
	if len(before.Environments) != len(desired.Environments) {
		return true
	}
	for _, name := range desired.Environments {
		if _, ok := beforeSet[envIdentity[name]]; !ok {
			return true
		}
	}
	return false
}

// validateKeyReferences rejects a key whose group or explicit presence names an
// entity absent from the bundle's own topology — a dangling reference desired
// state cannot resolve.
func validateKeyReferences(k Key, envNames, groupNames map[string]struct{}) error {
	if k.Group != "" {
		if _, ok := groupNames[k.Group]; !ok {
			return invalidDetail("key %q references key group %q, which the bundle does not declare", k.Name, k.Group)
		}
	}
	for _, p := range []struct {
		what string
		rule Presence
	}{{"required_in", k.RequiredIn}, {"forbidden_in", k.ForbiddenIn}} {
		for _, name := range p.rule.Environments {
			if _, ok := envNames[name]; !ok {
				return invalidDetail(
					"key %q %s references environment %q, which the bundle does not declare", k.Name, p.what, name)
			}
		}
	}
	return nil
}

func entityName(list any, id string) string {
	switch v := list.(type) {
	case []Environment:
		for _, e := range v {
			if e.ID == id {
				return e.Name
			}
		}
	case []entity:
		for _, e := range v {
			if e.id == id {
				return e.name
			}
		}
	}
	return ""
}

func refsFor(envs []Environment, ids []string) []Ref {
	out := make([]Ref, 0, len(ids))
	for _, id := range ids {
		out = append(out, Ref{ID: id, Name: entityName(envs, id)})
	}
	return out
}

func refsForGroups(gs []KeyGroup, ids []string) []Ref {
	byID := make(map[string]string, len(gs))
	for _, g := range gs {
		byID[g.ID] = g.Name
	}
	out := make([]Ref, 0, len(ids))
	for _, id := range ids {
		out = append(out, Ref{ID: id, Name: byID[id]})
	}
	return out
}

func refsForKeys(keys []CurrentKey, ids []string) []Ref {
	byID := make(map[string]string, len(keys))
	for _, k := range keys {
		byID[k.ID] = k.Name
	}
	out := make([]Ref, 0, len(ids))
	for _, id := range ids {
		out = append(out, Ref{ID: id, Name: byID[id]})
	}
	return out
}
