package definitions

// Matching is a set operation over final state, resolved in the fixed order the
// source-of-truth ADR § Identity and absence locks: id-bearing entries bind
// first, bound identities leave the name-matching pool, remaining entries match
// by name, unmatched entries are creates, and the final state is validated
// globally before anything executes. The same algorithm runs independently for
// environments, key groups, and keys — so it lives once, here, generic over
// {id, name}.

// entity is the id+name pair the matcher pairs on. Extra fields (a key's
// declaration, an environment's topology) are compared by the diff, not the
// matcher.
type entity struct {
	id   string
	name string
}

// kindMatch is the resolved pairing for one kind. boundDBID[i] is the database
// id that bundle entry i bound to, or "" when it is a create. deletes are the
// database ids no bundle entry claimed — deletions under desired-state
// semantics, empty under additive.
type kindMatch struct {
	boundDBID []string
	creates   []int
	deletes   []string
}

// bound reports whether bundle entry i matched an existing identity.
func (m kindMatch) bound(i int) bool { return m.boundDBID[i] != "" }

// matchEntities resolves bundle entries against current database entities for
// one kind. `kind` labels refusals ("environment", "key group", "key").
func matchEntities(kind string, bundle, current []entity, additive bool) (kindMatch, error) {
	dbNames := make(map[string]string, len(current)) // id -> name
	dbByName := make(map[string]string, len(current))
	dbIDs := make(map[string]struct{}, len(current))
	for _, c := range current {
		dbNames[c.id] = c.name
		dbByName[c.name] = c.id
		dbIDs[c.id] = struct{}{}
	}

	m := kindMatch{boundDBID: make([]string, len(bundle))}
	boundBy := make(map[string]int, len(bundle)) // db id -> bundle index

	// Steps 1-2: id-bearing entries bind and leave the name pool. An id absent
	// from the database is a stale file — a hard error, never a silent create.
	for i := range bundle {
		id := bundle[i].id
		if id == "" {
			continue
		}
		if _, ok := dbIDs[id]; !ok {
			return kindMatch{}, invalidDetail(
				"bundle %s %q binds id %q, which does not exist — stale file, re-export", kind, bundle[i].name, id)
		}
		if prev, dup := boundBy[id]; dup {
			return kindMatch{}, invalidDetail(
				"bundle %ss %q and %q both bind identity %q", kind, bundle[prev].name, bundle[i].name, id)
		}
		boundBy[id] = i
		m.boundDBID[i] = id
	}

	// Step 3: remaining entries match by name against UNBOUND identities only.
	// Step 4: the rest are creates.
	for i := range bundle {
		if bundle[i].id != "" {
			continue
		}
		if dbID, ok := dbByName[bundle[i].name]; ok {
			if _, alreadyBound := boundBy[dbID]; !alreadyBound {
				boundBy[dbID] = i
				m.boundDBID[i] = dbID
				continue
			}
		}
		m.creates = append(m.creates, i)
	}

	// Step 5: final-state validation. Two entries resolving to one final name is
	// a hard error naming both; two entries binding one identity was caught in
	// step 1.
	finalNames := make(map[string]int, len(bundle))
	for i := range bundle {
		name := bundle[i].name
		if prev, dup := finalNames[name]; dup {
			return kindMatch{}, invalidDetail(
				"bundle %ss %q and %q resolve to the same final name %q", kind, bundle[prev].name, bundle[i].name, name)
		}
		finalNames[name] = i
	}

	// Unmatched database identities are deletions under desired state; additive
	// bundles derive no deletion.
	if !additive {
		for _, c := range current {
			if _, matched := boundBy[c.id]; !matched {
				m.deletes = append(m.deletes, c.id)
			}
		}
	}
	return m, nil
}
