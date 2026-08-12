package schema

import "strings"

// Presence rules (schema-model ADR § Presence, as amended by the flat-model
// ADR: presence resolves over `set | absent`, and the value a rule talks about
// attaches to a `(key, environment)` pair).
//
// Required-ness varies per environment because a project-wide `required`
// boolean is broken by the ordinary case: STRIPE_SECRET_KEY is required in
// prod and meaningless in local. `required` is a predicate about PRESENCE
// only — it means "resolves to `set`" and says nothing about content, which is
// the type's business.

// PresenceMode is the rule's shape. It is a mode plus an explicit set rather
// than a bare id list because `all` must be SYMBOLIC: had it been expanded
// into the ids existing at declaration time, a newly created environment would
// silently be exempt from a rule the operator wrote as "always".
type PresenceMode string

const (
	// PresenceNone is the default for both rules.
	PresenceNone PresenceMode = "none"
	// PresenceAll covers environments created later, by construction.
	PresenceAll PresenceMode = "all"
	// PresenceExplicit carries the environment-id set.
	PresenceExplicit PresenceMode = "explicit"
)

// Presence is one rule: `required_in` or `forbidden_in`.
type Presence struct {
	Mode         PresenceMode `json:"mode"`
	Environments []string     `json:"environment_ids,omitempty"`
}

// PresenceRules is a key's pair of rules, which is the unit the group check
// compares.
type PresenceRules struct {
	Required  Presence `json:"required_in"`
	Forbidden Presence `json:"forbidden_in"`
}

// DefaultPresenceRules is the declaration default: neither required nor
// forbidden anywhere.
func DefaultPresenceRules() PresenceRules {
	return PresenceRules{
		Required:  Presence{Mode: PresenceNone},
		Forbidden: Presence{Mode: PresenceNone},
	}
}

// CheckPresence enforces well-formedness and the statically decidable
// conflict: a key both required and forbidden in the same environment —
// including via `mode: all` on either side — is rejected at DECLARATION rather
// than discovered at publish, because a rule that can never be satisfied is a
// broken rule, not a value that happens to be wrong.
func CheckPresence(required, forbidden Presence) error {
	if err := checkPresenceShape("required_in", required); err != nil {
		return err
	}
	if err := checkPresenceShape("forbidden_in", forbidden); err != nil {
		return err
	}
	if conflict, why := overlap(required, forbidden); conflict {
		return declErr("a key cannot be both `required_in` and `forbidden_in` the same environment (%s)", why)
	}
	return nil
}

// CheckGroupPresence is the same conflict across two members of one key group.
// A group's all-or-none resolved presence means either every member resolves
// to `set` in an environment or none do, so one member required where another
// is forbidden can never hold — statically, before any value exists.
func CheckGroupPresence(a, b PresenceRules) error {
	ab, _ := overlap(a.Required, b.Forbidden)
	ba, _ := overlap(b.Required, a.Forbidden)
	if ab || ba {
		return declErr("two members of one key group cannot be `required_in` and `forbidden_in` the same environment — a group's presence is all-or-none")
	}
	return nil
}

func checkPresenceShape(what string, p Presence) error {
	switch p.Mode {
	case PresenceNone, PresenceAll:
		if len(p.Environments) > 0 {
			return declErr("`%s` mode %q carries no environment ids", what, p.Mode)
		}
	case PresenceExplicit:
		if len(p.Environments) == 0 {
			return declErr("`%s` mode `explicit` names at least one environment", what)
		}
		seen := make(map[string]bool, len(p.Environments))
		for _, id := range p.Environments {
			if id == "" {
				return declErr("`%s` names an empty environment id", what)
			}
			if seen[id] {
				return declErr("`%s` names environment %q more than once", what, id)
			}
			seen[id] = true
		}
	default:
		return declErr("`%s` mode %q is not one of all|none|explicit", what, p.Mode)
	}
	return nil
}

// overlap answers whether the two rules can bind the same environment, and
// names the reason in one pass. `none` never binds anything; `all` binds
// everything including environments created later, so `all` against anything
// but `none` overlaps.
//
// The reason rides along because the caller needs both and computing them
// separately meant walking the same intersection twice, in two functions that
// had to agree. Environment ids are server-minted vocabulary, so naming them
// discloses nothing a caller could not already address.
func overlap(required, forbidden Presence) (bool, string) {
	if required.Mode == PresenceNone || forbidden.Mode == PresenceNone {
		return false, ""
	}
	if required.Mode == PresenceAll || forbidden.Mode == PresenceAll {
		return true, "one of the rules uses mode `all`"
	}
	inRequired := make(map[string]bool, len(required.Environments))
	for _, id := range required.Environments {
		inRequired[id] = true
	}
	var both []string
	for _, id := range forbidden.Environments {
		if inRequired[id] {
			both = append(both, id)
		}
	}
	if len(both) == 0 {
		return false, ""
	}
	return true, "environments " + strings.Join(both, ", ")
}
