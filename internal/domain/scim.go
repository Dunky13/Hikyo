package domain

import (
	"errors"
	"sort"
	"strings"
)

// SCIM provisioning vocabulary (#73, scim-provisioning ADR). Closed sets only:
// the provider kinds a binding may reference, the attention states, the
// lockout-retention causes, the templates a mapping row may target, and the
// origin kinds the SCIM engine — as opposed to the human grant surface — is
// allowed to write.

// ProviderKind is the identity-protocol family a binding references (§1).
type ProviderKind string

const (
	ProviderOIDC ProviderKind = "oidc"
	ProviderSAML ProviderKind = "saml"
)

// IsProviderKind reports membership of the closed set.
func IsProviderKind(k ProviderKind) bool { return k == ProviderOIDC || k == ProviderSAML }

// SCIMAttention is one enumerated attention state on a binding (§9). Each is
// audited on entry and on exit and names a cause and a remediation.
type SCIMAttention string

const (
	// AttentionProviderUnavailable — the referenced provider is disabled or
	// removed; the binding's entire wire surface fails closed (§1).
	AttentionProviderUnavailable SCIMAttention = "provider_unavailable"
	// AttentionLockoutRetention — a `lockout-retention` origin is holding a
	// grant the IdP withdrew (§2.4).
	AttentionLockoutRetention SCIMAttention = "lockout_retention"
	// AttentionManualGrantsRemain — the IdP deprovisioned a user who still
	// holds manual grants in this org (§5.3).
	AttentionManualGrantsRemain SCIMAttention = "manual_grants_remain"
	// AttentionInertMapping — a mapping row names a group that no longer
	// exists (§5.4, Group DELETE).
	AttentionInertMapping SCIMAttention = "inert_mapping"
	// AttentionStale — no IdP contact past the staleness threshold (§9).
	AttentionStale SCIMAttention = "stale"
	// AttentionPostRestore — from restore until re-mint plus the first
	// completed re-assertion cycle (§9.1).
	AttentionPostRestore SCIMAttention = "post_restore"
)

// SCIMAttentionStates returns the closed enumeration, sorted.
func SCIMAttentionStates() []SCIMAttention {
	out := []SCIMAttention{
		AttentionProviderUnavailable, AttentionLockoutRetention,
		AttentionManualGrantsRemain, AttentionInertMapping,
		AttentionStale, AttentionPostRestore,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsSCIMAttention reports membership of the closed set.
func IsSCIMAttention(s SCIMAttention) bool {
	for _, k := range SCIMAttentionStates() {
		if k == s {
			return true
		}
	}
	return false
}

// SCIMCause is the triggering operation recorded on a `lockout-retention`
// origin and on the attention state it raises (§10's closed `cause` enum).
type SCIMCause string

const (
	CauseDeprovision   SCIMCause = "deprovision"
	CauseUserDeleted   SCIMCause = "user_deleted"
	CauseMemberRemoved SCIMCause = "member_removed"
	CauseGroupDeleted  SCIMCause = "group_deleted"
	CauseMappingDelete SCIMCause = "mapping_deleted"
	CauseBindingDelete SCIMCause = "binding_deleted"
	// CauseReactivation is an EXIT cause only: the identity provider set
	// `active` back to true, which ends the deprovisioned-with-remainder
	// condition. No retention is ever created under it.
	CauseReactivation SCIMCause = "reactivation"
)

// SCIMCauses returns the closed enumeration, sorted.
func SCIMCauses() []SCIMCause {
	out := []SCIMCause{
		CauseDeprovision, CauseUserDeleted, CauseMemberRemoved,
		CauseGroupDeleted, CauseMappingDelete, CauseBindingDelete,
		CauseReactivation,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsSCIMCause reports membership of the closed set.
func IsSCIMCause(c SCIMCause) bool {
	for _, k := range SCIMCauses() {
		if k == c {
			return true
		}
	}
	return false
}

// systemOrigins is the subset of the closed origin enumeration the SCIM
// engine writes. It is deliberately a SECOND predicate rather than a widening
// of mintableOrigins: the human grant surface uses IsMintableOrigin as its
// RELEASE gate — a revoke releases every origin that set contains — so
// widening it would make an administrator's revoke tear out `scim` origins,
// which is precisely the hand-mutation the ADR §4 refuses.
var systemOrigins = map[OriginKind]bool{
	OriginSCIM:             true,
	OriginStructural:       true,
	OriginLockoutRetention: true,
}

// IsSystemOrigin reports whether the SCIM engine may write this origin kind.
func IsSystemOrigin(k OriginKind) bool { return systemOrigins[k] }

// MappableTemplates returns the templates a mapping row may target (§3): the
// seven org/project/environment-applicable ones. `operator` is instance-scoped
// and structurally out of an org binding's reach — a binding can cause grants
// only inside its own org subtree (§1), so an instance-scope template has no
// scope it could be applied at.
func MappableTemplates() []Template {
	out := make([]Template, 0, len(templates))
	for t, spec := range templates {
		if spec.applicable[LevelNone] {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsMappableTemplate reports whether a mapping row may target t.
func IsMappableTemplate(t Template) bool {
	spec, ok := templates[t]
	return ok && !spec.applicable[LevelNone]
}

// ErrSubjectSourceUserName refuses `userName` as a binding's subject source BY
// NAME (§5.1). RFC 7643 defines `userName` as `caseExact: false` and
// server-unique, which contradicts byte-exact identity material; it keeps its
// RFC semantics as a lookup attribute and nothing more.
var ErrSubjectSourceUserName = errors.New("domain: userName is refused as a SCIM subject source")

// ErrSubjectSourceEmpty refuses a binding with no declared subject source.
var ErrSubjectSourceEmpty = errors.New("domain: a SCIM binding must declare a subject source")

// SubjectSourceUserName is the one spelling the ADR refuses by name.
const SubjectSourceUserName = "userName"

// SubjectSourceExternalID is the ordinary subject source.
const SubjectSourceExternalID = "externalId"

// ErrSubjectSourceShape refuses a subject source that is neither `externalId`
// nor a schema-qualified extension path.
var ErrSubjectSourceShape = errors.New(
	"domain: a SCIM subject source must be externalId or a urn:-qualified extension attribute path")

// CheckSubjectSource validates a binding's declared subject-source attribute
// path. The rule is an ALLOWLIST, not "anything but userName": §5.1 admits
// `externalId` or a declared enterprise/custom extension path, and every other
// core attribute is mutable display metadata that must never become identity
// material. `userName` is refused by name and case-insensitively, because SCIM
// attribute names are case-insensitive and a case-sensitive refusal is a
// refusal in name only.
func CheckSubjectSource(path string) error {
	if path == "" {
		return ErrSubjectSourceEmpty
	}
	if strings.EqualFold(path, SubjectSourceUserName) {
		return ErrSubjectSourceUserName
	}
	if strings.EqualFold(path, SubjectSourceExternalID) {
		return nil
	}
	// An extension path: a schema URN, a colon, and one attribute name.
	if !strings.HasPrefix(path, "urn:") {
		return ErrSubjectSourceShape
	}
	i := strings.LastIndex(path, ":")
	if i <= len("urn:") || i == len(path)-1 {
		return ErrSubjectSourceShape
	}
	for _, c := range path[i+1:] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return ErrSubjectSourceShape
		}
	}
	// The URN must be an EXTENSION schema. A core-schema URN is the long
	// spelling of a core attribute — `urn:…:core:2.0:User:userName` is
	// `userName` — so admitting it would reinstate exactly the mutable
	// display metadata the allowlist exists to keep out of identity material,
	// and would smuggle `userName` itself past the refusal above.
	if isCoreSchemaURN(path[:i]) {
		return ErrSubjectSourceCore
	}
	return nil
}

// ErrSubjectSourceCore refuses a core-schema URN as a subject source.
var ErrSubjectSourceCore = errors.New(
	"domain: a core-schema attribute path is not a SCIM subject source; use externalId or an extension schema")

// coreSchemaURNs are the RFC 7643 core resource schemas. Case-insensitively
// compared: a URN is case-insensitive in its namespace-specific string only by
// convention, and a case-variant refusal is a refusal in name only.
var coreSchemaURNs = []string{
	"urn:ietf:params:scim:schemas:core:2.0:User",
	"urn:ietf:params:scim:schemas:core:2.0:Group",
}

func isCoreSchemaURN(urn string) bool {
	for _, core := range coreSchemaURNs {
		if strings.EqualFold(urn, core) {
			return true
		}
	}
	// Nested core paths (`urn:…:core:2.0:User:name`) carry the core URN as a
	// prefix; the whole `urn:…:core:` namespace is refused rather than the two
	// exact spellings, so a future core resource cannot slip through.
	return strings.HasPrefix(strings.ToLower(urn), "urn:ietf:params:scim:schemas:core:")
}

// SplitExtensionPath splits a subject-source extension path into its schema
// URN and the attribute it names. It reports false for a path that is not an
// extension path at all (`externalId`), so callers do not have to re-derive
// the shape CheckSubjectSource already validated.
func SplitExtensionPath(path string) (urn, attribute string, ok bool) {
	if !strings.HasPrefix(path, "urn:") {
		return "", "", false
	}
	i := strings.LastIndex(path, ":")
	if i <= len("urn:") || i == len(path)-1 {
		return "", "", false
	}
	return path[:i], path[i+1:], true
}

// SCIMOriginKey is the identity half of a `scim(binding, mapping_row, group)`
// origin (§2). The three parts are encoded into `grant_origins.subject`, which
// is one column, so the encoding is here rather than spread across writers.
//
// Why all three when the mapping row id alone determines the other two: an
// origin chip must be readable on the membership line WITHOUT a join into the
// SCIM tables, because the membership surface authorizes `manage-members` and
// the SCIM tables answer to `scim-provision` — different proofs, different
// operations. A self-describing subject is what lets "why can they?" be
// answered on the line the ADR says it must be answered on.
type SCIMOriginKey struct {
	Binding    string
	MappingRow string
	Group      string
}

// scimOriginSep separates the three parts. It is legal in none of them: all
// three are minted ids from this server's own prefixed-id grammar.
const scimOriginSep = "/"

// Subject renders the key into the origin's `subject` column.
func (k SCIMOriginKey) Subject() string {
	return k.Binding + scimOriginSep + k.MappingRow + scimOriginSep + k.Group
}

// ParseSCIMOriginSubject is the exact inverse. It reports false for anything
// this package did not write — a malformed subject is a storage defect, and a
// caller that guesses at it would release the wrong origin.
func ParseSCIMOriginSubject(s string) (SCIMOriginKey, bool) {
	parts := strings.Split(s, scimOriginSep)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return SCIMOriginKey{}, false
	}
	return SCIMOriginKey{Binding: parts[0], MappingRow: parts[1], Group: parts[2]}, true
}

// SCIMRetentionKey is the identity of a `lockout-retention` origin: which
// binding's release caused the conversion, and which operation triggered it.
//
// Both are encoded into the origin's `subject` column, for the same reason the
// `scim` origin encodes three parts: a retention origin SURVIVES its binding
// (§6 step 2), so by the time it is cured the binding row may be gone and no
// join could recover the id §10 requires the cure event to carry. Recording it
// on the origin makes the pair joinable after the fact, which is the only time
// anyone reads it.
type SCIMRetentionKey struct {
	Binding string
	Cause   SCIMCause
}

// Subject renders the key into the origin's `subject` column.
func (k SCIMRetentionKey) Subject() string {
	return k.Binding + scimOriginSep + string(k.Cause)
}

// ParseSCIMRetentionSubject is the exact inverse.
func ParseSCIMRetentionSubject(s string) (SCIMRetentionKey, bool) {
	binding, cause, ok := strings.Cut(s, scimOriginSep)
	if !ok || binding == "" || !IsSCIMCause(SCIMCause(cause)) {
		// The cause enum is CLOSED (§10). Accepting any non-empty string let
		// malformed storage escape the enum and produce a cure audit carrying a
		// value no reader can interpret.
		return SCIMRetentionKey{}, false
	}
	return SCIMRetentionKey{Binding: binding, Cause: SCIMCause(cause)}, true
}
