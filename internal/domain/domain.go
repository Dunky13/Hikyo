// Package domain holds the leaf vocabulary shared by the authorization
// package, the store, and the service layer: tenant identifiers, capability
// atoms, scopes, and the canonical error sentinels. It imports nothing from
// this module so every layer can depend on it without cycles.
package domain

import (
	"errors"
	"fmt"
	"sort"
)

// Tenant identifiers. Distinct types so the proof-signature analyzer can ban
// them from store-method signatures: a caller-supplied tenant id must never
// be able to reach a chain predicate (tenant-isolation ADR).
type (
	OrgID     string
	ProjectID string
	EnvID     string
)

// PrincipalID identifies a principal (human or machine) in the grant table.
type PrincipalID string

// Capability is one atom from the permission-model ADR's CLOSED set. The whole set
// is declared below (#55); Capabilities() is the closed enumeration the grant
// API validates against, so a capability string that is not an atom is
// refused rather than stored as an unreachable row.
type Capability string

const (
	// Environment atoms.
	CapRead          Capability = "read"
	CapReveal        Capability = "reveal"
	CapRevealHistory Capability = "reveal-history"
	CapEdit          Capability = "edit"
	CapPublish       Capability = "publish"
	CapPin           Capability = "pin"

	// Project atoms.
	CapDefinitionsEdit  Capability = "definitions-edit"
	CapProjectSettings  Capability = "project-settings"
	CapManageIdentities Capability = "manage-identities"
	CapManageAdapters   Capability = "manage-adapters"

	// Org / project.
	CapManageMembers Capability = "manage-members"
	// Org.
	CapManageProjects Capability = "manage-projects"

	// The instance operator set (encryption-model ADR #14).
	CapBackupExport     Capability = "backup-export"
	CapRestore          Capability = "restore"
	CapRotateRootKey    Capability = "rotate-root-key"
	CapRotateMasterKey  Capability = "rotate-master-key"
	CapRotateDEK        Capability = "rotate-dek"
	CapReencrypt        Capability = "reencrypt"
	CapInstanceConfig   Capability = "instance-config"
	CapInstanceDirector Capability = "instance-directory"

	// CapSCIMProvision is the scim-provisioning amendment (c): org scope,
	// machine-only, never grantable to a human, system-created with the
	// provisioning binding and refused through the grant API (#73 mints it).
	CapSCIMProvision Capability = "scim-provision"

	// CapAuditRead is the audit-model ADR's amendment part 1: reading the
	// trail is surveillance power over colleagues — its own capability, an
	// ordinary additive downward-inheriting grant, never bundled into
	// manage-members.
	CapAuditRead Capability = "audit-read"

	// CapCredentialReset is the human-auth ADR's administrator-issued reset
	// authority (#54), valid at org and instance scope.
	CapCredentialReset Capability = "credential-reset"
)

// capabilityLevels is the closed atom table: each atom mapped to the DEEPEST
// scope level it may be granted at. A grant is legal at that level or any
// level above it (grants inherit downward, so granting `read` at org scope is
// granting it on every environment beneath). An atom whose deepest level is
// LevelNone is instance-only.
var capabilityLevels = map[Capability]Level{
	CapRead:          LevelEnv,
	CapReveal:        LevelEnv,
	CapRevealHistory: LevelEnv,
	CapEdit:          LevelEnv,
	CapPublish:       LevelEnv,
	CapPin:           LevelEnv,

	CapDefinitionsEdit:  LevelProject,
	CapProjectSettings:  LevelProject,
	CapManageIdentities: LevelProject,
	CapManageAdapters:   LevelProject,

	CapManageMembers: LevelProject,

	CapManageProjects:  LevelOrg,
	CapAuditRead:       LevelEnv,
	CapCredentialReset: LevelOrg,
	CapSCIMProvision:   LevelOrg,

	CapBackupExport:     LevelNone,
	CapRestore:          LevelNone,
	CapRotateRootKey:    LevelNone,
	CapRotateMasterKey:  LevelNone,
	CapRotateDEK:        LevelNone,
	CapReencrypt:        LevelNone,
	CapInstanceConfig:   LevelNone,
	CapInstanceDirector: LevelNone,
}

// Capabilities returns the closed atom set, sorted, for enumeration surfaces
// and the registry-completeness tests.
func Capabilities() []Capability {
	out := make([]Capability, 0, len(capabilityLevels))
	for c := range capabilityLevels {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsCapability reports whether c is in the closed set.
func IsCapability(c Capability) bool { _, ok := capabilityLevels[c]; return ok }

// DeepestLevel returns the deepest scope level an atom may be granted at.
func DeepestLevel(c Capability) (Level, bool) { l, ok := capabilityLevels[c]; return l, ok }

// OperatorSet is the encryption-model ADR's instance operator set, in the order the
// `operator` template seeds it.
var OperatorSet = []Capability{
	CapBackupExport, CapRestore, CapRotateRootKey, CapRotateMasterKey,
	CapRotateDEK, CapReencrypt, CapInstanceConfig,
}

// Scope addresses a node in the tenant chain as the request names it:
// org, org+project, or org+project+env. The zero value addresses nothing.
type Scope struct {
	Org     OrgID
	Project ProjectID
	Env     EnvID
}

// Level is the depth a Scope addresses.
type Level int

const (
	LevelNone Level = iota
	LevelOrg
	LevelProject
	LevelEnv
)

// Level derives the addressed depth and rejects gaps (an env without a
// project is not an address, it is a bug).
func (s Scope) Level() (Level, error) {
	switch {
	case s.Org == "" && s.Project == "" && s.Env == "":
		return LevelNone, nil
	case s.Org != "" && s.Project == "" && s.Env == "":
		return LevelOrg, nil
	case s.Org != "" && s.Project != "" && s.Env == "":
		return LevelProject, nil
	case s.Org != "" && s.Project != "" && s.Env != "":
		return LevelEnv, nil
	default:
		return LevelNone, errors.New("domain: scope has a gap in its chain")
	}
}

// Grant is the permission-model ADR's triple: (principal, capability, scope). The
// principal is implied by the lookup; a zero Scope is an instance-scope
// grant. Grants are purely additive — absence is denial, there are no deny
// rules.
type Grant struct {
	Capability Capability
	Scope      Scope
}

// ErrNotFound is the canonical "no such row" — and, per the permission-model ADR's
// unauthorized ≡ nonexistent rule, also the uniform outcome for every
// tenant-scoped request the principal may not perform. Callers must not be
// able to distinguish the two.
var ErrNotFound = errors.New("not found")

// ErrUnauthorized is the uniform refusal for instance-scoped operations,
// where there is no tenant object whose nonexistence could be mimicked —
// the probe contract is grant refusal, not tenancy.
var ErrUnauthorized = errors.New("unauthorized")

// ErrUnauthenticated is the uniform outcome when no usable authentication
// artifact was presented. Absent, malformed, unknown, expired, revoked,
// generation-superseded and epoch-superseded artifacts all answer this, so
// presentation reveals nothing about which artifacts exist — the same
// indistinguishability rule as unauthorized ≡ nonexistent, one layer earlier.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrInvalid is a malformed request the contract could not reject on shape
// alone — a name outside the grammar, a reorder list that does not name the
// project's environments. It is decided before or independently of any tenant
// resolution and therefore discloses nothing about what exists.
var ErrInvalid = errors.New("invalid request")

// ErrConflict is the uniform outcome for a request the caller IS authorized
// to make but the current state refuses: a name already in use among live
// siblings, or a parent that still has children (v1 deletes never cascade —
// see the hierarchy handoff). It is reached only after authorization
// succeeded, so it discloses nothing a caller could not already read; the
// fixed message per code means it names no specific row either way.
var ErrConflict = errors.New("conflict")

// CollectedRevisionError is the loud post-authorization refusal for a lineage
// row whose value-bearing payload has been collected. The revision and stored
// policy are safe detail: the caller named the former and is authorized to read
// the latter's scope.
type CollectedRevisionError struct {
	Revision int64
	Policy   string
}

func (e *CollectedRevisionError) Error() string {
	return fmt.Sprintf("%v: revision %d was collected by retention policy %s", ErrConflict, e.Revision, e.Policy)
}

func (e *CollectedRevisionError) Unwrap() error { return ErrConflict }

func (e *CollectedRevisionError) SafeDetail() string {
	return fmt.Sprintf("revision %d was collected by retention policy %s", e.Revision, e.Policy)
}

// ErrLimitExceeded is a structural bound refusing an operation by name — the
// ops spec's environment-count cap being the first. Distinct from ErrConflict
// so the fixed-per-code message can state the bound, which is what "loud
// refusal naming the budget" requires of a response body that may not carry
// anything derived from the request.
var ErrLimitExceeded = errors.New("limit exceeded")
