// Package domain holds the leaf vocabulary shared by the authorization
// package, the store, and the service layer: tenant identifiers, capability
// atoms, scopes, and the canonical error sentinels. It imports nothing from
// this module so every layer can depend on it without cycles.
package domain

import "errors"

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

// Capability is one atom from the permission ADR's closed set. This package
// declares only the atoms the demonstration operations use; the full lattice
// lands with the permission ticket (#55) and stays the permission ADR's.
type Capability string

const (
	CapRead            Capability = "read"
	CapEdit            Capability = "edit"
	CapDefinitionsEdit Capability = "definitions-edit"
	CapManageProjects  Capability = "manage-projects"
	CapInstanceConfig  Capability = "instance-config"
	// CapAuditRead is the audit-model ADR's amendment part 1: reading the
	// trail is surveillance power over colleagues — its own capability, an
	// ordinary additive downward-inheriting grant, never bundled into
	// manage-members.
	CapAuditRead Capability = "audit-read"

	// The MFA-mandatory atoms (human-auth ADR § Assurance). Declared here
	// with the rest of the closed set so the assurance rule can name them;
	// the operations that carry them arrive with #50/#55.
	CapReveal          Capability = "reveal"
	CapRevealHistory   Capability = "reveal-history"
	CapManageMembers   Capability = "manage-members"
	CapCredentialReset Capability = "credential-reset"
)

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

// Grant is the permission ADR's triple: (principal, capability, scope). The
// principal is implied by the lookup; a zero Scope is an instance-scope
// grant. Grants are purely additive — absence is denial, there are no deny
// rules.
type Grant struct {
	Capability Capability
	Scope      Scope
}

// ErrNotFound is the canonical "no such row" — and, per the permission ADR's
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

// ErrLimitExceeded is a structural bound refusing an operation by name — the
// ops spec's environment-count cap being the first. Distinct from ErrConflict
// so the fixed-per-code message can state the bound, which is what "loud
// refusal naming the budget" requires of a response body that may not carry
// anything derived from the request.
var ErrLimitExceeded = errors.New("limit exceeded")
