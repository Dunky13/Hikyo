package authz

import (
	"slices"
	"strings"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
)

// Operation names one entry in the operation registry — the single table
// mapping each operation to its authorization formula (permission ADR: per
// operation formulas, never "the capability for this endpoint"). authorize()
// evaluates the named formula and the proof records which operation it was
// minted for; the store boundary rejects a proof minted for a different
// operation.
type Operation string

// The registered operations. Service code names operations through these
// constants; the registry below is keyed by them.
const (
	OpOrgCreate     Operation = "org.create"
	OpOrgGet        Operation = "org.get"
	OpOrgList       Operation = "org.list"
	OpProjectCreate Operation = "project.create"
	OpEnvCreate     Operation = "environment.create"
	OpEnvRead       Operation = "environment.read"
	OpEnvUpdateNote Operation = "environment.update-note"

	// Audit trail reads (#45, audit-model ADR). One operation per addressed
	// depth — the registry pins one depth per tenant operation, so the three
	// depths are three rows sharing one service implementation; the formula
	// atom is audit-read at the addressed depth (grants inherit downward, so
	// an org-level audit-read covers all three). The instance trail is read
	// under an instance-scope audit-read grant — grant-evaluated like every
	// instance operation, never route-implied.
	OpAuditQueryOrg       Operation = "audit.query-org"
	OpAuditQueryProject   Operation = "audit.query-project"
	OpAuditQueryEnv       Operation = "audit.query-env"
	OpAuditExportOrg      Operation = "audit.export-org"
	OpAuditExportProject  Operation = "audit.export-project"
	OpAuditExportEnv      Operation = "audit.export-env"
	OpAuditInstanceQuery  Operation = "audit.instance-query"
	OpAuditInstanceExport Operation = "audit.instance-export"
)

// StoreOp names one store method in the trusted query registry. Every store
// method is registered to the operation(s) it serves (invariant 6); the
// boundary check consults this registry on every call.
type StoreOp string

const (
	StoreOrgsCreate             StoreOp = "orgs.Create"
	StoreOrgsGet                StoreOp = "orgs.Get"
	StoreOrgsList               StoreOp = "orgs.List"
	StoreOrgsCount              StoreOp = "orgs.Count"
	StoreProjectsCreate         StoreOp = "projects.Create"
	StoreEnvironmentsCreate     StoreOp = "environments.Create"
	StoreEnvironmentsGet        StoreOp = "environments.Get"
	StoreEnvironmentsUpdateNote StoreOp = "environments.UpdateNote"

	// Keyring persistence (#43). These carry no tenant chain: wrapped-key
	// rows are instance-scoped crypto material, and the scope a tier-3 key
	// belongs to is part of its AAD, not a tenant predicate.
	StoreKeysActiveMasterWrappers       StoreOp = "keys.ActiveMasterWrappers"
	StoreKeysActiveTier3                StoreOp = "keys.ActiveTier3"
	StoreKeysAcquireHierarchyGeneration StoreOp = "keys.AcquireHierarchyGeneration"
	StoreKeysInsertMaster               StoreOp = "keys.InsertMaster"
	StoreKeysInsertTier3                StoreOp = "keys.InsertTier3"
	StoreKeysInsertScopeGeneration      StoreOp = "keys.InsertScopeGeneration"

	// Audit trails (#45). INSERT and SELECT only — the append-only invariant
	// lives at the query layer; these are the only store doors to it. The
	// denial writer does NOT pass through these: it is the authorization
	// package's own enumerated write path (audit-model ADR amendment part 4)
	// and runs with no proof to verify.
	StoreAuditTenantInsert         StoreOp = "audit.InsertTenant"
	StoreAuditInstanceInsert       StoreOp = "audit.InsertInstance"
	StoreAuditTenantPage           StoreOp = "audit.PageTenant"
	StoreAuditInstancePage         StoreOp = "audit.PageInstance"
	StoreAuditSettledBelowTenant   StoreOp = "audit.SettledBelowTenant"
	StoreAuditSettledBelowInstance StoreOp = "audit.SettledBelowInstance"
)

// readOnlyStoreOps pins which store operations mutate nothing — the
// machine-checked half of the `audited: none` permit rule (audit-model ADR
// CI invariant 2): an operation may skip audit mapping only when every store
// op it can invoke is in this set. A wrongly listed op is caught by review
// of this pinned table, exactly like the formula pins.
var readOnlyStoreOps = map[StoreOp]bool{
	StoreOrgsGet:                   true,
	StoreOrgsList:                  true,
	StoreOrgsCount:                 true,
	StoreEnvironmentsGet:           true,
	StoreKeysActiveMasterWrappers:  true,
	StoreKeysActiveTier3:           true,
	StoreAuditTenantPage:           true,
	StoreAuditInstancePage:         true,
	StoreAuditSettledBelowTenant:   true,
	StoreAuditSettledBelowInstance: true,
}

// bootKeyringOps is boot's closed operation set. The tenant-isolation ADR
// names it verbatim — "boot to its pragma/keyring checks" — so the keyring
// reaches the store under a SystemProof minted at SiteBoot, not under an
// ambient exemption. Widening this set reopens the ADR (invariant 11).
var bootKeyringOps = map[StoreOp]bool{
	StoreKeysActiveMasterWrappers:       true,
	StoreKeysActiveTier3:                true,
	StoreKeysAcquireHierarchyGeneration: true,
	StoreKeysInsertMaster:               true,
	StoreKeysInsertTier3:                true,
	StoreKeysInsertScopeGeneration:      true,
}

// Class is the probe classification (tenant-isolation ADR § enforcement
// machinery): every operation carries exactly one, and each class has its
// own probe contract. Classification is the completeness mechanism.
type Class int

const (
	// ClassTenant: cross-tenant probes, uniform nonexistent response.
	ClassTenant Class = iota
	// ClassInstance: probed for grant refusal, not tenancy.
	ClassInstance
	// ClassUnauthenticated: pre-auth contracts (enumeration uniformity).
	ClassUnauthenticated
	// ClassSystem: no network route may exist; local-authority preconditions.
	ClassSystem
)

// Atom is one conjunct of an authorization formula: the principal must hold
// Cap at the resolved chain truncated to level At, or at any scope above it
// (grants inherit downward; permission ADR § scope lattice).
type Atom struct {
	Cap domain.Capability
	At  domain.Level
}

// Formula is a conjunction of atoms over dynamically resolved scopes.
type Formula []Atom

// opSpec is one operation registry row.
type opSpec struct {
	class    Class
	level    domain.Level // tenant ops: the depth the request must address
	formula  Formula
	storeOps map[StoreOp]bool

	// events maps the operation to the audit event type(s) it emits, or —
	// exactly one of the two — auditedNone declares a proof-scoped pure read
	// whose result the trail would only duplicate. auditedNone is
	// default-deny (audit-model ADR CI invariant 2): the completeness
	// invariant permits it only for tenant-class, formula-bare-`read`,
	// non-mutating operations, and refuses it everywhere else.
	events      []audit.EventType
	auditedNone bool
}

// operations is the operation registry. The demonstration set exercises the
// mechanism at every chain depth using only capability atoms the permission
// ADR already fixes — no new atoms, no new formula rows beyond scaffolding
// for the walking skeleton's Org aggregate (the real endpoint enumeration
// lands with #47/#48 against this same table; registry completeness is
// invariant 6).
var operations = map[Operation]opSpec{
	// Scaffolding: the walking skeleton's Org aggregate. Org administration
	// is cross-tenant by definition, so these are instance-scoped under the
	// operator set's instance-config atom until the real surface (#48) fixes
	// their formulas.
	OpOrgCreate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsCreate: true, StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOrgCreated},
	},
	OpOrgGet: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsGet: true, StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOrgRead},
	},
	OpOrgList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsList: true, StoreOrgsCount: true, StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOrgRead},
	},

	// Tenant-scoped demonstration operations, one per chain depth. Their
	// domain events are committed in-transaction with the write (audit-model
	// ADR durability discipline).
	OpProjectCreate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapManageProjects, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreProjectsCreate: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventProjectCreated},
	},
	OpEnvCreate: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsCreate: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventEnvCreated},
	},
	OpEnvRead: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsGet: true},
		// A proof-scoped pure read whose result the trail would only
		// duplicate — the exact (and only) shape the default-deny permit
		// rule accepts.
		auditedNone: true,
	},
	OpEnvUpdateNote: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapEdit, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsUpdateNote: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventEnvNoteChanged},
	},

	// Audit trail reads and exports (#45). Reading the trail is itself
	// audited, unconditionally — no toggle exists (audit-model ADR): the
	// query op emits its own event in the same transaction, the export pair
	// takes the INTENT/OUTCOME shape.
	OpAuditQueryOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true, StoreAuditSettledBelowTenant: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditQueryProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true, StoreAuditSettledBelowTenant: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditQueryEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true, StoreAuditSettledBelowTenant: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditExportOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true, StoreAuditSettledBelowTenant: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
	OpAuditExportProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true, StoreAuditSettledBelowTenant: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
	OpAuditExportEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true, StoreAuditSettledBelowTenant: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
	OpAuditInstanceQuery: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstancePage: true, StoreAuditInstanceInsert: true, StoreAuditSettledBelowInstance: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditInstanceExport: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstancePage: true, StoreAuditInstanceInsert: true, StoreAuditSettledBelowInstance: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
}

// SystemSite is a SystemProof mint site. The set is closed by the
// tenant-isolation ADR (invariant 11): boot, migration, recovery-mode
// reconciliation, break-glass local host authority — the ADR names the
// existing no-principal set, it adds no new authority. Growth of this set,
// or of any site's operation set, fails the build until the ADR is amended.
type SystemSite string

const (
	SiteBoot              SystemSite = "boot"
	SiteMigration         SystemSite = "migration"
	SiteRecoveryReconcile SystemSite = "recovery-mode-reconciliation"
	SiteBreakGlass        SystemSite = "break-glass"
)

// systemSites maps each mint site to the store operations it may invoke. A
// SystemProof presented for any operation outside its site's set is rejected
// fail-closed, exactly like an operation-mismatched ordinary proof. Boot
// carries the keyring set the ADR names verbatim ("boot to its pragma/
// keyring checks"); migration's DDL runs below the store-method surface,
// and recovery reconciliation and break-glass arrive with #54/#55 — for
// those three an empty set is the fail-closed default.
var systemSites = map[SystemSite]map[StoreOp]bool{
	SiteBoot:              bootKeyringOps,
	SiteMigration:         {},
	SiteRecoveryReconcile: {},
	SiteBreakGlass:        {},
}

// Registry exposes read-only registry facts to the invariant tests (registry
// completeness, classification totality, system-site enumeration) without
// exposing mutation. Production code has no business calling these.
type RegistryFacts struct{}

// Operations lists every registered operation and its class.
func (RegistryFacts) Operations() map[Operation]Class {
	out := make(map[Operation]Class, len(operations))
	for op, spec := range operations {
		out[op] = spec.class
	}
	return out
}

// TenantOperations lists each tenant-class operation with the chain depth it
// addresses, for registry well-formedness checks.
func (RegistryFacts) TenantOperations() map[Operation]domain.Level {
	out := map[Operation]domain.Level{}
	for op, spec := range operations {
		if spec.class == ClassTenant {
			out[op] = spec.level
		}
	}
	return out
}

// StoreOps returns the union of store operations reachable through the
// operation registry, keyed by which operations may invoke them.
func (RegistryFacts) StoreOps() map[StoreOp][]Operation {
	out := make(map[StoreOp][]Operation)
	for op, spec := range operations {
		for so := range spec.storeOps {
			out[so] = append(out[so], op)
		}
	}
	return out
}

// Formulas returns each operation's formula; a registered operation with an
// empty formula fails invariant 6.
func (RegistryFacts) Formulas() map[Operation]Formula {
	out := make(map[Operation]Formula, len(operations))
	for op, spec := range operations {
		out[op] = append(Formula(nil), spec.formula...)
	}
	return out
}

// SystemSites returns the closed mint-site enumeration and each site's
// operation set.
func (RegistryFacts) SystemSites() map[SystemSite][]StoreOp {
	out := make(map[SystemSite][]StoreOp, len(systemSites))
	for site, ops := range systemSites {
		list := make([]StoreOp, 0, len(ops))
		for op := range ops {
			list = append(list, op)
		}
		out[site] = list
	}
	return out
}

// AuditMapping is one operation's audit linkage, for the completeness
// invariant (audit-model ADR CI invariant 2).
type AuditMapping struct {
	Class       Class
	Formula     Formula
	Events      []audit.EventType
	AuditedNone bool
	// ReadOnly reports whether every store op the operation can invoke is in
	// the pinned read-only set — the mutates-nothing half of the
	// `audited: none` permit rule.
	ReadOnly bool
}

// AuditMappings returns every registered operation's audit linkage.
func (RegistryFacts) AuditMappings() map[Operation]AuditMapping {
	out := make(map[Operation]AuditMapping, len(operations))
	for op, spec := range operations {
		ro := true
		for so := range spec.storeOps {
			if !readOnlyStoreOps[so] {
				ro = false
			}
		}
		out[op] = AuditMapping{
			Class:       spec.class,
			Formula:     append(Formula(nil), spec.formula...),
			Events:      append([]audit.EventType(nil), spec.events...),
			AuditedNone: spec.auditedNone,
			ReadOnly:    ro,
		}
	}
	return out
}

// FormulaPin is one row of the pinned operation registry (invariant 6's
// anti-widening half): silently changing an operation's formula — say
// environment.update-note from edit(E) to read(E) — widens authority
// without failing any probe whose fixtures happen to hold both. The pin
// makes every such change a reviewed fixture diff.
type FormulaPin struct {
	Operation string   `json:"operation"`
	Class     string   `json:"class"`
	Level     string   `json:"level"`
	Formula   []string `json:"formula"`
}

var classNames = map[Class]string{
	ClassTenant: "tenant", ClassInstance: "instance",
	ClassUnauthenticated: "unauthenticated", ClassSystem: "system", ClassStub: "stub",
}

var levelNames = map[domain.Level]string{
	domain.LevelNone: "instance", domain.LevelOrg: "org",
	domain.LevelProject: "project", domain.LevelEnv: "environment",
}

// FormulaPins returns the whole operation registry in a stable, diffable
// shape, sorted by operation name.
func (RegistryFacts) FormulaPins() []FormulaPin {
	out := make([]FormulaPin, 0, len(operations))
	for op, spec := range operations {
		pin := FormulaPin{
			Operation: string(op),
			Class:     classNames[spec.class],
			Level:     levelNames[spec.level],
		}
		for _, atom := range spec.formula {
			pin.Formula = append(pin.Formula, string(atom.Cap)+"@"+levelNames[atom.At])
		}
		out = append(out, pin)
	}
	slices.SortFunc(out, func(a, b FormulaPin) int { return strings.Compare(a.Operation, b.Operation) })
	return out
}
