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
	// The hierarchy surface (#48): Organization, Project, Environment, Folder.
	//
	// Org creation and enumeration are instance-scoped — a create has no
	// parent tenant and a list spans all of them — while every BY-ID org
	// operation is tenant-class at org depth, so an org the caller may not
	// reach answers exactly like one that is not there (mvp-boundary C1).
	OpOrgCreate Operation = "org.create"
	OpOrgGet    Operation = "org.get"
	OpOrgList   Operation = "org.list"
	OpOrgRename Operation = "org.rename"
	OpOrgDelete Operation = "org.delete"

	OpProjectCreate Operation = "project.create"
	OpProjectGet    Operation = "project.get"
	OpProjectList   Operation = "project.list"
	OpProjectRename Operation = "project.rename"
	OpProjectDelete Operation = "project.delete"

	OpEnvCreate     Operation = "environment.create"
	OpEnvRead       Operation = "environment.read"
	OpEnvList       Operation = "environment.list"
	OpEnvRename     Operation = "environment.rename"
	OpEnvReorder    Operation = "environment.reorder"
	OpEnvDelete     Operation = "environment.delete"
	OpEnvUpdateNote Operation = "environment.update-note"

	OpFolderCreate Operation = "folder.create"
	OpFolderGet    Operation = "folder.get"
	OpFolderList   Operation = "folder.list"
	OpFolderRename Operation = "folder.rename"
	OpFolderDelete Operation = "folder.delete"

	// OIDC provider administration (#54, human-auth ADR - Login methods).
	// Instance-config operations, MFA-mandatory like every instance capability.
	OpProviderPut    Operation = "oidc-provider.put"
	OpProviderGet    Operation = "oidc-provider.get"
	OpProviderList   Operation = "oidc-provider.list"
	OpProviderDelete Operation = "oidc-provider.delete"

	// Administrator-issued credential reset (#54, human-auth ADR - Recovery).
	// The capability is credential-reset, valid at org and instance scope only.
	// One route dispatches between these two by the target's grant
	// classification: an org-bounded target (grants within one org, no instance
	// capability) is reached through the org-scoped operation — an org-scope OR
	// instance-scope credential-reset grant covers it by downward inheritance; a
	// multi-org (no instance capability) target has no single org to address and
	// is reached only at instance scope. Instance-capability targets have no
	// network path at all (break-glass only). Both are MFA-mandatory (the atom
	// is in MFAMandatory) and audit through the resolution surface.
	OpCredentialReset         Operation = "credential-reset.org"
	OpCredentialResetInstance Operation = "credential-reset.instance"

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
	StoreOrgsCreate StoreOp = "orgs.Create"
	StoreOrgsGet    StoreOp = "orgs.Get"
	StoreOrgsList   StoreOp = "orgs.List"
	StoreOrgsCount  StoreOp = "orgs.Count"
	StoreOrgsRename StoreOp = "orgs.Rename"
	StoreOrgsDelete StoreOp = "orgs.Delete"

	StoreProjectsCreate StoreOp = "projects.Create"
	StoreProjectsGet    StoreOp = "projects.Get"
	StoreProjectsList   StoreOp = "projects.List"
	StoreProjectsLock   StoreOp = "projects.Lock"
	StoreProjectsRename StoreOp = "projects.Rename"
	StoreProjectsDelete StoreOp = "projects.Delete"

	StoreEnvironmentsCreate     StoreOp = "environments.Create"
	StoreEnvironmentsGet        StoreOp = "environments.Get"
	StoreEnvironmentsList       StoreOp = "environments.List"
	StoreEnvironmentsCount      StoreOp = "environments.Count"
	StoreEnvironmentsNextOrder  StoreOp = "environments.NextOrder"
	StoreEnvironmentsUpdateNote StoreOp = "environments.UpdateNote"
	StoreEnvironmentsRename     StoreOp = "environments.Rename"
	StoreEnvironmentsSetOrder   StoreOp = "environments.SetOrder"
	StoreEnvironmentsDelete     StoreOp = "environments.Delete"

	StoreFoldersCreate StoreOp = "folders.Create"
	StoreFoldersGet    StoreOp = "folders.Get"
	StoreFoldersList   StoreOp = "folders.List"
	StoreFoldersRename StoreOp = "folders.Rename"
	StoreFoldersDelete StoreOp = "folders.Delete"

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
	StoreAuditTenantInsert   StoreOp = "audit.InsertTenant"
	StoreAuditInstanceInsert StoreOp = "audit.InsertInstance"
	StoreAuditTenantPage     StoreOp = "audit.PageTenant"
	StoreAuditInstancePage   StoreOp = "audit.PageInstance"
)

// readOnlyStoreOps pins which store operations mutate nothing — the
// machine-checked half of the `audited: none` permit rule (audit-model ADR
// CI invariant 2): an operation may skip audit mapping only when every store
// op it can invoke is in this set. A wrongly listed op is caught by review
// of this pinned table, exactly like the formula pins.
var readOnlyStoreOps = map[StoreOp]bool{
	StoreOrgsGet:                  true,
	StoreOrgsList:                 true,
	StoreOrgsCount:                true,
	StoreProjectsGet:              true,
	StoreProjectsList:             true,
	StoreEnvironmentsGet:          true,
	StoreEnvironmentsList:         true,
	StoreEnvironmentsCount:        true,
	StoreEnvironmentsNextOrder:    true,
	StoreFoldersGet:               true,
	StoreFoldersList:              true,
	StoreKeysActiveMasterWrappers: true,
	StoreKeysActiveTier3:          true,
	StoreAuditTenantPage:          true,
	StoreAuditInstancePage:        true,
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

// operations is the operation registry. Every formula is built from capability
// atoms the permission ADR already fixes — this ticket adds no atom and
// invents no capability. Registry completeness is invariant 6.
var operations = map[Operation]opSpec{
	// The Org aggregate (#48). Creation and enumeration are instance-scoped
	// under the operator set's instance-config atom: a create has no parent
	// tenant to authorize against, and an enumeration of every org is
	// cross-tenant by definition, so there is no tenant object whose
	// nonexistence a refusal could mimic.
	OpOrgCreate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsCreate: true, StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOrgCreated},
	},
	OpOrgList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsList: true, StoreOrgsCount: true, StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOrgRead},
	},
	// Every BY-ID org operation is tenant-class at org depth, which is what
	// mvp-boundary C1 requires of "each level": an org the caller cannot reach
	// answers byte-identically to one that does not exist. Reading it is bare
	// `read`, so it takes the audited-none permit like environment.read does.
	OpOrgGet: {
		class:       ClassTenant,
		level:       domain.LevelOrg,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelOrg}},
		storeOps:    map[StoreOp]bool{StoreOrgsGet: true},
		auditedNone: true,
	},
	// Renaming and deleting an org is instance operator work: the permission
	// ADR's closed atom set has no org-lifecycle capability (`manage-projects`
	// is explicitly "create and delete projects"), and inventing one would
	// reopen that ADR. The atom therefore sits at instance scope while the
	// operation addresses org depth — legal, and the honest reading: an org
	// administrator cannot rename or delete the org they administer, and
	// learns nothing from trying.
	// Rename and Delete read the row first, in the same transaction, so the
	// trail records the transition that actually happened rather than only the
	// value the caller asked for. That read is part of the operation, hence the
	// Get store op beside the mutation.
	OpOrgRename: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsGet: true, StoreOrgsRename: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventOrgRenamed},
	},
	OpOrgDelete: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreOrgsGet: true, StoreOrgsDelete: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventOrgDeleted},
	},

	// OIDC provider administration (#54). Instance-config, MFA-mandatory. The
	// provider table is class=authn, so the read and the mutation ride the
	// proof-free resolution surface (like the session lifecycle) AFTER this
	// operation authorizes the caller; only the audit write is a store op here.
	// The put/delete paths also sweep federated sessions on the resolution
	// surface (A4).
	OpProviderPut: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOIDCProviderChanged},
	},
	OpProviderGet: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOIDCProviderRead},
	},
	OpProviderList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOIDCProviderRead},
	},
	OpProviderDelete: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOIDCProviderChanged},
	},

	// Credential reset (#54). The formula IS the ADR's org-bounded rule: at the
	// target's org, an org-scoped credential-reset grant covers it and an
	// instance-scoped one covers it by inheritance, while an org-P grant (P != the
	// target's org) does not. The instance variant is for multi-org targets, which
	// only an instance-scope holder can reach. Writes (generation advance, session
	// revocation, authority mint) and the audit event ride the resolution surface,
	// so there is no store op here; the event is declared for completeness.
	OpCredentialReset: {
		class:   ClassTenant,
		level:   domain.LevelOrg,
		formula: Formula{{Cap: domain.CapCredentialReset, At: domain.LevelOrg}},
		events:  []audit.EventType{audit.EventAuthCredentialResetIssued},
	},
	OpCredentialResetInstance: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapCredentialReset, At: domain.LevelNone}},
		events:  []audit.EventType{audit.EventAuthCredentialResetIssued},
	},

	// The Project aggregate (#48). `manage-projects` is the permission ADR's
	// own wording for project lifecycle ("create and delete projects"), and a
	// rename is lifecycle too — identity is the immutable id, so a rename
	// changes the label an org administrator owns, nothing a reader depends on.
	OpProjectCreate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapManageProjects, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreProjectsCreate: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventProjectCreated},
	},
	OpProjectGet: {
		class:       ClassTenant,
		level:       domain.LevelProject,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps:    map[StoreOp]bool{StoreProjectsGet: true},
		auditedNone: true,
	},
	OpProjectList: {
		class:       ClassTenant,
		level:       domain.LevelOrg,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelOrg}},
		storeOps:    map[StoreOp]bool{StoreProjectsList: true},
		auditedNone: true,
	},
	OpProjectRename: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageProjects, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreProjectsGet: true, StoreProjectsRename: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventProjectRenamed},
	},
	OpProjectDelete: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageProjects, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreProjectsGet: true, StoreProjectsDelete: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventProjectDeleted},
	},

	// The Environment aggregate (#48). `definitions-edit` is the permission
	// ADR's atom for "environment topology (create/delete environments)", and
	// rename and reorder are topology under the same authority. Creation reads
	// the count inside its own transaction: the ops-spec environment cap is
	// enforced where the row is written, never checked earlier and hoped for.
	OpEnvCreate: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreEnvironmentsCount: true,
			StoreEnvironmentsNextOrder: true, StoreEnvironmentsCreate: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventEnvCreated},
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
	OpEnvList: {
		class:       ClassTenant,
		level:       domain.LevelProject,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps:    map[StoreOp]bool{StoreEnvironmentsList: true},
		auditedNone: true,
	},
	OpEnvRename: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsGet: true, StoreEnvironmentsRename: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventEnvRenamed},
	},
	// Reorder addresses the PROJECT: it rewrites the whole ordered set in one
	// transaction, so no caller can observe a duplicate or a gap, and there is
	// no per-environment write that could race another.
	OpEnvReorder: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreEnvironmentsList: true,
			StoreEnvironmentsSetOrder: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventEnvReordered},
	},
	OpEnvDelete: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsGet: true, StoreEnvironmentsDelete: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventEnvDeleted},
	},
	OpEnvUpdateNote: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapEdit, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsUpdateNote: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventEnvNoteChanged},
	},

	// The Folder aggregate (#48). Folders are organizational only: the
	// permission ADR forbids folder-scoped grants outright, and names the
	// folder path as `definitions-edit` territory. Every folder operation
	// therefore addresses PROJECT depth — there is no folder scope to address.
	OpFolderCreate: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreFoldersCreate: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventFolderCreated},
	},
	OpFolderGet: {
		class:       ClassTenant,
		level:       domain.LevelProject,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps:    map[StoreOp]bool{StoreFoldersGet: true},
		auditedNone: true,
	},
	OpFolderList: {
		class:       ClassTenant,
		level:       domain.LevelProject,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps:    map[StoreOp]bool{StoreFoldersList: true},
		auditedNone: true,
	},
	OpFolderRename: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreFoldersGet: true, StoreFoldersRename: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventFolderRenamed},
	},
	OpFolderDelete: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreFoldersGet: true, StoreFoldersDelete: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventFolderDeleted},
	},

	// Audit trail reads and exports (#45). Reading the trail is itself
	// audited, unconditionally — no toggle exists (audit-model ADR): the
	// query op emits its own event in the same transaction, the export pair
	// takes the INTENT/OUTCOME shape.
	OpAuditQueryOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditQueryProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditQueryEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditExportOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
	OpAuditExportProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
	OpAuditExportEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreAuditTenantPage: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventAuditExportStarted, audit.EventAuditExportCompleted},
	},
	OpAuditInstanceQuery: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstancePage: true, StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventAuditQuery},
	},
	OpAuditInstanceExport: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapAuditRead, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstancePage: true, StoreAuditInstanceInsert: true},
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
