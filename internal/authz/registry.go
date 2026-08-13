package authz

import (
	"slices"
	"strings"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/domain"
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

	// The key catalogue (#49, schema-model ADR). Every operation addresses
	// PROJECT depth: a key is declared once per project and the scope lattice
	// has no key level (permission-model ADR: no key-scoped grants in v1).
	//
	// The atom is `definitions-edit`, which the permission ADR fixes as the
	// definitions bundle — "keys, rules, folder paths, and environment
	// topology" — and which explicitly RETIRES the schema ADR's earlier
	// `schema-edit` name for the same grant.
	OpKeyCreate            Operation = "key.create"
	OpKeyGet               Operation = "key.get"
	OpKeyList              Operation = "key.list"
	OpKeyRename            Operation = "key.rename"
	OpKeyUpdateDeclaration Operation = "key.update-declaration"
	OpKeyUpdateMetadata    Operation = "key.update-metadata"
	OpKeySetGroup          Operation = "key.set-group"
	OpKeyDelete            Operation = "key.delete"
	OpKeyReclassify        Operation = "key.reclassify"

	// The two reveal gates. They are OPERATIONS rather than an inline
	// capability check because the chokepoint is the only place authorization
	// is evaluated: a second authorize() call against a registered formula
	// gets the denial writer, the assurance leg, the formula pin and the
	// probe contract for free, where a hand-rolled grant lookup would get none
	// of them and would be a parallel authorization path.
	//
	// Both are evaluated BEFORE any evaluation of the changed rule against a
	// value, per the schema ADR's load-bearing security rule: the operation is
	// rejected without evaluating, because timing and abort/success are
	// themselves the channel.
	OpKeySecretRuleChange Operation = "key.secret-rule-change"
	OpKeyDeclassify       Operation = "key.declassify"

	// The flat value model (#50, flat-model ADR + permission-model ADR's
	// locked formula table). Every operation addresses ENVIRONMENT depth: a
	// value attaches to a (key, environment) and there are no other layers,
	// so there is no shallower thing to address.
	//
	// The formulas, and why each is what it is:
	//
	//   - read      → `read(E)`. The permission ADR's `read` carries "the
	//                 project key catalogue … validation status, diffs
	//                 (write-presence only for `secret` keys); **`config`
	//                 values**". Presence is write-presence; `config`
	//                 plaintext rides `read` because classification IS the
	//                 sensitivity boundary.
	//   - reveal    → `read(E) ∧ reveal(E)`, the locked disclosure row for
	//                 current `secret` material, with one audit event per
	//                 disclosed key.
	//   - write     → `edit(E) ∧ publish(E)`. `edit` alone is the ADR's
	//                 working-state atom and "creates no revision"; this slice
	//                 has no working state, so a write here IS delivered
	//                 material the moment it commits. Requiring `publish` as
	//                 well is the fail-closed reading of the same table that
	//                 puts `publish(destination)` on every operation that
	//                 makes an environment start delivering something. When
	//                 #51 lands drafts, the draft write is `edit` alone and
	//                 this pair moves to the publish step.
	//   - copy      → the locked row, split across the two scopes it names,
	//                 because a formula is evaluated against ONE addressed
	//                 scope and this one spans two: `reveal(source E)` on the
	//                 source and `reveal(destination E) ∧ publish(destination
	//                 E)` on each destination. Clone-at-creation and
	//                 bulk-apply are the same pair — the ADR's three
	//                 ergonomic operations differ in what they copy, never in
	//                 what authorizes it.
	//
	// `reveal-history(source E)` — the historical-material half of the locked
	// row — has no operation here because this slice stores no historical
	// material: revisions are #51's. It joins when its material does.
	OpValueRead   Operation = "value.read"
	OpValueList   Operation = "value.list"
	OpValueReveal Operation = "value.reveal"
	// The reveal guard's own read (#58). It answers "will disclosing here
	// prompt me, and with which factor" — the window state, the protected
	// flag, and whether TOTP may open a window at all. Its formula is `read`
	// ALONE and deliberately not `reveal`: the browser has to render the
	// ceremony modal's shape before it holds any disclosure, and the answer is
	// project settings plus the caller's own session state, never material.
	OpRevealWindowRead Operation = "reveal.window_read"
	OpValueSet         Operation = "value.set"
	OpValueClear       Operation = "value.clear"
	// The copy pair. Both are reached by copy-to, bulk-apply AND
	// clone-at-creation: one authorization story for every server-side
	// duplication of stored material, which is exactly what the flat model's
	// closed trigger list asks for.
	OpValueCopySource      Operation = "value.copy-source"
	OpValueCopyDestination Operation = "value.copy-destination"
	// The destination leg for `config` material, which is NOT reveal-gated on
	// either side. One surface, two registry rows, because one formula cannot
	// express two authorization stories — the same shape credential-reset's
	// org/instance pair takes.
	//
	// This is not a softening of the locked row; it is the only reading under
	// which the locked row's own consequences are reachable. Grants inherit
	// DOWNWARD only, so `reveal` on an environment that does not exist yet can
	// come only from a project-or-wider grant — which necessarily covers every
	// source environment in that project. Requiring destination `reveal` for
	// `config` material would therefore make source-`reveal` always hold at a
	// clone, and the flat-model ADR's "creation proceeds and the uncopied
	// secrets land absent, enumerated by name" — and mvp-boundary C2's "a clone
	// that would leave a `mode: all` required secret absent aborts naming the
	// keys" — would be unreachable text. The gate is classification-scoped in
	// its own wording ("begin delivering a **`secret`** value occurrence the
	// publisher did not supply"), and the permission ADR puts `config` values
	// under `read`.
	OpValueCopyDestinationConfig Operation = "value.copy-destination-config"

	OpKeyGroupCreate Operation = "key-group.create"
	OpKeyGroupGet    Operation = "key-group.get"
	OpKeyGroupList   Operation = "key-group.list"
	OpKeyGroupRename Operation = "key-group.rename"
	OpKeyGroupDelete Operation = "key-group.delete"

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

	// SAML provider administration (#72, saml-sp ADR). These join the same
	// instance-config capability surface as OIDC. Metadata refresh is an action
	// on the provider resource, not a new authority or noun family.
	OpSAMLProviderPut             Operation = "saml-provider.put"
	OpSAMLProviderPatch           Operation = "saml-provider.patch"
	OpSAMLProviderGet             Operation = "saml-provider.get"
	OpSAMLProviderList            Operation = "saml-provider.list"
	OpSAMLProviderDelete          Operation = "saml-provider.delete"
	OpSAMLProviderRefreshMetadata Operation = "saml-provider.refresh-metadata"
	OpSAMLSPKeyList               Operation = "saml-sp-key.list"
	OpSAMLSPKeyRotate             Operation = "saml-sp-key.rotate"
	OpSAMLSPKeyRetire             Operation = "saml-sp-key.retire"
	OpSAMLSPKeyCompromiseRetire   Operation = "saml-sp-key.compromise-retire"

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

	// The grant surface (#55, permission-model ADR). One operation per
	// ADDRESSED depth, as with audit reads and credential-reset: the registry
	// pins one depth per tenant operation, so the four depths are four rows
	// sharing one service implementation.
	//
	// The formula atom sits at the depth `manage-members` is grantable at,
	// which is NOT always the addressed depth. Granting `read` on one
	// environment is authorized by `manage-members(project)` — the atom's
	// level truncates the resolved chain, so an env-addressed grant asks the
	// project question. That is the ADR's own rule ("manage-members at org /
	// project: create, modify and revoke grants at or below that scope")
	// expressed in the formula rather than in service code.
	OpGrantCreateOrg      Operation = "grant.create-org"
	OpGrantCreateProject  Operation = "grant.create-project"
	OpGrantCreateEnv      Operation = "grant.create-env"
	OpGrantCreateInstance Operation = "grant.create-instance"

	OpGrantRevokeOrg      Operation = "grant.revoke-org"
	OpGrantRevokeProject  Operation = "grant.revoke-project"
	OpGrantRevokeEnv      Operation = "grant.revoke-env"
	OpGrantRevokeInstance Operation = "grant.revoke-instance"

	// Listing the membership surface is `manage-members` too, not `read`:
	// who holds which capability is administrative information, and the ADR
	// puts every grant read and write under the same atom ("create, modify
	// and revoke grants at or below that scope" is the administration of the
	// list the surface shows).
	OpGrantListOrg      Operation = "grant.list-org"
	OpGrantListProject  Operation = "grant.list-project"
	OpGrantListInstance Operation = "grant.list-instance"

	// Template application is grant creation with a name attached: the
	// expansion happens AT GRANT TIME and produces ordinary grants, so it
	// carries the same formula as a create at the same depth.
	OpTemplateApplyOrg      Operation = "grant.template-org"
	OpTemplateApplyProject  Operation = "grant.template-project"
	OpTemplateApplyEnv      Operation = "grant.template-env"
	OpTemplateApplyInstance Operation = "grant.template-instance"

	// The protected-environment flag and the per-environment reauthentication
	// window (#55). `project-settings` is deliberately split out of
	// `definitions-edit` — these exist to restrain the definitions editor, and
	// a guard whose off-switch sits in the hand it restrains is not a guard.
	// The read is bare `read(E)`: an environment's protection state is part of
	// its public shape, and hiding it from a reader would make the reveal
	// ceremony inexplicable.
	OpEnvSettingsRead   Operation = "environment.settings-read"
	OpEnvSettingsUpdate Operation = "environment.settings-update"

	// Machine identities (#61). Every one of these asks
	// `manage-identities(project)` and nothing more, because that is the
	// whole of what the CHOKEPOINT decides here.
	//
	// The mint and widen formulas' reveal conjuncts are deliberately NOT in
	// this table, and that is the load-bearing part: they range over a set
	// computed from the RESULTING STATE — every environment reachable in the
	// post-state for a mint, only the newly reachable set for a grant
	// mutation — which no static (capability, level) atom can express. They
	// are evaluated in service.Identities, in the same transaction, against
	// the same grant rows, and refuse before any row is written. A formula
	// atom here would have been a claim the registry could not keep.
	OpServiceAccountCreate   Operation = "identity.service-account-create"
	OpServiceAccountList     Operation = "identity.service-account-list"
	OpServiceAccountDelete   Operation = "identity.service-account-delete"
	OpCredentialMint         Operation = "identity.credential-mint"
	OpCredentialList         Operation = "identity.credential-list"
	OpCredentialRevoke       Operation = "identity.credential-revoke"
	OpCredentialPolicyRead   Operation = "identity.credential-policy-read"
	OpCredentialPolicyUpdate Operation = "identity.credential-policy-update"

	// OIDC federation (#62). Issuer configuration is INSTANCE-scoped under
	// `instance-config`, never org- or project-scoped: #16 fixed this exact
	// argument for human providers, because an org-scoped issuer would let an
	// org admin add a provider and mint identities authenticating into the
	// instance.
	OpFederationIssuerCreate Operation = "federation.issuer-create"
	OpFederationIssuerList   Operation = "federation.issuer-list"
	OpFederationIssuerUpdate Operation = "federation.issuer-update"
	OpFederationIssuerDelete Operation = "federation.issuer-delete"

	// Creating a federated binding is a MINT, so it sits beside
	// identity.credential-mint and carries the same capability half here and the
	// same post-state disclosure conjunct in the service. There is no
	// binding-UPDATE operation, and that absence is the immutability rule
	// expressed in the registry: a change is a replacement mint through this
	// same row, carrying the full formula, and an operation for editing in place
	// would be the authority-laundering path #15 closed for adapters.
	//
	// Binding DELETE and LIST reuse identity.credential-revoke and
	// identity.credential-list: a binding IS a credential row, so a second pair
	// of operations over the same rows would be two places for one formula to
	// drift. Reactivation (§ Restore) rides credential-revoke too, because it
	// only ever NARROWS what the binding accepts.
	OpBindingCreate Operation = "identity.binding-create"

	// The machine delivery surface (#62; ADR § Authentication, authorization
	// and the fetch path). Tenant-class at ENVIRONMENT depth under bare `read`,
	// which is what makes a caller who lost `read` receive the
	// uniform-nonexistent answer rather than "current" — the conditional path
	// authorizes exactly like the delivering path.
	//
	// It is NOT `audited: none` despite being a bare-`read` tenant operation:
	// the ADR requires one immutable access record per fetch, including the
	// conditional fetch that delivers nothing.
	OpDeliveryFetch Operation = "delivery.fetch"
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
	// The protected flag and per-environment window (#55).
	StoreEnvironmentsGetSettings StoreOp = "environments.Settings"
	StoreEnvironmentsSetSettings StoreOp = "environments.SetSettings"

	// The key catalogue (#49). Named `catalogue.*` and not `keys.*`: that
	// prefix is the KEYRING's (#43, wrapped crypto material), and two unrelated
	// senses of "key" sharing an operation prefix is how a proof minted for one
	// would look admissible for the other.
	StoreCatalogueCreate            StoreOp = "catalogue.Create"
	StoreCatalogueGet               StoreOp = "catalogue.Get"
	StoreCatalogueList              StoreOp = "catalogue.List"
	StoreCatalogueCount             StoreOp = "catalogue.Count"
	StoreCatalogueRename            StoreOp = "catalogue.Rename"
	StoreCatalogueUpdateMetadata    StoreOp = "catalogue.UpdateMetadata"
	StoreCatalogueUpdateDeclaration StoreOp = "catalogue.UpdateDeclaration"
	StoreCatalogueSetClassification StoreOp = "catalogue.SetClassification"
	StoreCatalogueSetGroup          StoreOp = "catalogue.SetGroup"
	StoreCatalogueDelete            StoreOp = "catalogue.Delete"
	StoreCatalogueGroupCreate       StoreOp = "catalogue.CreateGroup"
	StoreCatalogueGroupGet          StoreOp = "catalogue.GetGroup"
	StoreCatalogueGroupList         StoreOp = "catalogue.ListGroups"
	StoreCatalogueGroupCount        StoreOp = "catalogue.CountGroups"
	StoreCatalogueGroupRename       StoreOp = "catalogue.RenameGroup"
	StoreCatalogueGroupDelete       StoreOp = "catalogue.DeleteGroup"
	StoreCatalogueGroupClearMembers StoreOp = "catalogue.ClearGroupMembers"
	StoreCataloguePresenceList      StoreOp = "catalogue.ListPresence"
	StoreCataloguePresenceReplace   StoreOp = "catalogue.ReplacePresence"
	StoreCataloguePresenceCascade   StoreOp = "catalogue.DeletePresenceForEnvironment"
	StoreCatalogueRevisionGet       StoreOp = "catalogue.SchemaRevision"
	StoreCatalogueRevisionBump      StoreOp = "catalogue.BumpSchemaRevision"

	StoreFoldersCreate StoreOp = "folders.Create"
	StoreFoldersGet    StoreOp = "folders.Get"
	StoreFoldersList   StoreOp = "folders.List"
	StoreFoldersRename StoreOp = "folders.Rename"
	StoreFoldersDelete StoreOp = "folders.Delete"

	// The flat value model (#50). `values.*` rather than `value.*` to match
	// the CLI noun and to keep the prefix distinct from `catalogue.*` (the
	// key DECLARATIONS) and `keys.*` (the KEYRING, #43) — three neighbouring
	// senses of "key" that must never share a store-op prefix.
	StoreValuesGet                   StoreOp = "values.Get"
	StoreValuesList                  StoreOp = "values.List"
	StoreValuesEnvironmentsWithValue StoreOp = "values.EnvironmentsWithValue"
	StoreValuesPut                   StoreOp = "values.Put"
	StoreValuesClear                 StoreOp = "values.Clear"
	StoreValuesClearEnvironment      StoreOp = "values.ClearEnvironment"

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
	StoreOrgsGet:                     true,
	StoreOrgsList:                    true,
	StoreOrgsCount:                   true,
	StoreProjectsGet:                 true,
	StoreProjectsList:                true,
	StoreEnvironmentsGet:             true,
	StoreEnvironmentsList:            true,
	StoreEnvironmentsCount:           true,
	StoreEnvironmentsNextOrder:       true,
	StoreFoldersGet:                  true,
	StoreFoldersList:                 true,
	StoreEnvironmentsGetSettings:     true,
	StoreCatalogueGet:                true,
	StoreCatalogueList:               true,
	StoreCatalogueCount:              true,
	StoreCatalogueGroupGet:           true,
	StoreCatalogueGroupList:          true,
	StoreCatalogueGroupCount:         true,
	StoreCataloguePresenceList:       true,
	StoreCatalogueRevisionGet:        true,
	StoreValuesGet:                   true,
	StoreValuesList:                  true,
	StoreValuesEnvironmentsWithValue: true,
	StoreKeysActiveMasterWrappers:    true,
	StoreKeysActiveTier3:             true,
	StoreAuditTenantPage:             true,
	StoreAuditInstancePage:           true,
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

	// SAML provider administration (#72). Provider storage and session sweeps
	// are proof-free authentication-resolution operations after this gate, just
	// like OIDC administration; the operation registry therefore owns the
	// instance-config proof and audit linkage, not those storage calls.
	OpSAMLProviderPut: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events: []audit.EventType{
			audit.EventSAMLProviderConfigure,
			audit.EventSAMLCertChange,
			audit.EventSAMLEmailNameIDOptIn,
			audit.EventSAMLSPKey,
			audit.EventSAMLMetadataExpiryWarning,
		},
	},
	OpSAMLProviderPatch: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events: []audit.EventType{
			audit.EventSAMLProviderConfigure,
			audit.EventSAMLEmailNameIDOptIn,
		},
	},
	OpSAMLProviderGet: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		// auth.provider_read is protocol-neutral on the wire even though its Go
		// constant predates SAML; the locked SAML event list adds no second read
		// event, and instance reads cannot take audited-none.
		events: []audit.EventType{audit.EventOIDCProviderRead, audit.EventSAMLMetadataExpiryWarning},
	},
	OpSAMLProviderList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOIDCProviderRead, audit.EventSAMLMetadataExpiryWarning},
	},
	OpSAMLProviderDelete: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventSAMLProviderRemove},
	},
	OpSAMLProviderRefreshMetadata: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events: []audit.EventType{
			audit.EventSAMLProviderRefresh,
			audit.EventSAMLCertChange,
			audit.EventSAMLMetadataExpiryWarning,
		},
	},
	OpSAMLSPKeyList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventOIDCProviderRead},
	},
	OpSAMLSPKeyRotate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventSAMLSPKey},
	},
	OpSAMLSPKeyRetire: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventSAMLSPKey},
	},
	OpSAMLSPKeyCompromiseRetire: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventSAMLSPKey},
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
	// Deleting an environment now also cascades its id out of every explicit
	// presence set, in the SAME transaction (#49, schema-model ADR § Presence).
	// The project row is taken first because environment lifecycle and presence
	// rules are one serialization domain: without it, this delete and a
	// concurrent `required_in` edit naming the same environment can both read a
	// consistent world and both commit into an inconsistent one.
	OpEnvDelete: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreEnvironmentsGet: true,
			// The cascade reads the project's presence rows and its keys,
			// collapses any explicit set it empties, and advances the catalogue
			// revision — the catalogue changed, so its revision must.
			StoreCataloguePresenceList: true, StoreCataloguePresenceCascade: true,
			StoreCatalogueList: true, StoreCatalogueUpdateDeclaration: true,
			StoreCatalogueRevisionBump: true,
			// The environment's own values go with it (#50): they attach to
			// this environment and nothing else, the composite foreign key
			// would refuse the delete while they existed, and there is no
			// other environment for them to survive in.
			StoreValuesClearEnvironment: true,
			StoreEnvironmentsDelete:     true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventEnvDeleted},
	},
	OpEnvUpdateNote: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapEdit, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsUpdateNote: true, StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventEnvNoteChanged},
	},

	// The key catalogue (#49). Every mutation takes the project row first
	// (StoreProjectsLock): the schema ADR binds ONE serialization domain per
	// project covering the schema, environment create/delete and presence
	// cascades, and the named race is a presence rule naming an environment
	// another transaction is deleting.
	//
	// Reads take the audited-none permit (tenant class, bare `read`, mutating
	// nothing) exactly as the hierarchy reads do. The permission ADR's
	// "any environment-scoped grant implies visibility of the project's key
	// names, descriptions and schemas" is why the read atom sits at project
	// depth: the key catalogue is project-scoped, values are not.
	OpKeyCreate: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueCount: true,
			StoreCatalogueList: true, StoreCataloguePresenceList: true,
			StoreCatalogueGroupGet: true, StoreCatalogueCreate: true,
			StoreCataloguePresenceReplace: true, StoreCatalogueRevisionBump: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyCreated},
	},
	OpKeyGet: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueGet: true, StoreCataloguePresenceList: true,
		},
		auditedNone: true,
	},
	OpKeyList: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList: true, StoreCataloguePresenceList: true,
			StoreCatalogueRevisionGet: true,
		},
		auditedNone: true,
	},
	// A rename changes the delivered payload's KEY SET, so it is a
	// content-affecting schema change and advances the revision — unlike the
	// hierarchy renames, which change a label nothing is delivered under.
	OpKeyRename: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGet: true, StoreCatalogueRename: true,
			StoreCatalogueRevisionBump: true, StoreCataloguePresenceList: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyRenamed},
	},
	OpKeyUpdateDeclaration: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGet: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreCatalogueUpdateDeclaration: true,
			StoreCataloguePresenceReplace: true, StoreCatalogueRevisionBump: true,
			// The resulting revision is read back inside the same transaction:
			// the audit record names the revision the change LANDED at, not the
			// one it started from.
			StoreCatalogueRevisionGet: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyDeclarationChanged},
	},
	// Metadata is the schema ADR's one exemption: description, deprecated,
	// deprecation_note and folder path cannot change what any environment
	// delivers or whether it validates, so they need `definitions-edit` alone,
	// take no reveal gate, and move no revision — hence no revision bump in
	// this operation's store set, which is where that claim is enforceable.
	OpKeyUpdateMetadata: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueGet: true, StoreCatalogueUpdateMetadata: true,
			StoreCataloguePresenceList: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyMetadataChanged},
	},
	OpKeySetGroup: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGet: true, StoreCatalogueGroupGet: true,
			StoreCatalogueList: true, StoreCataloguePresenceList: true,
			StoreCatalogueSetGroup: true, StoreCatalogueRevisionBump: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyGroupMembershipChanged},
	},
	OpKeyDelete: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGet: true,
			StoreCataloguePresenceReplace: true, StoreCatalogueDelete: true,
			// A key that any environment still holds a value for is REFUSED
			// (#50), naming those environments: destroying delivered material
			// needs the per-affected-environment `publish` leg, which is the
			// publish pipeline's to define (#51). Reading which environments
			// those are is what this store op is for.
			StoreValuesEnvironmentsWithValue: true,
			StoreCatalogueRevisionBump:       true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyDeleted},
	},
	// Reclassification is a DISTINCT operation, never a field of an ordinary
	// update: the ceremony's gates and its disclosure-class audit exist only
	// on this path, and an update that could carry a classification would be a
	// way around both.
	OpKeyReclassify: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGet: true,
			StoreCatalogueSetClassification: true, StoreCatalogueRevisionBump: true,
			StoreCataloguePresenceList: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyReclassified},
	},
	// The reveal gates. Their formula is `reveal` alone: the acting principal
	// has ALREADY passed `definitions-edit` on the operation this gate guards,
	// and repeating that atom here would only make the denial record ambiguous
	// about which half failed.
	//
	// They are tenant-class, so a refusal is the uniform ErrNotFound — a
	// definitions-edit holder without reveal gets the same answer as for a key
	// that is not there. That is the correct outcome twice over: it is the
	// project's standing unauthorized-≡-nonexistent rule, and a distinguishable
	// refusal would itself be a one-bit oracle about the gate.
	//
	// They reach NO store operation at all: the gate decides, and its attempt
	// record rides the rollback-surviving settlement path rather than the
	// proof-carrying store surface — because the outcomes worth recording are
	// exactly the ones that roll their transaction back. The mutation a passed
	// gate guards runs under its own operation's proof.
	OpKeySecretRuleChange: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapReveal, At: domain.LevelProject}},
		events:  []audit.EventType{audit.EventKeyRevealGateAttempt},
	},
	OpKeyDeclassify: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapReveal, At: domain.LevelProject}},
		events:  []audit.EventType{audit.EventKeyRevealGateAttempt},
	},

	// The flat value model (#50). Every mutation takes the project row first,
	// for the same reason the catalogue does: a value is validated against the
	// key's declaration, and a concurrent declaration change would otherwise
	// let a value commit against rules that no longer exist. It costs
	// per-project write serialization on values, which is the same ceiling the
	// schema already pays and is nowhere near binding for the write rate a
	// configuration store sees.
	//
	// Reads resolve the key by NAME through the catalogue list, so every value
	// operation carries StoreCatalogueList: `values set DATABASE_URL` is the
	// spelling the CLI ADR fixes, and the id is server vocabulary.
	OpValueRead: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList: true, StoreValuesGet: true,
		},
		// Write-presence and `config` plaintext, mutating nothing: the exact
		// shape the audited-none permit rule accepts. A `secret` plaintext
		// read is NOT this operation — it is OpValueReveal, which audits.
		auditedNone: true,
	},
	OpValueList: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			// Values().Get joins List because the `config` half of a copy and
			// of a clone reads its material under THIS operation: `config`
			// values are `read`-class material, so duplicating them needs no
			// reveal-gated read anywhere.
			StoreCatalogueList: true, StoreValuesList: true, StoreValuesGet: true,
			// The presence rules are project schema, which the permission ADR
			// puts under `read` along with the rest of the catalogue. The
			// clone preflight reads them here to answer "would this leave a
			// required secret absent?" before anything is written.
			StoreCataloguePresenceList: true,
		},
		auditedNone: true,
	},
	// The reveal guard's state (#58). Reads nothing from the tenant store: the
	// window, the protected flag and the effective window are resolved through
	// the authorization package's own enumerated resolution surface, which is
	// the same seam every window opener already uses. It mutates nothing and
	// its formula is bare `read`, which is exactly the audited-none permit
	// rule's shape — and recording "someone looked at whether they would be
	// prompted" would bury the disclosures themselves in noise.
	OpRevealWindowRead: {
		class:       ClassTenant,
		level:       domain.LevelEnv,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps:    map[StoreOp]bool{},
		auditedNone: true,
	},
	// The disclosure operation. `read ∧ reveal` is the permission ADR's locked
	// row for current `secret` material; the MFA-mandatory rule rides along
	// automatically, because `reveal` is in MFAMandatory and the chokepoint
	// evaluates that after the grant check.
	OpValueReveal: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelEnv},
			{Cap: domain.CapReveal, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList: true, StoreValuesGet: true, StoreValuesList: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueRevealed},
	},
	OpValueSet: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapEdit, At: domain.LevelEnv},
			{Cap: domain.CapPublish, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreValuesPut: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueSet},
	},
	OpValueClear: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapEdit, At: domain.LevelEnv},
			{Cap: domain.CapPublish, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			// A key `required_in` this environment refuses to be cleared, so
			// the presence rows are an input to the clear as much as to the
			// write.
			StoreCataloguePresenceList: true,
			StoreValuesClear:           true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueCleared},
	},
	// The source half of the locked copy row. It records one disclosure event
	// per `secret` key whose plaintext it opened — the source-side fact the
	// destination-side `value_copied` event does not carry. The open is always
	// reached only once no in-transaction abort can roll it back: copy authorizes
	// every destination (formula and protected-destination ceremony) BEFORE
	// opening any source secret (see service.Copy), and clone runs its
	// born-invalid abort against a plan that opens nothing, opening the material
	// only after the abort cannot fire (see service.cloneInto). So this event is
	// only ever written for material genuinely read, and never written-then-rolled-
	// back. `config` material opens no event, because reading it discloses nothing
	// beyond the `read` the caller has.
	//
	// It is NOT audited-none: the permit rule is bare `read` and nothing more,
	// and this formula is `reveal`.
	OpValueCopySource: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapReveal, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList: true, StoreValuesGet: true, StoreValuesList: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueRevealed},
	},
	// The destination half for SECRET material: `reveal ∧ publish` on the
	// environment that is about to start delivering material its publisher did
	// not supply. Reached by copy-to, bulk-apply and clone-at-creation alike.
	OpValueCopyDestination: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapReveal, At: domain.LevelEnv},
			{Cap: domain.CapPublish, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreEnvironmentsGetSettings: true,
			StoreValuesPut: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueCopied},
	},
	// The destination half for CONFIG material: `publish` alone. Classification
	// IS the sensitivity boundary, so duplicating a value that any reader of
	// the destination could already read discloses nothing; what it does do is
	// change what the environment delivers, which is `publish`.
	OpValueCopyDestinationConfig: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapPublish, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreEnvironmentsGetSettings: true,
			StoreValuesPut: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueCopied},
	},

	OpKeyGroupCreate: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGroupCount: true,
			StoreCatalogueGroupCreate: true, StoreCatalogueRevisionBump: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyGroupCreated},
	},
	OpKeyGroupGet: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueGroupGet: true, StoreCatalogueList: true,
		},
		auditedNone: true,
	},
	OpKeyGroupList: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueGroupList: true, StoreCatalogueList: true,
		},
		auditedNone: true,
	},
	OpKeyGroupRename: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGroupGet: true,
			StoreCatalogueGroupRename: true, StoreCatalogueList: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyGroupRenamed},
	},
	// Deleting a group dissolves a coupling and releases its members; it never
	// deletes the keys it coupled, which is why ClearGroupMembers sits beside
	// the delete rather than a cascade doing it invisibly.
	OpKeyGroupDelete: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueGroupGet: true,
			StoreCatalogueList: true, StoreCatalogueGroupClearMembers: true,
			StoreCatalogueGroupDelete: true, StoreCatalogueRevisionBump: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventKeyGroupDeleted},
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

	// The grant surface (#55). The grant table is class=authn, so the writes
	// ride the enumerated resolution surface — authorize() reads grants to
	// mint a proof, and a grant write gated behind one would be a cycle. What
	// IS a store op here is the audit insert: the grant trail is tenant-owned
	// at org/project/env scope, instance-owned above it.
	OpGrantCreateOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventGrantCreated, audit.EventGrantModified,
		},
	},
	OpGrantCreateProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventGrantCreated, audit.EventGrantModified,
			// A widening on a MACHINE principal is a second, separate fact:
			// the grant re-scopes every credential already in circulation.
			audit.EventMachineGrantWidened,
		},
	},
	// Env-addressed grants ask the PROJECT question: `manage-members` is not
	// grantable at environment scope, so the atom truncates the chain.
	OpGrantCreateEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventGrantCreated, audit.EventGrantModified,
			// A widening on a MACHINE principal is a second, separate fact:
			// the grant re-scopes every credential already in circulation.
			audit.EventMachineGrantWidened,
		},
	},
	OpGrantCreateInstance: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events: []audit.EventType{
			audit.EventGrantCreated, audit.EventGrantModified,
		},
	},

	OpGrantRevokeOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		// A release that leaves the row alive (another origin kind still holds
		// it) is a MODIFICATION; only the release that deleted the row is a
		// revocation. Both are reachable from this operation.
		events: []audit.EventType{audit.EventGrantRevoked, audit.EventGrantModified},
	},
	OpGrantRevokeProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		// A release that leaves the row alive (another origin kind still holds
		// it) is a MODIFICATION; only the release that deleted the row is a
		// revocation. Both are reachable from this operation.
		events: []audit.EventType{audit.EventGrantRevoked, audit.EventGrantModified},
	},
	OpGrantRevokeEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		// A release that leaves the row alive (another origin kind still holds
		// it) is a MODIFICATION; only the release that deleted the row is a
		// revocation. Both are reachable from this operation.
		events: []audit.EventType{audit.EventGrantRevoked, audit.EventGrantModified},
	},
	OpGrantRevokeInstance: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventGrantRevoked, audit.EventGrantModified},
	},

	// Listing is not `audited: none`: the permit rule admits only tenant-class
	// bare-`read` operations, and reading who can reach production secrets is
	// not that. It is audited as an ordinary trail query would be — through
	// the surrounding operation's own event, which for a pure list is the
	// grant.list event the service emits.
	OpGrantListOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventGrantMembershipRead},
	},
	OpGrantListProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventGrantMembershipRead},
	},
	OpGrantListInstance: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventGrantMembershipRead},
	},

	// Template application. Same formula as a create at the same depth,
	// because that is exactly what it is: the template name exists only
	// inside the expansion, and what lands is ordinary grants.
	OpTemplateApplyOrg: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventGrantTemplateApplied, audit.EventGrantCreated, audit.EventGrantModified,
		},
	},
	OpTemplateApplyProject: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventGrantTemplateApplied, audit.EventGrantCreated, audit.EventGrantModified,
			// A widening on a MACHINE principal is a second, separate fact:
			// the grant re-scopes every credential already in circulation.
			audit.EventMachineGrantWidened,
		},
	},
	OpTemplateApplyEnv: {
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventGrantTemplateApplied, audit.EventGrantCreated, audit.EventGrantModified,
			// A widening on a MACHINE principal is a second, separate fact:
			// the grant re-scopes every credential already in circulation.
			audit.EventMachineGrantWidened,
		},
	},
	OpTemplateApplyInstance: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapManageMembers, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events: []audit.EventType{
			audit.EventGrantTemplateApplied, audit.EventGrantCreated, audit.EventGrantModified,
		},
	},

	// The protected flag and the per-environment reauthentication window.
	OpEnvSettingsRead: {
		class:       ClassTenant,
		level:       domain.LevelEnv,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps:    map[StoreOp]bool{StoreEnvironmentsGetSettings: true},
		auditedNone: true,
	},
	OpEnvSettingsUpdate: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapProjectSettings, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreEnvironmentsGetSettings: true, StoreEnvironmentsSetSettings: true,
			StoreAuditTenantInsert: true,
		},
		// auth.effective_window_lowered is emitted by the LowerEffectiveWindow
		// library this knob calls (#54 B6) — declared here because #55 is the
		// caller the completeness invariant was waiting for.
		events: []audit.EventType{
			audit.EventReauthWindowChanged, audit.EventProtectedFlagChange,
			audit.EventAuthEffectiveWindowLowered,
		},
	},

	// Machine identities (#61). The service-account and credential tables are
	// class=authn, so their reads and writes ride the resolution surface for
	// the same reason grants do; what IS a store op is the audit insert.
	OpServiceAccountCreate: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventServiceAccountCreated},
	},
	// Listing is not `audited: none`: the permit rule admits only
	// tenant-class bare-`read` operations, and reading which credentials can
	// reach production is not that.
	OpServiceAccountList: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventCredentialsListed},
	},
	// Deletion is a NARROWING, so it stays under the plain capability with no
	// reveal conjunct — the ADR's symmetric limit, so incident response is
	// never gated on disclosure rights.
	OpServiceAccountDelete: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventServiceAccountDeleted, audit.EventCredentialRevoked,
		},
	},
	// Minting is where the reveal conjunct and the reauthentication conjunct
	// live, both evaluated in service.Identities over the resulting
	// post-state. This row is only the capability half.
	OpCredentialMint: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventCredentialMinted},
	},
	OpCredentialList: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events:   []audit.EventType{audit.EventCredentialsListed},
	},
	// Revocation, and — via the same row — federated-binding DELETION and
	// restore-time RE-ACTIVATION. All three are narrowings over the same rows:
	// a binding is a credential, deleting one is revoking it, and re-activating
	// one only ever refuses tokens it would otherwise have accepted. One
	// formula, one place for it to be wrong.
	OpCredentialRevoke: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventCredentialRevoked, audit.EventBindingReactivated,
		},
	},
	// Not `audited: none`: the default-deny permit rule admits only
	// tenant-class bare-`read` operations, and reading the instance's
	// credential governance is neither. Same shape as the OIDC provider read.
	OpCredentialPolicyRead: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventCredentialPolicyRead},
	},
	OpCredentialPolicyUpdate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		// Two events, because this operation has two outcomes. A TIGHTENING
		// the actor has not confirmed changes no policy but enumerates every
		// live credential in the instance to them, and an instance-wide
		// credential enumeration with no record of who asked is the gap that
		// event closes.
		events: []audit.EventType{
			audit.EventCredentialPolicyChanged, audit.EventCredentialPolicyRead,
		},
	},

	// OIDC federation (#62). The issuer rows are instance-class under
	// `instance-config`, like every other instance knob; the federation tables
	// are class=authn, so their reads and writes ride the resolution surface and
	// what IS a store op is the audit insert.
	OpFederationIssuerCreate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventFederationIssuerChanged},
	},
	OpFederationIssuerUpdate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventFederationIssuerChanged},
	},
	OpFederationIssuerDelete: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventFederationIssuerChanged},
	},
	// Not `audited: none`: the permit rule admits only tenant-class bare-`read`
	// operations, and reading which external authorities the instance trusts to
	// name principals is neither.
	OpFederationIssuerList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventFederationIssuerRead},
	},
	// The binding mint. This row is the capability half only: the post-state
	// disclosure conjunct and the reauthentication conjunct are evaluated in
	// service.Federation, over a set computed from the resulting state, which no
	// static (capability, level) atom can express.
	OpBindingCreate: {
		class:    ClassTenant,
		level:    domain.LevelProject,
		formula:  Formula{{Cap: domain.CapManageIdentities, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{StoreAuditTenantInsert: true},
		events: []audit.EventType{
			audit.EventBindingCreated, audit.EventCredentialRevoked,
		},
	},
	// The machine fetch. Bare `read` at environment depth — the same formula the
	// delivering path uses, because they ARE the same path: a caller who lost
	// `read` gets the uniform nonexistent answer, never "current".
	//
	// It reads the key catalogue through the proof-carrying store, so those
	// store ops are named here as well as the audit insert.
	OpDeliveryFetch: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList:         true,
			StoreCataloguePresenceList: true,
			StoreCatalogueRevisionGet:  true,
			StoreAuditTenantInsert:     true,
		},
		events: []audit.EventType{audit.EventDeliveryFetched},
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
