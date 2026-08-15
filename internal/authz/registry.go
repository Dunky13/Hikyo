package authz

import (
	"slices"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/domain"
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

	// The import path (#68, import-paths ADR). Two operations, one per phase.
	//
	// `import.presence` is phase 1's ONLY server-side contact: it reads the
	// project's declared keys and, per key, the two-state presence in ONE
	// environment plus the server-minted occurrence token naming the exact
	// resolved state. The ADR's formula, exactly: structure reads carry the
	// project-scoped `read` the member already holds, and PRESENCE READS
	// REQUIRE `read(E)` for every environment whose presence is consulted —
	// which for an environment-depth operation is this environment. The
	// operation therefore carries both atoms: read@project for structure and
	// read@environment for presence. It never
	// requires `reveal`, never compares values and never writes; it is
	// audited-none like every other proof-scoped pure read.
	//
	// `value.import` is phase 2's batch write: one transaction, one
	// environment, the manifest precondition, and then ordinary value writes.
	// Its formula is `value.set`'s, unchanged — the writes it lands ARE
	// ordinary value writes, and an import that could write where `values set`
	// cannot would be a second write path with a weaker gate.
	OpImportPresence Operation = "import.presence"
	OpValueImport    Operation = "value.import"

	// Drafts, publishing and revisions (#51, revision-model ADR).
	OpValueStage   Operation = "value.stage"
	OpValuePublish Operation = "value.publish"
	// The one bulk-disclosure verb and its two material halves. `values export`
	// carries `read ∧ reveal` for CURRENT material and `read ∧ reveal-history`
	// for historical material; a mixed export evaluates each formula over
	// exactly the material it governs, which one formula cannot express.
	OpValueExport              Operation = "value.export"
	OpValueExportReveal        Operation = "value.export-reveal"
	OpValueExportRevealHistory Operation = "value.export-reveal-history"

	OpRevisionList           Operation = "revision.list"
	OpRevisionShow           Operation = "revision.show"
	OpRevisionSignals        Operation = "revision.signals"
	OpRevisionRestore        Operation = "revision.restore"
	OpRevisionRestoreHistory Operation = "revision.restore-reveal-history"
	OpRevisionRestoreCurrent Operation = "revision.restore-reveal-current"

	OpPinSet        Operation = "pin.set"
	OpPinSetHistory Operation = "pin.set-reveal-history"
	OpPinList       Operation = "pin.list"
	OpPinRelease    Operation = "pin.release"

	// The advisory channel's two checks: one at connect, over the project, and
	// one PER EVENT over the environment the event names.
	OpAdvisoryWatch Operation = "advisory.watch"
	OpAdvisoryEvent Operation = "advisory.event"

	// `rotate-token-key` rides `rotate-dek`: the permission ADR's capability
	// set is CLOSED and names four rotation atoms for five rotation verbs, and
	// the root token key is a tier-3 key alongside the DEKs -- same master,
	// same one-active-per-scope index, same retirement path.
	OpRotateTokenKey Operation = "crypto.rotate-token-key"

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
	OpEnvSettingsRead        Operation = "environment.settings-read"
	OpEnvSettingsUpdate      Operation = "environment.settings-update"
	OpOrgRetentionRead       Operation = "retention.org-read"
	OpOrgRetentionUpdate     Operation = "retention.org-update"
	OpProjectRetentionRead   Operation = "retention.project-read"
	OpProjectRetentionUpdate Operation = "retention.project-update"
	OpRetentionHealthRead    Operation = "retention.health-read"

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
	// SCIM provisioning (#73, scim-provisioning ADR). Two families, two
	// formulas, one depth.
	//
	// The ADMINISTRATION family is `manage-members(org)` AT ORG SCOPE EXACTLY
	// (§1): a mapping row causes grants the author need not hold, and
	// unheld-capability granting is an org/instance power under the locked
	// escalation asymmetry — a project-scope member manager must not reach it
	// through SCIM. The atom sits at LevelOrg rather than the capability's own
	// deepest level for exactly that reason.
	//
	// The WIRE family is `scim-provision(org)`, the machine-only atom the
	// provisioning connection holds structurally. There is no ambient routing
	// by credential: the presented credential must match the binding in the
	// path, and the org in the path is what the formula resolves against.
	OpSCIMBindingCreate Operation = "scim-binding.create"
	OpSCIMBindingGet    Operation = "scim-binding.get"
	OpSCIMBindingList   Operation = "scim-binding.list"
	OpSCIMBindingDelete Operation = "scim-binding.delete"

	OpSCIMMappingCreate Operation = "scim-mapping.create"
	OpSCIMMappingUpdate Operation = "scim-mapping.update"
	OpSCIMMappingDelete Operation = "scim-mapping.delete"
	OpSCIMMappingList   Operation = "scim-mapping.list"

	OpSCIMCredentialMint   Operation = "scim-credential.mint"
	OpSCIMCredentialGet    Operation = "scim-credential.get"
	OpSCIMCredentialList   Operation = "scim-credential.list"
	OpSCIMCredentialRevoke Operation = "scim-credential.revoke"

	OpSCIMDirectoryUsers  Operation = "scim-directory.users"
	OpSCIMDirectoryGroups Operation = "scim-directory.groups"

	OpSCIMUserCreate  Operation = "scim-user.create"
	OpSCIMUserGet     Operation = "scim-user.get"
	OpSCIMUserList    Operation = "scim-user.list"
	OpSCIMUserReplace Operation = "scim-user.replace"
	OpSCIMUserPatch   Operation = "scim-user.patch"
	OpSCIMUserDelete  Operation = "scim-user.delete"

	OpSCIMGroupCreate  Operation = "scim-group.create"
	OpSCIMGroupGet     Operation = "scim-group.get"
	OpSCIMGroupList    Operation = "scim-group.list"
	OpSCIMGroupReplace Operation = "scim-group.replace"
	OpSCIMGroupPatch   Operation = "scim-group.patch"
	OpSCIMGroupDelete  Operation = "scim-group.delete"

	// Discovery (ServiceProviderConfig / ResourceTypes / Schemas) is static
	// protocol documentation carrying no tenant data, but it still runs under
	// the binding's authentication and admission — so it is an operation like
	// any other rather than an unauthenticated hole in the mount.
	OpSCIMDiscovery Operation = "scim-discovery.read"

	// OpSCIMUnsupported is the authenticated refusal of Bulk, /Me and the
	// `.search` POST query. They are routes rather than 404s because the ADR
	// requires each to be refused with the RFC 7644 error shape, and they
	// authenticate like every other wire operation so an unauthenticated caller
	// gets the uniform refusal rather than a 501 confirming the binding exists.
	OpSCIMUnsupported Operation = "scim-unsupported.refuse"
	// Multi-instance, the serving side (#71). The directory-serve operation is
	// what an instance-connection credential presents against, and — per the
	// ADR's amendment to the artifact-eligibility matrix — the ONLY operation
	// it may reach. See internal/authz/eligibility.go for the other half of the
	// confinement; the formula alone would not carry it, because a later
	// operation adopting the same formula would widen every existing token.
	//
	// It is an instance-scope read that crosses org boundaries BY DESIGN: the
	// listing is instance identity, version, health, and the names and counts
	// of orgs and projects. That is why it is registered as its own operation
	// and probe-classified instance-scope rather than riding any tenant read —
	// there is no single tenant it addresses, and pretending otherwise would
	// put a cross-org read behind a per-org probe contract.
	OpRemoteDirectoryServe Operation = "remote.directory-serve"

	// Multi-instance, the VIEWING side (#71). The split follows the ADR's own
	// reasoning: CUSTODY of connections — add, remove, credential storage — is
	// instance configuration and rides `instance-config`; VIEWING the directory
	// is `instance-directory`, its own grantable atom, because reading is power
	// and is never bundled. The org/project NAMES in the listing are the reason
	// that gate exists: they are foreign structure, and the remote cannot scope
	// them per-viewer without the proxy machinery the ADR rejects.
	OpRemoteAdd    Operation = "remote.add"
	OpRemoteList   Operation = "remote.list"
	OpRemoteShow   Operation = "remote.show"
	OpRemoteRename Operation = "remote.rename"
	OpRemoteRemove Operation = "remote.remove"

	// Multi-instance, the SERVING side (#71). Credential custody and the origin
	// allowlist are both instance configuration.
	OpRemoteCredentialCreate Operation = "remote-credential.create"
	OpRemoteCredentialList   Operation = "remote-credential.list"
	OpRemoteCredentialShow   Operation = "remote-credential.show"
	OpRemoteCredentialRevoke Operation = "remote-credential.revoke"

	OpWorkspaceOriginList   Operation = "workspace-origin.list"
	OpWorkspaceOriginAdd    Operation = "workspace-origin.add"
	OpWorkspaceOriginRemove Operation = "workspace-origin.remove"

	// NOT REGISTERED, deliberately: the active-session listing and its revoke
	// (#71 criterion 5). Both are SELF-SCOPED — they address the caller's own
	// principal and nothing else — so they take the shape /api/v1/me/orgs
	// already takes: no operation, no capability, wire-classified
	// `unauthenticated` for enumeration uniformity, and the principal conjunct
	// lives in the SQL rather than in a formula. Requiring a grant to end one's
	// own session would make incident response depend on an authority an
	// attacker may have just taken away.
)

// StoreOp names one store method in the trusted query registry. Every store
// method is registered to the operation(s) it serves (invariant 6); the
// boundary check consults this registry on every call.
type StoreOp string

const (
	StoreOrgsCreate       StoreOp = "orgs.Create"
	StoreOrgsGet          StoreOp = "orgs.Get"
	StoreOrgsList         StoreOp = "orgs.List"
	StoreOrgsCount        StoreOp = "orgs.Count"
	StoreOrgsRename       StoreOp = "orgs.Rename"
	StoreOrgsLock         StoreOp = "orgs.Lock"
	StoreOrgsSetRetention StoreOp = "orgs.SetRetention"
	StoreOrgsDelete       StoreOp = "orgs.Delete"

	StoreProjectsCreate StoreOp = "projects.Create"
	StoreProjectsGet    StoreOp = "projects.Get"
	StoreProjectsList   StoreOp = "projects.List"
	// StoreProjectsListAll is the cross-org enumeration the multi-instance
	// directory serves (#71). It belongs to instance-scope operations only.
	StoreProjectsListAll      StoreOp = "projects.ListAll"
	StoreProjectsLock         StoreOp = "projects.Lock"
	StoreProjectsRename       StoreOp = "projects.Rename"
	StoreProjectsSetRetention StoreOp = "projects.SetRetention"
	StoreProjectsDelete       StoreOp = "projects.Delete"

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

	// Drafts and published revisions (#51). `pending.*` is the per-user
	// working state; `snapshots.*` is the published state, its lineage and
	// its payload — one aggregate because a revision, its resolved map and
	// its changed-key rows are written in one act and must never drift.
	StorePendingListForOwner       StoreOp = "pending.ListForOwner"
	StorePendingListMarkers        StoreOp = "pending.ListMarkers"
	StorePendingStage              StoreOp = "pending.Stage"
	StorePendingDiscard            StoreOp = "pending.Discard"
	StorePendingDiscardEnvironment StoreOp = "pending.DiscardEnvironment"
	StorePendingDiscardKey         StoreOp = "pending.DiscardKey"

	StoreSnapshotsLatest                      StoreOp = "snapshots.Latest"
	StoreSnapshotsAtRevision                  StoreOp = "snapshots.AtRevision"
	StoreSnapshotsList                        StoreOp = "snapshots.List"
	StoreSnapshotsEntries                     StoreOp = "snapshots.Entries"
	StoreSnapshotsChanges                     StoreOp = "snapshots.Changes"
	StoreSnapshotsInsert                      StoreOp = "snapshots.Insert"
	StoreSnapshotsInsertEntry                 StoreOp = "snapshots.InsertEntry"
	StoreSnapshotsSecretValueOccurrenceIDs    StoreOp = "snapshots.SecretValueOccurrenceIDs"
	StoreSnapshotsRecordSecretValueOccurrence StoreOp = "snapshots.RecordSecretValueOccurrence"
	StoreSnapshotsInsertChange                StoreOp = "snapshots.InsertChange"
	StoreSnapshotsDeleteEnvironment           StoreOp = "snapshots.DeleteEnvironment"

	StorePinsGetForWorkload    StoreOp = "pins.GetForWorkload"
	StorePinsList              StoreOp = "pins.List"
	StorePinsCountProject      StoreOp = "pins.CountProject"
	StorePinsInsert            StoreOp = "pins.Insert"
	StorePinsDelete            StoreOp = "pins.Delete"
	StorePinsDeleteEnvironment StoreOp = "pins.DeleteEnvironment"

	StoreRetentionEligible       StoreOp = "retention.Eligible"
	StoreRetentionMarkCollected  StoreOp = "retention.MarkCollected"
	StoreRetentionDeleteEntries  StoreOp = "retention.DeleteCollectedEntries"
	StoreRetentionLastSuccess    StoreOp = "retention.LastPruneSuccess"
	StoreRetentionSetLastSuccess StoreOp = "retention.SetLastPruneSuccess"

	// Keyring persistence (#43). These carry no tenant chain: wrapped-key
	// rows are instance-scoped crypto material, and the scope a tier-3 key
	// belongs to is part of its AAD, not a tenant predicate.
	StoreKeysActiveMasterWrappers       StoreOp = "keys.ActiveMasterWrappers"
	StoreKeysActiveTier3                StoreOp = "keys.ActiveTier3"
	StoreKeysAcquireHierarchyGeneration StoreOp = "keys.AcquireHierarchyGeneration"
	StoreKeysInsertMaster               StoreOp = "keys.InsertMaster"
	StoreKeysInsertTier3                StoreOp = "keys.InsertTier3"
	StoreKeysRotateTokenKey             StoreOp = "keys.RotateTokenKey"
	StoreKeysInsertScopeGeneration      StoreOp = "keys.InsertScopeGeneration"

	// Audit trails (#45). INSERT and SELECT only — the append-only invariant
	// lives at the query layer; these are the only store doors to it. The
	// denial writer does NOT pass through these: it is the authorization
	// package's own enumerated write path (audit-model ADR amendment part 4)
	// and runs with no proof to verify.
	// Multi-instance, the VIEWING side (#71). These are class=instance rows —
	// instance-scope configuration and foreign structure at rest — so unlike
	// the connection tables they ride the proof-gated repositories and need
	// registry entries. Reaching the sealed credential is its own StoreOp so
	// that an operation licensed to LIST remotes is not thereby licensed to
	// present one.
	StoreRemotesCreate    StoreOp = "remotes.Create"
	StoreRemotesList      StoreOp = "remotes.List"
	StoreRemotesGet       StoreOp = "remotes.Get"
	StoreRemotesGetByName StoreOp = "remotes.GetByName"
	StoreRemotesCount     StoreOp = "remotes.Count"
	StoreRemotesRename    StoreOp = "remotes.Rename"
	StoreRemotesDelete    StoreOp = "remotes.Delete"
	StoreRemotesSealed    StoreOp = "remotes.SealedCredential"

	StoreRemoteSnapshotsList  StoreOp = "remotes.Snapshots"
	StoreRemoteSnapshotsGet   StoreOp = "remotes.Snapshot"
	StoreRemoteSnapshotsWrite StoreOp = "remotes.WriteSnapshot"
	StoreRemoteSnapshotsFail  StoreOp = "remotes.RecordFetchFailure"

	StoreAuditTenantInsert   StoreOp = "audit.InsertTenant"
	StoreAuditInstanceInsert StoreOp = "audit.InsertInstance"
	StoreAuditTenantPage     StoreOp = "audit.PageTenant"
	StoreAuditInstancePage   StoreOp = "audit.PageInstance"

	// SCIM provisioning (#73). One StoreOp per method on store.SCIMRepo, as
	// invariant 6 requires: the registry is reflected against the repository
	// bundle, so a method without a row here — or a row here without a method —
	// fails the build. Grouping several methods behind one coarse op would have
	// been shorter and would have let an operation authorized to read the
	// directory write it.
	StoreSCIMLockBinding StoreOp = "scim.LockBinding"

	StoreSCIMCreateCredential            StoreOp = "scim.CreateCredential"
	StoreSCIMCredential                  StoreOp = "scim.Credential"
	StoreSCIMCredentials                 StoreOp = "scim.Credentials"
	StoreSCIMRevokeCredential            StoreOp = "scim.RevokeCredential"
	StoreSCIMRevokeCredentialsForBinding StoreOp = "scim.RevokeCredentialsForBinding"
	StoreSCIMDeleteCredentialsForBinding StoreOp = "scim.DeleteCredentialsForBinding"

	StoreSCIMCreateBinding StoreOp = "scim.CreateBinding"
	StoreSCIMBinding       StoreOp = "scim.Binding"
	StoreSCIMBindings      StoreOp = "scim.Bindings"
	StoreSCIMTouchBinding  StoreOp = "scim.TouchBinding"
	StoreSCIMDeleteBinding StoreOp = "scim.DeleteBinding"
	// StoreSCIMRetireConnection removes a binding's provisioning connection,
	// scoped by the proof's org AND the binding row that owns it.
	StoreSCIMRetireConnection StoreOp = "scim.RetireConnectionPrincipal"

	StoreSCIMCreateMapping            StoreOp = "scim.CreateMapping"
	StoreSCIMMapping                  StoreOp = "scim.Mapping"
	StoreSCIMMappings                 StoreOp = "scim.Mappings"
	StoreSCIMMappingsForGroup         StoreOp = "scim.MappingsForGroup"
	StoreSCIMSetMappingInert          StoreOp = "scim.SetMappingInert"
	StoreSCIMUpdateMappingTemplate    StoreOp = "scim.UpdateMappingTemplate"
	StoreSCIMDeleteMapping            StoreOp = "scim.DeleteMapping"
	StoreSCIMDeleteMappingsForBinding StoreOp = "scim.DeleteMappingsForBinding"

	StoreSCIMCreateUser            StoreOp = "scim.CreateUser"
	StoreSCIMUser                  StoreOp = "scim.User"
	StoreSCIMUserByUserName        StoreOp = "scim.UserByUserName"
	StoreSCIMUsersByExternalID     StoreOp = "scim.UsersByExternalID"
	StoreSCIMPageUsers             StoreOp = "scim.PageUsers"
	StoreSCIMUserBySubject         StoreOp = "scim.UserBySubject"
	StoreSCIMUserByAccount         StoreOp = "scim.UserByAccount"
	StoreSCIMUsers                 StoreOp = "scim.Users"
	StoreSCIMUpdateUser            StoreOp = "scim.UpdateUser"
	StoreSCIMDeleteUser            StoreOp = "scim.DeleteUser"
	StoreSCIMDeleteUsersForBinding StoreOp = "scim.DeleteUsersForBinding"

	StoreSCIMCreateGroup            StoreOp = "scim.CreateGroup"
	StoreSCIMGroup                  StoreOp = "scim.Group"
	StoreSCIMGroupsByDisplayName    StoreOp = "scim.GroupsByDisplayName"
	StoreSCIMGroupsByExternalID     StoreOp = "scim.GroupsByExternalID"
	StoreSCIMPageGroups             StoreOp = "scim.PageGroups"
	StoreSCIMGroups                 StoreOp = "scim.Groups"
	StoreSCIMUpdateGroup            StoreOp = "scim.UpdateGroup"
	StoreSCIMDeleteGroup            StoreOp = "scim.DeleteGroup"
	StoreSCIMDeleteGroupsForBinding StoreOp = "scim.DeleteGroupsForBinding"

	StoreSCIMAddGroupMember               StoreOp = "scim.AddGroupMember"
	StoreSCIMGroupMembers                 StoreOp = "scim.GroupMembers"
	StoreSCIMMembershipsForUser           StoreOp = "scim.MembershipsForUser"
	StoreSCIMRemoveGroupMember            StoreOp = "scim.RemoveGroupMember"
	StoreSCIMClearGroupMembers            StoreOp = "scim.ClearGroupMembers"
	StoreSCIMRemoveMembershipsForUser     StoreOp = "scim.RemoveMembershipsForUser"
	StoreSCIMDeleteGroupMembersForBinding StoreOp = "scim.DeleteGroupMembersForBinding"

	StoreSCIMEnterAttention            StoreOp = "scim.EnterAttention"
	StoreSCIMAttention                 StoreOp = "scim.Attention"
	StoreSCIMClearAttention            StoreOp = "scim.ClearAttention"
	StoreSCIMDeleteAttentionForBinding StoreOp = "scim.DeleteAttentionForBinding"
)

// readOnlyStoreOps pins which store operations mutate nothing — the
// machine-checked half of the `audited: none` permit rule (audit-model ADR
// CI invariant 2): an operation may skip audit mapping only when every store
// op it can invoke is in this set. A wrongly listed op is caught by review
// of this pinned table, exactly like the formula pins.
var readOnlyStoreOps = map[StoreOp]bool{
	StoreOrgsGet:             true,
	StoreOrgsList:            true,
	StoreOrgsCount:           true,
	StoreProjectsGet:         true,
	StoreProjectsList:        true,
	StoreProjectsListAll:     true,
	StoreRemotesList:         true,
	StoreRemotesGet:          true,
	StoreRemotesGetByName:    true,
	StoreRemotesCount:        true,
	StoreRemoteSnapshotsList: true,
	StoreRemoteSnapshotsGet:  true,
	// StoreRemotesSealed is deliberately ABSENT even though it mutates
	// nothing. This set's only job is to license `audited: none`, and reading a
	// stored credential is not something an unaudited operation may do — the
	// fetch that presents it rides remote.list/show, which carry their own
	// events.
	StoreEnvironmentsGet:                   true,
	StoreEnvironmentsList:                  true,
	StoreEnvironmentsCount:                 true,
	StoreEnvironmentsNextOrder:             true,
	StoreFoldersGet:                        true,
	StoreFoldersList:                       true,
	StoreEnvironmentsGetSettings:           true,
	StoreCatalogueGet:                      true,
	StoreCatalogueList:                     true,
	StoreCatalogueCount:                    true,
	StoreCatalogueGroupGet:                 true,
	StoreCatalogueGroupList:                true,
	StoreCatalogueGroupCount:               true,
	StoreCataloguePresenceList:             true,
	StoreCatalogueRevisionGet:              true,
	StoreKeysActiveMasterWrappers:          true,
	StoreKeysActiveTier3:                   true,
	StoreAuditTenantPage:                   true,
	StoreAuditInstancePage:                 true,
	StoreValuesGet:                         true,
	StoreValuesList:                        true,
	StoreValuesEnvironmentsWithValue:       true,
	StorePendingListForOwner:               true,
	StorePendingListMarkers:                true,
	StoreSnapshotsLatest:                   true,
	StoreSnapshotsAtRevision:               true,
	StoreSnapshotsList:                     true,
	StoreSnapshotsEntries:                  true,
	StoreSnapshotsSecretValueOccurrenceIDs: true,
	StoreSnapshotsChanges:                  true,
	StorePinsGetForWorkload:                true,
	StorePinsList:                          true,
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
	// invariant permits it only for tenant-class, non-empty read-only formulas,
	// non-mutating operations, and refuses it everywhere else.
	events      []audit.EventType
	auditedNone bool

	// humanOnly marks an operation on the api-cli-surface ADR's HUMAN-ONLY
	// list: `adopt`, `scaffold`, `values import`, `login`, and — under the
	// import ADR's declared amendment — `import`. A machine principal is
	// refused, after the grant check, exactly like an inadequate assurance is.
	//
	// It lives on the registry row rather than in a service-layer `if` for the
	// reason every other authorization property does: the chokepoint is the one
	// place the decision cannot diverge from the grant table, and a hand-rolled
	// check in one handler is a check the next handler forgets.
	humanOnly bool
}

// HumanOnly reports whether an operation refuses machine principals. Exported
// for the isolation harness, which asserts the list rather than restating it.
func HumanOnly(op Operation) bool { return operations[op].humanOnly }

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
			StoreValuesClearEnvironment:    true,
			StorePendingDiscardEnvironment: true, StoreSnapshotsDeleteEnvironment: true,
			StorePinsDeleteEnvironment: true,
			StoreEnvironmentsDelete:    true, StoreAuditTenantInsert: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueCount: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGet: true, StoreCatalogueRename: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGet: true, StoreCatalogueList: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGet: true, StoreCatalogueGroupGet: true,
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
			// Deleting a key collects every draft that referenced it.
			StorePendingDiscardKey: true,
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGet: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGet: true,
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

	// Phase 1's read. HUMAN-ONLY: `import` joins `adopt`, `scaffold`,
	// `values import` and `login` on the human-only list, so a machine
	// credential is refused here rather than being allowed to author a
	// migration's artifacts.
	OpImportPresence: {
		class: ClassTenant,
		level: domain.LevelEnv,
		// The import ADR's split formula is project-scoped structure read ∧
		// read(E) per consulted environment. Grants inherit downward, so
		// read@project subsumes read@environment on the same chain — the env
		// conjunct is never independently deniable and the registry carries
		// the minimal equivalent: read@project alone. An environment-only
		// reader still fails it, which is what keeps the response's
		// project-schema facts (declared types, catalogue revision, token
		// movement) off the environment-scoped read surface.
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelProject},
		},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList: true, StoreValuesList: true,
			// The catalogue revision is the definitions revision the run
			// manifest pins: phase 2 refuses a run whose declarations moved.
			StoreCatalogueRevisionGet: true,
		},
		humanOnly:   true,
		auditedNone: true,
	},
	// Phase 2's write. Same formula as `value.set`, same store surface, plus
	// the catalogue revision the precondition compares. Human-only and strict.
	OpValueImport: {
		class: ClassTenant,
		level: domain.LevelEnv,
		// read@project on top of value.set's formula: strict import's response
		// (imported / skipped / rejected-by-name) is a presence-and-catalogue
		// read even without a manifest, and presence is read-gated everywhere
		// else — a write-only editor (edit ∧ publish, no read) must not be
		// able to enumerate declarations or set/absent state by probing the
		// import verb. Write-only rotation keeps `values set`, which answers
		// nothing about prior state.
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelProject},
			{Cap: domain.CapEdit, At: domain.LevelEnv},
			{Cap: domain.CapPublish, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreCatalogueRevisionGet: true,
			StoreValuesList: true, StoreValuesPut: true,
			StoreAuditTenantInsert: true,
		},
		humanOnly: true,
		// The writes land as ordinary value writes, so they emit the ordinary
		// event: a trail that spelled an imported write differently would make
		// "which principal set this value" answerable only by knowing how it
		// arrived. The import as a RUN is recorded by its own event beside it.
		events: []audit.EventType{audit.EventValueSet, audit.EventValueImported},
	},

	// DRAFTS AND PUBLISHING (#51).
	//
	// `edit` ALONE stages. The permission ADR is explicit that `edit` confers
	// no delivery power and that a draft is never a disclosure, so staging must
	// not require `publish` -- edit-without-publish IS the propose-and-review
	// flow v1 ships instead of an approval engine.
	OpValueStage: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapEdit, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreValuesGet: true, StoreSnapshotsLatest: true,
			StorePendingStage: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueStaged},
	},
	// `publish` alone commits. It reaches everything a materialization touches
	// because it IS the materialization: the published cells, the immutable
	// snapshot, its entries, its lineage, and the drafts it consumes.
	OpValuePublish: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapPublish, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreCatalogueRevisionGet: true,
			StoreValuesList: true, StoreValuesPut: true, StoreValuesClear: true,
			StorePendingListForOwner: true, StorePendingListMarkers: true,
			StorePendingDiscard:  true,
			StoreSnapshotsLatest: true, StoreSnapshotsEntries: true,
			StoreSnapshotsInsert: true, StoreSnapshotsInsertEntry: true,
			StoreSnapshotsSecretValueOccurrenceIDs:    true,
			StoreSnapshotsRecordSecretValueOccurrence: true,
			StoreSnapshotsInsertChange:                true,
			StoreAuditTenantInsert:                    true,
		},
		events: []audit.EventType{
			audit.EventRevisionPublished,
			// The per-key delivery facts: a publish is where a cell starts and
			// stops delivering, so the two transition events are emitted here.
			audit.EventValueSet, audit.EventValueCleared,
		},
	},
	// The export triple. `read` alone exports `config` plaintext and `secret`
	// write-presence; the reveal legs are evaluated only where the material
	// they govern is actually present.
	OpValueExport: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreSnapshotsLatest: true, StoreSnapshotsAtRevision: true,
			StoreSnapshotsEntries: true,
		},
		auditedNone: true,
	},
	OpValueExportReveal: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelEnv},
			{Cap: domain.CapReveal, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreSnapshotsLatest: true, StoreSnapshotsAtRevision: true,
			StoreSnapshotsEntries: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueRevealed},
	},
	OpValueExportRevealHistory: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelEnv},
			{Cap: domain.CapRevealHistory, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreSnapshotsLatest: true, StoreSnapshotsAtRevision: true,
			StoreSnapshotsEntries: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventValueRevealed},
	},
	// History is lineage: numbers, publishers, timestamps and which keys moved.
	// It never carries a value, so it rides `read` like any other browse verb.
	// `rotate-token-key` is instance-class: the root token key belongs to the
	// instance, not to a tenant, so there is no tenant object whose
	// nonexistence a refusal could mimic.
	OpRotateTokenKey: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapRotateDEK, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{
			StoreKeysRotateTokenKey:  true,
			StoreAuditInstanceInsert: true,
		},
		events: []audit.EventType{audit.EventTokenKeyRotated},
	},
	OpRevisionList: {
		class:       ClassTenant,
		level:       domain.LevelEnv,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps:    map[StoreOp]bool{StoreSnapshotsList: true, StoreSnapshotsChanges: true},
		auditedNone: true,
	},
	// `revision show` returns the change token, which is NON-SECRET metadata by
	// construction: keyed, un-invertible, and designed to travel in pod
	// annotations. It is not a reveal, and gating it on one would make the
	// operator's own change-detection value harder to read than the annotation
	// it lands in.
	OpRevisionShow: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreSnapshotsLatest: true, StoreSnapshotsAtRevision: true,
			StoreSnapshotsEntries: true, StoreSnapshotsChanges: true,
		},
		auditedNone: true,
	},
	// The matrix signals, and the advisory channel's documented polling
	// fallback. Both signals degrade to write-presence for `secret` keys, which
	// is what `read` already covers.
	OpRevisionSignals: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreCatalogueList: true, StorePendingListMarkers: true,
			StoreSnapshotsLatest: true, StoreSnapshotsChanges: true,
		},
		auditedNone: true,
	},
	OpRevisionRestore: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapEdit, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCatalogueRevisionGet: true,
			StoreValuesList:           true, StoreSnapshotsLatest: true,
			StoreSnapshotsAtRevision: true, StoreSnapshotsEntries: true,
			StoreSnapshotsSecretValueOccurrenceIDs: true,
			StorePendingListForOwner:               true, StorePendingListMarkers: true,
			StorePendingStage: true, StoreAuditTenantInsert: true,
		},
		humanOnly: true,
		events: []audit.EventType{
			audit.EventValueStaged, audit.EventRevisionRestoreStaged, audit.EventValueRevealed,
		},
	},
	OpRevisionRestoreHistory: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelEnv},
			{Cap: domain.CapRevealHistory, At: domain.LevelEnv},
		},
		storeOps:  map[StoreOp]bool{},
		humanOnly: true,
		events:    []audit.EventType{audit.EventValueStaged, audit.EventRevisionRestoreStaged},
	},
	OpRevisionRestoreCurrent: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapRead, At: domain.LevelEnv},
			{Cap: domain.CapReveal, At: domain.LevelEnv},
		},
		storeOps:  map[StoreOp]bool{},
		humanOnly: true,
		events:    []audit.EventType{audit.EventValueStaged, audit.EventRevisionRestoreStaged},
	},
	OpPinSet: {
		class: ClassTenant,
		level: domain.LevelEnv,
		formula: Formula{
			{Cap: domain.CapPin, At: domain.LevelEnv},
			{Cap: domain.CapPublish, At: domain.LevelEnv},
		},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StoreCatalogueList: true,
			StoreCataloguePresenceList: true, StoreSnapshotsLatest: true,
			StoreSnapshotsAtRevision: true, StoreSnapshotsEntries: true,
			StoreSnapshotsSecretValueOccurrenceIDs: true,
			StorePinsGetForWorkload:                true, StorePinsCountProject: true,
			StorePinsInsert: true, StorePinsDelete: true, StoreAuditTenantInsert: true,
		},
		humanOnly: true,
		events: []audit.EventType{
			audit.EventPinCreated, audit.EventPinReassigned, audit.EventPinRenewed,
			audit.EventPinExpiryRefused, audit.EventValueRevealed,
		},
	},
	OpPinSetHistory: {
		class:     ClassTenant,
		level:     domain.LevelEnv,
		formula:   Formula{{Cap: domain.CapRevealHistory, At: domain.LevelEnv}},
		storeOps:  map[StoreOp]bool{},
		humanOnly: true,
		events: []audit.EventType{
			audit.EventPinCreated, audit.EventPinReassigned, audit.EventPinRenewed,
		},
	},
	OpPinList: {
		class:       ClassTenant,
		level:       domain.LevelEnv,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps:    map[StoreOp]bool{StorePinsList: true},
		humanOnly:   true,
		auditedNone: true,
	},
	OpPinRelease: {
		class:   ClassTenant,
		level:   domain.LevelEnv,
		formula: Formula{{Cap: domain.CapPin, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{
			StoreProjectsLock: true, StorePinsGetForWorkload: true, StorePinsDelete: true,
			StoreAuditTenantInsert: true,
		},
		humanOnly: true,
		events:    []audit.EventType{audit.EventPinReleased},
	},
	// The advisory channel touches no store operation at all: the events are
	// metadata the server already emitted, and every one of them is authorized
	// here before it is written to a stream.
	OpAdvisoryWatch: {
		class:       ClassTenant,
		level:       domain.LevelProject,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps:    map[StoreOp]bool{},
		auditedNone: true,
	},
	OpAdvisoryEvent: {
		class:       ClassTenant,
		level:       domain.LevelEnv,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps:    map[StoreOp]bool{},
		auditedNone: true,
	},

	OpKeyGroupCreate: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapDefinitionsEdit, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGroupCount: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGroupGet: true,
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
			// The semantic schema fan-out enumerates the project's
			// environments; each one is then authorized for `publish`
			// separately, immediately before commit.
			StoreEnvironmentsList: true,
			StoreProjectsLock:     true, StoreCatalogueGroupGet: true,
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
		storeOps: withCure(map[StoreOp]bool{StoreAuditTenantInsert: true}),
		// §2.4's deterministic cure runs inside this transaction, so its
		// events are reachable from this operation.
		events: append([]audit.EventType{
			audit.EventGrantCreated, audit.EventGrantModified,
		}, grantCureEvents...),
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
		// §2.4's deterministic cure runs inside this transaction; an
		// INSTANCE-scope `manage-members` grant cures every org at once.
		events: append([]audit.EventType{
			audit.EventGrantCreated, audit.EventGrantModified,
		}, grantCureEvents...),
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
		storeOps: withCure(map[StoreOp]bool{StoreAuditTenantInsert: true}),
		// §2.4's deterministic cure runs inside this transaction, so its
		// events are reachable from this operation.
		events: append([]audit.EventType{
			audit.EventGrantTemplateApplied, audit.EventGrantCreated, audit.EventGrantModified,
		}, grantCureEvents...),
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
		// §2.4's deterministic cure runs inside this transaction; an
		// INSTANCE-scope `manage-members` grant cures every org at once.
		events: append([]audit.EventType{
			audit.EventGrantTemplateApplied, audit.EventGrantCreated, audit.EventGrantModified,
		}, grantCureEvents...),
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
	OpOrgRetentionRead: {
		class:       ClassTenant,
		level:       domain.LevelOrg,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelOrg}},
		storeOps:    map[StoreOp]bool{StoreOrgsGet: true},
		auditedNone: true,
	},
	OpOrgRetentionUpdate: {
		class:   ClassTenant,
		level:   domain.LevelOrg,
		formula: Formula{{Cap: domain.CapProjectSettings, At: domain.LevelOrg}},
		storeOps: map[StoreOp]bool{
			StoreOrgsGet: true, StoreOrgsLock: true, StoreOrgsSetRetention: true, StoreProjectsList: true,
			StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventOrgRetentionChanged},
	},
	OpProjectRetentionRead: {
		class:       ClassTenant,
		level:       domain.LevelProject,
		formula:     Formula{{Cap: domain.CapRead, At: domain.LevelProject}},
		storeOps:    map[StoreOp]bool{StoreOrgsGet: true, StoreProjectsGet: true},
		auditedNone: true,
	},
	OpProjectRetentionUpdate: {
		class:   ClassTenant,
		level:   domain.LevelProject,
		formula: Formula{{Cap: domain.CapProjectSettings, At: domain.LevelProject}},
		storeOps: map[StoreOp]bool{
			StoreOrgsGet: true, StoreOrgsLock: true, StoreProjectsGet: true,
			StoreProjectsSetRetention: true, StoreAuditTenantInsert: true,
		},
		events: []audit.EventType{audit.EventProjectRetentionChanged},
	},
	OpRetentionHealthRead: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{
			StoreRetentionLastSuccess: true,
			StoreAuditInstanceInsert:  true,
		},
		events: []audit.EventType{audit.EventRetentionHealthRead},
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
			StoreSnapshotsLatest: true, StoreSnapshotsEntries: true,
			StoreSnapshotsAtRevision: true, StorePinsGetForWorkload: true,
			StoreCatalogueList:         true,
			StoreCataloguePresenceList: true,
			StoreCatalogueRevisionGet:  true,
			StoreAuditTenantInsert:     true,
		},
		events: []audit.EventType{audit.EventDeliveryFetched},
	},
	// --- SCIM provisioning (#73) ---------------------------------------------
	//
	// Every row below is ClassTenant at org depth: a binding a caller may not
	// reach answers byte-identically to one that is not there, which is what
	// keeps the mount from being a cross-org oracle.
	//
	// The store-op sets are COMPOSED from named groups rather than enumerated
	// per row. One SCIM operation touches a dozen store methods — the binding
	// read, the attention bookkeeping every path shares, the directory reads a
	// render needs — and enumerating them per row is how one row silently ends
	// up narrower than the code it authorizes, which shows up as a runtime
	// boundary refusal rather than a compile error.

	OpSCIMBindingCreate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimAttentionReadOps, map[StoreOp]bool{StoreSCIMCreateBinding: true}),
		events: []audit.EventType{
			audit.EventSCIMBindingCreated, audit.EventGrantCreated,
			audit.EventSCIMAttentionEntered,
		},
	},
	OpSCIMBindingGet: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimAttentionReadOps),
		events:   []audit.EventType{audit.EventSCIMAdminRead, audit.EventSCIMAttentionEntered, audit.EventSCIMAttentionCleared},
	},
	OpSCIMBindingList: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimAttentionReadOps, map[StoreOp]bool{StoreSCIMBindings: true}),
		events:   []audit.EventType{audit.EventSCIMAdminRead, audit.EventSCIMAttentionEntered, audit.EventSCIMAttentionCleared},
	},
	// The §6 state machine, in one transaction and in the ADR's order:
	// credentials dead, origins released, connection retired, directory and
	// mapping table gone, binding row gone. Identity links are untouched — they
	// are account property, exactly as they would be had the user been invited.
	OpSCIMBindingDelete: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimDirectoryOps, scimTeardownOps, scimCredentialOps),
		events: []audit.EventType{
			audit.EventSCIMBindingDeleted, audit.EventGrantRevoked, audit.EventGrantModified,
			audit.EventSCIMLockoutRetention, audit.EventSCIMAttentionEntered,
			audit.EventSCIMAttentionCleared,
		},
	},

	// Mapping authoring is where the blast-radius moment lives (§3): the same
	// transaction that shows the human the consequence language creates the
	// origins for every member the group ALREADY has.
	OpSCIMMappingCreate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimDirectoryOps, scimMappingWriteOps),
		events: []audit.EventType{
			audit.EventSCIMMappingCreated, audit.EventGrantCreated, audit.EventGrantModified,
			audit.EventSCIMLockoutRetentionReleased, audit.EventSCIMAttentionCleared,
		},
	},
	OpSCIMMappingUpdate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimDirectoryOps, scimMappingWriteOps),
		events: []audit.EventType{
			audit.EventSCIMMappingUpdated, audit.EventGrantCreated, audit.EventGrantModified,
			audit.EventGrantRevoked, audit.EventSCIMLockoutRetention,
			audit.EventSCIMLockoutRetentionReleased, audit.EventSCIMAttentionEntered,
			audit.EventSCIMAttentionCleared,
		},
	},
	OpSCIMMappingDelete: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimDirectoryOps, scimMappingWriteOps),
		events: []audit.EventType{
			audit.EventSCIMMappingDeleted, audit.EventGrantRevoked, audit.EventGrantModified,
			audit.EventSCIMLockoutRetention, audit.EventSCIMAttentionEntered,
			audit.EventSCIMAttentionCleared,
		},
	},
	OpSCIMMappingList: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, map[StoreOp]bool{StoreSCIMMappings: true}),
		events:   []audit.EventType{audit.EventSCIMAdminRead},
	},

	// Credential administration. The credential rows are class=authn and ride
	// the resolution surface after this gate — the same shape OIDC and SAML
	// provider administration take — so the store ops here are the binding read
	// and the attention bookkeeping, plus the audit write.
	OpSCIMCredentialMint: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimCredentialOps),
		events: []audit.EventType{
			audit.EventSCIMCredentialMinted, audit.EventSCIMCredentialRotated,
		},
	},
	OpSCIMCredentialGet: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimCredentialOps),
		events:   []audit.EventType{audit.EventSCIMAdminRead},
	},
	OpSCIMCredentialList: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimCredentialOps),
		events:   []audit.EventType{audit.EventSCIMAdminRead},
	},
	OpSCIMCredentialRevoke: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimCredentialOps),
		events:   []audit.EventType{audit.EventSCIMCredentialRevoked},
	},

	OpSCIMDirectoryUsers: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimDirectoryOps),
		events:   []audit.EventType{audit.EventSCIMAdminRead},
	},
	OpSCIMDirectoryGroups: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimAdminFormula,
		storeOps: scimOps(scimBase, scimDirectoryOps),
		events:   []audit.EventType{audit.EventSCIMAdminRead},
	},

	// --- the wire ------------------------------------------------------------

	OpSCIMUserCreate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimUserWriteOps),
		events: []audit.EventType{
			audit.EventSCIMUserProvisioned, audit.EventGrantCreated, audit.EventGrantModified,
			audit.EventSCIMAttentionCleared,
		},
	},
	OpSCIMUserGet: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps),
		events:   []audit.EventType{audit.EventSCIMDirectoryRead, audit.EventSCIMAttentionCleared},
	},
	OpSCIMUserList: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps),
		events:   []audit.EventType{audit.EventSCIMDirectoryRead, audit.EventSCIMAttentionCleared},
	},
	OpSCIMUserReplace: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimUserWriteOps),
		events:   scimUserMutationEvents,
	},
	OpSCIMUserPatch: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimUserWriteOps),
		events:   scimUserMutationEvents,
	},
	OpSCIMUserDelete: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimUserWriteOps),
		events: []audit.EventType{
			audit.EventSCIMUserDeleted, audit.EventGrantRevoked, audit.EventGrantModified,
			audit.EventSCIMLockoutRetention, audit.EventSCIMAttentionEntered,
			audit.EventSCIMAttentionCleared,
		},
	},

	OpSCIMGroupCreate: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimGroupWriteOps),
		events: []audit.EventType{
			audit.EventSCIMGroupCreated, audit.EventSCIMGroupMembership,
			audit.EventGrantCreated, audit.EventGrantModified, audit.EventSCIMAttentionCleared,
		},
	},
	OpSCIMGroupGet: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps),
		events:   []audit.EventType{audit.EventSCIMDirectoryRead, audit.EventSCIMAttentionCleared},
	},
	OpSCIMGroupList: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps),
		events:   []audit.EventType{audit.EventSCIMDirectoryRead, audit.EventSCIMAttentionCleared},
	},
	OpSCIMGroupReplace: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimGroupWriteOps),
		events:   scimGroupMutationEvents,
	},
	OpSCIMGroupPatch: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimGroupWriteOps),
		events:   scimGroupMutationEvents,
	},
	OpSCIMGroupDelete: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase, scimDirectoryOps, scimGroupWriteOps, scimMappingWriteOps),
		events: []audit.EventType{
			audit.EventSCIMGroupDeleted, audit.EventSCIMGroupMembership,
			audit.EventGrantRevoked, audit.EventGrantModified,
			audit.EventSCIMLockoutRetention, audit.EventSCIMAttentionEntered,
			audit.EventSCIMAttentionCleared,
		},
	},

	// Discovery carries no tenant data, but it is neither unaudited nor
	// unauthenticated: it runs under the binding's credential and its read is
	// recorded with `resource_type: discovery`, which is the explicit registry
	// annotation the ADR asks for instead of silence.
	OpSCIMUnsupported: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimOps(scimBase, scimWireBase),
		events:   []audit.EventType{audit.EventSCIMDirectoryRead, audit.EventSCIMAttentionCleared},
	},
	// Discovery is the ONE SCIM operation that emits nothing (ADR §10): the
	// three documents are static protocol documentation carrying no tenant data,
	// so a `scim.directory_read` per probe would record the server's own manual
	// being read. It cannot take `auditedNone` — the default-deny permit rule
	// admits only bare-`read` non-mutating operations, and this one authenticates
	// a provisioning credential and records contact — so the ADR's "explicit
	// registry annotation on their probe class, not silence" is the name-pinned
	// exemption entry: one for this operation and one per discovery route, each
	// carrying its reason, each failing the build if removed without a mapping.
	OpSCIMDiscovery: {
		class:    ClassTenant,
		level:    domain.LevelOrg,
		formula:  scimWireFormula,
		storeOps: scimDiscoveryOps(),
	},
	// The serving side of the directory tier (#71). The formula is bare
	// `instance-directory` at instance scope, evaluated on the CONNECTION
	// PRINCIPAL's own grant — the viewing instance's grants confer nothing
	// here, and the human on the other side is not a party to this call at all.
	//
	// One event per authenticated serve, in the access retention class: it is
	// the machine-fetch stream shape, not a security event, and giving it
	// security retention would bury the trail it shares with fetch traffic.
	OpRemoteDirectoryServe: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceDirector, At: domain.LevelNone}},
		// The listing is org and project NAMES and counts, so it reads both
		// instance-scoped enumerations. Counts are len() of what it already
		// read - a separate COUNT query would be a second read of the same
		// fact that could disagree with the names beside it.
		storeOps: map[StoreOp]bool{
			StoreOrgsList:            true,
			StoreProjectsListAll:     true,
			StoreAuditInstanceInsert: true,
		},
		events: []audit.EventType{audit.EventRemoteDirectoryServed},
	},

	// The viewing side. `instance-config` for custody, `instance-directory`
	// for the reads — the ADR's split, following the audit ADR's precedent
	// that reading is power and is never bundled.
	//
	// Both READS carry two events, not one: the directory view itself and, per
	// failing remote, a named fetch failure. They are on the same operation
	// because the fetch happens BECAUSE of the view — a successful fetch is
	// not separately evented, and a failing one is, precisely because the
	// operator's fix differs per outcome.
	OpRemoteAdd: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		// The list and snapshot reads are here because DUPLICATE-IDENTITY
		// REFUSAL needs them: an add must know which instance identities the
		// existing entries already name, or the ADR's "same identity from two
		// entries" case is undetectable at the moment it can still be refused.
		storeOps: map[StoreOp]bool{
			StoreRemotesCount:         true,
			StoreRemotesList:          true,
			StoreRemoteSnapshotsList:  true,
			StoreRemotesCreate:        true,
			StoreRemoteSnapshotsWrite: true,
			StoreAuditInstanceInsert:  true,
		},
		events: []audit.EventType{audit.EventRemoteAdded},
	},
	OpRemoteList: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceDirector, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{
			StoreRemotesList:          true,
			StoreRemotesSealed:        true,
			StoreRemoteSnapshotsList:  true,
			StoreRemoteSnapshotsWrite: true,
			StoreRemoteSnapshotsFail:  true,
			StoreAuditInstanceInsert:  true,
		},
		events: []audit.EventType{audit.EventRemoteDirectoryViewed, audit.EventRemoteFetchFailed},
	},
	OpRemoteShow: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceDirector, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{
			StoreRemotesGet:           true,
			StoreRemotesGetByName:     true,
			StoreRemotesSealed:        true,
			StoreRemoteSnapshotsGet:   true,
			StoreRemoteSnapshotsWrite: true,
			StoreRemoteSnapshotsFail:  true,
			StoreAuditInstanceInsert:  true,
		},
		events: []audit.EventType{audit.EventRemoteDirectoryViewed, audit.EventRemoteFetchFailed},
	},
	OpRemoteRename: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{
			StoreRemotesGet:          true,
			StoreRemotesGetByName:    true,
			StoreRemotesRename:       true,
			StoreRemoteSnapshotsGet:  true,
			StoreAuditInstanceInsert: true,
		},
		events: []audit.EventType{audit.EventRemoteRenamed},
	},
	OpRemoteRemove: {
		class:   ClassInstance,
		formula: Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{
			StoreRemotesGet:          true,
			StoreRemotesGetByName:    true,
			StoreRemotesDelete:       true,
			StoreAuditInstanceInsert: true,
		},
		events: []audit.EventType{audit.EventRemoteRemoved},
	},

	// The serving side. The connection principal and its credential live on
	// the resolution surface (they decide WHO a caller is), so these
	// operations touch no proof-gated store method except the audit insert —
	// the authorization still happens here, at the chokepoint, before the
	// resolution-surface write runs.
	OpRemoteCredentialCreate: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventRemoteCredentialMinted},
	},
	// Not `audited: none`: the permit rule admits only tenant-class bare-read
	// operations, and reading which foreign installations may read this one's
	// directory is not that.
	OpRemoteCredentialList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventRemoteCredentialsListed},
	},
	OpRemoteCredentialShow: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventRemoteCredentialsListed},
	},
	OpRemoteCredentialRevoke: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventRemoteCredentialRevoked},
	},

	// The origin allowlist. Removal additionally revokes every workspace
	// session bound to the origin, in the SAME transaction — which is why the
	// remove operation carries the session-revoked event too.
	OpWorkspaceOriginList: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventRemoteOriginAllowlistRead},
	},
	OpWorkspaceOriginAdd: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events:   []audit.EventType{audit.EventRemoteOriginAllowlistChanged},
	},
	OpWorkspaceOriginRemove: {
		class:    ClassInstance,
		formula:  Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}},
		storeOps: map[StoreOp]bool{StoreAuditInstanceInsert: true},
		events: []audit.EventType{
			audit.EventRemoteOriginAllowlistChanged,
			audit.EventRemoteWorkspaceSessionRevoked,
		},
	},
}

// scimAdminFormula is `manage-members` AT ORG SCOPE EXACTLY (ADR §1). The atom
// sits at LevelOrg rather than at `manage-members`' own deepest level because
// a project-scope member manager must not reach the SCIM surface: a mapping row
// causes grants its author need not hold, which is an org/instance power.
var scimAdminFormula = Formula{{Cap: domain.CapManageMembers, At: domain.LevelOrg}}

// scimWireFormula is the machine-only atom the provisioning connection holds
// structurally. No human session can hold it (the grant API refuses it by
// name), and no other principal class may (the normative allowlist has one row).
var scimWireFormula = Formula{{Cap: domain.CapSCIMProvision, At: domain.LevelOrg}}

// grantCureEvents are the events §2.4's DETERMINISTIC CURE emits from inside
// whatever transaction created a `manage-members` grant. A grant writer is the
// only thing that can cure a lockout retention, so these ride every grant
// operation that can create one — and without them the audit write boundary
// (VerifyEvent binds event type to the minting operation) refuses the cure's
// own record, failing the very transaction §2.4 requires to succeed.
var grantCureEvents = []audit.EventType{
	audit.EventSCIMLockoutRetentionReleased,
	audit.EventSCIMAttentionCleared,
	audit.EventGrantRevoked,
}

// grantCureStoreOps is the cure's OTHER reach: it clears the binding's
// `lockout_retention` attention row through the audited exit path, in the same
// transaction, so a warning cannot outlive the retention it describes.
var grantCureStoreOps = map[StoreOp]bool{
	StoreSCIMAttention:      true,
	StoreSCIMClearAttention: true,
}

func withCure(base map[StoreOp]bool) map[StoreOp]bool {
	out := make(map[StoreOp]bool, len(base)+len(grantCureStoreOps))
	for k := range base {
		out[k] = true
	}
	for k := range grantCureStoreOps {
		out[k] = true
	}
	return out
}

var scimUserMutationEvents = []audit.EventType{
	audit.EventSCIMUserUpdated, audit.EventSCIMUserDeprovisioned,
	audit.EventGrantCreated, audit.EventGrantModified, audit.EventGrantRevoked,
	audit.EventSCIMLockoutRetention, audit.EventSCIMAttentionEntered,
	audit.EventSCIMAttentionCleared,
}

// PUT and PATCH reach exactly the same state and therefore the same events:
// both apply desired state to one resource, and the transition table (§5.4) is
// written about the STATE they reach, never about which verb reached it.
var scimGroupMutationEvents = []audit.EventType{
	audit.EventSCIMGroupUpdated, audit.EventSCIMGroupMembership,
	audit.EventGrantCreated, audit.EventGrantModified, audit.EventGrantRevoked,
	audit.EventSCIMLockoutRetention, audit.EventSCIMLockoutRetentionReleased,
	audit.EventSCIMAttentionEntered, audit.EventSCIMAttentionCleared,
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
	SiteScheduler         SystemSite = "scheduler"
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
	SiteScheduler: {
		StoreRetentionEligible: true, StoreRetentionMarkCollected: true,
		StoreRetentionDeleteEntries: true, StoreRetentionLastSuccess: true,
		StoreRetentionSetLastSuccess: true, StoreAuditTenantInsert: true,
		StoreAuditInstanceInsert: true,
	},
}

var systemSiteEvents = map[SystemSite][]audit.EventType{
	SiteScheduler: {
		audit.EventRetentionPayloadGC,
		audit.EventRetentionPruneRun,
	},
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

// SystemSiteEvents returns the event types each no-principal mint site may
// emit. Keeping this visible to the audit closure invariant prevents a system
// event from becoming dead catalogue merely because it has no human operation.
func (RegistryFacts) SystemSiteEvents() map[SystemSite][]audit.EventType {
	out := make(map[SystemSite][]audit.EventType, len(systemSiteEvents))
	for site, events := range systemSiteEvents {
		out[site] = append([]audit.EventType(nil), events...)
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

// scimOps unions the named store-op groups one SCIM operation reaches. The
// audit write is in every set because every SCIM operation is audited: the ADR
// permits no `audited: none` here, and the discovery endpoints are annotated
// rather than silent.
func scimOps(groups ...map[StoreOp]bool) map[StoreOp]bool {
	out := map[StoreOp]bool{StoreAuditTenantInsert: true}
	for _, g := range groups {
		for op := range g {
			out[op] = true
		}
	}
	return out
}

// scimCredentialOps is the administration surface's credential access.
var scimCredentialOps = map[StoreOp]bool{
	StoreSCIMCreateCredential:            true,
	StoreSCIMCredential:                  true,
	StoreSCIMCredentials:                 true,
	StoreSCIMRevokeCredential:            true,
	StoreSCIMRevokeCredentialsForBinding: true,
	StoreSCIMDeleteCredentialsForBinding: true,
}

// scimBase is what EVERY SCIM operation touches: the binding read that proves
// the addressed binding is this org's, plus the attention bookkeeping that
// keeps §9's states honest in both directions.
var scimBase = map[StoreOp]bool{
	StoreSCIMLockBinding:    true,
	StoreSCIMBinding:        true,
	StoreSCIMAttention:      true,
	StoreSCIMEnterAttention: true,
	StoreSCIMClearAttention: true,
}

// scimAttentionReadOps is what refreshBindingAttention reads on every
// administration view of a binding: the credential set, so §9.1's post-restore
// state can be raised from the one observable trace a restore leaves (every
// credential minted under an older instance epoch), and nothing else.
var scimAttentionReadOps = map[StoreOp]bool{StoreSCIMCredentials: true}

// scimWireBase is what every WIRE operation additionally touches: the
// last-contact record that makes the staleness warning mean something.
var scimWireBase = map[StoreOp]bool{StoreSCIMTouchBinding: true}

// scimDiscoveryOps is the discovery probe's whole store surface, declared apart
// from scimOps because it is the one SCIM operation that inserts no audit row:
// the binding read that proves the addressed binding is this org's, and the
// contact record that makes staleness mean something. No attention write, no
// directory read, no audit insert.
func scimDiscoveryOps() map[StoreOp]bool {
	return map[StoreOp]bool{StoreSCIMBinding: true, StoreSCIMTouchBinding: true}
}

// scimDirectoryOps is every directory READ. A render needs the resource, its
// memberships and the groups they name; a filter needs the lookup columns.
var scimDirectoryOps = map[StoreOp]bool{
	// The mapping surface's ancestry check (§1): a row naming a project outside
	// the binding's org is refused at authoring AND at every sync.
	StoreProjectsList:            true,
	StoreSCIMUser:                true,
	StoreSCIMUsers:               true,
	StoreSCIMUserByUserName:      true,
	StoreSCIMUsersByExternalID:   true,
	StoreSCIMPageUsers:           true,
	StoreSCIMUserBySubject:       true,
	StoreSCIMUserByAccount:       true,
	StoreSCIMGroup:               true,
	StoreSCIMGroups:              true,
	StoreSCIMGroupsByDisplayName: true,
	StoreSCIMGroupsByExternalID:  true,
	StoreSCIMPageGroups:          true,
	StoreSCIMGroupMembers:        true,
	StoreSCIMMembershipsForUser:  true,
	StoreSCIMMappings:            true,
	StoreSCIMMappingsForGroup:    true,
	StoreSCIMMapping:             true,
}

var scimUserWriteOps = map[StoreOp]bool{
	StoreSCIMCreateUser:               true,
	StoreSCIMUpdateUser:               true,
	StoreSCIMDeleteUser:               true,
	StoreSCIMRemoveMembershipsForUser: true,
}

var scimGroupWriteOps = map[StoreOp]bool{
	StoreSCIMCreateGroup:       true,
	StoreSCIMUpdateGroup:       true,
	StoreSCIMDeleteGroup:       true,
	StoreSCIMAddGroupMember:    true,
	StoreSCIMRemoveGroupMember: true,
	StoreSCIMClearGroupMembers: true,
}

var scimMappingWriteOps = map[StoreOp]bool{
	StoreSCIMCreateMapping:         true,
	StoreSCIMUpdateMappingTemplate: true,
	StoreSCIMDeleteMapping:         true,
	StoreSCIMSetMappingInert:       true,
}

// scimTeardownOps is §6's step-by-step demolition, which no other operation
// may reach: a binding's whole directory going away is a lifecycle act, not a
// side effect of editing it.
var scimTeardownOps = map[StoreOp]bool{
	StoreSCIMDeleteGroupMembersForBinding: true,
	StoreSCIMDeleteGroupsForBinding:       true,
	StoreSCIMDeleteUsersForBinding:        true,
	StoreSCIMDeleteMappingsForBinding:     true,
	StoreSCIMDeleteAttentionForBinding:    true,
	StoreSCIMDeleteBinding:                true,
	StoreSCIMRetireConnection:             true,
}
