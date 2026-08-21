package service

import "github.com/Hikyo-Org/hikyo/internal/authz"

// The §179 budget totality map: every authorization operation is classified as
// carrying a NAMED expensive-path category, the fail-closed DEFAULT (an
// expensive operation with no named category), or EXEMPT (not a §179 fan-out —
// its frequency is governed by the §10 authenticated-API budget, or a tighter
// mechanism named in the reason).
//
// This map is a LEDGER, not a dispatcher: the charge for a named or default
// operation happens at that operation's own service method (there is no
// once-per-operation post-authorization chokepoint — Authorize runs per-env and
// per-page). What the map buys is the build-time guarantee the ops-spec demands
// ("no path is unbudgeted by omission", §179): the conformance totality test
// fails the build unless EVERY registered operation appears here exactly once,
// so a new operation cannot be added without a deliberate budget decision. It is
// the same shape as the metrics-label grep and the keyword-allowlist diff — an
// omission is a red build, not a silent gap.

type budgetClass int

const (
	// budgetClassNamed: charged by a named §179 category at its service method
	// (export / publish / adapter sync / machine-fetch / schema-revision).
	budgetClassNamed budgetClass = iota
	// budgetClassDefaultExpensive: an expensive operation with no named category,
	// charged the §179 fail-closed default (budgetDefaultConc + budgetDefaultRate)
	// at its service method.
	budgetClassDefaultExpensive
	// budgetClassExempt: not a §179 expensive fan-out; the reason names what
	// governs its frequency instead.
	budgetClassExempt
)

type budgetClassification struct {
	class  budgetClass
	reason string
}

// operationBudgetClass classifies every authz operation. Exported for the
// conformance totality test via BudgetClassOf; never consulted at runtime.
var operationBudgetClass = buildBudgetClassification()

// BudgetClassOf reports an operation's classification and whether it is known.
// For the conformance totality test only.
func BudgetClassOf(op authz.Operation) (reason string, known bool) {
	c, ok := operationBudgetClass[op]
	return c.reason, ok
}

func buildBudgetClassification() map[authz.Operation]budgetClassification {
	m := map[authz.Operation]budgetClassification{}
	add := func(class budgetClass, reason string, ops ...authz.Operation) {
		for _, op := range ops {
			if _, dup := m[op]; dup {
				panic("service: operation classified twice in the budget totality map: " + string(op))
			}
			m[op] = budgetClassification{class, reason}
		}
	}

	// ---- NAMED §179 categories (charged at the owning service method) ----
	add(budgetClassNamed, "export §179: Audits.Export/InstanceExport (2/org·6/instance, 5/min·principal)",
		authz.OpAuditExportOrg, authz.OpAuditExportProject, authz.OpAuditExportEnv, authz.OpAuditInstanceExport)
	add(budgetClassNamed, "export §179: Revisions.Export (shares the export budget)",
		authz.OpValueExport, authz.OpValueExportReveal, authz.OpValueExportRevealHistory)
	add(budgetClassNamed, "publish §179: Revisions.PublishPlanned (4/org, 10/min·principal)",
		authz.OpValuePublish)
	add(budgetClassNamed, "adapter sync/trigger §179: SyncTarget + UpdateTarget enqueue (4/org, 10/min·principal)",
		authz.OpAdapterSync, authz.OpAdapterConfigure)
	add(budgetClassNamed, "machine-fetch §179: Delivery.FetchAs (300/min·org + 1000/min·instance)",
		authz.OpDeliveryFetch)
	add(budgetClassNamed, "schema-revision §151: chargeOnce before BumpSchemaRevision (60/h·project)",
		authz.OpKeyCreate, authz.OpKeyRename, authz.OpKeyUpdateDeclaration, authz.OpKeyUpdateMetadata,
		authz.OpKeySetGroup, authz.OpKeyDelete, authz.OpKeyReclassify,
		authz.OpKeyGroupCreate, authz.OpKeyGroupRename, authz.OpKeyGroupDelete,
		authz.OpEnvCreate, authz.OpEnvRename, authz.OpEnvDelete, authz.OpDefinitionsApply)

	// ---- DEFAULT-EXPENSIVE (charged budgetDefault at the owning service method) ----
	add(budgetClassDefaultExpensive, "crypto rewrap proportional to every stored/historical row",
		authz.OpReencryptProject, authz.OpReencryptInstance)
	add(budgetClassDefaultExpensive, "bulk value fan-out across environments/keys",
		authz.OpValueImport,
		authz.OpValueCopySource, authz.OpValueCopyDestination, authz.OpValueCopyDestinationConfig)
	add(budgetClassDefaultExpensive, "whole-project materialization / bulk offline flush",
		authz.OpDefinitionsExport, authz.OpDefinitionsCheck, authz.OpDeliveryReconcileOffline)
	add(budgetClassDefaultExpensive, "master-key rotation rewraps every project DEK (project-proportional)",
		authz.OpRotateMasterKey)

	// ---- EXEMPT ----
	add(budgetClassExempt, "SSE admission caps (§10, 4/32/128) own concurrency; per-event authz must not be budgeted",
		authz.OpAdvisoryWatch, authz.OpAdvisoryEvent)
	add(budgetClassExempt, "reveal ceremony + per-key gate limiter (GateAttemptsPerMinute) bound it",
		authz.OpValueReveal)
	add(budgetClassExempt, "paged audit read ≤1000/page (§2/§10)",
		authz.OpAuditQueryOrg, authz.OpAuditQueryProject, authz.OpAuditQueryEnv, authz.OpAuditInstanceQuery)
	add(budgetClassExempt, "outbox worker push; §12 outbox concurrency (1/target, 4/org) bounds it",
		authz.OpAdapterPush)
	add(budgetClassExempt, "O(1) key-hierarchy rotation (one DEK / the master / one token key); the row-proportional rework is the separately-budgeted reencrypt (OpReencrypt*). Master-key rotation, which rewraps every project DEK, is default-expensive above",
		authz.OpRotateDEK, authz.OpRotateRootKey,
		authz.OpRotateTokenKey, authz.OpRotateScanningKey)

	// The large remainder: single-row or paged CRUD/reads and admin config
	// mutations whose frequency is governed by the §10 authenticated-API budget
	// (300/min per session, burst 600). None is a per-value or per-environment
	// fan-out, so none earns the tighter §179 default.
	add(budgetClassExempt, "§10 authenticated API 300/min per session; single-row/paged CRUD, not a §179 fan-out",
		// orgs / projects / environments / folders (structure CRUD)
		authz.OpOrgCreate, authz.OpOrgGet, authz.OpOrgList, authz.OpOrgRename, authz.OpOrgDelete,
		authz.OpOrgRetentionRead, authz.OpOrgRetentionUpdate,
		authz.OpProjectCreate, authz.OpProjectGet, authz.OpProjectList, authz.OpProjectRename, authz.OpProjectDelete,
		authz.OpProjectRetentionRead, authz.OpProjectRetentionUpdate,
		authz.OpProjectMachineRevealGet, authz.OpProjectMachineRevealSet,
		authz.OpEnvRead, authz.OpEnvList, authz.OpEnvReorder, authz.OpEnvUpdateNote,
		authz.OpEnvSettingsRead, authz.OpEnvSettingsUpdate,
		authz.OpFolderCreate, authz.OpFolderGet, authz.OpFolderList, authz.OpFolderRename, authz.OpFolderDelete,
		// import presence/occurrence PREVIEW (Values.Occurrences); the bulk write
		// authorizes OpValueImport (default-expensive) which carries the charge
		authz.OpImportPresence,
		// key / key-group reads (the mutating ones are schema-revision above)
		authz.OpKeyGet, authz.OpKeyList, authz.OpKeyDeclassify, authz.OpKeySecretRuleChange,
		authz.OpKeyGroupGet, authz.OpKeyGroupList,
		// definitions (non-apply, non-export, non-check): single-plan writes and reads
		authz.OpDefinitionsPlanCreate, authz.OpDefinitionsPlanGet,
		authz.OpDefinitionsSettingsGet, authz.OpDefinitionsSettingsSet,
		// values (non-export, non-copy, non-import, non-publish): single-cell reads/writes
		authz.OpValueRead, authz.OpValueList, authz.OpValueSet, authz.OpValueClear,
		authz.OpValueStage, authz.OpValuePendingList, authz.OpRevealWindowRead,
		// revisions / pins: paged reads and single-revision restores
		authz.OpRevisionList, authz.OpRevisionShow, authz.OpRevisionSignals,
		authz.OpRevisionRestore, authz.OpRevisionRestoreHistory, authz.OpRevisionRestoreCurrent,
		authz.OpPinSet, authz.OpPinSetHistory, authz.OpPinList, authz.OpPinRelease,
		// grants
		authz.OpGrantCreateEnv, authz.OpGrantCreateProject, authz.OpGrantCreateOrg, authz.OpGrantCreateInstance,
		authz.OpGrantListProject, authz.OpGrantListOrg, authz.OpGrantListInstance,
		authz.OpGrantRevokeEnv, authz.OpGrantRevokeProject, authz.OpGrantRevokeOrg, authz.OpGrantRevokeInstance,
		// machine identities / credentials / bindings / service accounts
		authz.OpServiceAccountCreate, authz.OpServiceAccountList, authz.OpServiceAccountDelete,
		authz.OpCredentialMint, authz.OpCredentialList, authz.OpCredentialRevoke,
		authz.OpCredentialReset, authz.OpCredentialResetInstance,
		authz.OpCredentialPolicyRead, authz.OpCredentialPolicyUpdate,
		authz.OpBindingCreate,
		// federation issuers
		authz.OpFederationIssuerCreate, authz.OpFederationIssuerList,
		authz.OpFederationIssuerUpdate, authz.OpFederationIssuerDelete,
		// providers (OIDC)
		authz.OpProviderGet, authz.OpProviderList, authz.OpProviderPut, authz.OpProviderDelete,
		// SAML providers + SP keys
		authz.OpSAMLProviderGet, authz.OpSAMLProviderList, authz.OpSAMLProviderPut,
		authz.OpSAMLProviderPatch, authz.OpSAMLProviderDelete, authz.OpSAMLProviderRefreshMetadata,
		authz.OpSAMLSPKeyList, authz.OpSAMLSPKeyRotate, authz.OpSAMLSPKeyRetire, authz.OpSAMLSPKeyCompromiseRetire,
		// SCIM (provisioning bindings, credentials, mappings, and the provisioning verbs)
		authz.OpSCIMBindingCreate, authz.OpSCIMBindingGet, authz.OpSCIMBindingList, authz.OpSCIMBindingDelete,
		authz.OpSCIMCredentialMint, authz.OpSCIMCredentialGet, authz.OpSCIMCredentialList, authz.OpSCIMCredentialRevoke,
		authz.OpSCIMMappingCreate, authz.OpSCIMMappingList, authz.OpSCIMMappingUpdate, authz.OpSCIMMappingDelete,
		authz.OpSCIMUserCreate, authz.OpSCIMUserGet, authz.OpSCIMUserList, authz.OpSCIMUserPatch,
		authz.OpSCIMUserReplace, authz.OpSCIMUserDelete,
		authz.OpSCIMGroupCreate, authz.OpSCIMGroupGet, authz.OpSCIMGroupList, authz.OpSCIMGroupPatch,
		authz.OpSCIMGroupReplace, authz.OpSCIMGroupDelete,
		authz.OpSCIMDirectoryUsers, authz.OpSCIMDirectoryGroups, authz.OpSCIMDiscovery, authz.OpSCIMUnsupported,
		// remotes (multi-instance directory) + workspace origins
		authz.OpRemoteAdd, authz.OpRemoteList, authz.OpRemoteShow, authz.OpRemoteRename, authz.OpRemoteRemove,
		authz.OpRemoteDirectoryServe,
		authz.OpRemoteCredentialCreate, authz.OpRemoteCredentialList,
		authz.OpRemoteCredentialShow, authz.OpRemoteCredentialRevoke,
		authz.OpWorkspaceOriginAdd, authz.OpWorkspaceOriginList, authz.OpWorkspaceOriginRemove,
		// adapters: config / inspect / test / plan / adopt / delete / credential (non-sync)
		authz.OpAdapterAdopt, authz.OpAdapterDelete, authz.OpAdapterInspect, authz.OpAdapterPlan,
		authz.OpAdapterTest, authz.OpAdapterCredentialSet, authz.OpAdapterCredentialRevoke,
		// templates
		authz.OpTemplateApplyEnv, authz.OpTemplateApplyProject, authz.OpTemplateApplyOrg, authz.OpTemplateApplyInstance,
		// retention health read
		authz.OpRetentionHealthRead,
	)

	return m
}
