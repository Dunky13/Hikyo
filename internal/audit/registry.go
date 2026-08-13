package audit

import (
	"sort"
	"strings"
)

// EventType is one closed-registry entry, named category.action. An
// unregistered type cannot be written; an unvalidated payload cannot be
// written (CI invariant 1).
type EventType string

// The registered event types. This slice of the v1 catalogue covers every
// event today's operations emit: the audit trail's own events, the
// authorization denial, and scaffolding domain events for the walking
// skeleton's demonstration operations (their real catalogue rows land with
// the surfaces that replace them — #47/#48/#54/#55 — under the completeness
// invariant, which forces every newly registered operation to map here).
const (
	// grant.denied is the per-event authorization denial (#15's per-event
	// obligation; audit-model ADR § Denials). Resolvable denials land in the
	// tenant trail with the truthful resolved chain; unresolvable denials
	// land in the instance trail with the addressed identifiers preserved as
	// caller-asserted claims.
	EventGrantDenied EventType = "grant.denied"

	// audit.* — the trail watching itself (audit-model ADR § Storage and
	// export). One query event per trail query; INTENT/OUTCOME pair per
	// export.
	EventAuditQuery           EventType = "audit.query"
	EventAuditExportStarted   EventType = "audit.export_started"
	EventAuditExportCompleted EventType = "audit.export_completed"

	// auth.* — human authentication (#47, human-auth ADR § Propagations to
	// the audit ADR). Failures matter as much as successes, so every type
	// below licenses the failure outcome its path can produce.
	//
	// Note what these payloads deliberately do NOT carry: the presented
	// username. A human who types a password into the username field would
	// otherwise put it in a durable trail, which is the exact accident the
	// no-plaintext rule exists to prevent. Attribution is carried as the
	// resolved account id — definitively not a password, because it resolved
	// — plus a boolean saying whether resolution happened at all. Source IP
	// and user agent ride in the envelope, so incident response keeps the
	// signal it actually needs.
	EventAuthLogin  EventType = "auth.login"
	EventAuthLogout EventType = "auth.logout"
	// auth.session_created records the artifact minted and the assurance it
	// carries — the record the chokepoint will consult on every later request.
	EventAuthSessionCreated EventType = "auth.session_created"
	// auth.credential_authority_minted records a credential-establishment
	// authority coming into existence AND how it was delivered, because
	// delivery mode is the security property: a token that reached a log
	// shipper is a different event from one written to a root-owned file.
	EventAuthAuthorityMinted EventType = "auth.credential_authority_minted"
	// auth.credential_established is its consumption: exactly one initial
	// credential, atomically, and nothing more.
	EventAuthCredentialEstablished EventType = "auth.credential_established"
	// auth.credential_authority_refused covers failed presentation, expiry
	// and re-use — the ADR requires the failures, not just the successes.
	EventAuthAuthorityRefused EventType = "auth.credential_authority_refused"
	// auth.throttle_crossed fires when a per-account backoff threshold is
	// crossed, so a distributed attempt is visible rather than merely slowed.
	EventAuthThrottleCrossed EventType = "auth.throttle_crossed"

	// auth.* factor events (#54, human-auth ADR § Factors, § Account-security
	// mutations). Registering ANY of these is the tripwire that forces
	// authz.AssuranceEnforced to flip: a factor beyond a password now exists,
	// so the chokepoint must enforce the MFA-mandatory rule (see
	// isolation.TestAssuranceEnforcementCannotBeForgotten).
	//
	// auth.factor_enrolled / auth.factor_removed record a TOTP factor coming
	// into or out of existence, naming the credential class that authorized the
	// account-security mutation.
	EventAuthFactorEnrolled EventType = "auth.factor_enrolled"
	EventAuthFactorRemoved  EventType = "auth.factor_removed"
	// auth.recovery_codes_generated records a display-once batch replacing the
	// previous one.
	EventAuthRecoveryCodesGenerated EventType = "auth.recovery_codes_generated"
	// auth.recovery_code_consumed records the pre-auth break-in-glass path,
	// including its failures (the ADR requires the failures, uniform response
	// notwithstanding).
	EventAuthRecoveryCodeConsumed EventType = "auth.recovery_code_consumed"
	// auth.reauthenticated records a step-up: the acting session presented a
	// possession factor and gained a factor class.
	EventAuthReauthenticated EventType = "auth.reauthenticated"
	// auth.passkey_added / auth.passkey_removed record a WebAuthn credential
	// coming into or out of existence, naming the credential class that
	// authorized the account-security mutation (#54). auth.passkey_cloned is the
	// clone-detection security event: a real sign-count regression on a
	// non-backup credential disabled it and swept its sessions (B9).
	EventAuthPasskeyAdded   EventType = "auth.passkey_added"
	EventAuthPasskeyRemoved EventType = "auth.passkey_removed"
	EventAuthPasskeyCloned  EventType = "auth.passkey_cloned"

	// auth.* OIDC events (#54, human-auth ADR - Login methods, Identity
	// linking, The OIDC transaction). auth.oidc_login records a federated login
	// or reauth success with its method and the assurance the provider policy
	// yielded; auth.oidc_refused records every transaction failure BY CAUSE
	// (the ADR requires the failures, uniform response notwithstanding), with a
	// closed cause enum covering mix-up, nonce, purpose, state, issuer,
	// audience, signature, epoch and IdP-error refusals.
	EventOIDCLogin   EventType = "auth.oidc_login"
	EventOIDCRefused EventType = "auth.oidc_refused"
	// auth.identity_linked / auth.identity_unlinked record an external identity
	// bound to or removed from an account - account-security mutations both.
	EventIdentityLinked   EventType = "auth.identity_linked"
	EventIdentityUnlinked EventType = "auth.identity_unlinked"
	// auth.jit_provisioned records a JIT account creation, naming the verified
	// claim that admitted it - the evidence, never an email allowlist.
	EventJITProvisioned EventType = "auth.jit_provisioned"
	// auth.provider_changed records a provider configuration change and the
	// count of federated sessions it swept (A3/A4). auth.provider_read records
	// the instance-scoped provider reads (audit-model default-deny refuses
	// audited:none to instance-class operations).
	EventOIDCProviderChanged EventType = "auth.provider_changed"
	EventOIDCProviderRead    EventType = "auth.provider_read"

	// auth.* SAML events (#72, saml-sp ADR). Login and reauth outcomes keep
	// their distinct ceremony semantics; provider, certificate, metadata and
	// SP-key lifecycle events make every trust-root transition attributable.
	EventSAMLLogin                 EventType = "auth.saml_login"
	EventSAMLReauth                EventType = "auth.saml_reauth"
	EventSAMLProviderConfigure     EventType = "auth.saml_provider_configure"
	EventSAMLProviderRefresh       EventType = "auth.saml_provider_refresh"
	EventSAMLProviderRemove        EventType = "auth.saml_provider_remove"
	EventSAMLCertChange            EventType = "auth.saml_cert_change"
	EventSAMLEmailNameIDOptIn      EventType = "auth.saml_nameid_email_optin"
	EventSAMLSPKey                 EventType = "auth.saml_sp_key"
	EventSAMLMetadataExpiryWarning EventType = "auth.saml_metadata_expiry_warning"

	// auth.credential_reset_issued records an administrator-issued or break-glass
	// credential-establishment authority minted for a target (#54, human-auth ADR
	// - Recovery), naming the issuer tier and whether it ran under network
	// (credential-reset) or local host (break-glass) authority.
	EventAuthCredentialResetIssued EventType = "auth.credential_reset_issued"
	// auth.effective_window_lowered records an environment's effective
	// reauthentication window being lowered, the count of windows it invalidated,
	// and the principals the transition strands (reveal holders there without a
	// WebAuthn authenticator), so the trail carries the surfaced list (#54 B6).
	EventAuthEffectiveWindowLowered EventType = "auth.effective_window_lowered"

	// settings.* — the hierarchy's own catalogue rows (#48): Organization,
	// Project, Environment, Folder lifecycle. Every mutation has its own type,
	// because "a project was renamed" and "a project was deleted" are different
	// facts for an investigator and collapsing them into one changed-event
	// would make the trail answer neither question.
	//
	// Reads are NOT here: a tenant-class bare-`read` operation takes the
	// audit-model ADR's audited-none permit, so the only read event is the
	// instance-scoped org enumeration below.
	EventOrgCreated EventType = "settings.org_created"
	EventOrgRenamed EventType = "settings.org_renamed"
	EventOrgDeleted EventType = "settings.org_deleted"
	// settings.org_read covers the instance-scoped org enumeration. The ADR's
	// default-deny rule refuses `audited: none` to instance-class
	// operations, and that is an operator read of cross-tenant metadata —
	// so it is audited, at the access retention class (read volume, not
	// grant history).
	EventOrgRead EventType = "settings.org_read"

	EventProjectCreated EventType = "settings.project_created"
	EventProjectRenamed EventType = "settings.project_renamed"
	EventProjectDeleted EventType = "settings.project_deleted"

	EventEnvCreated EventType = "settings.environment_created"
	EventEnvRenamed EventType = "settings.environment_renamed"
	EventEnvDeleted EventType = "settings.environment_deleted"
	// settings.environment_reordered records one authorized rewrite of a
	// project's whole display order, naming how many environments it covered.
	// The ids are the object of the operation, not free text, and the count is
	// what an investigator reads first.
	EventEnvReordered   EventType = "settings.environment_reordered"
	EventEnvNoteChanged EventType = "settings.environment_note_changed"

	EventFolderCreated EventType = "settings.folder_created"
	EventFolderRenamed EventType = "settings.folder_renamed"
	EventFolderDeleted EventType = "settings.folder_deleted"

	// grant.* — the permission model's own catalogue rows (#55). The ADR's
	// propagation to this one names created / modified / revoked with
	// self-grants distinguishable; the three map onto the origin model
	// exactly: a row that did not exist is created, a row an additional
	// origin joins is modified, and a row whose LAST origin was released is
	// revoked. `grant.template_applied` records one template expansion as a
	// single fact beside the per-capability rows it created — without it the
	// trail can say ten capabilities appeared but not that one administrator
	// performed one act.
	EventGrantCreated         EventType = "grant.created"
	EventGrantModified        EventType = "grant.modified"
	EventGrantRevoked         EventType = "grant.revoked"
	EventGrantTemplateApplied EventType = "grant.template_applied"
	// grant.membership_read is the membership surface's read event. It is not
	// `audited: none`: that permit covers tenant-class bare-`read` operations,
	// and "who can reveal production secrets" is administrative information
	// under `manage-members`, not an object read. Access retention class —
	// read volume, not grant history.
	EventGrantMembershipRead EventType = "grant.membership_read"

	// settings.reauthentication_window_changed and
	// settings.protected_flag_changed are the `project-settings` security
	// events the audit catalogue names — a widening and a protected-flag
	// clearing are the two changes an investigator looks for, so widening is
	// a field on the first and the direction is the whole of the second.
	EventReauthWindowChanged EventType = "settings.reauthentication_window_changed"
	EventProtectedFlagChange EventType = "settings.protected_flag_changed"

	// recovery.break_glass_grant records a grant issued under local host
	// authority — the one authorization path not evaluated against a grant.
	EventBreakGlassGrant EventType = "recovery.break_glass_grant"

	// backup.* / restore.* — the operator lifecycle (#76, encryption ADR
	// § Propagations "export and restore are auditable events"; ops spec § 11).
	// All four are instance-trail, local host authority, and all four are
	// SECURITY retention: a backup is a copy of every ciphertext in the
	// instance, and the record of one being taken, skipped, or replayed into a
	// new instance is exactly the evidence an incident starts from.
	//
	// backup.exported records an artifact coming into existence and WHERE it
	// went, because a backup nobody can find is a backup that does not exist.
	// It deliberately records the recipient MODE and count, never a recipient
	// value: the public recipients are not secret, but naming them in every
	// event would put the operator's escrow topology in the trail.
	EventBackupExported EventType = "backup.exported"
	// backup.export_skipped is the loud half of the ops spec's "automatic
	// pre-migration export when public recipients are configured, LOUD SKIP
	// otherwise". A skip that only warned to a log would be invisible the
	// morning after a migration went wrong.
	EventBackupExportSkipped EventType = "backup.export_skipped"
	// restore.completed records an instance being reconstructed from an
	// archive: the credential epoch it advanced to, and therefore the moment
	// every pre-restore artifact in the restored state became inert.
	EventRestoreCompleted EventType = "restore.completed"
	// restore.principal_reconciled records ONE principal's re-activation. One
	// event per principal is the point — the ADR's per-principal assertion has
	// to leave a per-principal record, and a single "reconciliation completed"
	// event would be exactly the bulk accept the surface refuses to offer.
	EventRestorePrincipalReconciled EventType = "restore.principal_reconciled"
	// settings.key_* — the key catalogue's lifecycle (#49). The catalogue IS
	// the project's schema, so these are schema events; they are named
	// `settings.*` like the rest of the definitions surface because an
	// investigator asks "who changed the project's definitions?", not "which
	// subsystem owned the row".
	//
	// NO PAYLOAD HERE EVER CARRIES A VALUE, A DECLARATION BODY, OR AN
	// INSTANCE-DERIVED PATH. Key NAMES are schema and are recorded; a folder
	// path is recorded as `namespace`, because the #48 convention reserves
	// every *_path spelling for instance-derived JSON pointers into a value.
	EventKeyCreated EventType = "settings.key_created"
	EventKeyRenamed EventType = "settings.key_renamed"
	EventKeyDeleted EventType = "settings.key_deleted"
	// settings.key_declaration_changed records a semantic schema change: the
	// value-dependent rules, the presence rules, or both. It carries the
	// resulting schema revision, because "the validation guarantee moved" is
	// the fact a later snapshot pins.
	EventKeyDeclarationChanged EventType = "settings.key_declaration_changed"
	// settings.key_metadata_changed records the NON-semantic half. It exists
	// separately precisely because it materializes nothing and moves no
	// revision — collapsing it into the declaration event would make the trail
	// unable to answer which changes could have affected delivery.
	EventKeyMetadataChanged EventType = "settings.key_metadata_changed"
	// settings.key_reclassified records the ceremony in both directions,
	// recorded under the STRICTER of the pre- and post-change classification
	// so neither direction lands under the laxer regime.
	EventKeyReclassified EventType = "settings.key_reclassified"
	// settings.key_reveal_gate_attempt is the disclosure-class record of EVERY
	// reveal-gated attempt on a `secret` key — a value-dependent rule change or
	// a declassification — whatever its outcome: allowed (success), refused
	// (denied), or rate-limited (failure). The schema ADR's obligation is
	// "every attempt is audited", so the denied and limited cases matter most,
	// and both roll their transaction back; the row therefore rides the
	// rollback-surviving settlement path rather than an in-transaction insert.
	//
	// The before-commit disclosure record the ADR separately requires for
	// declassification is settings.key_reclassified, which IS written inside
	// the committing transaction ahead of the classification write.
	EventKeyRevealGateAttempt EventType = "settings.key_reveal_gate_attempt"

	// value.* and disclosure.* — the flat value model (#50). Both categories
	// are the audit catalogue's own: `value` holds the acts that change what
	// an environment delivers, `disclosure` holds the acts that move stored
	// material to a principal or to another environment.
	//
	// NO PAYLOAD HERE EVER CARRIES A VALUE, IN ANY FORM — not the plaintext,
	// not a length, not a hash, not a "changed from" marker. A key name and
	// its classification are schema and are recorded; everything derived from
	// the material itself is exactly what the trail must not hold, because the
	// trail is readable under `audit-read` and `audit-read` is not `reveal`.
	//
	// value.set records a cell beginning to deliver material the actor
	// SUPPLIED (typed, piped, or read from a file they named). Material the
	// actor did not supply arrives through disclosure.value_copied instead —
	// the two are different authorization stories (supply needs no `reveal`,
	// duplication does), so they are different events.
	EventValueSet EventType = "value.set"
	// value.cleared records the `set` → `absent` transition. With no
	// inheritance there is nothing underneath, so this event means delivery of
	// that key in that environment STOPPED — which is why it is its own event
	// and not a `value.set` with an empty payload.
	EventValueCleared EventType = "value.cleared"
	// disclosure.value_revealed is one event per key per environment whose
	// current `secret` plaintext was opened under the caller's authority.
	// `surface` says where: `cell` and `diff` are reads rendered to the
	// principal, `copy` and `clone` are the source side of a duplication. The
	// audit ADR lists these as separate disclosure entries; they are one type
	// with a field because they disclose exactly the same thing, and an
	// investigator filtering "who read this key" must not have to know four
	// spellings.
	EventValueRevealed EventType = "disclosure.value_revealed"
	// disclosure.value_copied is one event per key per DESTINATION for every
	// server-side duplication: copy-to, bulk-apply and clone-at-creation. It
	// records the source environment, because "material this environment's
	// publisher did not supply" is the fact the re-delivery gate exists to
	// make auditable.
	EventValueCopied EventType = "disclosure.value_copied"

	EventKeyGroupCreated EventType = "settings.key_group_created"
	EventKeyGroupRenamed EventType = "settings.key_group_renamed"
	EventKeyGroupDeleted EventType = "settings.key_group_deleted"
	// settings.key_group_membership_changed records a key joining or leaving a
	// group. Membership is coupling, and coupling is a schema change.
	EventKeyGroupMembershipChanged EventType = "settings.key_group_membership_changed"

	// identity.* — machine identities (#61, machine-identities ADR §
	// Audit attribution). Every credential-lifecycle transition is here
	// because the forensic question after a leak is "which token", and one
	// service account holds several.
	//
	// identity.service_account_created / _deleted bracket the principal's
	// life; the deletion event carries the blast radius it took with it (the
	// credentials revoked and the grants released in the same transaction).
	EventServiceAccountCreated EventType = "identity.service_account_created"
	EventServiceAccountDeleted EventType = "identity.service_account_deleted"
	// identity.credential_minted records a credential coming into existence
	// AND the environments the authorizing formula ranged over, per authority
	// class — the delivery mode itself is the CLI's to record, since the
	// server never sees where the value went.
	EventCredentialMinted EventType = "identity.credential_minted"
	// identity.credential_revoked is the incident-response half. It is
	// reachable under the PLAIN capability, with no reveal gate, because
	// gating revocation on disclosure rights is a self-inflicted delay.
	EventCredentialRevoked EventType = "identity.credential_revoked"
	// identity.grant_widened records a grant mutation on a MACHINE principal
	// that made plaintext newly reachable. It is a separate event from
	// grant.created because it is a separate fact: a grant landing on a
	// machine principal re-scopes every credential already in circulation,
	// instantly, with nobody re-presenting anything.
	EventMachineGrantWidened EventType = "identity.grant_widened"
	// identity.lifetime_policy_changed records the instance lifetime
	// controls moving, with the credentials the change clamped or stranded —
	// the enumeration the actor was shown before it committed.
	EventCredentialPolicyChanged EventType = "identity.lifetime_policy_changed"
	// identity.credentials_listed is the metadata read. It is audited rather
	// than `audited: none` for the same reason grant.membership_read is:
	// reading which credentials can reach production is not a bare tenant
	// read.
	EventCredentialsListed EventType = "identity.credentials_listed"
	// identity.lifetime_policy_read is the instance-scoped read of the
	// lifetime controls. Instance-class operations cannot be `audited: none`
	// under the audit-model ADR's default-deny permit rule, and this is the
	// same shape auth.provider_read already has for OIDC configuration.
	EventCredentialPolicyRead EventType = "identity.lifetime_policy_read"

	// NOT REGISTERED HERE, deliberately: `identity.disclosure`, the per-key
	// disclosure event on a machine fetch. #15's locked cardinality — one
	// immutable event per disclosed key, never collapsed, never counted — is
	// unchanged and binding, but there is no fetch path in this repository
	// yet (no secret values, no delivery manifest, no cursor), so there is no
	// key for a per-key event to name. This registry's closure invariant
	// refuses a type with no emitter, and it is right to: registering it now
	// would be dead catalogue asserting a guarantee nothing upholds.
	//
	// The same reasoning applies to a machine authentication-failure event.
	// A failed machine presentation today rides the SAME silent path a failed
	// human session does at the chokepoint; giving machines a failure event
	// humans do not have would claim an asymmetry the system does not
	// implement. Both land with the fetch surface and the pre-authentication
	// admission wiring.
)

// TypeSpec is one registry row: the payload schema with its version, the
// retention class (exactly one — CI invariant 10), the licensed outcomes
// (CI invariant 12) and the trails the type may land in.
type TypeSpec struct {
	SchemaVersion int
	Retention     RetentionClass
	Outcomes      map[Outcome]bool
	Trails        map[Trail]bool
	Schema        Schema
}

// filterSchema is the normalized filter structure recorded on audit.* events
// — the parsed filter parameters, never the raw query string (audit-model
// ADR § Free-text hygiene).
var filterSchema = Schema{
	"filter_from":      {Kind: KindString},
	"filter_to":        {Kind: KindString},
	"filter_after_seq": {Kind: KindInt},
	"filter_limit":     {Kind: KindInt, Required: true},
}

func merged(a, b Schema) Schema {
	out := Schema{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// registry is the closed catalogue, unexported so closure holds
// structurally, not by convention — consumers read through Spec/Types.
// Every emitted event type exists here with a payload schema, version and
// retention class; growth happens only alongside the operation that emits
// the new type (completeness is CI invariant 2, wired to the
// probe-classification registry).
var registry = map[EventType]TypeSpec{
	EventGrantDenied: {
		SchemaVersion: 1,
		Retention:     RetentionAccess,
		Outcomes:      map[Outcome]bool{OutcomeDenied: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema: Schema{
			// The operation attempted and the formula that failed, by name —
			// never a missing-grant enumeration (authorization oracle).
			"operation":  {Kind: KindString, Required: true},
			"formula":    {Kind: KindString, Required: true},
			"resolution": {Kind: KindString, Required: true}, // resolvable | unresolvable
			// Unresolvable denials only: the addressed identifiers as
			// caller-asserted claims — no chain exists, so none is recorded.
			"claimed_org":     {Kind: KindFreeText},
			"claimed_project": {Kind: KindFreeText},
			"claimed_env":     {Kind: KindFreeText},
		},
	},
	EventAuditQuery: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema: merged(filterSchema, Schema{
			"row_count": {Kind: KindInt, Required: true},
		}),
	},
	EventAuditExportStarted: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeIntent: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema:        filterSchema,
	},
	EventAuditExportCompleted: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes: map[Outcome]bool{
			OutcomeSuccess: true, OutcomeFailure: true, OutcomeDisconnected: true,
		},
		Trails: map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema: Schema{
			"rows_streamed": {Kind: KindInt, Required: true},
			"cause":         {Kind: KindString},
		},
	},
	EventAuthLogin: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true, OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"method":           {Kind: KindString, Required: true}, // local-password | …
			"artifact":         {Kind: KindString, Required: true}, // cli | browser
			"subject_resolved": {Kind: KindBool, Required: true},
			"account_id":       {Kind: KindString},
			"assurance":        {Kind: KindString}, // single-factor | multi-factor
			"cause":            {Kind: KindString}, // failures only, by class never by detail
		},
	},
	EventAuthLogout: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"session_id": {Kind: KindString, Required: true},
			"artifact":   {Kind: KindString, Required: true},
		},
	},
	EventAuthSessionCreated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"session_id": {Kind: KindString, Required: true},
			"artifact":   {Kind: KindString, Required: true},
			"method":     {Kind: KindString, Required: true},
			"assurance":  {Kind: KindString, Required: true},
		},
	},
	EventAuthAuthorityMinted: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"authority_id": {Kind: KindString, Required: true},
			"account_id":   {Kind: KindString, Required: true},
			"issued_by":    {Kind: KindString, Required: true}, // bootstrap | credential-reset | break-glass | recovery
			"delivery":     {Kind: KindString, Required: true}, // file | terminal | response
		},
	},
	EventAuthCredentialEstablished: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"authority_id": {Kind: KindString, Required: true},
			"account_id":   {Kind: KindString, Required: true},
			"credential":   {Kind: KindString, Required: true}, // the credential class established
		},
	},
	EventAuthAuthorityRefused: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			// By class — unknown | expired | consumed | epoch — never by
			// detail, so the trail does not become the oracle the response
			// deliberately is not.
			"cause": {Kind: KindString, Required: true},
		},
	},
	EventAuthThrottleCrossed: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"scope":            {Kind: KindString, Required: true}, // account | source-ip | instance
			"subject_resolved": {Kind: KindBool, Required: true},
			"account_id":       {Kind: KindString},
		},
	},
	EventAuthFactorEnrolled: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"factor":                 {Kind: KindString, Required: true}, // totp
			"account_id":             {Kind: KindString, Required: true},
			"authorizing_credential": {Kind: KindString, Required: true}, // the proof class
		},
	},
	EventAuthFactorRemoved: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"factor":                 {Kind: KindString, Required: true},
			"account_id":             {Kind: KindString, Required: true},
			"authorizing_credential": {Kind: KindString, Required: true},
		},
	},
	EventAuthRecoveryCodesGenerated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"account_id":             {Kind: KindString, Required: true},
			"count":                  {Kind: KindInt, Required: true},
			"authorizing_credential": {Kind: KindString, Required: true},
		},
	},
	EventAuthRecoveryCodeConsumed: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true, OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"subject_resolved": {Kind: KindBool, Required: true},
			"account_id":       {Kind: KindString},
			"authority_id":     {Kind: KindString}, // success only
			"cause":            {Kind: KindString}, // failures only, by class
		},
	},
	EventAuthReauthenticated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"session_id": {Kind: KindString, Required: true},
			"factor":     {Kind: KindString, Required: true}, // totp
		},
	},
	EventAuthPasskeyAdded: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"account_id":             {Kind: KindString, Required: true},
			"credential_id":          {Kind: KindString, Required: true}, // the surrogate row id
			"authorizing_credential": {Kind: KindString, Required: true}, // the proof class
			"discoverable":           {Kind: KindBool, Required: true},   // login-capable (B13)
		},
	},
	EventAuthPasskeyRemoved: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"account_id":             {Kind: KindString, Required: true},
			"credential_id":          {Kind: KindString, Required: true},
			"authorizing_credential": {Kind: KindString, Required: true},
		},
	},
	EventAuthPasskeyCloned: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"account_id":     {Kind: KindString, Required: true},
			"credential_id":  {Kind: KindString, Required: true},
			"sessions_swept": {Kind: KindInt, Required: true},
		},
	},
	EventOIDCLogin: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"method":               {Kind: KindString, Required: true}, // oidc:<issuer>
			"purpose":              {Kind: KindString, Required: true}, // login | reauth
			"account_id":           {Kind: KindString, Required: true},
			"assurance":            {Kind: KindString, Required: true}, // single-factor | multi-factor
			"provider_id":          {Kind: KindString, Required: true},
			"acr":                  {Kind: KindString},              // provider-asserted, raw (A12)
			"amr":                  {Kind: KindString},              // provider-asserted, raw joined (A12)
			"provider_row_version": {Kind: KindInt, Required: true}, // policy read in the mint tx (A12)
		},
	},
	EventOIDCRefused: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			// Closed cause enum, by class never by detail: mixup | nonce |
			// purpose | state | issuer | audience | signature | epoch |
			// idp-error | expired | unknown-identity | no-assurance-policy |
			// no-auth-time | binding | jit-refused | reconciliation.
			"cause":       {Kind: KindString, Required: true},
			"provider_id": {Kind: KindString},
		},
	},
	EventIdentityLinked: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"kind":                   {Kind: KindString, Required: true},
			"account_id":             {Kind: KindString, Required: true},
			"identity_id":            {Kind: KindString, Required: true},
			"provider_id":            {Kind: KindString, Required: true},
			"authorizing_credential": {Kind: KindString, Required: true},
		},
	},
	EventIdentityUnlinked: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"kind":                   {Kind: KindString, Required: true},
			"account_id":             {Kind: KindString, Required: true},
			"identity_id":            {Kind: KindString, Required: true},
			"authorizing_credential": {Kind: KindString, Required: true},
		},
	},
	EventJITProvisioned: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"account_id":  {Kind: KindString, Required: true},
			"provider_id": {Kind: KindString, Required: true},
			"claim":       {Kind: KindString, Required: true}, // the verified claim name
		},
	},
	EventOIDCProviderChanged: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"provider_id":    {Kind: KindString, Required: true},
			"change":         {Kind: KindString, Required: true}, // created | updated | deleted
			"sessions_swept": {Kind: KindInt, Required: true},    // federated sessions deleted (A3/A4)
		},
	},
	EventOIDCProviderRead: {
		SchemaVersion: 1,
		Retention:     RetentionAccess,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"query":     {Kind: KindString, Required: true}, // get | list
			"row_count": {Kind: KindInt, Required: true},
		},
	},
	EventSAMLLogin:             samlCeremonyEvent(),
	EventSAMLReauth:            samlCeremonyEvent(),
	EventSAMLProviderConfigure: samlProviderEvent(),
	EventSAMLProviderRefresh:   samlProviderEvent(),
	EventSAMLProviderRemove:    samlProviderEvent(),
	EventSAMLCertChange: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"provider_id": {Kind: KindString, Required: true},
			"entity_id":   {Kind: KindString, Required: true},
			"change":      {Kind: KindString, Required: true},
			"fingerprint": {Kind: KindString, Required: true},
		},
	},
	EventSAMLEmailNameIDOptIn: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"provider_id": {Kind: KindString, Required: true},
			"entity_id":   {Kind: KindString, Required: true},
			"state":       {Kind: KindString, Required: true},
		},
	},
	EventSAMLSPKey: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"action":                {Kind: KindString, Required: true},
			"key_fingerprint":       {Kind: KindString, Required: true},
			"prior_key_fingerprint": {Kind: KindString},
		},
	},
	EventSAMLMetadataExpiryWarning: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"provider_id": {Kind: KindString, Required: true},
			"entity_id":   {Kind: KindString, Required: true},
			"valid_until": {Kind: KindString, Required: true},
			"threshold":   {Kind: KindString, Required: true},
		},
	},
	EventAuthCredentialResetIssued: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		// Failures are audited too (ADR - Recovery: "including failures"): a
		// network reset of an instance-capability target, or of an unknown
		// principal, records the attempt with its cause while the wire stays
		// uniform. The mint-specific fields are success-only.
		Outcomes: map[Outcome]bool{OutcomeSuccess: true, OutcomeFailure: true},
		Trails:   map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"target_principal": {Kind: KindString, Required: true},
			"issued_by":        {Kind: KindString, Required: true}, // credential-reset | break-glass
			"authority":        {Kind: KindString, Required: true}, // network | local-host
			"target_account":   {Kind: KindString},                 // absent for an unknown-target failure
			"authority_id":     {Kind: KindString},                 // success only
			"delivery":         {Kind: KindString},                 // success only
			"sessions_revoked": {Kind: KindBool},                   // success only
			"cause":            {Kind: KindString},                 // failures only, by class
		},
	},
	EventAuthEffectiveWindowLowered: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"environment_id":      {Kind: KindString, Required: true},
			"new_window_seconds":  {Kind: KindInt, Required: true},
			"windows_invalidated": {Kind: KindInt, Required: true},
			"stranded_count":      {Kind: KindInt, Required: true},
			// The stranded-principal list the ADR requires the event to carry.
			// Principal ids are trusted vocabulary (prefixed UUIDs), joined with a
			// comma; empty when nothing is stranded.
			"stranded_principals": {Kind: KindString},
		},
	},
	EventOrgRead: {
		SchemaVersion: 1,
		Retention:     RetentionAccess,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"query":     {Kind: KindString, Required: true}, // get | list
			"row_count": {Kind: KindInt, Required: true},
		},
	},
	EventOrgCreated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"org_id":   {Kind: KindString, Required: true},
			"org_name": {Kind: KindFreeText, Required: true},
		},
	},
	EventProjectCreated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"name": {Kind: KindFreeText, Required: true},
		},
	},
	EventEnvCreated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"name": {Kind: KindFreeText, Required: true},
		},
	},
	EventEnvNoteChanged: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema:        Schema{},
	},

	// The rest of the hierarchy's lifecycle (#48). All tenant-trail,
	// security-class, success-only: each row records a committed mutation, and
	// a refusal is either the uniform nonexistent response (no event — the
	// denial writer covers authorization) or a constraint refusal that
	// rolled back, leaving nothing to record.
	//
	// A rename carries BOTH names: "renamed to prod" without the previous name
	// makes the trail unable to answer what the operator actually changed.
	EventOrgRenamed:     hierarchyEvent(renameSchema("name")),
	EventOrgDeleted:     hierarchyEvent(Schema{"name": {Kind: KindFreeText, Required: true}}),
	EventProjectRenamed: hierarchyEvent(renameSchema("name")),
	EventProjectDeleted: hierarchyEvent(Schema{"name": {Kind: KindFreeText, Required: true}}),
	EventEnvRenamed:     hierarchyEvent(renameSchema("name")),
	EventEnvDeleted:     hierarchyEvent(Schema{"name": {Kind: KindFreeText, Required: true}}),
	// The resulting order, not only its length: an investigator must be able to
	// tell "production and staging swapped" from any other permutation of the
	// same set. audit.Schema has no list kind, so the order is one
	// comma-joined string of server-minted ids — trusted vocabulary, not free
	// text, so no free-text bound applies.
	EventEnvReordered: hierarchyEvent(Schema{
		"environment_count": {Kind: KindInt, Required: true},
		"environment_order": {Kind: KindString, Required: true},
	}),
	// The folder payload field is `namespace`, not `path`: the forbidden-content
	// guard reserves every *_path spelling for instance-derived JSON pointers
	// into a value, and a folder path is not one — it is the namespace the
	// domain model calls it. Keeping the guard intact is worth the rename.
	EventFolderCreated: hierarchyEvent(Schema{"namespace": {Kind: KindFreeText, Required: true}}),
	EventFolderRenamed: hierarchyEvent(renameSchema("namespace")),
	EventFolderDeleted: hierarchyEvent(Schema{"namespace": {Kind: KindFreeText, Required: true}}),

	// The key catalogue (#49). Tenant-trail, security-class, success-only, for
	// the same reason as the hierarchy rows: each records a COMMITTED mutation,
	// and a refusal is either the uniform nonexistent response (the denial
	// writer covers authorization) or a constraint refusal that rolled back.
	//
	// `classification` is a schema-typed enum, not free text: `secret|config`
	// is trusted vocabulary. `name` is the key's name, which is schema and
	// therefore recordable — values never are.
	EventKeyCreated: hierarchyEvent(Schema{
		"name":           {Kind: KindFreeText, Required: true},
		"classification": {Kind: KindString, Required: true},
		"namespace":      {Kind: KindFreeText, Required: true},
	}),
	EventKeyRenamed: hierarchyEvent(renameSchema("name")),
	EventKeyDeleted: hierarchyEvent(Schema{"name": {Kind: KindFreeText, Required: true}}),
	// `rules_changed` and `presence_changed` are separate booleans rather than
	// one "changed" flag, because the two halves have different authorization
	// stories: value-dependent rules on a `secret` key are reveal-gated,
	// presence rules never are. An investigator must be able to tell which of
	// the two a given commit moved.
	EventKeyDeclarationChanged: hierarchyEvent(Schema{
		"name":             {Kind: KindFreeText, Required: true},
		"schema_revision":  {Kind: KindInt, Required: true},
		"rules_changed":    {Kind: KindBool, Required: true},
		"presence_changed": {Kind: KindBool, Required: true},
	}),
	EventKeyMetadataChanged: hierarchyEvent(Schema{
		"name":      {Kind: KindFreeText, Required: true},
		"namespace": {Kind: KindFreeText, Required: true},
	}),
	EventKeyReclassified: hierarchyEvent(Schema{
		"name":                    {Kind: KindFreeText, Required: true},
		"previous_classification": {Kind: KindString, Required: true},
		"classification":          {Kind: KindString, Required: true},
	}),
	// Three licensed outcomes, one per attempt disposition. No declaration
	// body and no instance data: these rows are written outside the operation's
	// own authorization scope, so they carry only schema vocabulary — the key's
	// id and name, and which gate was attempted.
	EventKeyRevealGateAttempt: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes: map[Outcome]bool{
			OutcomeSuccess: true, OutcomeDenied: true, OutcomeFailure: true,
		},
		Trails: map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"key_id": {Kind: KindString, Required: true},
			"name":   {Kind: KindFreeText, Required: true},
			// value-dependent-rule-change | declassification
			"gate": {Kind: KindString, Required: true},
		},
	},
	// The flat value model (#50). Tenant trail, security class, success-only:
	// each records a COMMITTED act, and a refusal is either the uniform
	// nonexistent response or a rollback.
	EventValueSet: hierarchyEvent(Schema{
		"key_id":         {Kind: KindString, Required: true},
		"name":           {Kind: KindFreeText, Required: true},
		"classification": {Kind: KindString, Required: true},
	}),
	EventValueCleared: hierarchyEvent(Schema{
		"key_id":         {Kind: KindString, Required: true},
		"name":           {Kind: KindFreeText, Required: true},
		"classification": {Kind: KindString, Required: true},
	}),
	// cell | diff | copy | clone — where the plaintext went. Never what it was.
	EventValueRevealed: hierarchyEvent(Schema{
		"key_id":  {Kind: KindString, Required: true},
		"name":    {Kind: KindFreeText, Required: true},
		"surface": {Kind: KindString, Required: true},
	}),
	// `operation` is copy | bulk-apply | clone: the same formula authorizes
	// all three, and the trail still has to say which act it was.
	EventValueCopied: hierarchyEvent(Schema{
		"key_id":                {Kind: KindString, Required: true},
		"name":                  {Kind: KindFreeText, Required: true},
		"classification":        {Kind: KindString, Required: true},
		"source_environment_id": {Kind: KindString, Required: true},
		"operation":             {Kind: KindString, Required: true},
	}),

	EventKeyGroupCreated: hierarchyEvent(Schema{"name": {Kind: KindFreeText, Required: true}}),
	EventKeyGroupRenamed: hierarchyEvent(renameSchema("name")),
	EventKeyGroupDeleted: hierarchyEvent(Schema{
		"name": {Kind: KindFreeText, Required: true},
		// Deleting a group dissolves a coupling; how many keys it uncoupled is
		// the fact that matters, and the ids are the object of the event.
		"members_released": {Kind: KindInt, Required: true},
	}),
	// The group ids are server-minted vocabulary; "" spells "no group", which
	// is why both sides are optional rather than required.
	EventKeyGroupMembershipChanged: hierarchyEvent(Schema{
		"name":              {Kind: KindFreeText, Required: true},
		"previous_group_id": {Kind: KindString},
		"group_id":          {Kind: KindString},
	}),
	// The grant lifecycle (#55). Both trails: a grant at org/project/env
	// scope is tenant-trail work, an instance-scope grant has no tenant to
	// own it. Security retention — grant history is the ADR's named
	// counter-example to the unbounded machine-fetch stream.
	//
	// `self_grant` is a first-class field rather than something a reader
	// derives by comparing two ids: the ADR requires self-grants to be
	// DISTINGUISHABLE, and a derived property is one join away from being
	// missed. `unheld` records the org/instance escalation path being used —
	// a grantor handing out a capability they do not themselves hold, which
	// the ADR permits at org/instance scope and which an investigator must
	// be able to filter for.
	EventGrantCreated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema:        grantSchema,
	},
	EventGrantModified: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema:        grantSchema,
	},
	EventGrantRevoked: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema: merged(grantSchema, Schema{
			// A revoke that released an origin without deleting the row is a
			// modification, and is recorded as one; this field says whether
			// the row survived so the two are never confused.
			"origins_remaining": {Kind: KindInt, Required: true},
			"sessions_revoked":  {Kind: KindBool, Required: true},
		}),
	},
	EventGrantTemplateApplied: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema: Schema{
			"template":         {Kind: KindString, Required: true},
			"target_principal": {Kind: KindString, Required: true},
			"scope":            {Kind: KindString, Required: true},
			"capability_count": {Kind: KindInt, Required: true},
			"grants_created":   {Kind: KindInt, Required: true},
			// deduped is the total that did not create a row; joined and
			// unchanged split it, because "an existing row gained this
			// administrator as an origin" and "nothing happened at all" are
			// different facts and only the first is a state transition.
			"grants_deduped":   {Kind: KindInt, Required: true},
			"grants_joined":    {Kind: KindInt, Required: true},
			"grants_unchanged": {Kind: KindInt, Required: true},
			"self_grant":       {Kind: KindBool, Required: true},
			"capabilities":     {Kind: KindString, Required: true},
		},
	},

	// `project-settings` changes (#55). Instance trail is NOT licensed:
	// every environment has a tenant chain, so these are tenant-trail facts.
	EventReauthWindowChanged: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"previous_window_seconds": {Kind: KindInt, Required: true},
			"window_seconds":          {Kind: KindInt, Required: true},
			// The STORED configuration either side, and whether the
			// environment inherited the instance default. An inheritance flip
			// changes no effective duration today and every one of them once
			// the instance default moves, so the trail records both.
			"previous_configured_seconds": {Kind: KindInt, Required: true},
			"configured_seconds":          {Kind: KindInt, Required: true},
			"previous_inherited":          {Kind: KindBool, Required: true},
			"inherited":                   {Kind: KindBool, Required: true},
			// Widening is the security-relevant direction, so it is its own
			// field rather than a subtraction the reader has to perform.
			"widened":   {Kind: KindBool, Required: true},
			"protected": {Kind: KindBool, Required: true},
		},
	},
	EventProtectedFlagChange: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"protected": {Kind: KindBool, Required: true},
			// Marking an environment protected CAPS its window at the
			// protected default; the capped value is part of the same fact.
			"window_seconds": {Kind: KindInt, Required: true},
		},
	},

	// Break-glass grants (#55, permission ADR - Break-glass). Instance trail
	// only: local host authority has no session, no tenant actor and, by the
	// ADR's own words, no grant to be evaluated against.
	EventBreakGlassGrant: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"target_principal": {Kind: KindString, Required: true},
			"capability":       {Kind: KindString, Required: true},
			"scope":            {Kind: KindString, Required: true},
			"authority":        {Kind: KindString, Required: true}, // local-host
			"grant_created":    {Kind: KindBool, Required: true},
		},
	},
	// Backup and restore (#76). Instance trail only: every one of these runs
	// under local host authority, which has no session and no tenant actor.
	EventBackupExported: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		// Success only: an export that failed produced no artifact to record,
		// and the failure surfaces as a refusal on the operator's terminal or
		// as the migration's own loud error. Declaring an outcome nothing can
		// emit is the same smell as declaring a type nothing emits.
		Outcomes: map[Outcome]bool{OutcomeSuccess: true},
		Trails:   map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			// Why the export ran: `manual` or `pre-migration`.
			"trigger": {Kind: KindString, Required: true},
			// The recipient MODE, never a recipient value.
			"recipient_mode":  {Kind: KindString, Required: true},
			"recipient_count": {Kind: KindInt, Required: true},
			"engine":          {Kind: KindString, Required: true},
			"schema_version":  {Kind: KindInt, Required: true},
			"artifact_bytes":  {Kind: KindInt, Required: true},
			// The path the artifact was published to. It is operator
			// infrastructure, not tenant data, and an export nobody can
			// locate afterwards is not a backup.
			"destination": {Kind: KindFreeText, Required: true},
		},
	},
	EventBackupExportSkipped: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"trigger": {Kind: KindString, Required: true},
			"reason":  {Kind: KindString, Required: true},
		},
	},
	EventRestoreCompleted: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"engine":         {Kind: KindString, Required: true},
			"schema_version": {Kind: KindInt, Required: true},
			// The epoch every pre-restore artifact is now behind, and the
			// count of principals the operator must reconcile before their
			// grants authorize anything again.
			"credential_epoch":   {Kind: KindInt, Required: true},
			"restore_epoch":      {Kind: KindInt, Required: true},
			"pending_principals": {Kind: KindInt, Required: true},
			"authority":          {Kind: KindString, Required: true}, // local-host
		},
	},
	EventRestorePrincipalReconciled: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"target_principal":   {Kind: KindString, Required: true},
			"restore_epoch":      {Kind: KindInt, Required: true},
			"pending_principals": {Kind: KindInt, Required: true},
			"authority":          {Kind: KindString, Required: true}, // local-host
		},
	},

	EventGrantMembershipRead: {
		SchemaVersion: 1,
		Retention:     RetentionAccess,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true, TrailInstance: true},
		Schema: Schema{
			"scope":     {Kind: KindString, Required: true},
			"row_count": {Kind: KindInt, Required: true},
		},
	},

	// Machine identities (#61). `principal_class` rides every one of these:
	// the ADR requires machine principals to be visibly distinct from humans
	// in audit attribution, and the distinction has to be a field an exporter
	// can filter on, not an inference from the id's prefix.
	EventServiceAccountCreated: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"service_account_id": {Kind: KindString, Required: true},
			"target_principal":   {Kind: KindString, Required: true},
			"principal_class":    {Kind: KindString, Required: true},
			"name":               {Kind: KindFreeText, Required: true},
		},
	},
	EventServiceAccountDeleted: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"service_account_id": {Kind: KindString, Required: true},
			"target_principal":   {Kind: KindString, Required: true},
			"principal_class":    {Kind: KindString, Required: true},
			// The blast radius the deletion took with it, in one transaction.
			"credentials_revoked": {Kind: KindInt, Required: true},
		},
	},
	EventCredentialMinted: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"service_account_id": {Kind: KindString, Required: true},
			"target_principal":   {Kind: KindString, Required: true},
			"principal_class":    {Kind: KindString, Required: true},
			"credential_id":      {Kind: KindString, Required: true},
			"credential_kind":    {Kind: KindString, Required: true},
			"lifetime":           {Kind: KindString, Required: true},
			"expires_at":         {Kind: KindString},
			// Whether the instance ceiling shortened what the caller asked
			// for. A clamp that is invisible in the trail is a surprise
			// waiting for the day the credential dies early.
			"clamped": {Kind: KindBool, Required: true},
			// The two authority classes the formula ranged over, kept
			// separate here for the same reason they are computed separately:
			// collapsing them loses which disclosure right was exercised.
			"reveal_environments":         {Kind: KindStringList, Required: true},
			"reveal_history_environments": {Kind: KindStringList, Required: true},
		},
	},
	EventCredentialRevoked: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"service_account_id": {Kind: KindString, Required: true},
			"target_principal":   {Kind: KindString, Required: true},
			"principal_class":    {Kind: KindString, Required: true},
			"credential_id":      {Kind: KindString, Required: true},
			// `expire` distinguishes a credential the operator killed from
			// one the clock did, which is the difference between an incident
			// and a Tuesday.
			"cause": {Kind: KindString, Required: true},
		},
	},
	EventMachineGrantWidened: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"target_principal": {Kind: KindString, Required: true},
			"principal_class":  {Kind: KindString, Required: true},
			"capability":       {Kind: KindString, Required: true},
			"scope":            {Kind: KindString, Required: true},
			// The DELTA, per class. These are the newly reachable sets — not
			// the post-state — because the delta is what the actor's own
			// disclosure rights had to cover.
			"newly_reachable_current":    {Kind: KindStringList, Required: true},
			"newly_reachable_historical": {Kind: KindStringList, Required: true},
		},
	},
	EventCredentialPolicyChanged: {
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"max_finite_lifetime_seconds": {Kind: KindInt, Required: true},
			"allow_indefinite":            {Kind: KindBool, Required: true},
			"max_live_credentials":        {Kind: KindInt, Required: true},
			// The enumeration the actor was shown BEFORE the change
			// committed, carried into the trail so the surfaced list and the
			// recorded one cannot differ.
			"affected_credentials": {Kind: KindStringList, Required: true},
			"clamped_count":        {Kind: KindInt, Required: true},
		},
	},
	EventCredentialsListed: {
		SchemaVersion: 1,
		Retention:     RetentionAccess,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema: Schema{
			"scope":     {Kind: KindString, Required: true},
			"row_count": {Kind: KindInt, Required: true},
		},
	},
	EventCredentialPolicyRead: {
		SchemaVersion: 1,
		Retention:     RetentionAccess,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema:        Schema{},
	},
}

// grantSchema is the shared shape of the three grant-lifecycle rows. The
// scope is a rendered string rather than three chain columns because the
// event's own chain columns already carry the tenant address; this field
// answers "at which level was it granted", which the chain cannot.
var grantSchema = Schema{
	"target_principal": {Kind: KindString, Required: true},
	"capability":       {Kind: KindString, Required: true},
	"scope":            {Kind: KindString, Required: true},
	"origin_kind":      {Kind: KindString, Required: true},
	"self_grant":       {Kind: KindBool, Required: true},
	"unheld":           {Kind: KindBool, Required: true},
	"target_class":     {Kind: KindString, Required: true},
	"template":         {Kind: KindString},
}

func samlCeremonyEvent() TypeSpec {
	return TypeSpec{
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true, OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"provider_id":                {Kind: KindString, Required: true},
			"entity_id":                  {Kind: KindString, Required: true},
			"purpose":                    {Kind: KindString, Required: true},
			"transaction_id":             {Kind: KindString, Required: true},
			"pinned_certificate_expired": {Kind: KindBool},
			"cause":                      {Kind: KindString},
			"name_id_format":             {Kind: KindString},
			"authn_context_class_ref":    {Kind: KindString},
		},
	}
}

func samlProviderEvent() TypeSpec {
	diffSchema := Schema{
		"endpoints_added":   {Kind: KindStringList, Required: true},
		"endpoints_removed": {Kind: KindStringList, Required: true},
		"certs_added_fps":   {Kind: KindStringList, Required: true},
		"certs_removed_fps": {Kind: KindStringList, Required: true},
		"valid_until":       {Kind: KindString},
	}
	return TypeSpec{
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true, OutcomeFailure: true},
		Trails:        map[Trail]bool{TrailInstance: true},
		Schema: Schema{
			"provider_id":   {Kind: KindString, Required: true},
			"entity_id":     {Kind: KindString, Required: true},
			"source":        {Kind: KindString, Required: true},
			"signed":        {Kind: KindBool, Required: true},
			"diff":          {Kind: KindObject, Required: true, ObjectSchema: diffSchema},
			"confirmed_fps": {Kind: KindStringList, Required: true},
			"cause":         {Kind: KindString},
		},
	}
}

// hierarchyEvent is the shared shape of every hierarchy-lifecycle row. It
// exists so the fifteen rows differ in exactly the thing that differs — their
// payload — rather than repeating four identical lines each and inviting one
// of them to drift.
func hierarchyEvent(schema Schema) TypeSpec {
	return TypeSpec{
		SchemaVersion: 1,
		Retention:     RetentionSecurity,
		Outcomes:      map[Outcome]bool{OutcomeSuccess: true},
		Trails:        map[Trail]bool{TrailTenant: true},
		Schema:        schema,
	}
}

// renameSchema is the two-name payload: what it was called, and what it is
// called now.
func renameSchema(field string) Schema {
	return Schema{
		"previous_" + field: {Kind: KindFreeText, Required: true},
		field:               {Kind: KindFreeText, Required: true},
	}
}

// Category returns the category half of a type name; invalid names return
// "" (the registry well-formedness test refuses them).
func (t EventType) Category() string {
	cat, _, ok := strings.Cut(string(t), ".")
	if !ok {
		return ""
	}
	return cat
}

// Spec returns a type's registry row, reporting whether the type is
// registered at all.
func Spec(t EventType) (TypeSpec, bool) {
	spec, ok := registry[t]
	return spec, ok
}

// Types returns the registered types sorted, for the invariant tests.
func Types() []EventType {
	out := make([]EventType, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
