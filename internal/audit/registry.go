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
