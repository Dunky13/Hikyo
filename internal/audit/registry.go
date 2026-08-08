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

	// settings.* — scaffolding domain events for the demonstration
	// operations (#42/#44). Instance-scoped org administration and the
	// tenant-chain demonstration writes audit under these until the real
	// surfaces (#48) land their catalogue rows.
	EventOrgCreated EventType = "settings.org_created"
	// settings.org_read covers the instance-scoped org reads. The ADR's
	// default-deny rule refuses `audited: none` to instance-class
	// operations, and these are operator reads of cross-tenant metadata —
	// so they are audited, at the access retention class (read volume, not
	// grant history).
	EventOrgRead        EventType = "settings.org_read"
	EventProjectCreated EventType = "settings.project_created"
	EventEnvCreated     EventType = "settings.environment_created"
	EventEnvNoteChanged EventType = "settings.environment_note_changed"
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
