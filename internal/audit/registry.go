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

	// settings.* — scaffolding domain events for the demonstration
	// operations (#42/#44). Instance-scoped org administration and the
	// tenant-chain demonstration writes audit under these until the real
	// surfaces (#48) land their catalogue rows.
	EventOrgCreated     EventType = "settings.org_created"
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
