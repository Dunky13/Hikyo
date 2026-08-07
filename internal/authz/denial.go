package authz

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
)

// An authorization denial from an authenticated principal is an operation
// outcome, and its event is durable before the error response is sent — no
// async fire-and-forget path exists for it (audit-model ADR § Denials).
//
// The mechanics honour "re-authorize before every sensitive step": a denial
// can follow real writes inside the same closure, and those writes must roll
// back while the denial event must not. authorize()'s fail path therefore
// CAPTURES the denial here, bound to the attempt's authorizer; the
// transaction package rolls the attempt back and then flushes every captured
// denial through the enumerated resolution surface (authn.WriteDenial — the
// interface's single write path, amendment part 4) in its own small
// transaction, before the error returns to the caller. A flush failure is a
// loud error, never the uniform denial: a denial response without its
// durable record is exactly what fail-closed forbids.

// Denial is one captured denial event awaiting its durable flush. The actor
// class is resolved (principals.kind) inside the flush transaction, so the
// probe-visible attempt keeps its fixed query count. Scope is the chain
// authorize() itself resolved (tenant trail) or empty (instance trail) —
// carried beside the event because the envelope deliberately has no chain
// field a caller could populate.
type Denial struct {
	Trail audit.Trail
	Scope domain.Scope
	Event audit.Event
}

// PendingDenials hands the attempt's captured denials to the transaction
// package. The authorizer lives exactly one attempt, so there is no reset.
func (a *TxAuthorizer) PendingDenials() []Denial { return a.denials }

// DenialCaptureError reports a denial that could not even be captured
// (event-id mint failure). The transaction package MUST treat it exactly
// like a flush failure: loud refusal, never the uniform denial — a denial
// answer without its durable record is what fail-closed forbids.
func (a *TxAuthorizer) DenialCaptureError() error { return a.captureErr }

const (
	resolutionResolvable   = "resolvable"
	resolutionUnresolvable = "unresolvable"
)

// captureDenial records one denial. resolvedChain is the truthful chain for
// resolvable denials (tenant trail — org A's audit-read holders see org A
// being probed); unresolvable denials carry no chain (recording a foreign
// org's real chain would itself be an oracle) and land in the instance
// trail with the addressed identifiers as bounded, sanitized caller-asserted
// claims. Instance-operation refusals are resolvable grant refusals with no
// tenant object, so they take the instance trail too.
func (a *TxAuthorizer) captureDenial(ctx context.Context, principal domain.PrincipalID, op Operation, spec opSpec, resolution string, resolvedChain domain.Scope, claimed domain.Scope) {
	id, err := audit.NewEventID()
	if err != nil {
		// Cannot mint an id (entropy exhaustion): nothing writable exists,
		// so record the capture failure — settleDenials converts it into
		// the loud refusal instead of the uniform denial (fail-closed).
		a.captureErr = errors.Join(a.captureErr, err)
		return
	}
	wire := audit.FromContext(ctx)
	payload := audit.Payload{
		"operation":  string(op),
		"formula":    formulaName(spec.formula),
		"resolution": resolution,
	}
	trail := audit.TrailInstance
	scope := domain.Scope{}
	if resolution == resolutionUnresolvable {
		// The addressed identifiers are caller-asserted claims: free text at
		// the trust boundary, bounded and sanitized like all of it.
		if claimed.Org != "" {
			payload["claimed_org"] = audit.SanitizeFreeText(string(claimed.Org))
		}
		if claimed.Project != "" {
			payload["claimed_project"] = audit.SanitizeFreeText(string(claimed.Project))
		}
		if claimed.Env != "" {
			payload["claimed_env"] = audit.SanitizeFreeText(string(claimed.Env))
		}
	} else if resolvedChain != (domain.Scope{}) {
		trail = audit.TrailTenant
		scope = resolvedChain
	}
	a.denials = append(a.denials, Denial{
		Trail: trail,
		Scope: scope,
		Event: audit.Event{
			ID:            id,
			Type:          audit.EventGrantDenied,
			SchemaVersion: 1,
			OccurredAt:    time.Now().UTC(),
			// Actor class is resolved at flush (principals.kind), inside the
			// flush transaction.
			Actor:     audit.Actor{ID: string(principal)},
			Outcome:   audit.OutcomeDenied,
			SourceIP:  wire.SourceIP,
			UserAgent: wire.UserAgent,
			Origin:    wire.Origin,
			Payload:   payload,
		},
	})
}

// formulaName renders the failed formula by name — never a missing-grant
// enumeration, which would hand an authorization oracle to the probing
// account the moment any audit surface leaks (audit-model ADR § Denials).
func formulaName(f Formula) string {
	parts := make([]string, 0, len(f))
	for _, atom := range f {
		parts = append(parts, string(atom.Cap)+"@"+levelNames[atom.At])
	}
	return strings.Join(parts, "+")
}
