package authz

import (
	"context"
	"errors"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// AdmitOperation enforces the artifact classes declared by the exact OpenAPI
// operation attached to an HTTP request. Authentication still resolves the
// live identity inside this transaction; this check then refuses a resolved
// bearer whose class the contract excludes before handler logic can use it.
//
// An absent operation means an in-process caller. HTTP validation attaches an
// operation to every contract route before dispatch, so there is no HTTP
// fallback table and a new declaration takes effect without a second edit.
func (a *TxAuthorizer) AdmitOperation(ctx context.Context, caller Identity) error {
	op, ok := api.OperationFromContext(ctx)
	if !ok {
		return nil
	}
	class := ContractArtifactClass(caller)
	if op.AdmitsArtifact(class) {
		return nil
	}

	id, err := audit.NewEventID()
	if err != nil {
		a.captureErr = errors.Join(a.captureErr, err)
		return domain.ErrNotFound
	}
	wire := audit.FromContext(ctx)
	credentialID := caller.CredentialID
	if credentialID == "" {
		credentialID = caller.SessionID
	}
	a.CaptureAudit(audit.TrailInstance, domain.Scope{}, audit.Event{
		ID:            id,
		Type:          audit.EventAuthArtifactClassRefused,
		SchemaVersion: 1,
		OccurredAt:    time.Now().UTC(),
		Actor: audit.Actor{
			ID:           string(caller.Principal),
			CredentialID: credentialID,
		},
		Object:    audit.Object{Type: "api-operation", ID: op.ID},
		Outcome:   audit.OutcomeFailure,
		SourceIP:  wire.SourceIP,
		UserAgent: wire.UserAgent,
		Origin:    wire.Origin,
		Payload: audit.Payload{
			"operation":      op.ID,
			"artifact_class": class,
			"cause":          "class-mismatch",
		},
	})
	return domain.ErrNotFound
}
