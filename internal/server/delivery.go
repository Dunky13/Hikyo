package server

import (
	"context"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The machine delivery transport (#62).
//
// This is the ONE handler that passes the raw presented artifact into the
// service rather than wrapping it in service.Bearer, and the reason is the
// artifact class: a `hik_` bearer credential resolves at the chokepoint from its
// verifier, while an externally issued OIDC ID token needs its signature checked
// against a cached JWKS first — network work that must happen before any
// transaction opens. The service owns that branch, because it owns both the JWKS
// cache and the transaction boundary; the transport's job is to hand over the
// value the caller sent, unexamined.
//
// There is little else here to get wrong: the cursor is a string the handler
// neither builds nor parses, the projection and acknowledgement are opaque
// terms the service authorizes and records, and the scope is the path. A
// delivered value is present iff the service authorized it; the handler renders
// the pointer through unchanged.

// DeliveryService is the domain surface this transport exposes.
type DeliveryService interface {
	Fetch(ctx context.Context, presented string, scope domain.Scope, cursor string, opts service.FetchOptions) (service.FetchResult, error)
}

func (a *API) FetchDelivery(ctx context.Context, req apigen.FetchDeliveryRequestObject) (apigen.FetchDeliveryResponseObject, error) {
	cursor := ""
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	opts := service.FetchOptions{}
	if req.Params.Projection != nil {
		opts.Projection = delivery.Mode(*req.Params.Projection)
	}
	if req.Params.AcknowledgedKeys != nil {
		opts.AcknowledgedKeys = []string(*req.Params.AcknowledgedKeys)
	}
	scope := domain.Scope{
		Org: domain.OrgID(req.Org), Project: domain.ProjectID(req.Project),
		Env: domain.EnvID(req.Environment),
	}
	res, err := a.Delivery.Fetch(ctx, bearer(ctx), scope, cursor, opts)
	if err != nil {
		return nil, err
	}
	// `keys` is a non-null empty array on the "current" disposition rather than
	// omitted: a client that has to distinguish "no keys" from "field absent"
	// would be deciding disclosure by JSON shape.
	keys := make([]apigen.DeliveredKey, 0, len(res.Keys))
	for _, k := range res.Keys {
		keys = append(keys, apigen.DeliveredKey{
			Name:           k.Name,
			Classification: apigen.KeyClassification(k.Classification),
			Presence:       apigen.DeliveredKeyPresence(k.Presence),
			// Nil iff presence-only; rendered as the optional `value` member,
			// so absent means no plaintext crossed rather than an empty value.
			Value: k.Value,
		})
	}
	out := apigen.FetchDelivery200JSONResponse{
		Current:        res.Current,
		Cursor:         res.Cursor,
		ChangeToken:    res.ChangeToken,
		SchemaRevision: int(res.SchemaRevision),
		Keys:           keys,
		PinExpired:     res.PinExpired,
	}
	// Finite credential expiry surfaces as the optional member; the zero time
	// is an indefinite credential and stays absent.
	if !res.CredentialExpiresAt.IsZero() {
		expires := res.CredentialExpiresAt
		out.CredentialExpiresAt = &expires
	}
	if res.PinnedRevision > 0 {
		revision := res.PinnedRevision
		out.PinnedRevision = &revision
	}
	return out, nil
}
