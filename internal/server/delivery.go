package server

import (
	"context"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/service"
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
// There is nothing else here to get wrong. The response type has no value
// member, the cursor is a string the handler neither builds nor parses, and the
// scope is the path.

// DeliveryService is the domain surface this transport exposes.
type DeliveryService interface {
	Fetch(ctx context.Context, presented string, scope domain.Scope, cursor string) (service.FetchResult, error)
}

func (a *API) FetchDelivery(ctx context.Context, req apigen.FetchDeliveryRequestObject) (apigen.FetchDeliveryResponseObject, error) {
	cursor := ""
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	scope := domain.Scope{
		Org: domain.OrgID(req.Org), Project: domain.ProjectID(req.Project),
		Env: domain.EnvID(req.Environment),
	}
	res, err := a.Delivery.Fetch(ctx, bearer(ctx), scope, cursor)
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
		})
	}
	return apigen.FetchDelivery200JSONResponse{
		Current:        res.Current,
		Cursor:         res.Cursor,
		ChangeToken:    res.ChangeToken,
		SchemaRevision: int(res.SchemaRevision),
		Keys:           keys,
	}, nil
}
