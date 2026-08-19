package server

import (
	"context"

	"github.com/Hikyo-Org/hikyo/api/apigen"
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
// The cursor is a string the handler neither builds nor parses; values and
// snapshot assertions are mapped from the service's authorized result.

// DeliveryService is the domain surface this transport exposes.
type DeliveryService interface {
	FetchMode(ctx context.Context, presented string, scope domain.Scope, cursor string, configOnly bool) (service.FetchResult, error)
	ReconcileOfflineRecords(ctx context.Context, presented string, scope domain.Scope, records []service.OfflineRecord) (service.ReconcileResult, error)
}

func (a *API) FetchDelivery(ctx context.Context, req apigen.FetchDeliveryRequestObject) (apigen.FetchDeliveryResponseObject, error) {
	cursor := ""
	if req.Params.Cursor != nil {
		cursor = *req.Params.Cursor
	}
	configOnly := false
	if req.Params.ConfigOnly != nil {
		configOnly = *req.Params.ConfigOnly
	}
	scope := domain.Scope{
		Org: domain.OrgID(req.Org), Project: domain.ProjectID(req.Project),
		Env: domain.EnvID(req.Environment),
	}
	res, err := a.Delivery.FetchMode(ctx, bearer(ctx), scope, cursor, configOnly)
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
			Value:          k.Value,
		})
	}
	out := apigen.FetchDelivery200JSONResponse{
		Current:           res.Current,
		Cursor:            res.Cursor,
		ChangeToken:       res.ChangeToken,
		SchemaRevision:    int(res.SchemaRevision),
		Keys:              keys,
		PinExpired:        res.PinExpired,
		IssuedAt:          res.IssuedAt,
		SnapshotExpiresAt: res.SnapshotExpiresAt,
	}
	if res.PinnedRevision > 0 {
		revision := res.PinnedRevision
		out.PinnedRevision = &revision
	}
	return out, nil
}

func (a *API) ReconcileOfflineRecords(ctx context.Context, req apigen.ReconcileOfflineRecordsRequestObject) (apigen.ReconcileOfflineRecordsResponseObject, error) {
	scope := domain.Scope{
		Org: domain.OrgID(req.Org), Project: domain.ProjectID(req.Project),
		Env: domain.EnvID(req.Environment),
	}
	records := make([]service.OfflineRecord, 0, len(req.Body.Records))
	for _, record := range req.Body.Records {
		records = append(records, service.OfflineRecord{
			RecordID: record.RecordId, KeyID: record.KeyId, KeyName: record.KeyName,
			Classification: string(record.Classification), OccurredAt: record.OccurredAt,
			CredentialID: record.CredentialId, Generation: record.Generation,
			ServedFrom: record.ServedFrom,
		})
	}
	res, err := a.Delivery.ReconcileOfflineRecords(ctx, bearer(ctx), scope, records)
	if err != nil {
		return nil, err
	}
	return apigen.ReconcileOfflineRecords200JSONResponse{
		Accepted: res.Accepted, Duplicates: res.Duplicates,
	}, nil
}
