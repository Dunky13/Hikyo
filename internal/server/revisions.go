package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The revision transport (#51). Like every other file here it TRANSLATES and
// decides nothing; the two shapes worth reading twice are both disclosure
// boundaries:
//
//   - a signal cell emits `pending_version_id` only for the caller's OWN
//     draft. Another principal's draft flips `pending_by_others` and supplies
//     nothing else, because write-presence is the whole of what it may say.
//   - an exported value emits `value` only when the service says it was
//     revealed, so an unrevealed `secret` is a row with no value member rather
//     than an empty string a client could not tell from an empty value.

// heartbeat is the SSE keep-alive interval. Streams are not proxy-transparent
// by default -- intermediaries impose idle timeouts and nginx buffers
// responses unless told otherwise -- so the stream sends a comment on this
// interval to hold the connection open and to notice a dead peer.
const (
	heartbeat          = 20 * time.Second
	advisoryRetryBase  = 2 * time.Second
	advisoryRetryRange = time.Second
)

// RevisionService is the domain surface this transport exposes.
type RevisionService interface {
	PublishPlanned(ctx context.Context, actor service.Actor, scope domain.Scope, request service.PublishRequest) (service.PublishResult, error)
	Restore(ctx context.Context, actor service.Actor, scope domain.Scope, revision int64, keyName string) (service.RestoreResult, error)
	History(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.RevisionView, error)
	Show(ctx context.Context, actor service.Actor, scope domain.Scope, revision int64) (service.RevisionDetail, error)
	Signals(ctx context.Context, actor service.Actor, scope domain.Scope) (service.EnvironmentSignals, error)
	Export(ctx context.Context, actor service.Actor, scope domain.Scope, revision int64, reveal bool) ([]service.ExportedValue, int64, error)
	Watch(ctx context.Context, actor service.Actor, scope domain.Scope) (<-chan service.AdvisoryEvent, error)
	RotateTokenKey(ctx context.Context, actor service.Actor) (service.TokenKeyRotation, error)
}

type PinService interface {
	Set(ctx context.Context, actor service.Actor, scope domain.Scope, request service.SetPinRequest) (service.SetPinResult, error)
	List(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.PinView, error)
	Release(ctx context.Context, actor service.Actor, scope domain.Scope, workloadPrincipalID domain.PrincipalID) error
}

func (a *API) PublishPendingChanges(ctx context.Context, req apigen.PublishPendingChangesRequestObject) (apigen.PublishPendingChangesResponseObject, error) {
	previewToken := ""
	if req.Body.PreviewToken != nil {
		previewToken = *req.Body.PreviewToken
	}
	confirmedProtected := []string{}
	if req.Body.ConfirmedProtectedEnvironments != nil {
		confirmedProtected = make([]string, 0, len(*req.Body.ConfirmedProtectedEnvironments))
		for _, envID := range *req.Body.ConfirmedProtectedEnvironments {
			confirmedProtected = append(confirmedProtected, string(envID))
		}
	}
	result, err := a.Revisions.PublishPlanned(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), service.PublishRequest{
			VersionIDs:                     req.Body.VersionIds,
			PreviewToken:                   previewToken,
			ConfirmedProtectedEnvironments: confirmedProtected,
		})
	if err != nil {
		return nil, err
	}
	out := apigen.PublishResult{
		Published: emptyIfNil(result.Published),
		ClosedIn:  emptyIfNil(result.ClosedIn),
	}
	for _, env := range result.Environments {
		out.Environments = append(out.Environments, apigen.PublishedEnvironment{
			EnvironmentId:  env.EnvironmentID,
			Revision:       env.Revision,
			SchemaRevision: env.SchemaRevision,
			ChangeToken:    env.ChangeToken,
			ChangedKeys:    wireChangedKeys(env.ChangedKeys),
		})
	}
	if out.Environments == nil {
		out.Environments = []apigen.PublishedEnvironment{}
	}
	return apigen.PublishPendingChanges200JSONResponse(out), nil
}

// emptyIfNil keeps a list-shaped field `[]` rather than JSON null: "nothing was
// closed in" is a fact the server knows exactly, and null would read as
// "unknown".
func emptyIfNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func wirePending(changes []service.StagedChange) []apigen.PendingChange {
	out := make([]apigen.PendingChange, 0, len(changes))
	for _, change := range changes {
		out = append(out, apigen.PendingChange{
			VersionId: change.VersionID, KeyId: change.KeyID, Name: change.Name,
			Classification:     apigen.KeyClassification(change.Classification),
			Operation:          apigen.PendingChangeOperation(change.Operation),
			StagedFromRevision: change.StagedFromRevision, CreatedAt: change.CreatedAt,
		})
	}
	return out
}

func (a *API) RollbackRevision(ctx context.Context, req apigen.RollbackRevisionRequestObject) (apigen.RollbackRevisionResponseObject, error) {
	key := ""
	if req.Body != nil && req.Body.Key != nil {
		key = string(*req.Body.Key)
	}
	result, err := a.Revisions.Restore(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), req.Revision, key)
	if err != nil {
		return nil, err
	}
	return apigen.RollbackRevision200JSONResponse(apigen.RollbackResult{
		Revision: result.Revision, Changes: wirePending(result.Changes), Preview: wireImpactPreview(result.Preview),
	}), nil
}

func wireImpactPreview(preview service.ImpactPreview) apigen.ImpactPreview {
	out := apigen.ImpactPreview{Token: preview.Token, Environments: []apigen.ImpactEnvironment{}}
	for _, env := range preview.Environments {
		wireEnv := apigen.ImpactEnvironment{
			EnvironmentId: env.EnvironmentID, BaseRevision: env.BaseRevision,
			SchemaRevision: env.SchemaRevision, Protected: env.Protected,
			Changes: []apigen.ImpactChange{},
		}
		for _, change := range env.Changes {
			wireEnv.Changes = append(wireEnv.Changes, apigen.ImpactChange{
				VersionId: change.VersionID, KeyId: change.KeyID, Name: change.Name,
				Classification: apigen.KeyClassification(change.Classification),
				Operation:      apigen.ImpactChangeOperation(change.Operation), Status: apigen.ImpactChangeStatus(change.Status),
				Before: change.Before, After: change.After,
			})
		}
		out.Environments = append(out.Environments, wireEnv)
	}
	return out
}

func wirePin(pin service.PinView) apigen.RevisionPin {
	return apigen.RevisionPin{
		Id: pin.ID, WorkloadPrincipalId: pin.WorkloadPrincipalID,
		Revision: pin.Revision, AuthorityPrincipalId: pin.AuthorityPrincipalID,
		ExpiresAt: pin.ExpiresAt, CreatedAt: pin.CreatedAt, AuthorizedAt: pin.AuthorizedAt,
		HistoryAuthorized: pin.HistoryAuthorized,
		SchemaOverride:    pin.SchemaOverride, Expired: pin.Expired,
	}
}

func (a *API) CreateRevisionPin(ctx context.Context, req apigen.CreateRevisionPinRequestObject) (apigen.CreateRevisionPinResponseObject, error) {
	request := service.SetPinRequest{
		WorkloadPrincipalID: domain.PrincipalID(req.Body.WorkloadPrincipalId), Revision: req.Body.Revision,
		OverrideSchema: derefBool(req.Body.OverrideSchema),
	}
	if req.Body.ExpiresAt != nil {
		request.ExpiresAt = *req.Body.ExpiresAt
	}
	result, err := a.Pins.Set(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), request)
	if err != nil {
		return nil, err
	}
	return apigen.CreateRevisionPin200JSONResponse(apigen.RevisionPinResult{
		Action: apigen.RevisionPinResultAction(result.Action), Pin: wirePin(result.Pin),
	}), nil
}

func (a *API) ListRevisionPins(ctx context.Context, req apigen.ListRevisionPinsRequestObject) (apigen.ListRevisionPinsResponseObject, error) {
	pins, err := a.Pins.List(ctx, service.Bearer(bearer(ctx)), envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.RevisionPin, 0, len(pins))
	for _, pin := range pins {
		items = append(items, wirePin(pin))
	}
	return apigen.ListRevisionPins200JSONResponse(apigen.RevisionPinList{Items: items, Count: len(items)}), nil
}

func (a *API) ReleaseRevisionPin(ctx context.Context, req apigen.ReleaseRevisionPinRequestObject) (apigen.ReleaseRevisionPinResponseObject, error) {
	if err := a.Pins.Release(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), domain.PrincipalID(req.WorkloadPrincipal)); err != nil {
		return nil, err
	}
	return apigen.ReleaseRevisionPin204Response{}, nil
}

func wireChangedKeys(changes []service.ChangedKey) []apigen.ChangedKey {
	out := make([]apigen.ChangedKey, 0, len(changes))
	for _, change := range changes {
		out = append(out, apigen.ChangedKey{
			KeyId: change.KeyID, Name: change.Name,
			Change: apigen.ChangedKeyChange(change.Change),
		})
	}
	return out
}

func (a *API) ListRevisions(ctx context.Context, req apigen.ListRevisionsRequestObject) (apigen.ListRevisionsResponseObject, error) {
	history, err := a.Revisions.History(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Revision, 0, len(history))
	for _, rev := range history {
		items = append(items, apigen.Revision{
			Revision: rev.Revision, SchemaRevision: rev.SchemaRevision,
			PublishedBy: rev.PublishedBy, PublishedAt: rev.PublishedAt,
			ChangedKeys: wireChangedKeys(rev.ChangedKeys),
		})
	}
	return apigen.ListRevisions200JSONResponse(apigen.RevisionList{
		Items: items, Count: len(items),
	}), nil
}

func (a *API) GetRevision(ctx context.Context, req apigen.GetRevisionRequestObject) (apigen.GetRevisionResponseObject, error) {
	revision, err := parseRevision(req.Revision)
	if err != nil {
		return nil, err
	}
	detail, err := a.Revisions.Show(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), revision)
	if err != nil {
		return nil, err
	}
	keys := make([]apigen.SnapshotKey, 0, len(detail.Keys))
	for _, key := range detail.Keys {
		keys = append(keys, apigen.SnapshotKey{
			KeyId: key.KeyID, Name: key.Name,
			Classification: apigen.KeyClassification(key.Classification),
		})
	}
	return apigen.GetRevision200JSONResponse(apigen.RevisionDetail{
		Revision: detail.Revision, SchemaRevision: detail.SchemaRevision,
		PublishedBy: detail.PublishedBy, PublishedAt: detail.PublishedAt,
		ChangedKeys: wireChangedKeys(detail.ChangedKeys),
		ChangeToken: detail.ChangeToken, Keys: keys,
	}), nil
}

// parseRevision reads the path segment, which is a number or the literal
// `latest`. 0 means latest to the service.
func parseRevision(raw string) (int64, error) {
	if raw == "latest" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: a revision is a positive number or `latest`", domain.ErrInvalid)
	}
	return n, nil
}

func (a *API) GetEnvironmentSignals(ctx context.Context, req apigen.GetEnvironmentSignalsRequestObject) (apigen.GetEnvironmentSignalsResponseObject, error) {
	signals, err := a.Revisions.Signals(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	cells := make([]apigen.CellSignal, 0, len(signals.Cells))
	for _, cell := range signals.Cells {
		wire := apigen.CellSignal{
			KeyId: cell.KeyID, Name: cell.Name,
			Classification:  apigen.KeyClassification(cell.Classification),
			PendingByOthers: cell.PendingByOthers,
		}
		if cell.PendingVersionID != "" {
			versionID := cell.PendingVersionID
			operation := apigen.CellSignalPendingOperation(cell.PendingOperation)
			wire.PendingVersionId = &versionID
			wire.PendingOperation = &operation
		}
		if cell.ChangedInRevision > 0 {
			changed := cell.ChangedInRevision
			wire.ChangedInRevision = &changed
		}
		cells = append(cells, wire)
	}
	return apigen.GetEnvironmentSignals200JSONResponse(apigen.EnvironmentSignals{
		EnvironmentId: signals.EnvironmentID, Revision: signals.Revision, Cells: cells,
	}), nil
}

func (a *API) ExportValues(ctx context.Context, req apigen.ExportValuesRequestObject) (apigen.ExportValuesResponseObject, error) {
	var revision int64
	var reveal bool
	if req.Body != nil {
		if req.Body.Revision != nil {
			revision = *req.Body.Revision
		}
		reveal = derefBool(req.Body.Reveal)
	}
	values, served, err := a.Revisions.Export(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), revision, reveal)
	if err != nil {
		return nil, err
	}
	items := make([]apigen.ExportedValue, 0, len(values))
	for _, value := range values {
		item := apigen.ExportedValue{
			Name: value.Name, Classification: apigen.KeyClassification(value.Classification),
			Revealed: value.Revealed,
		}
		if value.Revealed {
			plain := value.Value
			item.Value = &plain
		}
		items = append(items, item)
	}
	return apigen.ExportValues200JSONResponse(apigen.ExportedValues{
		Revision: served, Items: items, Count: len(items),
	}), nil
}

func (a *API) RotateTokenKey(ctx context.Context, _ apigen.RotateTokenKeyRequestObject) (apigen.RotateTokenKeyResponseObject, error) {
	rotation, err := a.Revisions.RotateTokenKey(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	return apigen.RotateTokenKey200JSONResponse(apigen.TokenKeyRotation{
		TokenKeyVersion: int64(rotation.Version),
	}), nil
}

// WatchProjectEvents streams the advisory channel.
//
// The events arrive already authorized and already projected -- the service
// evaluates the per-event, per-object check before anything reaches this
// channel -- so this function does transport and nothing else: headers,
// framing, flushing, heartbeats, and giving up when the peer goes away.
func (a *API) WatchProjectEvents(ctx context.Context, req apigen.WatchProjectEventsRequestObject) (apigen.WatchProjectEventsResponseObject, error) {
	events, err := a.Revisions.Watch(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	retry := advisoryRetryBase + time.Duration(rand.Int64N(int64(advisoryRetryRange)))
	return eventStream{ctx: ctx, events: events, retry: retry}, nil
}

type eventStream struct {
	ctx    context.Context
	events <-chan service.AdvisoryEvent
	retry  time.Duration
}

func (s eventStream) VisitWatchProjectEventsResponse(w http.ResponseWriter) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Without a flusher every event would sit in a buffer until the
		// response ended, which for a stream is never. Loud rather than
		// silently useless.
		return fmt.Errorf("server: the advisory stream needs a flushing response writer")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	// no-cache and no proxy buffering: an intermediary that buffers a stream
	// turns it into a hang, and one that caches it turns it into a lie.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, "retry: %d\n\n", s.retry.Milliseconds()); err != nil {
		return nil
	}
	flusher.Flush()

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return nil
		case <-ticker.C:
			// A comment line: valid SSE, ignored by every client, and enough
			// to defeat an idle timeout and to notice a dead peer.
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return nil
			}
			flusher.Flush()
		case ev, ok := <-s.events:
			if !ok {
				// The subscriber fell behind or the instance is shutting down.
				// Ending the response is the right answer: the client
				// reconnects and refetches, and nothing was lost that the
				// signals endpoint cannot supply.
				return nil
			}
			payload, err := json.Marshal(wireAdvisory(ev))
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload); err != nil {
				return nil
			}
			flusher.Flush()
		}
	}
}

// wireAdvisory is the event body: metadata only. There is no value field and
// no change-token field, and there must never be one.
func wireAdvisory(ev service.AdvisoryEvent) map[string]any {
	out := map[string]any{
		"type":           ev.Type,
		"environment_id": ev.EnvironmentID,
	}
	if ev.KeyID != "" {
		out["key_id"] = ev.KeyID
		out["name"] = ev.KeyName
	}
	if ev.Revision > 0 {
		out["revision"] = ev.Revision
	}
	if ev.ActorID != "" {
		out["actor_id"] = ev.ActorID
	}
	return out
}
