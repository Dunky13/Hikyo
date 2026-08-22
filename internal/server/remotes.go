package server

import (
	"context"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// Multi-instance transport (#71). Nothing here relays a request to another
// instance: the directory tier's outbound calls happen in the service layer
// under a pinned connection, and the workspace tier is the browser talking to
// the remote directly. api/noproxy_test.go is what keeps that true over time.

// RemoteService is the viewing side's seam.
type RemoteService interface {
	AddRemote(ctx context.Context, actor service.Actor, name, url, pin, credential string) (service.RemoteView, error)
	ListRemotes(ctx context.Context, actor service.Actor) ([]service.RemoteView, error)
	ShowRemote(ctx context.Context, actor service.Actor, name string) (service.RemoteView, error)
	RenameRemote(ctx context.Context, actor service.Actor, name, newName string) (service.RemoteView, error)
	RemoveRemote(ctx context.Context, actor service.Actor, name string) error
	RemoteOrigins(ctx context.Context) ([]string, error)
}

// WorkspaceService is the serving side's seam.
type WorkspaceService interface {
	Serve(ctx context.Context, actor service.Actor) (remotefetch.Listing, error)
	MintConnection(ctx context.Context, actor service.Actor, label string, req service.MintRequest) (service.MintConnectionResult, error)
	ListConnections(ctx context.Context, actor service.Actor) ([]service.ConnectionView, error)
	ShowConnection(ctx context.Context, actor service.Actor, id string) (service.ConnectionView, error)
	RevokeConnection(ctx context.Context, actor service.Actor, id string) error
	ListOrigins(ctx context.Context, actor service.Actor) ([]service.OriginView, error)
	AddOrigin(ctx context.Context, actor service.Actor, origin string) (service.OriginView, error)
	RemoveOrigin(ctx context.Context, actor service.Actor, origin string) (int64, error)
	OriginAllowed(ctx context.Context, origin string) (bool, error)
	StartHandoff(ctx context.Context, req service.HandoffRequest) (service.HandoffStart, error)
	ShowHandoff(ctx context.Context, actor service.Actor, state string) (service.HandoffView, error)
	ApproveHandoff(ctx context.Context, actor service.Actor, state string) (string, string, error)
	RedeemHandoff(ctx context.Context, code, pkceVerifier, origin string) (service.WorkspaceSession, error)
	ListSessions(ctx context.Context, actor service.Actor) ([]service.SessionView, error)
	RevokeSession(ctx context.Context, actor service.Actor, id string) error
}

// ---------------------------------------------------------------------------
// Serving side.
// ---------------------------------------------------------------------------

func (a *API) ServeDirectory(ctx context.Context, _ apigen.ServeDirectoryRequestObject) (apigen.ServeDirectoryResponseObject, error) {
	l, err := a.Workspace.Serve(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	return apigen.ServeDirectory200JSONResponse(wireListing(l)), nil
}

func (a *API) ListInstanceConnections(ctx context.Context, _ apigen.ListInstanceConnectionsRequestObject) (apigen.ListInstanceConnectionsResponseObject, error) {
	conns, err := a.Workspace.ListConnections(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.InstanceConnection, 0, len(conns))
	for _, c := range conns {
		items = append(items, wireConnection(c))
	}
	return apigen.ListInstanceConnections200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) MintInstanceConnection(ctx context.Context, req apigen.MintInstanceConnectionRequestObject) (apigen.MintInstanceConnectionResponseObject, error) {
	var want service.MintRequest
	if req.Body.LifetimeSeconds != nil {
		want.Lifetime = time.Duration(*req.Body.LifetimeSeconds) * time.Second
	}
	if req.Body.Indefinite != nil {
		want.Indefinite = *req.Body.Indefinite
	}
	res, err := a.Workspace.MintConnection(ctx, service.Bearer(bearer(ctx)), req.Body.Label, want)
	if err != nil {
		return nil, err
	}
	return apigen.MintInstanceConnection201JSONResponse{
		Value: res.Value, Connection: wireConnection(res.Connection), Clamped: res.Clamped,
	}, nil
}

func (a *API) ShowInstanceConnection(ctx context.Context, req apigen.ShowInstanceConnectionRequestObject) (apigen.ShowInstanceConnectionResponseObject, error) {
	c, err := a.Workspace.ShowConnection(ctx, service.Bearer(bearer(ctx)), req.Connection)
	if err != nil {
		return nil, err
	}
	return apigen.ShowInstanceConnection200JSONResponse(wireConnection(c)), nil
}

func (a *API) RevokeInstanceConnection(ctx context.Context, req apigen.RevokeInstanceConnectionRequestObject) (apigen.RevokeInstanceConnectionResponseObject, error) {
	if err := a.Workspace.RevokeConnection(ctx, service.Bearer(bearer(ctx)), req.Connection); err != nil {
		return nil, err
	}
	return apigen.RevokeInstanceConnection204Response{}, nil
}

func (a *API) ListWorkspaceOrigins(ctx context.Context, _ apigen.ListWorkspaceOriginsRequestObject) (apigen.ListWorkspaceOriginsResponseObject, error) {
	origins, err := a.Workspace.ListOrigins(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.WorkspaceOrigin, 0, len(origins))
	for _, o := range origins {
		items = append(items, apigen.WorkspaceOrigin{
			Origin: o.Origin, CreatedAt: o.CreatedAt, CreatedBy: string(o.CreatedBy),
		})
	}
	return apigen.ListWorkspaceOrigins200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) AddWorkspaceOrigin(ctx context.Context, req apigen.AddWorkspaceOriginRequestObject) (apigen.AddWorkspaceOriginResponseObject, error) {
	o, err := a.Workspace.AddOrigin(ctx, service.Bearer(bearer(ctx)), req.Body.Origin)
	if err != nil {
		return nil, err
	}
	return apigen.AddWorkspaceOrigin201JSONResponse{
		Origin: o.Origin, CreatedAt: o.CreatedAt, CreatedBy: string(o.CreatedBy),
	}, nil
}

// RemoveWorkspaceOrigin takes the origin in the BODY, never in the path. A path
// parameter naming an origin is one review lapse away from a path parameter
// naming a target, and api/noproxy_test.go refuses that shape by name.
func (a *API) RemoveWorkspaceOrigin(ctx context.Context, req apigen.RemoveWorkspaceOriginRequestObject) (apigen.RemoveWorkspaceOriginResponseObject, error) {
	killed, err := a.Workspace.RemoveOrigin(ctx, service.Bearer(bearer(ctx)), req.Body.Origin)
	if err != nil {
		return nil, err
	}
	return apigen.RemoveWorkspaceOrigin200JSONResponse{
		Origin: req.Body.Origin, SessionsRevoked: int(killed),
	}, nil
}

// ---------------------------------------------------------------------------
// The handoff. Pre-authentication, in the auth-protocol exception class.
// ---------------------------------------------------------------------------

func (a *API) StartWorkspaceHandoff(ctx context.Context, req apigen.StartWorkspaceHandoffRequestObject) (apigen.StartWorkspaceHandoffResponseObject, error) {
	release, err := a.enterWorkspaceAdmission(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	r := service.HandoffRequest{
		Origin:        req.Body.Origin,
		RedirectURI:   req.Body.RedirectUri,
		PKCEChallenge: req.Body.PkceChallenge,
		Purpose:       service.HandoffPurpose(req.Body.Purpose),
	}
	if req.Body.Session != nil {
		r.SessionID = *req.Body.Session
	}
	if r.Purpose == service.HandoffEstablishment {
		if req.Body.Session != nil || req.Body.Operation != nil || req.Body.Environment != nil || req.Body.KeySet != nil {
			return nil, fmt.Errorf("%w: an establishment carries no step-up binding", domain.ErrInvalid)
		}
	} else if r.Purpose == service.HandoffStepUp {
		if req.Body.Session == nil || req.Body.Operation == nil || req.Body.Environment == nil {
			return nil, fmt.Errorf("%w: a step-up requires session, operation and environment", domain.ErrInvalid)
		}
		var keyIDs []string
		if req.Body.KeySet != nil {
			keyIDs = append(keyIDs, (*req.Body.KeySet)...)
		}
		intent, intentErr := service.NewDisclosureReauthIntent(service.ReauthPurpose(*req.Body.Operation), []string{*req.Body.Environment}, keyIDs)
		if intentErr != nil {
			return nil, fmt.Errorf("%w: invalid workspace step-up intent", domain.ErrInvalid)
		}
		purpose, purposeErr := intent.Purpose()
		if purposeErr != nil || purpose == service.PurposeMint {
			return nil, fmt.Errorf("%w: invalid workspace step-up intent", domain.ErrInvalid)
		}
		r.ReauthIntent = &intent
	}
	started, err := a.Workspace.StartHandoff(ctx, r)
	if err != nil {
		return nil, err
	}
	return apigen.StartWorkspaceHandoff201JSONResponse{
		Handoff: started.HandoffID, State: started.State, ExpiresAt: started.ExpiresAt,
	}, nil
}

func (a *API) ShowWorkspaceHandoff(ctx context.Context, req apigen.ShowWorkspaceHandoffRequestObject) (apigen.ShowWorkspaceHandoffResponseObject, error) {
	view, err := a.Workspace.ShowHandoff(ctx, service.Bearer(bearer(ctx)), req.State)
	if err != nil {
		policy := workspaceHandoffLookupWireErrorFor(err)
		switch policy.code {
		case apigen.ErrorCodeUnauthenticated:
			return apigen.ShowWorkspaceHandoff401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(
					policy.body(err),
				),
			}, nil
		case apigen.ErrorCodeNotFound:
			// A not-found or expired/consumed transaction is a 404, not a 403: to a
			// caller holding a stale state the answer is "there is no such live
			// transaction", uniformly, whichever of those it is.
			return apigen.ShowWorkspaceHandoff404JSONResponse{
				NotFoundJSONResponse: apigen.NotFoundJSONResponse(
					policy.body(err),
				),
			}, nil
		}
		return nil, err
	}
	keyIDs := make([]apigen.ID, 0, len(view.KeySet))
	for _, k := range view.KeySet {
		keyIDs = append(keyIDs, apigen.ID(k))
	}
	resp := apigen.ShowWorkspaceHandoff200JSONResponse{
		State:     req.State,
		Purpose:   apigen.WorkspaceHandoffTransactionPurpose(view.Purpose),
		KeyIds:    keyIDs,
		ExpiresAt: view.ExpiresAt,
	}
	if view.Operation != "" {
		op := apigen.WorkspaceHandoffTransactionOperation(view.Operation)
		resp.Operation = &op
	}
	if view.EnvID != "" {
		env := apigen.ID(view.EnvID)
		resp.Environment = &env
	}
	return resp, nil
}

func (a *API) ApproveWorkspaceHandoff(ctx context.Context, req apigen.ApproveWorkspaceHandoffRequestObject) (apigen.ApproveWorkspaceHandoffResponseObject, error) {
	code, redirect, err := a.Workspace.ApproveHandoff(ctx, service.Bearer(bearer(ctx)), req.Body.State)
	if err != nil {
		return nil, err
	}
	return apigen.ApproveWorkspaceHandoff200JSONResponse{Code: code, RedirectUri: redirect}, nil
}

func (a *API) RedeemWorkspaceHandoff(ctx context.Context, req apigen.RedeemWorkspaceHandoffRequestObject) (apigen.RedeemWorkspaceHandoffResponseObject, error) {
	release, err := a.enterWorkspaceAdmission(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	ws, err := a.Workspace.RedeemHandoff(ctx, req.Body.Code, req.Body.PkceVerifier, req.Body.Origin)
	if err != nil {
		return nil, err
	}
	out := apigen.RedeemWorkspaceHandoff201JSONResponse{
		Value: ws.Value, Session: ws.SessionID, Origin: ws.Origin, Handoff: ws.HandoffID,
		IdleExpiresAt: ws.IdleExpiresAt, AbsoluteExpiresAt: ws.AbsoluteExpiresAt,
	}
	if ws.Elevated {
		elevated, env, window := true, ws.EnvironmentID, ws.WindowExpiresAt
		out.Elevated, out.Environment, out.WindowExpiresAt = &elevated, &env, &window
	}
	return out, nil
}

// enterWorkspaceAdmission keeps both unauthenticated transaction-writing
// handoff endpoints inside the shared pre-authentication resource budget.
// Nil remains the test-only unlimited mode used by API seam tests.
func (a *API) enterWorkspaceAdmission(ctx context.Context) (func(), error) {
	if a.Admission == nil {
		return func() {}, nil
	}
	return a.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
}

// ---------------------------------------------------------------------------
// The active-session surface (criterion 5).
// ---------------------------------------------------------------------------

func (a *API) ListMySessions(ctx context.Context, _ apigen.ListMySessionsRequestObject) (apigen.ListMySessionsResponseObject, error) {
	sessions, err := a.Workspace.ListSessions(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		if wireErrorFor(err).code == apigen.ErrorCodeUnauthenticated {
			return apigen.ListMySessions401JSONResponse{
				UnauthenticatedJSONResponse: apigen.UnauthenticatedJSONResponse(errorBody(apigen.ErrorCodeUnauthenticated, "")),
			}, nil
		}
		return nil, err
	}
	items := make([]apigen.ActiveSession, 0, len(sessions))
	for _, s := range sessions {
		item := apigen.ActiveSession{
			Id: s.ID, Artifact: apigen.ActiveSessionArtifact(s.Artifact),
			AuthMethod: s.AuthMethod, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt,
			IdleExpiresAt: s.IdleExpiresAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt,
		}
		if s.SourceIP != "" {
			item.SourceIp = &s.SourceIP
		}
		if s.UserAgent != "" {
			ua := s.UserAgent
			item.UserAgent = &ua
		}
		if s.RequestingOrigin != "" {
			o := s.RequestingOrigin
			item.RequestingOrigin = &o
		}
		if s.HandoffID != "" {
			h := s.HandoffID
			item.Handoff = &h
		}
		items = append(items, item)
	}
	return apigen.ListMySessions200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) RevokeMySession(ctx context.Context, req apigen.RevokeMySessionRequestObject) (apigen.RevokeMySessionResponseObject, error) {
	if err := a.Workspace.RevokeSession(ctx, service.Bearer(bearer(ctx)), req.Session); err != nil {
		return nil, err
	}
	return apigen.RevokeMySession204Response{}, nil
}

// ---------------------------------------------------------------------------
// Viewing side.
// ---------------------------------------------------------------------------

func (a *API) ListRemotes(ctx context.Context, _ apigen.ListRemotesRequestObject) (apigen.ListRemotesResponseObject, error) {
	views, err := a.Remotes.ListRemotes(ctx, service.Bearer(bearer(ctx)))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Remote, 0, len(views))
	for _, v := range views {
		items = append(items, wireRemote(v))
	}
	return apigen.ListRemotes200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) AddRemote(ctx context.Context, req apigen.AddRemoteRequestObject) (apigen.AddRemoteResponseObject, error) {
	v, err := a.Remotes.AddRemote(ctx, service.Bearer(bearer(ctx)),
		req.Body.Name, req.Body.Url, req.Body.SpkiPin, req.Body.Credential)
	if err != nil {
		return nil, err
	}
	return apigen.AddRemote201JSONResponse(wireRemote(v)), nil
}

func (a *API) ShowRemote(ctx context.Context, req apigen.ShowRemoteRequestObject) (apigen.ShowRemoteResponseObject, error) {
	v, err := a.Remotes.ShowRemote(ctx, service.Bearer(bearer(ctx)), req.Remote)
	if err != nil {
		return nil, err
	}
	return apigen.ShowRemote200JSONResponse(wireRemote(v)), nil
}

func (a *API) RenameRemote(ctx context.Context, req apigen.RenameRemoteRequestObject) (apigen.RenameRemoteResponseObject, error) {
	v, err := a.Remotes.RenameRemote(ctx, service.Bearer(bearer(ctx)), req.Remote, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.RenameRemote200JSONResponse(wireRemote(v)), nil
}

func (a *API) RemoveRemote(ctx context.Context, req apigen.RemoveRemoteRequestObject) (apigen.RemoveRemoteResponseObject, error) {
	if err := a.Remotes.RemoveRemote(ctx, service.Bearer(bearer(ctx)), req.Remote); err != nil {
		return nil, err
	}
	return apigen.RemoveRemote204Response{}, nil
}

func wireListing(l remotefetch.Listing) apigen.DirectoryListing {
	orgs := make([]apigen.DirectoryOrg, 0, len(l.Orgs))
	for _, o := range l.Orgs {
		projects := o.Projects
		if projects == nil {
			projects = []string{}
		}
		orgs = append(orgs, apigen.DirectoryOrg{Name: o.Name, Projects: projects})
	}
	return apigen.DirectoryListing{
		Identity: l.Identity, Version: l.Version, Orgs: orgs,
		OrgCount: l.OrgCount, ProjectCount: l.ProjectCount,
	}
}

func wireConnection(c service.ConnectionView) apigen.InstanceConnection {
	out := apigen.InstanceConnection{
		Id: c.ID, Principal: string(c.Principal), Label: c.Label,
		Kind:       apigen.CredentialKind(c.Kind),
		PrefixHint: c.PrefixHint,
		Lifetime:   apigen.CredentialLifetime(c.Lifetime),
		CreatedAt:  c.CreatedAt, CreatedBy: string(c.CreatedBy), Live: c.Live,
	}
	if !c.ExpiresAt.IsZero() {
		t := c.ExpiresAt
		out.ExpiresAt = &t
	}
	if !c.RevokedAt.IsZero() {
		t := c.RevokedAt
		out.RevokedAt = &t
	}
	if !c.LastUsedAt.IsZero() {
		t := c.LastUsedAt
		out.LastUsedAt = &t
	}
	return out
}

func wireRemote(v service.RemoteView) apigen.Remote {
	out := apigen.Remote{
		Id: v.ID, Name: v.Name, Url: v.URL, SpkiPin: v.SPKIPin,
		CreatedAt: v.CreatedAt, CreatedBy: string(v.CreatedBy),
		State:         apigen.RemoteState(v.State),
		LastAttemptAt: v.LastAttemptAt,
		Stale:         v.Stale,
	}
	if !v.ObservedAt.IsZero() {
		t := v.ObservedAt
		out.ObservedAt = &t
	}
	if v.Stale {
		secs := int(v.StaleFor / time.Second)
		out.StaleForSeconds = &secs
	}
	if v.Identity != "" {
		id := v.Identity
		out.Identity = &id
	}
	if v.Version != "" {
		ver := v.Version
		out.Version = &ver
	}
	orgCount, projectCount := int(v.OrgCount), int(v.ProjectCount)
	out.OrgCount, out.ProjectCount = &orgCount, &projectCount
	if v.Orgs != nil {
		orgs := make([]apigen.DirectoryOrg, 0, len(v.Orgs))
		for _, o := range v.Orgs {
			projects := o.Projects
			if projects == nil {
				projects = []string{}
			}
			orgs = append(orgs, apigen.DirectoryOrg{Name: o.Name, Projects: projects})
		}
		out.Orgs = &orgs
	}
	return out
}
