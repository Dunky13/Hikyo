package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The multi-instance SERVING side (#71): the directory this instance serves,
// the credentials that reach it, the origin allowlist, and the workspace
// handoff.
//
// The workspace tier's one structural rule, from which everything else here
// follows: THE BROWSER TALKS TO THIS INSTANCE DIRECTLY. Nothing in this file
// proxies anything. The viewing instance's server contributes a shell and a
// deep link; the session, the calls and the values are between the human's
// browser and this server.

var (
	// ErrOriginNotAllowed is a handoff attempted from an origin this instance
	// has not consented to. It is refused at the TRANSACTION, not merely at
	// CORS: CORS controls what a browser may read, never what a token may do.
	// It wraps ErrUnauthorized so the transport answers 403 rather than a
	// fault: the caller IS refused, and a 500 would read as "we broke".
	ErrOriginNotAllowed = fmt.Errorf("%w: that origin is not on the workspace allowlist", domain.ErrUnauthorized)
	// ErrHandoffInvalid is the uniform refusal for every unusable handoff:
	// unknown, expired, already consumed, or presented with the wrong verifier.
	// One error for all of them deliberately — distinguishing them would be an
	// oracle for transactions in flight.
	// Uniform 403, like the origin refusal: an unusable handoff must not be
	// distinguishable from a refused one, and neither is a server fault.
	ErrHandoffInvalid = fmt.Errorf("%w: the handoff transaction is not valid", domain.ErrUnauthorized)
	// ErrConnectionRevoked is a revoke of a connection already revoked.
	ErrConnectionRevoked = fmt.Errorf("%w: that connection credential is already revoked", domain.ErrConflict)
)

// Workspace is the serving side's service.
type Workspace struct {
	DB *store.DB
	// Version is this build's version string, served in the directory listing.
	// It is injected rather than read from internal/app because app imports
	// service; a display string is not worth an import cycle. Empty is
	// tolerated: the listing's version field is DISPLAY-ONLY and never feeds a
	// compatibility decision — the shell reads meta live for that.
	Version string
	// Reauth is the human-auth service, consulted for one thing only: the
	// per-environment reauthentication bounds a step-up elevation opens its
	// window under. It is the concrete service rather than an interface
	// because there is exactly one, and duplicating the effective-window
	// resolution here is how a lowered environment ends up honoured on one
	// path and not the other.
	Reauth *Auth
	Now    func() time.Time
}

func (s *Workspace) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// ---------------------------------------------------------------------------
// The directory this instance serves.
// ---------------------------------------------------------------------------

// Serve builds the authenticated directory listing.
//
// What the connection credential authorizes, exhaustively: instance identity,
// version, and the NAMES and counts of orgs and projects. No values, no keys,
// no environments, no membership, no settings, no audit — and there is no
// field on remotefetch.Listing that could carry one.
//
// The listing is an INSTANCE-SCOPE READ CROSSING ORG BOUNDARIES BY DESIGN,
// which is why it is its own registered operation served under an InstanceProof
// rather than a tenant read repeated per org. Project names come from ONE
// instance-scoped query: looping per org would mint N tenant proofs for one
// operation and misreport it in the boundary check.
func (s *Workspace) Serve(ctx context.Context, actor Actor) (remotefetch.Listing, error) {
	now := s.now()
	var out remotefetch.Listing
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteDirectoryServe, domain.Scope{})
		if err != nil {
			return err
		}
		identity, err := az.InstanceIdentity(ctx)
		if err != nil {
			return err
		}
		orgs, err := r.Orgs().List(ctx, p)
		if err != nil {
			return err
		}
		projects, err := r.Projects().ListAll(ctx, p)
		if err != nil {
			return err
		}
		byOrg := map[string][]string{}
		for _, pr := range projects {
			byOrg[pr.OrgID] = append(byOrg[pr.OrgID], pr.Name)
		}
		out = remotefetch.Listing{Identity: identity, Version: s.Version}
		for _, o := range orgs {
			names := byOrg[o.ID]
			sort.Strings(names)
			out.Orgs = append(out.Orgs, remotefetch.OrgEntry{Name: o.Name, Projects: names})
		}
		// Derived here, once, from the names being sent — never counted
		// separately, or the two could disagree in the same response.
		out.OrgCount, out.ProjectCount = len(out.Orgs), out.CountProjects()

		// The last-used stamp is what an operator reads before revoking a
		// connection: "is anyone still using this".
		//
		// NO ROW is the ordinary case: a human holding `instance-directory`
		// reaches this listing too, and no connection names them. Any OTHER
		// error is a database fault and fails loud — swallowing it would stamp
		// nothing, audit an empty actor, and look exactly like the human case.
		connID, label := "", ""
		conn, cerr := az.InstanceConnectionByPrincipal(ctx, caller.Principal)
		switch {
		case cerr == nil:
			connID, label = conn.ID, conn.Label
			if err := az.TouchInstanceConnection(ctx, conn.ID, now); err != nil {
				return err
			}
		case !errors.Is(cerr, domain.ErrNotFound):
			return cerr
		}
		// The actor is whoever authenticated, and the CLASS says which kind
		// they are: an instance-connection credential (the foreign
		// installation's fetch) or a human holding `instance-directory` through
		// the UI. Both reach this operation legitimately; recording only the
		// first would leave the second's reads of foreign structure unattributed.
		e, err := domainEvent(ctx, audit.EventRemoteDirectoryServed, caller.Principal,
			audit.Object{Type: "instance_connection", ID: connID}, audit.Payload{
				"connection_id": connID, "label": label,
				"principal_class": string(callerClass(caller)),
				"org_count":       out.OrgCount, "project_count": out.ProjectCount,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Connection credentials: `remote-credential create|list|show|revoke`.
// ---------------------------------------------------------------------------

// ConnectionView is one connection's metadata. There is no value field and no
// query that selects one: a credential is display-once at mint and write-only
// after.
type ConnectionView struct {
	ID         string
	Principal  domain.PrincipalID
	Label      string
	Kind       domain.CredentialKind
	PrefixHint string
	Lifetime   domain.CredentialLifetime
	ExpiresAt  time.Time
	CreatedAt  time.Time
	CreatedBy  domain.PrincipalID
	RevokedAt  time.Time
	LastUsedAt time.Time
	Live       bool
}

// MintConnectionResult carries the one and only disclosure of the value.
type MintConnectionResult struct {
	Value      string
	Connection ConnectionView
	Clamped    bool
}

// MintConnection creates the principal, its single credential and its single
// `instance-directory` grant AS ONE UNIT, in one transaction.
//
// One credential per principal, ever. Rotation is a new create and a revoke of
// the predecessor, never a second credential on this row — which is why revoke
// retires the principal with the credential and no orphan can accumulate.
//
// The grant is written at the STORE layer by this minter and not through the
// grants API, so the grants API's mintable-origin set is untouched. The class
// allowlist is what makes the grant safe: `instance-connection` may hold
// exactly `instance-directory` and nothing else, and the grants API refuses to
// attach that capability to a machine principal by hand.
func (s *Workspace) MintConnection(ctx context.Context, actor Actor, label string, req MintRequest) (MintConnectionResult, error) {
	if label == "" {
		return MintConnectionResult{}, fmt.Errorf("%w: a label naming the intended peer is required", domain.ErrInvalid)
	}
	if req.Lifetime < 0 {
		return MintConnectionResult{}, ErrCredentialLifetime
	}
	connID, err := newID("icn")
	if err != nil {
		return MintConnectionResult{}, err
	}
	principalID, err := newID("mch")
	if err != nil {
		return MintConnectionResult{}, err
	}
	grantID, err := newID("grn")
	if err != nil {
		return MintConnectionResult{}, err
	}
	now := s.now()
	var out MintConnectionResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteCredentialCreate, domain.Scope{})
		if err != nil {
			return err
		}
		if err := az.LockCredentialPolicy(ctx); err != nil {
			return err
		}
		policy, err := az.CredentialPolicy(ctx)
		if err != nil {
			return err
		}
		lifetime, expires, clamped, err := resolveLifetime(req, policy, now)
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		value, verifier, err := crypto.NewArtifact(crypto.ArtifactInstanceConn)
		if err != nil {
			return err
		}
		hint, err := prefixHint(value)
		if err != nil {
			return err
		}
		pid := domain.PrincipalID(principalID)
		if err := az.CreateMachinePrincipal(ctx, pid, domain.ClassInstanceConn, now); err != nil {
			return err
		}
		if err := az.CreateGrant(ctx, grantID, pid, domain.Grant{
			Capability: domain.CapInstanceDirector, Scope: domain.Scope{},
		}, now); err != nil {
			return err
		}
		if err := az.MintInstanceConnection(ctx, authz.NewInstanceConnection{
			ID: connID, PrincipalID: pid, Label: label,
			Kind: domain.CredentialHikyoToken, Verifier: verifier, PrefixHint: hint,
			Lifetime: lifetime, ExpiresAt: expires, CredentialEpoch: epoch,
			CreatedAt: now, CreatedBy: caller.Principal,
		}); err != nil {
			return err
		}
		out = MintConnectionResult{
			Value:   value,
			Clamped: clamped,
			Connection: ConnectionView{
				ID: connID, Principal: pid, Label: label,
				Kind: domain.CredentialHikyoToken, PrefixHint: hint,
				Lifetime: lifetime, ExpiresAt: expires,
				CreatedAt: now, CreatedBy: caller.Principal, Live: true,
			},
		}
		payload := audit.Payload{
			"connection_id": connID, "target_principal": principalID, "label": label,
			"credential_kind": string(domain.CredentialHikyoToken),
			"lifetime":        string(lifetime), "clamped": clamped,
		}
		if lifetime == domain.LifetimeFinite {
			payload["expires_at"] = expires.Format(time.RFC3339)
		}
		e, err := domainEvent(ctx, audit.EventRemoteCredentialMinted, caller.Principal,
			audit.Object{Type: "instance_connection", ID: connID}, payload)
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	if err != nil {
		return MintConnectionResult{}, err
	}
	return out, nil
}

// ListConnections is metadata only. It is audited rather than `audited: none`
// because reading which foreign installations may read this one's directory is
// not a bare tenant read — the audit-model ADR's default-deny refuses the permit.
func (s *Workspace) ListConnections(ctx context.Context, actor Actor) ([]ConnectionView, error) {
	now := s.now()
	var out []ConnectionView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteCredentialList, domain.Scope{})
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		conns, err := az.InstanceConnections(ctx)
		if err != nil {
			return err
		}
		out = make([]ConnectionView, 0, len(conns))
		for _, c := range conns {
			out = append(out, connectionView(c, now, epoch))
		}
		e, err := domainEvent(ctx, audit.EventRemoteCredentialsListed, caller.Principal,
			audit.Object{Type: "instance_connection", ID: ""}, audit.Payload{"row_count": len(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// ShowConnection is one connection's metadata.
func (s *Workspace) ShowConnection(ctx context.Context, actor Actor, id string) (ConnectionView, error) {
	now := s.now()
	var out ConnectionView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteCredentialShow, domain.Scope{})
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		conn, err := az.InstanceConnectionByID(ctx, id)
		if err != nil {
			return err
		}
		out = connectionView(conn, now, epoch)
		e, err := domainEvent(ctx, audit.EventRemoteCredentialsListed, caller.Principal,
			audit.Object{Type: "instance_connection", ID: id}, audit.Payload{"row_count": 1})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// RevokeConnection kills the credential and retires the principal with it. It
// bites at the NEXT presentation: the liveness predicate is read in the
// authenticating transaction, uncached, so there is no window in which a
// revoked connection still serves a listing.
func (s *Workspace) RevokeConnection(ctx context.Context, actor Actor, id string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteCredentialRevoke, domain.Scope{})
		if err != nil {
			return err
		}
		conn, err := az.InstanceConnectionByID(ctx, id)
		if err != nil {
			return err
		}
		did, err := az.RevokeInstanceConnection(ctx, id, now)
		if err != nil {
			return err
		}
		if !did {
			// A double revoke is a no-op the caller can SEE, not a silent
			// success that would put a second event on the trail for an act
			// that did not happen.
			return ErrConnectionRevoked
		}
		e, err := domainEvent(ctx, audit.EventRemoteCredentialRevoked, caller.Principal,
			audit.Object{Type: "instance_connection", ID: id}, audit.Payload{
				"connection_id": id, "target_principal": string(conn.PrincipalID),
				"label": conn.Label,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
}

func connectionView(c authz.InstanceConnection, now time.Time, epoch int64) ConnectionView {
	return ConnectionView{
		ID: c.ID, Principal: c.PrincipalID, Label: c.Label, Kind: c.Kind,
		PrefixHint: c.PrefixHint, Lifetime: c.Lifetime, ExpiresAt: c.ExpiresAt,
		CreatedAt: c.CreatedAt, CreatedBy: c.CreatedBy, RevokedAt: c.RevokedAt,
		LastUsedAt: c.LastUsedAt, Live: c.Live(now, epoch),
	}
}

// ---------------------------------------------------------------------------
// The origin allowlist.
// ---------------------------------------------------------------------------

// OriginView is one allowlist entry as the transport sees it. The service
// owns this shape rather than handing out the store's carrier: the
// import-boundary rule is that only this package names resolution-surface
// types, and a transport that could name one could build one.
type OriginView struct {
	Origin    string
	CreatedAt time.Time
	CreatedBy domain.PrincipalID
}

// HandoffPurpose is the closed two-member set, re-exported for the transport.
type HandoffPurpose = authz.HandoffPurpose

// The two members, re-exported with it.
const (
	HandoffEstablishment = authz.HandoffEstablishment
	HandoffStepUp        = authz.HandoffStepUp
)

// ListOrigins is the consent list.
func (s *Workspace) ListOrigins(ctx context.Context, actor Actor) ([]OriginView, error) {
	now := s.now()
	var out []OriginView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpWorkspaceOriginList, domain.Scope{})
		if err != nil {
			return err
		}
		rows, err := az.WorkspaceOrigins(ctx)
		if err != nil {
			return err
		}
		out = make([]OriginView, 0, len(rows))
		for _, row := range rows {
			out = append(out, OriginView{
				Origin: row.Origin, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy,
			})
		}
		e, err := domainEvent(ctx, audit.EventRemoteOriginAllowlistRead, caller.Principal,
			audit.Object{Type: "workspace_origin", ID: ""}, audit.Payload{"row_count": len(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// AddOrigin consents to one EXACT origin, and RETURNS the entry it wrote.
//
// Returning it is not a convenience: the transport's 201 body needs the
// canonical origin and its provenance, and the only alternative — calling
// ListOrigins straight after — authorizes a second time and puts a spurious
// `remote.origin_allowlist_read` on the trail for an add nobody asked to read.
func (s *Workspace) AddOrigin(ctx context.Context, actor Actor, origin string) (OriginView, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return OriginView{}, err
	}
	now := s.now()
	var out OriginView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpWorkspaceOriginAdd, domain.Scope{})
		if err != nil {
			return err
		}
		if err := az.AllowWorkspaceOrigin(ctx, authz.WorkspaceOrigin{
			Origin: canonical, CreatedAt: now, CreatedBy: caller.Principal,
		}); err != nil {
			return err
		}
		out = OriginView{Origin: canonical, CreatedAt: now, CreatedBy: caller.Principal}
		e, err := domainEvent(ctx, audit.EventRemoteOriginAllowlistChanged, caller.Principal,
			audit.Object{Type: "workspace_origin", ID: canonical}, audit.Payload{
				"origin": canonical, "change": "added", "sessions_revoked": 0,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	if err != nil {
		return OriginView{}, err
	}
	return out, nil
}

// RemoveOrigin is the KILL SWITCH. Removing the entry and revoking every
// workspace session bound to it happen in ONE transaction, which is what makes
// de-allowlisting a real kill switch rather than a headers change: there is no
// window in which the origin is de-allowlisted and its sessions still
// authenticate.
func (s *Workspace) RemoveOrigin(ctx context.Context, actor Actor, origin string) (int64, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return 0, err
	}
	now := s.now()
	var killed int64
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpWorkspaceOriginRemove, domain.Scope{})
		if err != nil {
			return err
		}
		existed, err := az.RemoveWorkspaceOrigin(ctx, canonical)
		if err != nil {
			return err
		}
		if !existed {
			return store.ErrNotFound
		}
		killed, err = az.RevokeWorkspaceSessionsForOrigin(ctx, canonical)
		if err != nil {
			return err
		}
		e, err := domainEvent(ctx, audit.EventRemoteOriginAllowlistChanged, caller.Principal,
			audit.Object{Type: "workspace_origin", ID: canonical}, audit.Payload{
				"origin": canonical, "change": "removed", "sessions_revoked": int(killed),
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertInstance(ctx, p, e); err != nil {
			return err
		}
		// One event for the sweep, not one per session: the sessions are gone
		// and their ids are with them, and the count is the fact an incident
		// review acts on.
		rev, err := domainEvent(ctx, audit.EventRemoteWorkspaceSessionRevoked, caller.Principal,
			audit.Object{Type: "workspace_origin", ID: canonical}, audit.Payload{
				"session_id": "", "origin": canonical, "cause": "origin-removed",
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, rev)
	})
	return killed, err
}

// OriginAllowed is the pre-authentication membership check CORS and handoff
// issuance both consult. It runs in its own read transaction and takes no
// actor: it is consulted BEFORE anyone is authenticated, which is the whole
// point of an allowlist.
func (s *Workspace) OriginAllowed(ctx context.Context, origin string) (bool, error) {
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return false, nil
	}
	var ok bool
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var e error
		ok, e = az.WorkspaceOriginAllowed(ctx, canonical)
		return e
	})
	return ok, err
}

// CanonicalOrigin normalizes and validates an origin to scheme://host[:port].
//
// A path, query, fragment or userinfo is REFUSED rather than stripped: an
// allowlist entry is an exact origin, and silently normalizing one is how an
// operator ends up trusting something other than what they typed.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%w: origin does not parse", domain.ErrInvalid)
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return "", fmt.Errorf("%w: an origin must be http or https", domain.ErrInvalid)
	case u.Host == "":
		return "", fmt.Errorf("%w: an origin must name a host", domain.ErrInvalid)
	case u.User != nil:
		return "", fmt.Errorf("%w: an origin must not carry userinfo", domain.ErrInvalid)
	case u.Path != "" && u.Path != "/":
		return "", fmt.Errorf("%w: an origin must not carry a path", domain.ErrInvalid)
	case u.RawQuery != "" || u.Fragment != "":
		return "", fmt.Errorf("%w: an origin must not carry a query or fragment", domain.ErrInvalid)
	case strings.Contains(u.Host, "*"):
		return "", fmt.Errorf("%w: wildcards are not origins", domain.ErrInvalid)
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

// ---------------------------------------------------------------------------
// The handoff transaction and the workspace session.
// ---------------------------------------------------------------------------

// HandoffRequest opens a transaction. Purpose alone licenses an establishment;
// a step-up additionally binds the initiating session, the exact operation, and
// — where the operation is key-scoped — the environment and key set, so an
// elevated consent cannot be replayed against a different one.
type HandoffRequest struct {
	Origin        string
	RedirectURI   string
	PKCEChallenge string
	Purpose       HandoffPurpose
	SessionID     string
	ReauthIntent  *ReauthIntent
}

// HandoffStart is what the shell needs to open the popup: the transaction's
// opaque state value, which crosses the front channel.
type HandoffStart struct {
	HandoffID string
	State     string
	ExpiresAt time.Time
}

// StartHandoff opens a single-use transaction bound to an allowlisted origin.
//
// It is PRE-AUTHENTICATION: no session exists yet for an establishment, and the
// step-up case authenticates inside the popup on this instance's own origin.
// The allowlist is the gate, and it is checked here rather than only at CORS
// because CORS binds browsers, not tokens.
func (s *Workspace) StartHandoff(ctx context.Context, req HandoffRequest) (HandoffStart, error) {
	canonical, err := CanonicalOrigin(req.Origin)
	if err != nil {
		return HandoffStart{}, err
	}
	if !validPKCEChallenge(req.PKCEChallenge) {
		return HandoffStart{}, fmt.Errorf("%w: a PKCE S256 challenge must be 43 canonical base64url characters", domain.ErrInvalid)
	}
	// The redirect URI's authority IS the allowlist entry: a callback that
	// does not live at the consented origin is not the consented code.
	if !strings.HasPrefix(req.RedirectURI, canonical+"/") && req.RedirectURI != canonical {
		return HandoffStart{}, fmt.Errorf("%w: the callback must live at the allowlisted origin", domain.ErrInvalid)
	}
	var operation, envID, keySet string
	switch req.Purpose {
	case authz.HandoffEstablishment:
		if req.SessionID != "" || req.ReauthIntent != nil {
			return HandoffStart{}, fmt.Errorf("%w: an establishment binds no session and no operation", domain.ErrInvalid)
		}
	case authz.HandoffStepUp:
		if req.SessionID == "" || req.ReauthIntent == nil {
			return HandoffStart{}, fmt.Errorf("%w: a step-up binds the initiating session and the exact operation", domain.ErrInvalid)
		}
		intent := *req.ReauthIntent
		adapter, err := intent.isAdapter()
		if err != nil {
			return HandoffStart{}, err
		}
		unbound, err := intent.isUnbound()
		if err != nil {
			return HandoffStart{}, err
		}
		if adapter || unbound || len(intent.EnvironmentIDs()) != 1 {
			return HandoffStart{}, fmt.Errorf("%w: a workspace step-up requires one disclosure intent", domain.ErrInvalid)
		}
		binding, err := intent.bindingFor("")
		if err != nil {
			return HandoffStart{}, err
		}
		if binding.purpose == PurposeMint {
			return HandoffStart{}, fmt.Errorf("%w: a workspace step-up requires reveal, copy, or publish", domain.ErrInvalid)
		}
		operation, envID, keySet = string(binding.operation), binding.environmentID, binding.keySet
	default:
		return HandoffStart{}, fmt.Errorf("%w: unknown handoff purpose %q", domain.ErrInvalid, req.Purpose)
	}

	id, err := newID("hnd")
	if err != nil {
		return HandoffStart{}, err
	}
	state, stateVerifier, err := crypto.NewArtifact(crypto.ArtifactHandoffState)
	if err != nil {
		return HandoffStart{}, err
	}
	now := s.now()
	expires := now.Add(remotefetch.HandoffExpiry)
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		allowed, err := az.WorkspaceOriginAllowed(ctx, canonical)
		if err != nil {
			return err
		}
		if !allowed {
			// The refusal is audited on the settlement path: this return rolls
			// the transaction back, so an in-transaction insert would lose the
			// one record an operator needs to see a foreign origin probing.
			e, err := newAuditEvent(ctx, audit.EventRemoteHandoffFailed, "",
				audit.Object{Type: "workspace_handoff", ID: id},
				audit.OutcomeFailure, "", audit.Payload{
					"handoff_id": id, "origin": canonical,
					"stage": "start", "cause": "origin-not-allowed",
				})
			if err != nil {
				return err
			}
			az.CaptureAudit(audit.TrailInstance, domain.Scope{}, e)
			return ErrOriginNotAllowed
		}
		// Opportunistic housekeeping, not a correctness mechanism: an expired
		// transaction is refused by the clock check whether or not its row is
		// still here. There is no poller, and the ADR's no-job-framework rule
		// stands.
		if _, err := az.SweepExpiredWorkspaceHandoffs(ctx, now); err != nil {
			return err
		}
		return az.CreateWorkspaceHandoff(ctx, authz.NewWorkspaceHandoff{
			ID: id, StateVerifier: stateVerifier, Origin: canonical,
			RedirectURI: req.RedirectURI, PKCEChallenge: req.PKCEChallenge,
			Purpose: req.Purpose, SessionID: req.SessionID, Operation: operation,
			EnvID: envID, KeySet: keySet, CreatedAt: now, ExpiresAt: expires,
		})
	})
	if err != nil {
		return HandoffStart{}, err
	}
	return HandoffStart{HandoffID: id, State: state, ExpiresAt: expires}, nil
}

// ApproveHandoff binds the authenticated human and mints the authorization
// code. The human authenticated in the popup, on THIS instance's origin, with
// THIS instance's own ceremonies — which is why the actor here is an ordinary
// session of this instance and not anything the viewing side supplied.
//
// The front channel receives code and state only. The artifact never crosses
// a redirect.
func (s *Workspace) ApproveHandoff(ctx context.Context, actor Actor, state string) (code string, redirectURI string, err error) {
	if err := crypto.ParseArtifact(state, crypto.ArtifactHandoffState); err != nil {
		return "", "", ErrHandoffInvalid
	}
	now := s.now()
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		// The popup's human is a full session of this instance, so the
		// human-session surface (Authenticate, not AuthenticateCaller) is the
		// right door — a workspace bearer must not be able to approve the
		// issuance of another workspace bearer.
		caller, err := az.Authenticate(ctx, actor.bearer, now)
		if err != nil {
			return err
		}
		h, err := az.WorkspaceHandoffByState(ctx, crypto.ArtifactVerifier(state))
		if err != nil {
			return s.handoffFailure(ctx, az, caller.Principal, "", "", "callback", "unknown-transaction")
		}
		if !h.Live(now) {
			return s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "expired-or-consumed")
		}
		allowed, err := az.WorkspaceOriginAllowed(ctx, h.Origin)
		if err != nil {
			return err
		}
		if !allowed {
			// The origin was de-allowlisted while the popup was open. New
			// handoffs refuse at the transaction — that is the ADR's wording,
			// and this is the moment it means.
			return s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "origin-removed")
		}
		value, verifier, err := crypto.NewArtifact(crypto.ArtifactHandoffCode)
		if err != nil {
			return err
		}
		// The assurance record travels with the transaction, not with a later
		// lookup of the approving session: what the workspace session must
		// inherit is what the human DEMONSTRATED in this popup, and the session
		// that demonstrated it may be revoked, rotated or logged out by the time
		// the code is redeemed minutes later.
		// A STEP-UP additionally requires a FRESH CEREMONY, completed as part of
		// this approval. Inheriting the factors an approving session recorded at
		// login would make "step up" mean "be logged in", which is exactly the
		// elevation the ADR does not want: a human who authenticated with MFA
		// days ago must touch an authenticator again before a foreign shell may
		// reveal anything. Freshness is measured against the transaction's own
		// creation time, so the ceremony demonstrably happened AFTER the popup
		// asked for it.
		demonstrated := caller.Assurance.Factors
		var factorClass string
		if h.Purpose == authz.HandoffStepUp {
			factorClass, err = s.freshCeremonyClass(ctx, az, caller, h, now)
			if err != nil {
				return err
			}
			// The ceremony's class JOINS the record, because the human really
			// did just demonstrate it. A reauthentication does not rewrite the
			// session's own factors (`ReauthTOTP` rotates the bearer and leaves
			// the record alone), so without this a password login plus a live
			// TOTP ceremony would read as single-factor — under-recording an
			// assurance the human actually met.
			demonstrated = withFactor(demonstrated, factorClass)
		}
		factors, err := json.Marshal(demonstrated)
		if err != nil {
			return err
		}
		claimed, err := az.ApproveWorkspaceHandoff(ctx, h.ID, verifier, caller.Principal, string(factors), factorClass)
		if err != nil {
			return err
		}
		if !claimed {
			return s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "already-approved")
		}
		code, redirectURI = value, h.RedirectURI
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return code, redirectURI, nil
}

// HandoffView is a live handoff transaction's step-up policy as the remote's
// approve page reads it: the operation, environment and enumerated key set the
// transaction was opened against. Identifiers only — never a value, a bearer or
// a verifier.
type HandoffView struct {
	Purpose   HandoffPurpose
	Operation string
	EnvID     string
	KeySet    []string
	ExpiresAt time.Time
}

// ShowHandoff returns the step-up policy a live transaction binds, so the
// approve page can name the operation, environment and exact key set to this
// instance's own reauthentication ceremony rather than trusting them from its
// URL — the key set can be large, and a URL is the wrong place for the
// authoritative binding to live.
//
// It READS, it does not consume, and it answers only the authenticated human on
// this instance (the approve page always has that session for a step-up). What
// it returns are identifiers; a stolen state would leak env and key ids, never
// values, and only for the transaction's few live minutes.
func (s *Workspace) ShowHandoff(ctx context.Context, actor Actor, state string) (HandoffView, error) {
	if err := crypto.ParseArtifact(state, crypto.ArtifactHandoffState); err != nil {
		return HandoffView{}, ErrHandoffInvalid
	}
	now := s.now()
	var out HandoffView
	// A write transaction, not a read: the successful read is AUDITED
	// (remote.workspace_handoff_read), which the audit ADR forces for an
	// authenticated instance-class read of ceremony state — a caller can read
	// then close the popup, so no approval or issuance event subsumes it.
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		// A human session on THIS instance, or nothing (401).
		caller, err := az.Authenticate(ctx, actor.bearer, now)
		if err != nil {
			return err
		}
		h, err := az.WorkspaceHandoffByState(ctx, crypto.ArtifactVerifier(state))
		if err != nil {
			return ErrHandoffInvalid
		}
		// ONLY a step-up is readable here. An establishment binds no session, so
		// there is nothing to anchor ownership on — and the approve page never
		// reads one (it shows an establishment its plain Authorize button). A
		// bare establishment state presented here is treated as not found.
		if h.Purpose != authz.HandoffStepUp {
			return ErrHandoffInvalid
		}
		if !h.Live(now) {
			return ErrHandoffInvalid
		}
		// OWNERSHIP, and it is the whole point of the endpoint's security.
		// `StartHandoff` is pre-authentication, so anyone may open a step-up
		// transaction naming ANY session id; resolving that bound session within
		// the CALLER's own sessions is what stops one human — or one tenant —
		// reading another's bound environment and enumerated key set from a
		// leaked state. The refusal is the SAME `ErrHandoffInvalid` (a 404) as an
		// unknown state, so the endpoint never distinguishes "not yours" from
		// "not there". Mirrors the ownership check `elevate` performs at
		// redemption, moved earlier so a read cannot outrun it.
		rows, err := az.SessionsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		owned := false
		for _, row := range rows {
			if row.ID == h.SessionID {
				owned = true
				break
			}
		}
		if !owned {
			return ErrHandoffInvalid
		}
		intent, err := newReauthIntentForOperation(authz.Operation(h.Operation), h.EnvID, splitKeySet(h.KeySet))
		if err != nil {
			return ErrHandoffInvalid
		}
		binding, err := intent.bindingFor("")
		if err != nil || string(binding.operation) != h.Operation || binding.keySet != h.KeySet {
			return ErrHandoffInvalid
		}
		out = HandoffView{
			Purpose:   h.Purpose,
			Operation: string(binding.purpose),
			EnvID:     h.EnvID,
			KeySet:    []string{},
			ExpiresAt: h.ExpiresAt,
		}
		if h.KeySet != "" {
			out.KeySet = splitKeySet(h.KeySet)
		}
		// The trail records THAT this human read the transaction's shape, keyed
		// by the handoff id — never the key set, the environment or any value.
		e, err := domainEvent(ctx, audit.EventRemoteWorkspaceHandoffRead, caller.Principal,
			audit.Object{Type: "workspace_handoff", ID: h.ID},
			audit.Payload{"handoff_id": h.ID, "origin": h.Origin})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return HandoffView{}, err
	}
	return out, nil
}

// freshCeremonyClass is the step-up approval's factor-verification gate. It
// returns the class of the reauthentication the approving human completed
// INSIDE this popup, or a refusal.
//
// It reads the #54 reauthentication window on the APPROVING session over the
// environment the transaction bound — the same row TOTP, OIDC and WebAuthn
// reauth each write when their ceremony verifies, so this gate is satisfied by
// a real factor verification through the product's own ceremonies and by
// nothing else. Three predicates, all fail-closed:
//
//   - the window exists over (approving session, bound environment);
//   - it is live at the current credential epoch and both clocks;
//   - its ceremony happened AT OR AFTER the transaction was created, which is
//     what makes it FRESH rather than inherited. A window opened for an earlier
//     disclosure is not consent for this one.
//
// The environment conjunct matters as much as the freshness one: a ceremony
// over staging must not license an elevation over production.
func (s *Workspace) freshCeremonyClass(
	ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity,
	h authz.WorkspaceHandoff, now time.Time,
) (string, error) {
	if h.EnvID == "" {
		return "", s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "step-up-not-environment-scoped")
	}
	w, err := az.ReauthWindowFor(ctx, caller.SessionID, h.EnvID)
	if errors.Is(err, domain.ErrNotFound) {
		return "", s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "step-up-no-fresh-ceremony")
	}
	if err != nil {
		return "", err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return "", err
	}
	if w.CredentialEpoch != epoch || !now.Before(w.HardExpiresAt) || !now.Before(w.WindowExpiresAt) {
		return "", s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "step-up-ceremony-lapsed")
	}
	if w.AuthenticatedAt.Before(h.CreatedAt) {
		return "", s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "step-up-ceremony-stale")
	}
	if w.FactorClass == "" {
		return "", s.handoffFailure(ctx, az, caller.Principal, h.ID, h.Origin, "callback", "step-up-ceremony-classless")
	}
	return w.FactorClass, nil
}

// WorkspaceSession is a redeemed workspace bearer. The value is returned once
// and lives in the shell's JS MEMORY ONLY — never a cookie, never localStorage
// or sessionStorage, gone on tab close.
type WorkspaceSession struct {
	Value             string
	SessionID         string
	Origin            string
	HandoffID         string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	// Elevated is set when this redemption ELEVATED the session it was bound to
	// rather than establishing a new one. The id is the same session's; the
	// value is that same session's rotated bearer, not a second one.
	Elevated bool
	// EnvironmentID and WindowExpiresAt describe the reauthentication window the
	// elevation opened. Both are empty on an establishment.
	EnvironmentID   string
	WindowExpiresAt time.Time
}

// RedeemHandoff exchanges code + PKCE verifier for a workspace session.
//
// The session row is a `sessions` row in every locked mechanical respect —
// fast-hash verifier, artifact type, generation binding, credential epoch, idle
// and absolute clocks — differing only in transport and in its two bound
// extras. That is not a shortcut: it is what makes explicit revocation,
// grant-change invalidation, generation bumps, account disablement and restore
// inertness apply to a workspace session for free and structurally.
//
// The CSRF verifier is nil, like a CLI session's: the bearer rides an
// Authorization header, nothing is ambient, and demanding a synchronizer token
// on a non-cookie transport would be theatre.
func (s *Workspace) RedeemHandoff(ctx context.Context, code, pkceVerifier, origin string) (WorkspaceSession, error) {
	if !validPKCEVerifier(pkceVerifier) {
		return WorkspaceSession{}, fmt.Errorf("%w: a PKCE verifier must be 43-128 canonical base64url characters", domain.ErrInvalid)
	}
	if err := crypto.ParseArtifact(code, crypto.ArtifactHandoffCode); err != nil {
		return WorkspaceSession{}, ErrHandoffInvalid
	}
	canonical, err := CanonicalOrigin(origin)
	if err != nil {
		return WorkspaceSession{}, err
	}
	sessionID, err := newID("ses")
	if err != nil {
		return WorkspaceSession{}, err
	}
	now := s.now()
	var out WorkspaceSession
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		h, err := az.WorkspaceHandoffByCode(ctx, crypto.ArtifactVerifier(code))
		if err != nil {
			return s.handoffFailure(ctx, az, "", "", canonical, "redeem", "unknown-code")
		}
		if !h.Live(now) {
			return s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", "expired-or-consumed")
		}
		if h.Origin != canonical {
			return s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", "origin-mismatch")
		}
		if h.PrincipalID == "" {
			return s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", "never-approved")
		}
		if pkceS256(pkceVerifier) != h.PKCEChallenge {
			return s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", "pkce-mismatch")
		}
		// The allowlist check is taken UNDER THE ENTRY'S OWN ROW LOCK and held
		// through the mint below. Postgres runs READ COMMITTED, so a plain read
		// here would let RemoveOrigin delete the entry and sweep its sessions
		// between this check and the insert, committing a live workspace session
		// for an origin nobody consents to any more — the kill switch would have
		// a hole exactly the width of one redemption. The lock makes the two
		// transactions order: whichever commits second sees the other's work.
		allowed, err := az.LockWorkspaceOrigin(ctx, h.Origin)
		if err != nil {
			return err
		}
		if !allowed {
			return s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", "origin-removed")
		}
		// Single-use, claimed atomically: two concurrent redemptions of one
		// code cannot both yield a session.
		claimed, err := az.ConsumeWorkspaceHandoff(ctx, h.ID, now)
		if err != nil {
			return err
		}
		if !claimed {
			return s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", "already-consumed")
		}

		if h.Purpose == authz.HandoffStepUp {
			// A STEP-UP ELEVATES the session it bound; it never mints a second
			// one. Minting would hand the shell a fresh full-lifetime bearer per
			// elevated operation, which is the opposite of an elevation.
			elevated, err := s.elevate(ctx, az, h, now)
			if err != nil {
				return err
			}
			out = elevated
			return nil
		}

		generation, err := az.PrincipalGeneration(ctx, h.PrincipalID)
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		value, verifier, err := crypto.NewArtifact(crypto.ArtifactWorkspaceSession)
		if err != nil {
			return err
		}
		idle := now.Add(remotefetch.WorkspaceSessionIdle)
		absolute := now.Add(remotefetch.WorkspaceSessionAbsolute)
		wire := audit.FromContext(ctx)
		if err := az.MintSession(ctx, authz.NewSession{
			ID: sessionID, PrincipalID: h.PrincipalID, Verifier: verifier,
			// The DATABASE artifact string, not the bearer-grammar type. The
			// two are different strings on purpose and confusing them is the
			// trap that makes an eligibility row inert.
			Artifact:          workspaceArtifact,
			SessionGeneration: generation, CredentialEpoch: epoch,
			AuthMethod: "workspace-handoff",
			// The assurance record the human DEMONSTRATED in the popup, on this
			// instance's origin, carried across the two requests by the
			// transaction row (migration 00020). Minting "[]" here — which is
			// what this did before — made every workspace session permanently
			// single-factor and structurally unable to reach any MFA-mandatory
			// operation, whatever ceremony the human had just performed.
			Factors:         h.Factors,
			AuthenticatedAt: now, CeremonyID: h.ID, CreatedAt: now,
			IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
			SourceIP: wire.SourceIP, UserAgent: wire.UserAgent,
			RequestingOrigin: h.Origin, HandoffID: h.ID,
		}); err != nil {
			return err
		}
		out = WorkspaceSession{
			Value: value, SessionID: sessionID, Origin: h.Origin, HandoffID: h.ID,
			IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
		}
		e, err := domainEvent(ctx, audit.EventRemoteWorkspaceSessionIssued, h.PrincipalID,
			audit.Object{Type: "session", ID: sessionID}, audit.Payload{
				"session_id": sessionID, "origin": h.Origin,
				"handoff_id": h.ID, "purpose": string(h.Purpose),
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return WorkspaceSession{}, err
	}
	return out, nil
}

// elevate is the step-up half of redemption: it opens a reauthentication window
// over the environment the transaction bound, on the workspace session the
// transaction bound, and rotates that session's bearer to carry the assurance
// the human just demonstrated. It runs INSIDE the redeeming transaction, after
// the single-use claim, so a refused elevation consumes the code exactly as a
// refused establishment does.
//
// Why rotation rather than a factors-only update: this is the same act the
// human-side step-up performs (`RotateSessionFactors`), and the verifier swap
// is the point — a bearer stolen BEFORE the elevation must not become an
// elevated bearer after it. The session id, its clocks and its origin binding
// are untouched, so it is still one session; only the value the shell holds in
// memory changes, and the redemption response is where it gets the new one.
func (s *Workspace) elevate(
	ctx context.Context, az *authz.TxAuthorizer, h authz.WorkspaceHandoff, now time.Time,
) (WorkspaceSession, error) {
	fail := func(cause string) (WorkspaceSession, error) {
		return WorkspaceSession{}, s.handoffFailure(ctx, az, h.PrincipalID, h.ID, h.Origin, "redeem", cause)
	}
	if s.Reauth == nil {
		// Not a caller error and not an oracle: a build wired without the
		// human-auth service cannot elevate anything, and pretending otherwise
		// would open a window with invented bounds.
		return WorkspaceSession{}, fmt.Errorf("service: the workspace surface has no reauthentication seam wired")
	}
	if h.EnvID == "" {
		// The only elevation mechanism this product has is a per-environment
		// reauthentication window, so a step-up that named no environment has
		// nothing to elevate. Refused by name rather than silently succeeding
		// into a window nobody can consume.
		return fail("step-up-not-environment-scoped")
	}
	intent, err := newReauthIntentForOperation(authz.Operation(h.Operation), h.EnvID, splitKeySet(h.KeySet))
	if err != nil {
		return fail("step-up-binding-invalid")
	}
	binding, err := intent.bindingFor("")
	if err != nil || string(binding.operation) != h.Operation || binding.keySet != h.KeySet {
		return fail("step-up-binding-invalid")
	}
	var factors []string
	if err := json.Unmarshal([]byte(h.Factors), &factors); err != nil {
		return fail("step-up-assurance-unreadable")
	}
	// The class is the FRESH ceremony recorded at approval, never
	// reauthFactorClass(h.Factors): the second reads what the approving session
	// once demonstrated, which is the inherited assurance this path exists to
	// refuse. Empty means either no fresh ceremony was recorded or the row
	// predates the gate (a rolling deployment can leave one) — both refuse.
	class := h.FactorClass
	if class == "" {
		return fail("step-up-no-fresh-ceremony")
	}
	if !authz.AdequateAssurance(authz.Assurance{Factors: factors}) {
		// An elevation must be at least as strong as the ordinary step-up it
		// stands in for. A popup the human walked through with a password alone
		// has demonstrated nothing the workspace session did not already have.
		return fail("step-up-assurance-inadequate")
	}

	// The bound session is looked up UNDER THE APPROVING PRINCIPAL, and that is
	// the security check the shape exists for: `StartHandoff` is
	// pre-authentication, so anyone may open a step-up transaction naming any
	// session id. Resolving the id within the approver's own sessions is what
	// stops a stolen workspace bearer from being elevated with the thief's
	// factors.
	rows, err := az.SessionsForPrincipal(ctx, h.PrincipalID)
	if err != nil {
		return WorkspaceSession{}, err
	}
	var target authz.SessionSummary
	for _, row := range rows {
		if row.ID == h.SessionID {
			target = row
		}
	}
	switch {
	case target.ID == "":
		return fail("step-up-session-unknown")
	case target.Artifact != workspaceArtifact:
		// A step-up handoff elevates a workspace session. Elevating a browser
		// or CLI session through a cross-origin popup would put the viewing
		// origin in the path of the human's own same-origin session.
		return fail("step-up-not-a-workspace-session")
	case target.RequestingOrigin != h.Origin:
		return fail("step-up-origin-mismatch")
	case !now.Before(target.IdleExpiresAt) || !now.Before(target.AbsoluteExpiresAt):
		return fail("step-up-session-expired")
	}

	// The bounds are the human-auth service's own, resolved through the one
	// seam every other opener uses (A2): an environment lowered there is
	// honoured here, and a 0 effective window fails closed rather than opening
	// a sliding window nobody may extend.
	effWin, err := s.Reauth.effectiveReauthWindow(ctx, az, h.EnvID)
	if err != nil {
		return WorkspaceSession{}, err
	}
	if effWin <= 0 {
		return fail("step-up-window-closed")
	}
	hardExpires := now.Add(s.Reauth.hardCap())
	windowExpires := now.Add(effWin)
	if windowExpires.After(hardExpires) {
		windowExpires = hardExpires
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return WorkspaceSession{}, err
	}
	windowID, err := newID("raw")
	if err != nil {
		return WorkspaceSession{}, err
	}
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactWorkspaceSession)
	if err != nil {
		return WorkspaceSession{}, err
	}
	if err := az.RotateSessionFactors(ctx, target.ID, verifier, h.Factors); err != nil {
		return WorkspaceSession{}, err
	}
	if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
		// Never single-decision: a single-decision window is resolved back to a
		// WebAuthn ceremony row for byte-exact unit matching, and a handoff
		// transaction is not one. The EXACT BINDING is carried instead, on the
		// window itself: the operation the human consented to and the canonical
		// key set beside it. ConsumeReauthWindow refuses a bound window
		// presented for anything else, so this window authorizes one operation
		// over one key set and is not an environment-wide grant with a consent
		// record filed next to it.
		ID: windowID, SessionID: target.ID, EnvironmentID: h.EnvID,
		CeremonyID: h.ID, FactorClass: class, SingleDecision: false,
		AuthenticatedAt: now, WindowExpiresAt: windowExpires, HardExpiresAt: hardExpires,
		CredentialEpoch: epoch, CreatedAt: now,
		BoundOperation: string(binding.operation), BoundKeySet: binding.keySet,
	}); err != nil {
		return WorkspaceSession{}, err
	}
	e, err := domainEvent(ctx, audit.EventAuthReauthenticated, h.PrincipalID,
		audit.Object{Type: "session", ID: target.ID}, audit.Payload{
			"session_id": target.ID, "factor": class,
		})
	if err != nil {
		return WorkspaceSession{}, err
	}
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return WorkspaceSession{}, err
	}
	return WorkspaceSession{
		Value: value, SessionID: target.ID, Origin: target.RequestingOrigin,
		HandoffID: h.ID, IdleExpiresAt: target.IdleExpiresAt,
		AbsoluteExpiresAt: target.AbsoluteExpiresAt,
		Elevated:          true, EnvironmentID: h.EnvID, WindowExpiresAt: windowExpires,
	}, nil
}

// reauthFactorClass picks the window's factor class from an assurance record.
// The table admits exactly three, so the strongest present wins and anything
// else (a password-only record) yields "" — which the caller reads as "this
// ceremony demonstrated no possession factor" rather than storing a class the
// CHECK would refuse.
func reauthFactorClass(factors []string) string {
	for _, want := range []string{"webauthn", "totp", "oidc"} {
		for _, f := range factors {
			if f == want {
				return want
			}
		}
	}
	return ""
}

// workspaceArtifact is the value the sessions row's `artifact` column stores,
// re-exported from authz so there is exactly one spelling of it: the
// authentication leg's origin-binding predicate and this file's listing and
// elevation rules must not be able to disagree about which string means
// "workspace".
const workspaceArtifact = authz.WorkspaceArtifact

// handoffFailure records the refusal and returns the uniform error. Every
// unusable handoff answers ErrHandoffInvalid regardless of cause: the CAUSE
// goes on the audit trail, where an operator can see it, and not to the
// caller, where it would be an oracle for transactions in flight.
//
// It rides the DURABLE SETTLEMENT path (CaptureAudit), not an in-transaction
// insert, and that is load-bearing rather than stylistic: this function's
// return value ROLLS THE TRANSACTION BACK, and an in-transaction insert would
// vanish exactly when it matters — every handoff failure would be unaudited.
// It is the same reason the reveal gates use this path, and the payload
// carries no instance data for the same reason theirs does not: these rows are
// written outside the operation's own authorization scope.
func (s *Workspace) handoffFailure(
	ctx context.Context, az *authz.TxAuthorizer, actor domain.PrincipalID,
	handoffID, origin, stage, cause string,
) error {
	// The ACTOR is recorded whenever one is known. Most refusals genuinely are
	// anonymous — an unknown state value, an unapproved code — but the callback
	// stage has already authenticated a human, and the redeem stage of an
	// approved transaction knows the principal who approved it. Constructing
	// every one of them as anonymous discarded the single most useful fact on
	// the trail: an operator investigating repeated step-up refusals could see
	// that they happened and not to whom.
	e, err := newAuditEvent(ctx, audit.EventRemoteHandoffFailed, actor,
		audit.Object{Type: "workspace_handoff", ID: handoffID},
		audit.OutcomeFailure, "", audit.Payload{
			"handoff_id": handoffID, "origin": origin, "stage": stage, "cause": cause,
		})
	if err != nil {
		return err
	}
	az.CaptureAudit(audit.TrailInstance, domain.Scope{}, e)
	return ErrHandoffInvalid
}

// withFactor adds one demonstrated factor class to an assurance record,
// idempotently. Order is preserved so the record reads as it was accumulated.
func withFactor(factors []string, class string) []string {
	if class == "" {
		return factors
	}
	for _, f := range factors {
		if f == class {
			return factors
		}
	}
	return append(append([]string(nil), factors...), class)
}

// splitKeySet reverses the transport's newline join. The wire carries a list;
// the row carries one canonical string, because a consent is compared and a
// list is not.
func splitKeySet(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, "\n")
}

// callerClass names the principal class an event should record. An Identity
// resolved through any authentication leg carries one; a LocalPrincipal actor
// (local host authority, below the network) carries none, and is named as such
// rather than defaulting into "human".
func callerClass(caller authz.Identity) domain.PrincipalClass {
	if caller.Class == "" {
		return "local-authority"
	}
	return caller.Class
}

// pkceS256 is RFC 7636's S256 transform.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func validPKCEChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == challenge
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(verifier)
	return err == nil && len(decoded) >= sha256.Size &&
		base64.RawURLEncoding.EncodeToString(decoded) == verifier
}

// ---------------------------------------------------------------------------
// The active-session listing and its revoke (criterion 5).
// ---------------------------------------------------------------------------

// SessionView is one row of the caller's own active-session list. A workspace
// session appears here AS ITS OWN ARTIFACT TYPE — that is the ADR's
// requirement, and it is why the workspace session is a `sessions` row at all.
type SessionView struct {
	ID                string
	Artifact          string
	AuthMethod        string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	SourceIP          string
	UserAgent         string
	// RequestingOrigin is set for workspace sessions only. It is the field
	// that makes "which foreign shell is holding a session on my account"
	// answerable at a glance.
	RequestingOrigin string
	HandoffID        string
}

// ListSessions is SELF-SCOPED: the caller's own sessions and nothing else. It
// needs no capability for the reason /api/v1/me/orgs needs none — it is a
// projection of what the caller already holds — and requiring one would make
// incident response depend on an authority an attacker may have just removed.
func (s *Workspace) ListSessions(ctx context.Context, actor Actor) ([]SessionView, error) {
	now := s.now()
	var out []SessionView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolveSelf(ctx, az, now)
		if err != nil {
			return err
		}
		rows, err := az.SessionsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		rows = selfScope(caller, rows)
		out = make([]SessionView, 0, len(rows))
		for _, row := range rows {
			out = append(out, SessionView{
				ID: row.ID, Artifact: row.Artifact, AuthMethod: row.AuthMethod,
				CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt,
				IdleExpiresAt: row.IdleExpiresAt, AbsoluteExpiresAt: row.AbsoluteExpiresAt,
				SourceIP: row.SourceIP, UserAgent: row.UserAgent,
				RequestingOrigin: row.RequestingOrigin, HandoffID: row.HandoffID,
			})
		}
		return nil
	})
	return out, err
}

// selfScope narrows the caller's session set to what THIS ARTIFACT may see.
//
// A same-origin session (cli, browser) sees the whole set: that is the incident
// -response surface, and it is why the listing needs no capability. A WORKSPACE
// bearer sees exactly its own row, because it lives in another origin's
// JavaScript: an XSS on the viewing shell must not be able to enumerate the
// human's CLI and browser sessions — with their source IPs and user agents —
// nor end them. Its own row is enough for the two things it legitimately does,
// the liveness poll and self-termination, and both kill switches stay visible.
//
// A LocalPrincipal actor carries no artifact and is local host authority; it
// sees everything, as it does everywhere else.
func selfScope(caller authz.Identity, rows []authz.SessionSummary) []authz.SessionSummary {
	if caller.Artifact != workspaceArtifact {
		return rows
	}
	for _, row := range rows {
		if row.ID == caller.SessionID {
			return []authz.SessionSummary{row}
		}
	}
	return nil
}

// RevokeSession kills one of the caller's OWN sessions, and it bites mid-flight
// because the next request re-resolves the row in its own transaction.
//
// The principal conjunct lives in the SQL, not in a Go check: one caller is
// structurally unable to reach another's row by guessing an id.
func (s *Workspace) RevokeSession(ctx context.Context, actor Actor, id string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolveSelf(ctx, az, now)
		if err != nil {
			return err
		}
		rows, err := az.SessionsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		var target authz.SessionSummary
		for _, row := range selfScope(caller, rows) {
			if row.ID == id {
				target = row
			}
		}
		if target.ID == "" {
			return store.ErrNotFound
		}
		did, err := az.RevokeSessionForPrincipal(ctx, id, caller.Principal)
		if err != nil {
			return err
		}
		if !did {
			return store.ErrNotFound
		}
		if target.Artifact != workspaceArtifact {
			// An ordinary session's revocation is a logout, already audited as
			// one. Giving it a second event under a #71 type would double-count
			// a fact the trail already carries.
			e, err := domainEvent(ctx, audit.EventAuthLogout, caller.Principal,
				audit.Object{Type: "session", ID: id}, audit.Payload{
					"session_id": id, "artifact": target.Artifact,
				})
			if err != nil {
				return err
			}
			return az.RecordAuthEvent(ctx, e)
		}
		e, err := domainEvent(ctx, audit.EventRemoteWorkspaceSessionRevoked, caller.Principal,
			audit.Object{Type: "session", ID: id}, audit.Payload{
				"session_id": id, "origin": target.RequestingOrigin, "cause": "explicit",
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}
