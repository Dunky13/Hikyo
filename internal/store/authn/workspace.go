package authn

import (
	"context"
	"errors"
	"time"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// The workspace tier's resolution surface (#71, multi-instance ADR § The
// workspace tier). Three things live here and all three are authn-resolution
// rather than proof-gated reads:
//
//   - the ORIGIN ALLOWLIST, consulted at handoff issuance and by CORS, both of
//     which run pre-authentication;
//   - the HANDOFF TRANSACTION, which resolves a caller the same way a session
//     verifier does — a proof cannot gate it, because the proof is what the
//     answer produces;
//   - the SESSION LISTING and the two revocation statements, which read and
//     write `sessions` rows and therefore belong where every other session
//     statement already is.

// WorkspaceOrigin is one allowlist entry: an EXACT UI origin. There is no
// pattern field and no matching function, deliberately — the primary key is
// the origin string, so an inexact entry is unrepresentable.
type WorkspaceOrigin struct {
	Origin    string
	CreatedAt time.Time
	CreatedBy domain.PrincipalID
}

// HandoffPurpose is the closed two-member set the table's CHECK enforces.
type HandoffPurpose string

const (
	// HandoffEstablishment issues a first workspace session. Purpose alone
	// licenses issuance: there is no prior session to name.
	HandoffEstablishment HandoffPurpose = "establishment"
	// HandoffStepUp elevates an existing workspace session for one exact
	// operation. Its three extra bindings are what stop an elevated consent
	// being replayed against a different operation, environment or key set.
	HandoffStepUp HandoffPurpose = "step-up"
)

// WorkspaceHandoff is one short-lived, single-use handoff transaction.
//
// StateVerifier and CodeVerifier are VERIFIERS, never values: both cross a
// redirect, and the front channel carries code and state only. CodeVerifier is
// nil until approval, because a transaction nobody approved has issued no code.
type WorkspaceHandoff struct {
	ID            string
	StateVerifier []byte
	CodeVerifier  []byte
	Origin        string
	RedirectURI   string
	PKCEChallenge string
	Purpose       HandoffPurpose
	// SessionID, Operation, EnvID and KeySet are the step-up bindings. All are
	// empty on an establishment transaction, and the table CHECK refuses the
	// mixed shapes.
	SessionID string
	Operation string
	EnvID     string
	KeySet    string
	// PrincipalID is the human the remote authenticated, empty until approval.
	PrincipalID domain.PrincipalID
	// Factors is the approving session's assurance record as stored JSON, and
	// it is the reason this column exists: approval and redemption are two
	// requests minutes apart, so the transaction row is the only carrier for
	// what the human actually demonstrated at the ceremony. "[]" until
	// approval.
	Factors string
	// FactorClass is the FRESH reauthentication the approving human completed
	// inside the popup, as part of the approval — "webauthn", "totp" or "oidc",
	// empty when no fresh ceremony was demonstrated. It is deliberately not
	// derived from Factors: an assurance record says what a session once
	// demonstrated, this says what was demonstrated for THIS transaction, and
	// only the second one may license an elevation.
	FactorClass string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// ConsumedAt is the zero time while the transaction is still redeemable.
	ConsumedAt time.Time
}

// Live reports whether the transaction may still be acted on at `now`: not
// consumed and not expired. Both halves in one place, so the issuing path and
// the redeeming path cannot answer differently about the same row.
func (h WorkspaceHandoff) Live(now time.Time) bool {
	return h.ConsumedAt.IsZero() && now.Before(h.ExpiresAt)
}

// NewWorkspaceHandoff is one transaction insert.
type NewWorkspaceHandoff struct {
	ID            string
	StateVerifier []byte
	Origin        string
	RedirectURI   string
	PKCEChallenge string
	Purpose       HandoffPurpose
	SessionID     string
	Operation     string
	EnvID         string
	KeySet        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// SessionSummary is one row of the active-session listing (#71 criterion 5).
// Metadata only: no verifier is selected here or anywhere, and the two
// workspace fields are what let the listing show a workspace session AS its own
// artifact type rather than as an anonymous third row.
type SessionSummary struct {
	ID                string
	Artifact          string
	AuthMethod        string
	Factors           string
	AuthenticatedAt   time.Time
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	SourceIP          string
	UserAgent         string
	RequestingOrigin  string
	HandoffID         string
}

// WorkspaceOrigins lists the allowlist.
func (r *Resolver) WorkspaceOrigins(ctx context.Context) ([]WorkspaceOrigin, error) {
	if r.sq != nil {
		rows, err := r.sq.ListWorkspaceOrigins(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]WorkspaceOrigin, 0, len(rows))
		for _, row := range rows {
			created, err := decodeTime(row.CreatedAt)
			if err != nil {
				return nil, err
			}
			out = append(out, WorkspaceOrigin{
				Origin: row.Origin, CreatedAt: created,
				CreatedBy: domain.PrincipalID(row.CreatedBy),
			})
		}
		return out, nil
	}
	rows, err := r.pg.ListWorkspaceOrigins(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]WorkspaceOrigin, 0, len(rows))
	for _, row := range rows {
		out = append(out, WorkspaceOrigin{
			Origin: row.Origin, CreatedAt: row.CreatedAt.Time,
			CreatedBy: domain.PrincipalID(row.CreatedBy),
		})
	}
	return out, nil
}

// originFound maps the exact-match read's outcome to membership: a miss is
// "not allowlisted", any other error is an error. It is a function rather than
// two inline branches so the two engines cannot answer differently.
func originFound(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// WorkspaceOriginAllowed is the exact-match membership read CORS and handoff
// issuance both consult. It answers a boolean and not a row because no caller
// needs the provenance, and returning the row invites a caller to branch on it.
func (r *Resolver) WorkspaceOriginAllowed(ctx context.Context, origin string) (bool, error) {
	if origin == "" {
		return false, nil
	}
	if r.sq != nil {
		_, err := r.sq.GetWorkspaceOrigin(ctx, origin)
		return originFound(err)
	}
	_, err := r.pg.GetWorkspaceOrigin(ctx, origin)
	return originFound(err)
}

// AllowWorkspaceOrigin adds one exact origin.
func (r *Resolver) AllowWorkspaceOrigin(ctx context.Context, o WorkspaceOrigin) error {
	if r.sq != nil {
		return r.sq.InsertWorkspaceOrigin(ctx, sqlitegen.InsertWorkspaceOriginParams{
			Origin: o.Origin, CreatedAt: encodeTime(o.CreatedAt), CreatedBy: string(o.CreatedBy),
		})
	}
	return r.pg.InsertWorkspaceOrigin(ctx, pggen.InsertWorkspaceOriginParams{
		Origin: o.Origin, CreatedAt: pgTime(o.CreatedAt), CreatedBy: string(o.CreatedBy),
	})
}

// RemoveWorkspaceOrigin deletes one entry and reports whether it existed. The
// caller MUST run RevokeWorkspaceSessionsForOrigin in the same transaction:
// that pairing is the ADR's atomic kill switch, and splitting it across two
// transactions would leave a window in which the origin is de-allowlisted and
// its sessions still authenticate.
func (r *Resolver) RemoveWorkspaceOrigin(ctx context.Context, origin string) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.DeleteWorkspaceOrigin(ctx, origin)
		return n > 0, err
	}
	n, err := r.pg.DeleteWorkspaceOrigin(ctx, origin)
	return n > 0, err
}

// RevokeWorkspaceSessionsForOrigin is the kill switch's second half. Only
// workspace rows carry a requesting_origin, so no cli or browser session can be
// caught by it.
func (r *Resolver) RevokeWorkspaceSessionsForOrigin(ctx context.Context, origin string) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteSessionsForOrigin(ctx, nullString(origin))
	}
	return r.pg.DeleteSessionsForOrigin(ctx, pgText(origin))
}

// SessionsForPrincipal is the active-session listing.
func (r *Resolver) SessionsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]SessionSummary, error) {
	if r.sq != nil {
		rows, err := r.sq.ListSessionsForPrincipal(ctx, string(p))
		if err != nil {
			return nil, err
		}
		out := make([]SessionSummary, 0, len(rows))
		for _, row := range rows {
			s, err := summaryFromSQLite(row)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	rows, err := r.pg.ListSessionsForPrincipal(ctx, string(p))
	if err != nil {
		return nil, err
	}
	out := make([]SessionSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, SessionSummary{
			ID: row.ID, Artifact: row.Artifact, AuthMethod: row.AuthMethod,
			Factors: row.Factors, AuthenticatedAt: row.AuthenticatedAt.Time,
			CreatedAt: row.CreatedAt.Time, LastSeenAt: row.LastSeenAt.Time,
			IdleExpiresAt: row.IdleExpiresAt.Time, AbsoluteExpiresAt: row.AbsoluteExpiresAt.Time,
			SourceIP: row.SourceIp, UserAgent: row.UserAgent,
			RequestingOrigin: row.RequestingOrigin.String, HandoffID: row.HandoffID.String,
		})
	}
	return out, nil
}

func summaryFromSQLite(row sqlitegen.ListSessionsForPrincipalRow) (SessionSummary, error) {
	authenticated, err := decodeTime(row.AuthenticatedAt)
	if err != nil {
		return SessionSummary{}, err
	}
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return SessionSummary{}, err
	}
	seen, err := decodeTime(row.LastSeenAt)
	if err != nil {
		return SessionSummary{}, err
	}
	idle, err := decodeTime(row.IdleExpiresAt)
	if err != nil {
		return SessionSummary{}, err
	}
	absolute, err := decodeTime(row.AbsoluteExpiresAt)
	if err != nil {
		return SessionSummary{}, err
	}
	return SessionSummary{
		ID: row.ID, Artifact: row.Artifact, AuthMethod: row.AuthMethod,
		Factors: row.Factors, AuthenticatedAt: authenticated, CreatedAt: created,
		LastSeenAt: seen, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
		SourceIP: row.SourceIp, UserAgent: row.UserAgent,
		RequestingOrigin: row.RequestingOrigin.String, HandoffID: row.HandoffID.String,
	}, nil
}

// RevokeSessionForPrincipal deletes one of the caller's OWN sessions. The
// principal conjunct is in the statement, not in a Go check: it is what makes
// one caller structurally unable to revoke another's session by guessing an id.
func (r *Resolver) RevokeSessionForPrincipal(ctx context.Context, id string, p domain.PrincipalID) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.DeleteSessionForPrincipal(ctx, sqlitegen.DeleteSessionForPrincipalParams{
			ID: id, PrincipalID: string(p),
		})
		return n > 0, err
	}
	n, err := r.pg.DeleteSessionForPrincipal(ctx, pggen.DeleteSessionForPrincipalParams{
		ID: id, PrincipalID: string(p),
	})
	return n > 0, err
}

// CreateWorkspaceHandoff opens one transaction.
func (r *Resolver) CreateWorkspaceHandoff(ctx context.Context, h NewWorkspaceHandoff) error {
	if r.sq != nil {
		return r.sq.InsertWorkspaceHandoff(ctx, sqlitegen.InsertWorkspaceHandoffParams{
			ID: h.ID, StateVerifier: h.StateVerifier, Origin: h.Origin,
			RedirectUri: h.RedirectURI, PkceChallenge: h.PKCEChallenge,
			Purpose:   string(h.Purpose),
			SessionID: nullString(h.SessionID), Operation: nullString(h.Operation),
			EnvID: nullString(h.EnvID), KeySet: nullString(h.KeySet),
			CreatedAt: encodeTime(h.CreatedAt), ExpiresAt: encodeTime(h.ExpiresAt),
		})
	}
	return r.pg.InsertWorkspaceHandoff(ctx, pggen.InsertWorkspaceHandoffParams{
		ID: h.ID, StateVerifier: h.StateVerifier, Origin: h.Origin,
		RedirectUri: h.RedirectURI, PkceChallenge: h.PKCEChallenge,
		Purpose:   string(h.Purpose),
		SessionID: pgText(h.SessionID), Operation: pgText(h.Operation),
		EnvID: pgText(h.EnvID), KeySet: pgText(h.KeySet),
		CreatedAt: pgTime(h.CreatedAt), ExpiresAt: pgTime(h.ExpiresAt),
	})
}

// WorkspaceHandoffByState resolves a returning front-channel `state`.
//
// Liveness is decided by the CALLER against the returned row, not in the WHERE
// clause: filtering there would make an unknown transaction cost one row and a
// consumed one zero, which is an existence oracle for handoffs in flight.
func (r *Resolver) WorkspaceHandoffByState(ctx context.Context, verifier []byte) (WorkspaceHandoff, error) {
	if r.sq != nil {
		row, err := r.sq.WorkspaceHandoffByState(ctx, verifier)
		if err != nil {
			return WorkspaceHandoff{}, notFoundOr(err)
		}
		return handoffFromSQLite(sqlitegen.WorkspaceHandoff(row))
	}
	row, err := r.pg.WorkspaceHandoffByState(ctx, verifier)
	if err != nil {
		return WorkspaceHandoff{}, notFoundOr(err)
	}
	return handoffFromPG(pggen.WorkspaceHandoff(row))
}

// WorkspaceHandoffByCode resolves a redeemed authorization code.
func (r *Resolver) WorkspaceHandoffByCode(ctx context.Context, verifier []byte) (WorkspaceHandoff, error) {
	if r.sq != nil {
		row, err := r.sq.WorkspaceHandoffByCode(ctx, verifier)
		if err != nil {
			return WorkspaceHandoff{}, notFoundOr(err)
		}
		return handoffFromSQLite(sqlitegen.WorkspaceHandoff(row))
	}
	row, err := r.pg.WorkspaceHandoffByCode(ctx, verifier)
	if err != nil {
		return WorkspaceHandoff{}, notFoundOr(err)
	}
	return handoffFromPG(pggen.WorkspaceHandoff(row))
}

// ApproveWorkspaceHandoff binds the authenticated human and mints the code. The
// NULL guard in the statement is the atomic claim, so it reports whether THIS
// call did the approving.
func (r *Resolver) ApproveWorkspaceHandoff(ctx context.Context, id string, codeVerifier []byte, p domain.PrincipalID, factors, factorClass string) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ApproveWorkspaceHandoff(ctx, sqlitegen.ApproveWorkspaceHandoffParams{
			CodeVerifier: codeVerifier, PrincipalID: nullString(string(p)),
			Factors: factors, FactorClass: factorClass, ID: id,
		})
		return n > 0, err
	}
	n, err := r.pg.ApproveWorkspaceHandoff(ctx, pggen.ApproveWorkspaceHandoffParams{
		CodeVerifier: codeVerifier, PrincipalID: pgText(string(p)),
		Factors: factors, FactorClass: factorClass, ID: id,
	})
	return n > 0, err
}

// LockWorkspaceOrigin takes the allowlist entry's row lock so a membership
// check and the write that depends on it cannot straddle a concurrent removal
// (postgres FOR UPDATE; sqlite's single writer serializes). It reports whether
// the entry is still there — false means it was removed, and the caller must
// refuse rather than proceed on the read it took a moment earlier.
func (r *Resolver) LockWorkspaceOrigin(ctx context.Context, origin string) (bool, error) {
	if r.sq != nil {
		_, err := r.sq.LockWorkspaceOrigin(ctx, origin)
		return lockHeld(err)
	}
	_, err := r.pg.LockWorkspaceOrigin(ctx, origin)
	return lockHeld(err)
}

// LockInstanceIdentityRow takes the instance singleton's row lock. It is the
// mutex for decisions about THIS INSTANCE AS A WHOLE — the remote-count cap and
// the duplicate-identity refusal are census questions with no per-remote row to
// lock, because the row being decided about does not exist yet.
func (r *Resolver) LockInstanceIdentityRow(ctx context.Context) error {
	if r.sq != nil {
		_, err := r.sq.LockInstanceIdentityRow(ctx)
		return notFoundOr(err)
	}
	_, err := r.pg.LockInstanceIdentityRow(ctx)
	return notFoundOr(err)
}

// lockHeld maps a lock SELECT's result to "the row is still there".
func lockHeld(err error) (bool, error) {
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ConsumeWorkspaceHandoff is the single-use claim.
func (r *Resolver) ConsumeWorkspaceHandoff(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeWorkspaceHandoff(ctx, sqlitegen.ConsumeWorkspaceHandoffParams{
			ConsumedAt: nullTimeString(at), ID: id,
		})
		return n > 0, err
	}
	n, err := r.pg.ConsumeWorkspaceHandoff(ctx, pggen.ConsumeWorkspaceHandoffParams{
		ConsumedAt: nullPGTime(at), ID: id,
	})
	return n > 0, err
}

// SweepExpiredWorkspaceHandoffs is opportunistic housekeeping, run at issuance.
// It is not a correctness mechanism — an expired transaction is refused by the
// caller's clock check whether or not its row is still there — so there is no
// poller, and the ADR's no-generic-job-framework rule stands.
func (r *Resolver) SweepExpiredWorkspaceHandoffs(ctx context.Context, before time.Time) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteExpiredWorkspaceHandoffs(ctx, encodeTime(before))
	}
	return r.pg.DeleteExpiredWorkspaceHandoffs(ctx, pgTime(before))
}

func handoffFromSQLite(row sqlitegen.WorkspaceHandoff) (WorkspaceHandoff, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return WorkspaceHandoff{}, err
	}
	expires, err := decodeTime(row.ExpiresAt)
	if err != nil {
		return WorkspaceHandoff{}, err
	}
	consumed, err := decodeNullTime(row.ConsumedAt)
	if err != nil {
		return WorkspaceHandoff{}, err
	}
	return WorkspaceHandoff{
		ID: row.ID, StateVerifier: row.StateVerifier, CodeVerifier: row.CodeVerifier,
		Origin: row.Origin, RedirectURI: row.RedirectUri, PKCEChallenge: row.PkceChallenge,
		Purpose:   HandoffPurpose(row.Purpose),
		SessionID: row.SessionID.String, Operation: row.Operation.String,
		EnvID: row.EnvID.String, KeySet: row.KeySet.String,
		PrincipalID: domain.PrincipalID(row.PrincipalID.String), Factors: row.Factors,
		FactorClass: row.FactorClass,
		CreatedAt:   created, ExpiresAt: expires, ConsumedAt: consumed,
	}, nil
}

func handoffFromPG(row pggen.WorkspaceHandoff) (WorkspaceHandoff, error) {
	return WorkspaceHandoff{
		ID: row.ID, StateVerifier: row.StateVerifier, CodeVerifier: row.CodeVerifier,
		Origin: row.Origin, RedirectURI: row.RedirectUri, PKCEChallenge: row.PkceChallenge,
		Purpose:   HandoffPurpose(row.Purpose),
		SessionID: row.SessionID.String, Operation: row.Operation.String,
		EnvID: row.EnvID.String, KeySet: row.KeySet.String,
		PrincipalID: domain.PrincipalID(row.PrincipalID.String), Factors: row.Factors,
		FactorClass: row.FactorClass,
		CreatedAt:   row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time,
		ConsumedAt: row.ConsumedAt.Time,
	}, nil
}

// RemoteOrigins reads the configured remotes' URLs proof-free.
//
// KNOWING DEVIATION, recorded rather than discovered: `remotes` is class=instance
// and every other read of it rides the proof-gated repositories. This one
// cannot, and the reason is structural — its only consumer is the viewing
// instance's Content-Security-Policy `connect-src` extension, which is emitted
// on the PRE-AUTHENTICATION document response, where there is no caller to
// authorize. The same disposition covers `Resolver.InstanceIdentity`, which is
// proof-free for the same class of reason.
//
// What it returns is not secret and not tenant data: the origins this instance
// is configured to talk to, which the CSP header then publishes to every
// browser that loads the SPA anyway. A proof gate on a value the response
// itself discloses would be ceremony, not confinement.
func (r *Resolver) RemoteOrigins(ctx context.Context) ([]string, error) {
	if r.sq != nil {
		rows, err := r.sq.ListRemotes(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.Url)
		}
		return out, nil
	}
	rows, err := r.pg.ListRemotes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Url)
	}
	return out, nil
}
