package authn

import (
	"context"
	"database/sql"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// Reauth-window consumption at disclosure and the credential-reset target
// surface (#54, human-auth ADR - Reauthentication, Recovery). These live on the
// proof-free resolution surface for the same reason the login writers do: they
// read and mutate the artifacts that decide how strongly a caller authenticated,
// which is resolution rather than authorization. Every mutating method here is
// named in lint.ResolutionSurfaceWriters.

// ReauthWindow is a resolved reauthentication-window row.
type ReauthWindow struct {
	ID              string
	SessionID       string
	EnvironmentID   string
	CeremonyID      string
	FactorClass     string
	SingleDecision  bool
	AuthenticatedAt time.Time
	WindowExpiresAt time.Time
	HardExpiresAt   time.Time
	CredentialEpoch int64
	Consumed        bool
	// BoundOperation and BoundKeySet are the EXACT consent a step-up window
	// carries: the one operation and the one canonical (sorted, newline-joined)
	// key set the human approved. Both empty means UNBOUND, which is what every
	// pre-#71 opener writes and is the environment-wide window #54 designed. A
	// bound window is refused for anything else, so an approval for `key.reveal`
	// over DATABASE_URL cannot be spent on a different operation or key.
	BoundOperation      string
	BoundKeySet         string
	BoundPurpose        string
	BoundEnvironmentSet string
}

// ReauthWindowFor resolves the window over one environment for one session, or
// domain.ErrNotFound when none is open.
func (r *Resolver) ReauthWindowFor(ctx context.Context, sessionID, environmentID string) (ReauthWindow, error) {
	if r.sq != nil {
		row, err := r.sq.GetReauthWindow(ctx, sqlitegen.GetReauthWindowParams{SessionID: sessionID, EnvironmentID: environmentID})
		if err != nil {
			return ReauthWindow{}, notFoundOr(err)
		}
		authAt, err := decodeTime(row.AuthenticatedAt)
		if err != nil {
			return ReauthWindow{}, err
		}
		winExp, err := decodeTime(row.WindowExpiresAt)
		if err != nil {
			return ReauthWindow{}, err
		}
		hardExp, err := decodeTime(row.HardExpiresAt)
		if err != nil {
			return ReauthWindow{}, err
		}
		return ReauthWindow{
			ID: row.ID, SessionID: row.SessionID, EnvironmentID: row.EnvironmentID,
			CeremonyID: row.CeremonyID, FactorClass: row.FactorClass,
			SingleDecision: row.SingleDecision == 1, AuthenticatedAt: authAt,
			WindowExpiresAt: winExp, HardExpiresAt: hardExp,
			CredentialEpoch: row.CredentialEpoch, Consumed: row.ConsumedAt.Valid,
			BoundOperation: row.BoundOperation, BoundKeySet: row.BoundKeySet,
			BoundPurpose: row.BoundPurpose, BoundEnvironmentSet: row.BoundEnvironmentSet,
		}, nil
	}
	row, err := r.pg.GetReauthWindow(ctx, pggen.GetReauthWindowParams{SessionID: sessionID, EnvironmentID: environmentID})
	if err != nil {
		return ReauthWindow{}, notFoundOr(err)
	}
	return ReauthWindow{
		ID: row.ID, SessionID: row.SessionID, EnvironmentID: row.EnvironmentID,
		CeremonyID: row.CeremonyID, FactorClass: row.FactorClass,
		SingleDecision: row.SingleDecision == 1, AuthenticatedAt: row.AuthenticatedAt.Time,
		WindowExpiresAt: row.WindowExpiresAt.Time, HardExpiresAt: row.HardExpiresAt.Time,
		CredentialEpoch: row.CredentialEpoch, Consumed: row.ConsumedAt.Valid,
		BoundOperation: row.BoundOperation, BoundKeySet: row.BoundKeySet,
		BoundPurpose: row.BoundPurpose, BoundEnvironmentSet: row.BoundEnvironmentSet,
	}, nil
}

// SlideReauthWindow advances a sliding window's idle clock; false means the row
// moved (single-decision or already claimed) and the caller must not extend it.
func (r *Resolver) SlideReauthWindow(ctx context.Context, id string, windowExpires time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.SlideReauthWindow(ctx, sqlitegen.SlideReauthWindowParams{
			WindowExpiresAt: encodeTime(windowExpires), ID: id,
		})
		return n == 1, err
	}
	n, err := r.pg.SlideReauthWindow(ctx, pggen.SlideReauthWindowParams{
		WindowExpiresAt: pgTime(windowExpires), ID: id,
	})
	return n == 1, err
}

// ConsumeSingleDecisionWindow claims a single-decision window exactly once;
// false means it was already spent and the caller must refuse (B11 double-spend).
func (r *Resolver) ConsumeSingleDecisionWindow(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeSingleDecisionWindow(ctx, sqlitegen.ConsumeSingleDecisionWindowParams{
			ConsumedAt: sql.NullString{String: encodeTime(at), Valid: true}, ID: id,
		})
		return n == 1, err
	}
	n, err := r.pg.ConsumeSingleDecisionWindow(ctx, pggen.ConsumeSingleDecisionWindowParams{
		ConsumedAt: pgTime(at), ID: id,
	})
	return n == 1, err
}

// DeleteReauthWindowsForEnvironment invalidates every open window on one
// environment and returns the count, for the effective-window transition (B6).
func (r *Resolver) DeleteReauthWindowsForEnvironment(ctx context.Context, environmentID string) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteReauthWindowsForEnvironment(ctx, environmentID)
	}
	return r.pg.DeleteReauthWindowsForEnvironment(ctx, environmentID)
}

// StrandedRevealPrincipals enumerates the principals a 0 effective window would
// strand on environment (org, project, env): reveal/reveal-history holders there
// with no enabled WebAuthn authenticator (B6).
func (r *Resolver) StrandedRevealPrincipals(ctx context.Context, org, project, env string) ([]domain.PrincipalID, error) {
	var ids []string
	if r.sq != nil {
		rows, err := r.sq.StrandedRevealPrincipalsForEnvironment(ctx, sqlitegen.StrandedRevealPrincipalsForEnvironmentParams{
			Org: nullString(org), Project: nullString(project), Env: nullString(env),
		})
		if err != nil {
			return nil, err
		}
		ids = rows
	} else {
		rows, err := r.pg.StrandedRevealPrincipalsForEnvironment(ctx, pggen.StrandedRevealPrincipalsForEnvironmentParams{
			Org: pgText(org), Project: pgText(project), Env: pgText(env),
		})
		if err != nil {
			return nil, err
		}
		ids = rows
	}
	out := make([]domain.PrincipalID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.PrincipalID(id))
	}
	return out, nil
}

// GrantsForResetTarget reads the target principal's full grant set for the
// credential-reset org-bounded test. It is a distinct name from Grants so the
// reset path's read is visible in the trusted-query registry.
func (r *Resolver) GrantsForResetTarget(ctx context.Context, p domain.PrincipalID) ([]domain.Grant, error) {
	if r.sq != nil {
		rows, err := r.sq.ListGrantsForResetTarget(ctx, string(p))
		if err != nil {
			return nil, err
		}
		out := make([]domain.Grant, 0, len(rows))
		for _, row := range rows {
			g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	}
	rows, err := r.pg.ListGrantsForResetTarget(ctx, string(p))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// LockPrincipalRow takes the target principal's row lock (postgres FOR UPDATE;
// sqlite's single writer serializes) so the credential-reset org-bounded test
// and every grant mutation serialize on the same row — a concurrent grant
// landing conflicts with an in-flight reset (B14). ErrNotFound means no such
// principal. It is a read (SELECT), not a proof-free write.
func (r *Resolver) LockPrincipalRow(ctx context.Context, p domain.PrincipalID) error {
	if r.sq != nil {
		_, err := r.sq.LockPrincipalRow(ctx, string(p))
		return notFoundOr(err)
	}
	_, err := r.pg.LockPrincipalRow(ctx, string(p))
	return notFoundOr(err)
}

// EnvironmentChain is a resolved (org, project, env) chain.
type EnvironmentChain struct {
	Org     string
	Project string
	Env     string
}

// EnvironmentChainByID resolves an environment's full chain from its id, for the
// stranded-principal query. domain.ErrNotFound when no such environment.
func (r *Resolver) EnvironmentChainByID(ctx context.Context, envID string) (EnvironmentChain, error) {
	if r.sq != nil {
		row, err := r.sq.EnvironmentChainByID(ctx, envID)
		if err != nil {
			return EnvironmentChain{}, notFoundOr(err)
		}
		return EnvironmentChain{Org: row.OrgID, Project: row.ProjectID, Env: row.ID}, nil
	}
	row, err := r.pg.EnvironmentChainByID(ctx, envID)
	if err != nil {
		return EnvironmentChain{}, notFoundOr(err)
	}
	return EnvironmentChain{Org: row.OrgID, Project: row.ProjectID, Env: row.ID}, nil
}

// WebAuthnCeremonyByID resolves a ceremony by id, so a single-decision window's
// enumerated-unit binding can be matched at disclosure (the window row carries
// only the ceremony id).
func (r *Resolver) WebAuthnCeremonyByID(ctx context.Context, id string) (WebAuthnCeremony, error) {
	if r.sq != nil {
		row, err := r.sq.GetWebAuthnCeremonyByID(ctx, id)
		if err != nil {
			return WebAuthnCeremony{}, notFoundOr(err)
		}
		return sqliteWebAuthnCeremony(row)
	}
	row, err := r.pg.GetWebAuthnCeremonyByID(ctx, id)
	if err != nil {
		return WebAuthnCeremony{}, notFoundOr(err)
	}
	return pgWebAuthnCeremony(row), nil
}
