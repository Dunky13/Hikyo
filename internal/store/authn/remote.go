package authn

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// The instance connection (#71, multi-instance ADR § The instance-connection
// principal and its credential): the machine principal a serving instance
// mints to represent "some other installation may read my directory listing",
// together with its one credential.
//
// Principal and credential are ONE ROW because the ADR makes them one unit —
// created together with a stable immutable id, one credential per principal
// ever, and revoked together so no orphan principal accumulates and no revoked
// principal is re-armed. Rotation is a new create, never a second credential
// here.
//
// It sits BESIDE the service-account taxonomy, not inside it: instance-owned,
// mintable only under `instance-config`, with none of #17's project-ownership
// or subtree-confinement rules applying to it. That is why it is not a
// service_accounts row.

// InstanceConnection is one connection principal and its credential.
type InstanceConnection struct {
	ID string
	// PrincipalID is the grant-table subject. The connection's authority is
	// the union of the grants on it and nothing else — there is no
	// per-credential scope column here, and adding one would be the second
	// permission language #15 forbids.
	PrincipalID domain.PrincipalID
	// Label names the intended peer, for the audit trail. It is descriptive
	// and NOT enforced: the serving instance cannot verify who holds the
	// token, and does not pretend to.
	Label string
	Kind  domain.CredentialKind
	// PrefixHint is the leading, non-secret slice of the minted value, so an
	// operator can tell two connections apart in a list without either being
	// retrievable.
	PrefixHint string
	Lifetime   domain.CredentialLifetime
	// ExpiresAt is the zero time IFF Lifetime is indefinite. The database
	// CHECK makes the pairing total; this type keeps it total in Go.
	ExpiresAt       time.Time
	CredentialEpoch int64
	CreatedAt       time.Time
	CreatedBy       domain.PrincipalID
	// RevokedAt is the zero time while the credential is live.
	RevokedAt  time.Time
	LastUsedAt time.Time
}

// Live reports whether the credential authenticates at `now` under `epoch` —
// the whole predicate in one place, so the authenticating path and the listing
// path cannot answer differently about the same row.
func (c InstanceConnection) Live(now time.Time, epoch int64) bool {
	if !c.RevokedAt.IsZero() || c.CredentialEpoch != epoch {
		return false
	}
	return c.Lifetime == domain.LifetimeIndefinite || now.Before(c.ExpiresAt)
}

// NewInstanceConnection is one mint, all fields required.
type NewInstanceConnection struct {
	ID              string
	PrincipalID     domain.PrincipalID
	Label           string
	Kind            domain.CredentialKind
	Verifier        []byte
	PrefixHint      string
	Lifetime        domain.CredentialLifetime
	ExpiresAt       time.Time
	CredentialEpoch int64
	CreatedAt       time.Time
	CreatedBy       domain.PrincipalID
}

// InstanceConnectionByVerifier resolves a presented directory credential.
//
// It is work-shape uniform with the machine-credential leg and for the same
// reason: a miss decodes an engine-matched decoy row and runs the same
// constant-time compare, so unknown, revoked, expired and live presentations
// all cost one query, one decode and one compare. Returning early on a miss
// would make the outcome readable from the work, which is a credential-
// existence oracle.
//
// Liveness is NOT decided here — the caller applies Live() against the epoch
// it read in the same transaction. This function's only judgement is whether
// the verifier matches the row the index found.
func (r *Resolver) InstanceConnectionByVerifier(ctx context.Context, verifier []byte) (InstanceConnection, error) {
	if r.sq != nil {
		row, err := r.sq.InstanceConnectionByVerifier(ctx, verifier)
		if errors.Is(notFoundOr(err), domain.ErrNotFound) {
			return InstanceConnection{}, decoyConnectionWorkSQLite(verifier)
		}
		if err != nil {
			return InstanceConnection{}, err
		}
		if !verifierMatches(row.Verifier, verifier) {
			return InstanceConnection{}, domain.ErrNotFound
		}
		return connectionFromSQLite(sqlitegen.ListInstanceConnectionsRow{
			ID: row.ID, PrincipalID: row.PrincipalID, Label: row.Label, Kind: row.Kind,
			PrefixHint: row.PrefixHint, Lifetime: row.Lifetime, ExpiresAt: row.ExpiresAt,
			CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt,
			CreatedBy: row.CreatedBy, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
		})
	}
	row, err := r.pg.InstanceConnectionByVerifier(ctx, verifier)
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return InstanceConnection{}, decoyConnectionWorkPG(verifier)
	}
	if err != nil {
		return InstanceConnection{}, err
	}
	if !verifierMatches(row.Verifier, verifier) {
		return InstanceConnection{}, domain.ErrNotFound
	}
	return connectionFromPG(pggen.ListInstanceConnectionsRow{
		ID: row.ID, PrincipalID: row.PrincipalID, Label: row.Label, Kind: row.Kind,
		PrefixHint: row.PrefixHint, Lifetime: row.Lifetime, ExpiresAt: row.ExpiresAt,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt,
		CreatedBy: row.CreatedBy, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
	})
}

// The decoy rows are engine-matched: each miss path decodes through the SAME
// decoder its hit path uses, so a postgres miss does postgres' timestamptz
// work rather than sqlite's string parsing. #61's review found the mismatched
// version of this and it is the reason the pairing is spelled out twice.
var (
	decoyConnectionRowSQLite = sqlitegen.ListInstanceConnectionsRow{
		ID: "icn_decoy", PrincipalID: "mch_decoy", Label: "decoy",
		Kind: string(domain.CredentialHikyoToken), PrefixHint: "hik_1_ic_000000",
		Lifetime:        string(domain.LifetimeFinite),
		ExpiresAt:       sql.NullString{String: decoyTime, Valid: true},
		CredentialEpoch: 1, CreatedAt: decoyTime, CreatedBy: "usr_decoy",
		// EVERY nullable timestamp is PRESENT, and that is the point. sqlite's
		// decoder parses each present timestamp and skips each absent one, so a
		// decoy leaving revoked_at and last_used_at null did strictly less work
		// than a hit on a revoked, previously-used credential — and repeated
		// probes could tell "unknown" from "revoked" by timing alone. The
		// heaviest real shape is the only honest decoy shape.
		RevokedAt:  sql.NullString{String: decoyTime, Valid: true},
		LastUsedAt: sql.NullString{String: decoyTime, Valid: true},
	}

	decoyConnectionRowPG = pggen.ListInstanceConnectionsRow{
		ID: "icn_decoy", PrincipalID: "mch_decoy", Label: "decoy",
		Kind: string(domain.CredentialHikyoToken), PrefixHint: "hik_1_ic_000000",
		Lifetime:        string(domain.LifetimeFinite),
		ExpiresAt:       pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		CredentialEpoch: 1,
		CreatedAt:       pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		CreatedBy:       "usr_decoy",
		// Matched to the sqlite decoy above, for the same reason: both nullable
		// timestamps present, so the two engines' miss paths are the shape of
		// their own heaviest hit rather than of each other's lightest.
		RevokedAt:  pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		LastUsedAt: pgtype.Timestamptz{Time: decoyInstant, Valid: true},
	}
)

// decoyConnectionWork* performs a hit's decode and compare on the miss path and
// always answers domain.ErrNotFound. The compare's result reaches decoySink
// rather than the return value: the outcome must not depend on it, but the work
// must still happen, and only an observable side effect guarantees the compiler
// leaves it alone.
func decoyConnectionWorkSQLite(verifier []byte) error {
	c, err := connectionFromSQLite(decoyConnectionRowSQLite)
	if err != nil {
		return err
	}
	sinkDecoy(uint64(c.CredentialEpoch), verifierMatches(decoyVerifier, verifier))
	return domain.ErrNotFound
}

func decoyConnectionWorkPG(verifier []byte) error {
	c, err := connectionFromPG(decoyConnectionRowPG)
	if err != nil {
		return err
	}
	sinkDecoy(uint64(c.CredentialEpoch), verifierMatches(decoyVerifier, verifier))
	return domain.ErrNotFound
}

// InstanceConnections lists every connection, metadata only — never the value.
// #17's list/get rule, inherited unchanged: a credential is display-once at
// mint and write-only after, and no statement anywhere reads the verifier back
// out for display.
func (r *Resolver) InstanceConnections(ctx context.Context) ([]InstanceConnection, error) {
	if r.sq != nil {
		rows, err := r.sq.ListInstanceConnections(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]InstanceConnection, 0, len(rows))
		for _, row := range rows {
			c, err := connectionFromSQLite(row)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, nil
	}
	rows, err := r.pg.ListInstanceConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]InstanceConnection, 0, len(rows))
	for _, row := range rows {
		c, err := connectionFromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// InstanceConnectionByID reads one, metadata only.
func (r *Resolver) InstanceConnectionByID(ctx context.Context, id string) (InstanceConnection, error) {
	if r.sq != nil {
		row, err := r.sq.GetInstanceConnection(ctx, id)
		if err != nil {
			return InstanceConnection{}, notFoundOr(err)
		}
		return connectionFromSQLite(sqlitegen.ListInstanceConnectionsRow(row))
	}
	row, err := r.pg.GetInstanceConnection(ctx, id)
	if err != nil {
		return InstanceConnection{}, notFoundOr(err)
	}
	return connectionFromPG(pggen.ListInstanceConnectionsRow(row))
}

// MintInstanceConnection writes the principal's credential row. The caller
// writes the `principals` row and the single `instance-directory` grant in the
// SAME transaction — the three are one unit, and a credential that outlived its
// grant would authenticate to nothing while still being presentable.
func (r *Resolver) MintInstanceConnection(ctx context.Context, n NewInstanceConnection) error {
	if r.sq != nil {
		return r.sq.CreateInstanceConnection(ctx, sqlitegen.CreateInstanceConnectionParams{
			ID: n.ID, PrincipalID: string(n.PrincipalID), Label: n.Label,
			Kind: string(n.Kind), Verifier: n.Verifier, PrefixHint: n.PrefixHint,
			Lifetime:        string(n.Lifetime),
			ExpiresAt:       nullTimeString(n.ExpiresAt),
			CredentialEpoch: n.CredentialEpoch,
			CreatedAt:       encodeTime(n.CreatedAt), CreatedBy: string(n.CreatedBy),
		})
	}
	return r.pg.CreateInstanceConnection(ctx, pggen.CreateInstanceConnectionParams{
		ID: n.ID, PrincipalID: string(n.PrincipalID), Label: n.Label,
		Kind: string(n.Kind), Verifier: n.Verifier, PrefixHint: n.PrefixHint,
		Lifetime:        string(n.Lifetime),
		ExpiresAt:       nullPGTime(n.ExpiresAt),
		CredentialEpoch: n.CredentialEpoch,
		CreatedAt:       pgTime(n.CreatedAt), CreatedBy: string(n.CreatedBy),
	})
}

// RevokeInstanceConnection kills the credential. It reports whether a live row
// was actually revoked, so a double revoke is a no-op the caller can see rather
// than a silent success that would put a second audit event on the trail for an
// act that did not happen.
func (r *Resolver) RevokeInstanceConnection(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.RevokeInstanceConnection(ctx, sqlitegen.RevokeInstanceConnectionParams{
			RevokedAt: nullTimeString(at), ID: id,
		})
		return n > 0, err
	}
	n, err := r.pg.RevokeInstanceConnection(ctx, pggen.RevokeInstanceConnectionParams{
		RevokedAt: nullPGTime(at), ID: id,
	})
	return n > 0, err
}

// TouchInstanceConnection stamps the last successful serve.
func (r *Resolver) TouchInstanceConnection(ctx context.Context, id string, at time.Time) error {
	if r.sq != nil {
		return r.sq.TouchInstanceConnection(ctx, sqlitegen.TouchInstanceConnectionParams{
			LastUsedAt: nullTimeString(at), ID: id,
		})
	}
	return r.pg.TouchInstanceConnection(ctx, pggen.TouchInstanceConnectionParams{
		LastUsedAt: nullPGTime(at), ID: id,
	})
}

// InstanceIdentity reads this instance's own opaque id, minted by migration
// 00015. A missing row is a hard error, never an empty string: the identity is
// what self-connection refusal compares against, and an empty one would make
// every remote look like a stranger — including this instance itself.
func (r *Resolver) InstanceIdentity(ctx context.Context) (string, error) {
	var (
		id  string
		err error
	)
	if r.sq != nil {
		id, err = r.sq.InstanceIdentity(ctx)
	} else {
		id, err = r.pg.InstanceIdentity(ctx)
	}
	if err != nil {
		return "", notFoundOr(err)
	}
	if id == "" {
		return "", errors.New("authn: the instance identity row is present but empty")
	}
	return id, nil
}

func connectionFromSQLite(row sqlitegen.ListInstanceConnectionsRow) (InstanceConnection, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return InstanceConnection{}, err
	}
	expires, err := decodeNullTime(row.ExpiresAt)
	if err != nil {
		return InstanceConnection{}, err
	}
	revoked, err := decodeNullTime(row.RevokedAt)
	if err != nil {
		return InstanceConnection{}, err
	}
	used, err := decodeNullTime(row.LastUsedAt)
	if err != nil {
		return InstanceConnection{}, err
	}
	return InstanceConnection{
		ID: row.ID, PrincipalID: domain.PrincipalID(row.PrincipalID), Label: row.Label,
		Kind: domain.CredentialKind(row.Kind), PrefixHint: row.PrefixHint,
		Lifetime: domain.CredentialLifetime(row.Lifetime), ExpiresAt: expires,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: created,
		CreatedBy: domain.PrincipalID(row.CreatedBy), RevokedAt: revoked, LastUsedAt: used,
	}, nil
}

func connectionFromPG(row pggen.ListInstanceConnectionsRow) (InstanceConnection, error) {
	return InstanceConnection{
		ID: row.ID, PrincipalID: domain.PrincipalID(row.PrincipalID), Label: row.Label,
		Kind: domain.CredentialKind(row.Kind), PrefixHint: row.PrefixHint,
		Lifetime: domain.CredentialLifetime(row.Lifetime), ExpiresAt: row.ExpiresAt.Time,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt.Time,
		CreatedBy: domain.PrincipalID(row.CreatedBy), RevokedAt: row.RevokedAt.Time,
		LastUsedAt: row.LastUsedAt.Time,
	}, nil
}
