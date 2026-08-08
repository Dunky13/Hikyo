package authn

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// Human authentication storage (#47, human-auth ADR).
//
// Why this lives in the resolution surface rather than behind the
// proof-carrying store: deciding WHO a caller is cannot run under a proof,
// because the proof is what the answer produces. That is the same bootstrap
// carve-out the tenant-isolation ADR already opened for chain resolution and
// grant lookup, applied to the other half of the same circularity — and it is
// why `sessions`, `accounts`, `password_credentials`, `credential_authorities`
// and `auth_instance_state` are declared `class=authn`, which the SQL
// predicate analyzer refuses to let any unannotated query touch.
//
// The writes below are a DEVIATION from the audit-model ADR's amendment part
// 4, which pinned WriteDenial as the resolution surface's single write path.
// The deviation is stated rather than hidden, and it is bounded the same way
// the original was: internal/lint's sole-writer analyzer now checks a pinned
// enumerated writer list, so a mutating call from anywhere else in this
// package still fails the build, and growing the list is a reviewed diff.
// See docs/handoff/47-first-slice.md.

// timeLayout is fixed-width microsecond UTC on sqlite: lexicographic order is
// time order, so a future range predicate works, and every row is the same
// width whatever the sub-second value.
const timeLayout = "2006-01-02T15:04:05.000000Z"

func encodeTime(t time.Time) string { return t.UTC().Truncate(time.Microsecond).Format(timeLayout) }

func decodeTime(s string) (time.Time, error) { return time.Parse(timeLayout, s) }

func canon(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: canon(t), Valid: true}
}

// Account is a human account: the login handle and display name beside the
// principal that carries the grants. `Username` is a handle, never an email —
// email is never a linking key, at any point, for any provider.
type Account struct {
	ID          string
	PrincipalID domain.PrincipalID
	Username    string
	DisplayName string
	CreatedAt   time.Time
}

// KDFParams are the Argon2id parameters recorded per verifier, so the floor
// can be raised without invalidating existing credentials.
type KDFParams struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
}

// PasswordCredential is an envelope-encrypted Argon2id verifier plus the
// parameters it was derived under. RowVersion is the compare-and-swap target
// every writer must present.
type PasswordCredential struct {
	AccountID       string
	Verifier        []byte
	KDF             KDFParams
	DEKVersion      int64
	CredentialEpoch int64
	RowVersion      int64
}

// SessionRow is a resolved session with the assurance record the chokepoint
// consults. The verifier never leaves the database.
type SessionRow struct {
	ID                string
	PrincipalID       domain.PrincipalID
	Artifact          string
	SessionGeneration int64
	CredentialEpoch   int64
	AuthMethod        string
	Factors           string // JSON array of factor classes, as stored
	AuthenticatedAt   time.Time
	CeremonyID        string
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

// NewSession is the insert carrier for a freshly minted session.
type NewSession struct {
	ID                string
	PrincipalID       domain.PrincipalID
	Verifier          []byte
	Artifact          string
	SessionGeneration int64
	CredentialEpoch   int64
	AuthMethod        string
	Factors           string
	AuthenticatedAt   time.Time
	CeremonyID        string
	CreatedAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	SourceIP          string
	UserAgent         string
	// ProviderID is the federated-session sweep key (A4): the OIDC provider a
	// session authenticated through, empty for local sessions.
	ProviderID string
	// CSRFVerifier is the fast-hash verifier of a browser session's synchronizer
	// token (A9), nil for CLI sessions (a cookie's attributes protect nothing on
	// a non-browser client).
	CSRFVerifier []byte
}

// CredentialAuthority is a resolved credential-establishment authority.
// Consumed and expiry state travel with it so the caller refuses uniformly
// rather than branching on a second lookup.
type CredentialAuthority struct {
	ID              string
	AccountID       string
	Purpose         string
	IssuedBy        string
	CredentialEpoch int64
	ExpiresAt       time.Time
	Consumed        bool
}

// NewCredentialAuthority is the insert carrier for a minted authority.
type NewCredentialAuthority struct {
	ID              string
	Verifier        []byte
	AccountID       string
	Purpose         string
	IssuedBy        string
	CredentialEpoch int64
	ExpiresAt       time.Time
	CreatedAt       time.Time
}

// CredentialEpoch reads the instance epoch. Every artifact records the epoch
// it was created under; one from an earlier epoch is inert.
func (r *Resolver) CredentialEpoch(ctx context.Context) (int64, error) {
	if r.sq != nil {
		return r.sq.GetCredentialEpoch(ctx)
	}
	return r.pg.GetCredentialEpoch(ctx)
}

// AccountByUsername resolves a login handle. A missing account is
// domain.ErrNotFound — the caller must still traverse the dummy-verifier path
// so no pre-authentication path distinguishes an existing account from a
// missing one.
func (r *Resolver) AccountByUsername(ctx context.Context, username string) (Account, error) {
	if r.sq != nil {
		row, err := r.sq.GetAccountByUsername(ctx, username)
		if err != nil {
			return Account{}, notFoundOr(err)
		}
		return sqliteAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt)
	}
	row, err := r.pg.GetAccountByUsername(ctx, username)
	if err != nil {
		return Account{}, notFoundOr(err)
	}
	return pgAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt.Time), nil
}

// AccountByID resolves an account for the whoami and reset paths.
func (r *Resolver) AccountByID(ctx context.Context, id string) (Account, error) {
	if r.sq != nil {
		row, err := r.sq.GetAccountByID(ctx, id)
		if err != nil {
			return Account{}, notFoundOr(err)
		}
		return sqliteAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt)
	}
	row, err := r.pg.GetAccountByID(ctx, id)
	if err != nil {
		return Account{}, notFoundOr(err)
	}
	return pgAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt.Time), nil
}

// AccountByPrincipal resolves the account a session's principal owns — the
// bridge every factor path needs, since a session is keyed by principal but a
// factor row (password, TOTP, recovery) is keyed by account. A human principal
// owns exactly one account.
func (r *Resolver) AccountByPrincipal(ctx context.Context, p domain.PrincipalID) (Account, error) {
	if r.sq != nil {
		row, err := r.sq.GetAccountByPrincipal(ctx, string(p))
		if err != nil {
			return Account{}, notFoundOr(err)
		}
		return sqliteAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt)
	}
	row, err := r.pg.GetAccountByPrincipal(ctx, string(p))
	if err != nil {
		return Account{}, notFoundOr(err)
	}
	return pgAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt.Time), nil
}

// AccountCount answers the bootstrap path's one question: is this a fresh
// instance? It is deliberately not exposed over the network.
func (r *Resolver) AccountCount(ctx context.Context) (int64, error) {
	if r.sq != nil {
		return r.sq.CountAccounts(ctx)
	}
	return r.pg.CountAccounts(ctx)
}

// PasswordCredential reads an account's verifier row.
func (r *Resolver) PasswordCredential(ctx context.Context, accountID string) (PasswordCredential, error) {
	if r.sq != nil {
		row, err := r.sq.GetPasswordCredential(ctx, accountID)
		if err != nil {
			return PasswordCredential{}, notFoundOr(err)
		}
		return PasswordCredential{
			AccountID: row.AccountID, Verifier: row.Verifier,
			KDF:             KDFParams{MemoryKiB: uint32(row.KdfMemoryKib), Time: uint32(row.KdfTime), Parallelism: uint8(row.KdfParallelism)},
			DEKVersion:      row.DekVersion,
			CredentialEpoch: row.CredentialEpoch,
			RowVersion:      row.RowVersion,
		}, nil
	}
	row, err := r.pg.GetPasswordCredential(ctx, accountID)
	if err != nil {
		return PasswordCredential{}, notFoundOr(err)
	}
	return PasswordCredential{
		AccountID: row.AccountID, Verifier: row.Verifier,
		KDF:             KDFParams{MemoryKiB: uint32(row.KdfMemoryKib), Time: uint32(row.KdfTime), Parallelism: uint8(row.KdfParallelism)},
		DEKVersion:      row.DekVersion,
		CredentialEpoch: row.CredentialEpoch,
		RowVersion:      row.RowVersion,
	}, nil
}

// PrincipalGeneration reads the principal's current session generation. A
// session whose recorded generation is behind is dead — that is how a grant
// change reaches an idle or stolen session without needing to tell it.
// A principal with no row answers domain.ErrNotFound rather than a raw
// driver error: the session-liveness path reads a generation for every
// presentation including ones that resolved no session at all, so "no such
// principal" has to be an ordinary outcome there rather than a fault.
func (r *Resolver) PrincipalGeneration(ctx context.Context, p domain.PrincipalID) (int64, error) {
	if r.sq != nil {
		n, err := r.sq.GetPrincipalGeneration(ctx, string(p))
		return n, notFoundOr(err)
	}
	n, err := r.pg.GetPrincipalGeneration(ctx, string(p))
	return n, notFoundOr(err)
}

// SessionByVerifier resolves a presented artifact. Expiry, generation and
// epoch are NOT evaluated here: the caller does that with the clock and the
// live counters, so one place owns the liveness rule.
func (r *Resolver) SessionByVerifier(ctx context.Context, verifier []byte) (SessionRow, error) {
	if r.sq != nil {
		row, err := r.sq.GetSessionByVerifier(ctx, verifier)
		if err != nil {
			return SessionRow{}, notFoundOr(err)
		}
		return sqliteSession(row)
	}
	row, err := r.pg.GetSessionByVerifier(ctx, verifier)
	if err != nil {
		return SessionRow{}, notFoundOr(err)
	}
	return SessionRow{
		ID: row.ID, PrincipalID: domain.PrincipalID(row.PrincipalID), Artifact: row.Artifact,
		SessionGeneration: row.SessionGeneration, CredentialEpoch: row.CredentialEpoch,
		AuthMethod: row.AuthMethod, Factors: row.Factors,
		AuthenticatedAt: row.AuthenticatedAt.Time, CeremonyID: row.CeremonyID.String,
		CreatedAt: row.CreatedAt.Time, LastSeenAt: row.LastSeenAt.Time,
		IdleExpiresAt: row.IdleExpiresAt.Time, AbsoluteExpiresAt: row.AbsoluteExpiresAt.Time,
	}, nil
}

// CredentialAuthorityByVerifier resolves a presented establishment authority.
func (r *Resolver) CredentialAuthorityByVerifier(ctx context.Context, verifier []byte) (CredentialAuthority, error) {
	if r.sq != nil {
		row, err := r.sq.GetCredentialAuthorityByVerifier(ctx, verifier)
		if err != nil {
			return CredentialAuthority{}, notFoundOr(err)
		}
		expires, err := decodeTime(row.ExpiresAt)
		if err != nil {
			return CredentialAuthority{}, err
		}
		return CredentialAuthority{
			ID: row.ID, AccountID: row.AccountID, Purpose: row.Purpose, IssuedBy: row.IssuedBy,
			CredentialEpoch: row.CredentialEpoch, ExpiresAt: expires, Consumed: row.ConsumedAt.Valid,
		}, nil
	}
	row, err := r.pg.GetCredentialAuthorityByVerifier(ctx, verifier)
	if err != nil {
		return CredentialAuthority{}, notFoundOr(err)
	}
	return CredentialAuthority{
		ID: row.ID, AccountID: row.AccountID, Purpose: row.Purpose, IssuedBy: row.IssuedBy,
		CredentialEpoch: row.CredentialEpoch, ExpiresAt: row.ExpiresAt.Time, Consumed: row.ConsumedAt.Valid,
	}, nil
}

// ---------------------------------------------------------------------------
// Enumerated writers. internal/lint's sole-writer analyzer pins this list by
// name; a mutating generated-query call anywhere else in this package fails
// the build.
// ---------------------------------------------------------------------------

// CreatePrincipal and CreateAccount are the bootstrap path's writes. They run
// on the server's own host under local authority (`wenv admin create`), never
// over the network — the closed local-authority exception set's bootstrap
// member, not a new authority.
func (r *Resolver) CreatePrincipal(ctx context.Context, id domain.PrincipalID, kind string, at time.Time) error {
	if r.sq != nil {
		return r.sq.InsertPrincipal(ctx, sqlitegen.InsertPrincipalParams{
			ID: string(id), Kind: kind, CreatedAt: encodeTime(at),
		})
	}
	return r.pg.InsertPrincipal(ctx, pggen.InsertPrincipalParams{
		ID: string(id), Kind: kind, CreatedAt: pgTime(at),
	})
}

func (r *Resolver) CreateAccount(ctx context.Context, a Account) error {
	if r.sq != nil {
		return r.sq.InsertAccount(ctx, sqlitegen.InsertAccountParams{
			ID: a.ID, PrincipalID: string(a.PrincipalID), Username: a.Username,
			DisplayName: a.DisplayName, CreatedAt: encodeTime(a.CreatedAt),
		})
	}
	return r.pg.InsertAccount(ctx, pggen.InsertAccountParams{
		ID: a.ID, PrincipalID: string(a.PrincipalID), Username: a.Username,
		DisplayName: a.DisplayName, CreatedAt: pgTime(a.CreatedAt),
	})
}

// CreateGrant writes one grant row. The bootstrap path uses it to apply the
// `admin` template, which the permission ADR requires to expand into separate,
// visible, individually revocable rows rather than an implicit bundle. The
// general grant API — dedup, revocation, session-generation advance — is #55's.
func (r *Resolver) CreateGrant(ctx context.Context, id string, p domain.PrincipalID, g domain.Grant, at time.Time) error {
	if _, err := g.Scope.Level(); err != nil {
		return err
	}
	// Grant-lock obligation (#54 B14): take the target principal's row lock
	// before the insert so the credential-reset org-bounded test — which locks
	// the same row — serializes against a concurrent grant landing. A future
	// grant writer (#55) inherits this obligation, pinned by the grant-lock
	// analyzer. sqlite serializes on its single writer; postgres holds FOR UPDATE.
	if err := r.LockPrincipalRow(ctx, p); err != nil {
		return err
	}
	if r.sq != nil {
		return r.sq.InsertGrant(ctx, sqlitegen.InsertGrantParams{
			ID: id, PrincipalID: string(p), Capability: string(g.Capability),
			OrgID:     nullString(string(g.Scope.Org)),
			ProjectID: nullString(string(g.Scope.Project)),
			EnvID:     nullString(string(g.Scope.Env)),
			CreatedAt: encodeTime(at),
		})
	}
	return r.pg.InsertGrant(ctx, pggen.InsertGrantParams{
		ID: id, PrincipalID: string(p), Capability: string(g.Capability),
		OrgID:     pgText(string(g.Scope.Org)),
		ProjectID: pgText(string(g.Scope.Project)),
		EnvID:     pgText(string(g.Scope.Env)),
		CreatedAt: pgTime(at),
	})
}

func (r *Resolver) CreateCredentialAuthority(ctx context.Context, a NewCredentialAuthority) error {
	if r.sq != nil {
		return r.sq.InsertCredentialAuthority(ctx, sqlitegen.InsertCredentialAuthorityParams{
			ID: a.ID, Verifier: a.Verifier, AccountID: a.AccountID, Purpose: a.Purpose,
			IssuedBy: a.IssuedBy, CredentialEpoch: a.CredentialEpoch,
			ExpiresAt: encodeTime(a.ExpiresAt), CreatedAt: encodeTime(a.CreatedAt),
		})
	}
	return r.pg.InsertCredentialAuthority(ctx, pggen.InsertCredentialAuthorityParams{
		ID: a.ID, Verifier: a.Verifier, AccountID: a.AccountID, Purpose: a.Purpose,
		IssuedBy: a.IssuedBy, CredentialEpoch: a.CredentialEpoch,
		ExpiresAt: pgTime(a.ExpiresAt), CreatedAt: pgTime(a.CreatedAt),
	})
}

// ConsumeCredentialAuthority claims the authority atomically. It reports
// false when the row was already consumed — two concurrent presentations
// cannot both establish a credential, and the loser fails closed.
func (r *Resolver) ConsumeCredentialAuthority(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeCredentialAuthority(ctx, sqlitegen.ConsumeCredentialAuthorityParams{
			ConsumedAt: sql.NullString{String: encodeTime(at), Valid: true}, ID: id,
		})
		return n == 1, err
	}
	n, err := r.pg.ConsumeCredentialAuthority(ctx, pggen.ConsumeCredentialAuthorityParams{
		ConsumedAt: pgTime(at), ID: id,
	})
	return n == 1, err
}

func (r *Resolver) CreatePasswordCredential(ctx context.Context, c PasswordCredential, at time.Time) error {
	if r.sq != nil {
		return r.sq.InsertPasswordCredential(ctx, sqlitegen.InsertPasswordCredentialParams{
			AccountID: c.AccountID, Verifier: c.Verifier,
			KdfMemoryKib: int64(c.KDF.MemoryKiB), KdfTime: int64(c.KDF.Time),
			KdfParallelism: int64(c.KDF.Parallelism), DekVersion: c.DEKVersion,
			CredentialEpoch: c.CredentialEpoch, UpdatedAt: encodeTime(at),
		})
	}
	return r.pg.InsertPasswordCredential(ctx, pggen.InsertPasswordCredentialParams{
		AccountID: c.AccountID, Verifier: c.Verifier,
		KdfMemoryKib: int64(c.KDF.MemoryKiB), KdfTime: int64(c.KDF.Time),
		KdfParallelism: int64(c.KDF.Parallelism), DekVersion: c.DEKVersion,
		CredentialEpoch: c.CredentialEpoch, UpdatedAt: pgTime(at),
	})
}

// UpdatePasswordCredential compare-and-swaps on RowVersion, which must hold
// the value the caller read. It reports false when the row moved underneath —
// the caller then retries or fails loudly, never writing a stale verifier
// back.
func (r *Resolver) UpdatePasswordCredential(ctx context.Context, c PasswordCredential, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.UpdatePasswordCredentialCAS(ctx, sqlitegen.UpdatePasswordCredentialCASParams{
			Verifier: c.Verifier, KdfMemoryKib: int64(c.KDF.MemoryKiB), KdfTime: int64(c.KDF.Time),
			KdfParallelism: int64(c.KDF.Parallelism), DekVersion: c.DEKVersion,
			CredentialEpoch: c.CredentialEpoch, UpdatedAt: encodeTime(at),
			AccountID: c.AccountID, RowVersion: c.RowVersion,
		})
		return n == 1, err
	}
	n, err := r.pg.UpdatePasswordCredentialCAS(ctx, pggen.UpdatePasswordCredentialCASParams{
		Verifier: c.Verifier, KdfMemoryKib: int64(c.KDF.MemoryKiB), KdfTime: int64(c.KDF.Time),
		KdfParallelism: int64(c.KDF.Parallelism), DekVersion: c.DEKVersion,
		CredentialEpoch: c.CredentialEpoch, UpdatedAt: pgTime(at),
		AccountID: c.AccountID, RowVersion: c.RowVersion,
	})
	return n == 1, err
}

func (r *Resolver) CreateSession(ctx context.Context, s NewSession) error {
	if r.sq != nil {
		return r.sq.InsertSession(ctx, sqlitegen.InsertSessionParams{
			ID: s.ID, PrincipalID: string(s.PrincipalID), Verifier: s.Verifier,
			Artifact: s.Artifact, SessionGeneration: s.SessionGeneration,
			CredentialEpoch: s.CredentialEpoch, AuthMethod: s.AuthMethod, Factors: s.Factors,
			AuthenticatedAt: encodeTime(s.AuthenticatedAt), CeremonyID: nullString(s.CeremonyID),
			CreatedAt: encodeTime(s.CreatedAt), LastSeenAt: encodeTime(s.CreatedAt),
			IdleExpiresAt: encodeTime(s.IdleExpiresAt), AbsoluteExpiresAt: encodeTime(s.AbsoluteExpiresAt),
			SourceIp: s.SourceIP, UserAgent: s.UserAgent, ProviderID: nullString(s.ProviderID),
			CsrfVerifier: s.CSRFVerifier,
		})
	}
	return r.pg.InsertSession(ctx, pggen.InsertSessionParams{
		ID: s.ID, PrincipalID: string(s.PrincipalID), Verifier: s.Verifier,
		Artifact: s.Artifact, SessionGeneration: s.SessionGeneration,
		CredentialEpoch: s.CredentialEpoch, AuthMethod: s.AuthMethod, Factors: s.Factors,
		AuthenticatedAt: pgTime(s.AuthenticatedAt), CeremonyID: pgText(s.CeremonyID),
		CreatedAt: pgTime(s.CreatedAt), LastSeenAt: pgTime(s.CreatedAt),
		IdleExpiresAt: pgTime(s.IdleExpiresAt), AbsoluteExpiresAt: pgTime(s.AbsoluteExpiresAt),
		SourceIp: s.SourceIP, UserAgent: s.UserAgent, ProviderID: pgText(s.ProviderID),
		CsrfVerifier: s.CSRFVerifier,
	})
}

// TouchSession slides the idle clock. The absolute clock is never extended:
// two independent clocks is the point.
func (r *Resolver) TouchSession(ctx context.Context, id string, seen, idleExpires time.Time) error {
	if r.sq != nil {
		return r.sq.TouchSession(ctx, sqlitegen.TouchSessionParams{
			LastSeenAt: encodeTime(seen), IdleExpiresAt: encodeTime(idleExpires), ID: id,
		})
	}
	return r.pg.TouchSession(ctx, pggen.TouchSessionParams{
		LastSeenAt: pgTime(seen), IdleExpiresAt: pgTime(idleExpires), ID: id,
	})
}

// DeleteSession is revocation: a delete in the request's own transaction,
// which is the literal reading of the no-authorization-cache rule.
func (r *Resolver) DeleteSession(ctx context.Context, id string) error {
	if r.sq != nil {
		return r.sq.DeleteSession(ctx, id)
	}
	return r.pg.DeleteSession(ctx, id)
}

func (r *Resolver) DeleteSessionsForPrincipal(ctx context.Context, p domain.PrincipalID) error {
	if r.sq != nil {
		return r.sq.DeleteSessionsForPrincipal(ctx, string(p))
	}
	return r.pg.DeleteSessionsForPrincipal(ctx, string(p))
}

// AdvanceGeneration invalidates every session of the principal at once. It
// runs in the same transaction as the change that triggered it — grant
// revocation, grant addition or widening, password change, factor enrolment
// or removal, recovery-code consumption, administrative reset.
func (r *Resolver) AdvanceGeneration(ctx context.Context, p domain.PrincipalID) error {
	if r.sq != nil {
		return r.sq.AdvancePrincipalGeneration(ctx, string(p))
	}
	return r.pg.AdvancePrincipalGeneration(ctx, string(p))
}

// nullString and pgText encode structural absence rather than an empty
// string: "no ceremony" and "a ceremony whose id is blank" are different
// facts, and only one of them is true.
func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func pgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

// sqliteAccount and pgAccount build an Account from the five columns every
// account read selects. They take scalars rather than a row type because the
// accounts table gained webauthn_user_handle (#54): sqlc now emits a distinct
// Row type per query instead of the shared model, and a scalar signature reads
// them all.
func sqliteAccount(id, principalID, username, displayName, createdAt string) (Account, error) {
	created, err := decodeTime(createdAt)
	if err != nil {
		return Account{}, err
	}
	return Account{
		ID: id, PrincipalID: domain.PrincipalID(principalID),
		Username: username, DisplayName: displayName, CreatedAt: created,
	}, nil
}

func pgAccount(id, principalID, username, displayName string, createdAt time.Time) Account {
	return Account{
		ID: id, PrincipalID: domain.PrincipalID(principalID),
		Username: username, DisplayName: displayName, CreatedAt: createdAt,
	}
}

func sqliteSession(row sqlitegen.GetSessionByVerifierRow) (SessionRow, error) {
	var (
		out SessionRow
		err error
	)
	out = SessionRow{
		ID: row.ID, PrincipalID: domain.PrincipalID(row.PrincipalID), Artifact: row.Artifact,
		SessionGeneration: row.SessionGeneration, CredentialEpoch: row.CredentialEpoch,
		AuthMethod: row.AuthMethod, Factors: row.Factors, CeremonyID: row.CeremonyID.String,
	}
	for _, f := range []struct {
		src string
		dst *time.Time
	}{
		{row.AuthenticatedAt, &out.AuthenticatedAt},
		{row.CreatedAt, &out.CreatedAt},
		{row.LastSeenAt, &out.LastSeenAt},
		{row.IdleExpiresAt, &out.IdleExpiresAt},
		{row.AbsoluteExpiresAt, &out.AbsoluteExpiresAt},
	} {
		if *f.dst, err = decodeTime(f.src); err != nil {
			return SessionRow{}, errors.New("authn: session row carries an unparseable timestamp")
		}
	}
	return out, nil
}
