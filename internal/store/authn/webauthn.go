package authn

import (
	"context"
	"database/sql"
	"time"

	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// WebAuthn storage (#54, human-auth ADR § WebAuthn relying-party policy, §
// Passkey login). Public keys and ceremony session data are not secrets — the
// private key never leaves the authenticator — so nothing here is
// envelope-encrypted; this layer owns only the enumerated reads and writes,
// each pinned by the sole-writer analyzer like every other member of the
// resolution surface.

// WebAuthnCredential is a resolved registered credential.
type WebAuthnCredential struct {
	ID              string
	AccountID       string
	CredentialID    []byte
	PublicKey       []byte
	AAGUID          []byte
	SignCount       int64
	Transports      string
	Discoverable    bool
	BackupEligible  bool
	BackupState     bool
	Label           string
	CredentialEpoch int64
	RowVersion      int64
	Disabled        bool
	CreatedAt       time.Time
	LastUsedAt      time.Time
}

// NewWebAuthnCredential is the insert carrier for a freshly enrolled passkey.
type NewWebAuthnCredential struct {
	ID              string
	AccountID       string
	CredentialID    []byte
	PublicKey       []byte
	AAGUID          []byte
	SignCount       int64
	Transports      string
	Discoverable    bool
	BackupEligible  bool
	BackupState     bool
	Label           string
	CredentialEpoch int64
	CreatedAt       time.Time
}

// WebAuthnCeremony is a resolved ceremony row. Nullable ids flatten to empty
// strings, matching the OIDC transaction reader.
type WebAuthnCeremony struct {
	ID                string
	ChallengeVerifier []byte
	SessionData       []byte
	AccountID         string
	SessionID         string
	Purpose           string
	OperationBinding  string
	EnvironmentID     string
	CredentialID      string
	CredentialEpoch   int64
	ExpiresAt         time.Time
	Consumed          bool
	CreatedAt         time.Time
}

// NewWebAuthnCeremony is the ceremony insert carrier. Empty-string ids become
// NULL; credential_id is stamped only at consume, never at insert.
type NewWebAuthnCeremony struct {
	ID                string
	ChallengeVerifier []byte
	SessionData       []byte
	AccountID         string
	SessionID         string
	Purpose           string
	OperationBinding  string
	EnvironmentID     string
	CredentialEpoch   int64
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

func decodeNullTime(n sql.NullString) (time.Time, error) {
	if !n.Valid {
		return time.Time{}, nil
	}
	return decodeTime(n.String)
}

func sqliteWebAuthnCredential(row sqlitegen.WebauthnCredential) (WebAuthnCredential, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	lastUsed, err := decodeNullTime(row.LastUsedAt)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	return WebAuthnCredential{
		ID: row.ID, AccountID: row.AccountID, CredentialID: row.CredentialID,
		PublicKey: row.PublicKey, AAGUID: row.Aaguid, SignCount: row.SignCount,
		Transports: row.Transports, Discoverable: row.Discoverable == 1,
		BackupEligible: row.BackupEligible == 1, BackupState: row.BackupState == 1,
		Label: row.Label, CredentialEpoch: row.CredentialEpoch, RowVersion: row.RowVersion,
		Disabled: row.DisabledAt.Valid, CreatedAt: created, LastUsedAt: lastUsed,
	}, nil
}

func pgWebAuthnCredential(row pggen.WebauthnCredential) WebAuthnCredential {
	return WebAuthnCredential{
		ID: row.ID, AccountID: row.AccountID, CredentialID: row.CredentialID,
		PublicKey: row.PublicKey, AAGUID: row.Aaguid, SignCount: row.SignCount,
		Transports: row.Transports, Discoverable: row.Discoverable == 1,
		BackupEligible: row.BackupEligible == 1, BackupState: row.BackupState == 1,
		Label: row.Label, CredentialEpoch: row.CredentialEpoch, RowVersion: row.RowVersion,
		Disabled: row.DisabledAt.Valid, CreatedAt: row.CreatedAt.Time, LastUsedAt: row.LastUsedAt.Time,
	}
}

func sqliteWebAuthnCeremony(row sqlitegen.WebauthnCeremony) (WebAuthnCeremony, error) {
	expires, err := decodeTime(row.ExpiresAt)
	if err != nil {
		return WebAuthnCeremony{}, err
	}
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return WebAuthnCeremony{}, err
	}
	return WebAuthnCeremony{
		ID: row.ID, ChallengeVerifier: row.ChallengeVerifier, SessionData: row.SessionData,
		AccountID: row.AccountID.String, SessionID: row.SessionID.String, Purpose: row.Purpose,
		OperationBinding: row.OperationBinding.String, EnvironmentID: row.EnvironmentID.String,
		CredentialID: row.CredentialID.String, CredentialEpoch: row.CredentialEpoch,
		ExpiresAt: expires, Consumed: row.ConsumedAt.Valid, CreatedAt: created,
	}, nil
}

func pgWebAuthnCeremony(row pggen.WebauthnCeremony) WebAuthnCeremony {
	return WebAuthnCeremony{
		ID: row.ID, ChallengeVerifier: row.ChallengeVerifier, SessionData: row.SessionData,
		AccountID: row.AccountID.String, SessionID: row.SessionID.String, Purpose: row.Purpose,
		OperationBinding: row.OperationBinding.String, EnvironmentID: row.EnvironmentID.String,
		CredentialID: row.CredentialID.String, CredentialEpoch: row.CredentialEpoch,
		ExpiresAt: row.ExpiresAt.Time, Consumed: row.ConsumedAt.Valid, CreatedAt: row.CreatedAt.Time,
	}
}

// WebAuthnCredentialByID resolves a credential by its surrogate id.
func (r *Resolver) WebAuthnCredentialByID(ctx context.Context, id string) (WebAuthnCredential, error) {
	if r.sq != nil {
		row, err := r.sq.GetWebAuthnCredentialByID(ctx, id)
		if err != nil {
			return WebAuthnCredential{}, notFoundOr(err)
		}
		return sqliteWebAuthnCredential(row)
	}
	row, err := r.pg.GetWebAuthnCredentialByID(ctx, id)
	if err != nil {
		return WebAuthnCredential{}, notFoundOr(err)
	}
	return pgWebAuthnCredential(row), nil
}

// WebAuthnCredentialByCredentialID resolves the row an assertion names.
func (r *Resolver) WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (WebAuthnCredential, error) {
	if r.sq != nil {
		row, err := r.sq.GetWebAuthnCredentialByCredentialID(ctx, credentialID)
		if err != nil {
			return WebAuthnCredential{}, notFoundOr(err)
		}
		return sqliteWebAuthnCredential(row)
	}
	row, err := r.pg.GetWebAuthnCredentialByCredentialID(ctx, credentialID)
	if err != nil {
		return WebAuthnCredential{}, notFoundOr(err)
	}
	return pgWebAuthnCredential(row), nil
}

// WebAuthnCredentialsForAccount lists every credential of an account.
func (r *Resolver) WebAuthnCredentialsForAccount(ctx context.Context, accountID string) ([]WebAuthnCredential, error) {
	if r.sq != nil {
		rows, err := r.sq.ListWebAuthnCredentialsForAccount(ctx, accountID)
		if err != nil {
			return nil, err
		}
		out := make([]WebAuthnCredential, 0, len(rows))
		for _, row := range rows {
			c, err := sqliteWebAuthnCredential(row)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, nil
	}
	rows, err := r.pg.ListWebAuthnCredentialsForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]WebAuthnCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, pgWebAuthnCredential(row))
	}
	return out, nil
}

// CreateWebAuthnCredential inserts a freshly enrolled passkey.
func (r *Resolver) CreateWebAuthnCredential(ctx context.Context, c NewWebAuthnCredential) error {
	if r.sq != nil {
		return r.sq.InsertWebAuthnCredential(ctx, sqlitegen.InsertWebAuthnCredentialParams{
			ID: c.ID, AccountID: c.AccountID, CredentialID: c.CredentialID, PublicKey: c.PublicKey,
			Aaguid: c.AAGUID, SignCount: c.SignCount, Transports: c.Transports,
			Discoverable: boolInt(c.Discoverable), BackupEligible: boolInt(c.BackupEligible),
			BackupState: boolInt(c.BackupState), Label: c.Label, CredentialEpoch: c.CredentialEpoch,
			CreatedAt: encodeTime(c.CreatedAt),
		})
	}
	return r.pg.InsertWebAuthnCredential(ctx, pggen.InsertWebAuthnCredentialParams{
		ID: c.ID, AccountID: c.AccountID, CredentialID: c.CredentialID, PublicKey: c.PublicKey,
		Aaguid: c.AAGUID, SignCount: c.SignCount, Transports: c.Transports,
		Discoverable: boolInt(c.Discoverable), BackupEligible: boolInt(c.BackupEligible),
		BackupState: boolInt(c.BackupState), Label: c.Label, CredentialEpoch: c.CredentialEpoch,
		CreatedAt: pgTime(c.CreatedAt),
	})
}

// AdvanceWebAuthnSignCount writes the presented counter under a row_version CAS.
// False means the row moved or was disabled — the single-writer guarantee.
func (r *Resolver) AdvanceWebAuthnSignCount(ctx context.Context, id string, rowVersion, count int64, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.AdvanceWebAuthnSignCount(ctx, sqlitegen.AdvanceWebAuthnSignCountParams{
			SignCount: count, LastUsedAt: sql.NullString{String: encodeTime(at), Valid: true},
			ID: id, RowVersion: rowVersion,
		})
		return n == 1, err
	}
	n, err := r.pg.AdvanceWebAuthnSignCount(ctx, pggen.AdvanceWebAuthnSignCountParams{
		SignCount: count, LastUsedAt: pgTime(at), ID: id, RowVersion: rowVersion,
	})
	return n == 1, err
}

// DisableWebAuthnCredential sets disabled_at under a row_version CAS (the clone
// response). False means the row moved or was already disabled.
func (r *Resolver) DisableWebAuthnCredential(ctx context.Context, id string, rowVersion int64, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.DisableWebAuthnCredential(ctx, sqlitegen.DisableWebAuthnCredentialParams{
			DisabledAt: sql.NullString{String: encodeTime(at), Valid: true}, ID: id, RowVersion: rowVersion,
		})
		return n == 1, err
	}
	n, err := r.pg.DisableWebAuthnCredential(ctx, pggen.DisableWebAuthnCredentialParams{
		DisabledAt: pgTime(at), ID: id, RowVersion: rowVersion,
	})
	return n == 1, err
}

// DeleteWebAuthnCredential removes a credential (de-enrolment).
func (r *Resolver) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	if r.sq != nil {
		return r.sq.DeleteWebAuthnCredential(ctx, id)
	}
	return r.pg.DeleteWebAuthnCredential(ctx, id)
}

// DeleteSessionsForWebAuthnCredential sweeps every session a passkey login
// minted through a credential, tracing sessions.ceremony_id ->
// webauthn_ceremonies.credential_id. Returns the count for audit.
func (r *Resolver) DeleteSessionsForWebAuthnCredential(ctx context.Context, credentialID string) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteSessionsForWebAuthnCredential(ctx, nullString(credentialID))
	}
	return r.pg.DeleteSessionsForWebAuthnCredential(ctx, pgText(credentialID))
}

// CreateWebAuthnCeremony writes a single-use, expiring challenge row.
func (r *Resolver) CreateWebAuthnCeremony(ctx context.Context, c NewWebAuthnCeremony) error {
	if r.sq != nil {
		return r.sq.InsertWebAuthnCeremony(ctx, sqlitegen.InsertWebAuthnCeremonyParams{
			ID: c.ID, ChallengeVerifier: c.ChallengeVerifier, SessionData: c.SessionData,
			AccountID: nullString(c.AccountID), SessionID: nullString(c.SessionID), Purpose: c.Purpose,
			OperationBinding: nullString(c.OperationBinding), EnvironmentID: nullString(c.EnvironmentID),
			CredentialEpoch: c.CredentialEpoch, ExpiresAt: encodeTime(c.ExpiresAt), CreatedAt: encodeTime(c.CreatedAt),
		})
	}
	return r.pg.InsertWebAuthnCeremony(ctx, pggen.InsertWebAuthnCeremonyParams{
		ID: c.ID, ChallengeVerifier: c.ChallengeVerifier, SessionData: c.SessionData,
		AccountID: pgText(c.AccountID), SessionID: pgText(c.SessionID), Purpose: c.Purpose,
		OperationBinding: pgText(c.OperationBinding), EnvironmentID: pgText(c.EnvironmentID),
		CredentialEpoch: c.CredentialEpoch, ExpiresAt: pgTime(c.ExpiresAt), CreatedAt: pgTime(c.CreatedAt),
	})
}

// WebAuthnCeremonyByChallenge resolves a ceremony by its challenge verifier.
func (r *Resolver) WebAuthnCeremonyByChallenge(ctx context.Context, challengeVerifier []byte) (WebAuthnCeremony, error) {
	if r.sq != nil {
		row, err := r.sq.GetWebAuthnCeremonyByChallenge(ctx, challengeVerifier)
		if err != nil {
			return WebAuthnCeremony{}, notFoundOr(err)
		}
		return sqliteWebAuthnCeremony(row)
	}
	row, err := r.pg.GetWebAuthnCeremonyByChallenge(ctx, challengeVerifier)
	if err != nil {
		return WebAuthnCeremony{}, notFoundOr(err)
	}
	return pgWebAuthnCeremony(row), nil
}

// ConsumeWebAuthnCeremony claims a ceremony atomically and stamps the credential
// that answered it. False means it was already consumed and the caller must fail
// closed. credentialID is empty for a ceremony no credential answered (a refused
// finish still consumes its challenge).
func (r *Resolver) ConsumeWebAuthnCeremony(ctx context.Context, id, credentialID string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeWebAuthnCeremony(ctx, sqlitegen.ConsumeWebAuthnCeremonyParams{
			ConsumedAt:   sql.NullString{String: encodeTime(at), Valid: true},
			CredentialID: nullString(credentialID), ID: id,
		})
		return n == 1, err
	}
	n, err := r.pg.ConsumeWebAuthnCeremony(ctx, pggen.ConsumeWebAuthnCeremonyParams{
		ConsumedAt: pgTime(at), CredentialID: pgText(credentialID), ID: id,
	})
	return n == 1, err
}

// WebAuthnUserHandle reads an account's opaque handle, or nil when none is set.
func (r *Resolver) WebAuthnUserHandle(ctx context.Context, accountID string) ([]byte, error) {
	if r.sq != nil {
		h, err := r.sq.GetWebAuthnUserHandle(ctx, accountID)
		if err != nil {
			return nil, notFoundOr(err)
		}
		return h, nil
	}
	h, err := r.pg.GetWebAuthnUserHandle(ctx, accountID)
	if err != nil {
		return nil, notFoundOr(err)
	}
	return h, nil
}

// SetWebAuthnUserHandle sets the opaque handle once (NULL guard). False means
// the account already has one, which the caller reads back rather than rotates.
func (r *Resolver) SetWebAuthnUserHandle(ctx context.Context, accountID string, handle []byte) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.SetWebAuthnUserHandle(ctx, sqlitegen.SetWebAuthnUserHandleParams{
			WebauthnUserHandle: handle, ID: accountID,
		})
		return n == 1, err
	}
	n, err := r.pg.SetWebAuthnUserHandle(ctx, pggen.SetWebAuthnUserHandleParams{
		WebauthnUserHandle: handle, ID: accountID,
	})
	return n == 1, err
}

// AccountByWebAuthnUserHandle resolves the account a discoverable assertion's
// user handle names.
func (r *Resolver) AccountByWebAuthnUserHandle(ctx context.Context, handle []byte) (Account, error) {
	if r.sq != nil {
		row, err := r.sq.GetAccountByWebAuthnUserHandle(ctx, handle)
		if err != nil {
			return Account{}, notFoundOr(err)
		}
		return sqliteAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt)
	}
	row, err := r.pg.GetAccountByWebAuthnUserHandle(ctx, handle)
	if err != nil {
		return Account{}, notFoundOr(err)
	}
	return pgAccount(row.ID, row.PrincipalID, row.Username, row.DisplayName, row.CreatedAt.Time), nil
}
