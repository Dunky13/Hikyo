package authn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlite "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// SAMLProvider is the configured IdP and its pinned trust material. EntityID
// is immutable; policy and certificate changes advance RowVersion so a
// callback cannot mint against a stale Phase-A snapshot.
type SAMLProvider struct {
	ID                              string
	Slug                            string
	DisplayName                     string
	Kind                            string
	EntityID                        string
	ACSURL                          string
	SSORedirectURL                  string
	SigningCertificates             []byte
	AssurancePolicy                 *string
	AllowEmailNameID                bool
	ForceSignRequests               bool
	MetadataWantAuthnRequestsSigned bool
	MetadataSource                  string
	MetadataURL                     *string
	MetadataSigned                  bool
	MetadataSigningFingerprint      *string
	MetadataValidUntil              *time.Time
	Enabled                         bool
	RowVersion                      int64
	CreatedAt                       time.Time
	UpdatedAt                       time.Time
}

// NewSAMLProvider carries a confirmed provider configuration to storage.
type NewSAMLProvider struct {
	ID                              string
	Slug                            string
	DisplayName                     string
	EntityID                        string
	ACSURL                          string
	SSORedirectURL                  string
	SigningCertificates             []byte
	AssurancePolicy                 *string
	AllowEmailNameID                bool
	ForceSignRequests               bool
	MetadataWantAuthnRequestsSigned bool
	MetadataSource                  string
	MetadataURL                     *string
	MetadataSigned                  bool
	MetadataSigningFingerprint      *string
	MetadataValidUntil              *time.Time
	Enabled                         bool
	CreatedAt                       time.Time
	UpdatedAt                       time.Time
}

// SAMLProviderUpdate is a compare-and-swap reconfiguration. EntityID and slug
// are intentionally absent because both are immutable identity coordinates.
type SAMLProviderUpdate struct {
	ID                              string
	DisplayName                     string
	ACSURL                          string
	SSORedirectURL                  string
	SigningCertificates             []byte
	AssurancePolicy                 *string
	AllowEmailNameID                bool
	ForceSignRequests               bool
	MetadataWantAuthnRequestsSigned bool
	MetadataSource                  string
	MetadataURL                     *string
	MetadataSigned                  bool
	MetadataSigningFingerprint      *string
	MetadataValidUntil              *time.Time
	Enabled                         bool
	RowVersion                      int64
	UpdatedAt                       time.Time
}

func optionalSQLiteTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: encodeTime(*t), Valid: true}
}

func optionalPGTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgTime(*t)
}

func decodeOptionalSQLiteTime(t sql.NullString) (*time.Time, error) {
	if !t.Valid {
		return nil, nil
	}
	decoded, err := decodeTime(t.String)
	if err != nil {
		return nil, err
	}
	return &decoded, nil
}

func sqliteSAMLProvider(row sqlitegen.SamlProvider) (SAMLProvider, error) {
	validUntil, err := decodeOptionalSQLiteTime(row.MetadataValidUntil)
	if err != nil {
		return SAMLProvider{}, err
	}
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return SAMLProvider{}, err
	}
	updated, err := decodeTime(row.UpdatedAt)
	if err != nil {
		return SAMLProvider{}, err
	}
	return SAMLProvider{
		ID: row.ID, Slug: row.Slug, DisplayName: row.DisplayName, Kind: row.Kind,
		EntityID: row.EntityID, ACSURL: row.AcsUrl, SSORedirectURL: row.SsoRedirectUrl,
		SigningCertificates: row.SigningCertificates, AssurancePolicy: nullStringPtr(row.AssurancePolicy),
		AllowEmailNameID: row.AllowEmailNameid == 1, ForceSignRequests: row.ForceSignRequests == 1,
		MetadataWantAuthnRequestsSigned: row.MetadataWantAuthnRequestsSigned == 1,
		MetadataSource:                  row.MetadataSource, MetadataURL: nullStringPtr(row.MetadataUrl),
		MetadataSigned:             row.MetadataSigned == 1,
		MetadataSigningFingerprint: nullStringPtr(row.MetadataSigningFingerprint),
		MetadataValidUntil:         validUntil, Enabled: row.Enabled == 1, RowVersion: row.RowVersion,
		CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func pgSAMLProvider(row pggen.SamlProvider) SAMLProvider {
	var validUntil *time.Time
	if row.MetadataValidUntil.Valid {
		t := row.MetadataValidUntil.Time
		validUntil = &t
	}
	return SAMLProvider{
		ID: row.ID, Slug: row.Slug, DisplayName: row.DisplayName, Kind: row.Kind,
		EntityID: row.EntityID, ACSURL: row.AcsUrl, SSORedirectURL: row.SsoRedirectUrl,
		SigningCertificates: row.SigningCertificates, AssurancePolicy: pgTextPtr(row.AssurancePolicy),
		AllowEmailNameID: row.AllowEmailNameid == 1, ForceSignRequests: row.ForceSignRequests == 1,
		MetadataWantAuthnRequestsSigned: row.MetadataWantAuthnRequestsSigned == 1,
		MetadataSource:                  row.MetadataSource, MetadataURL: pgTextPtr(row.MetadataUrl),
		MetadataSigned:             row.MetadataSigned == 1,
		MetadataSigningFingerprint: pgTextPtr(row.MetadataSigningFingerprint),
		MetadataValidUntil:         validUntil, Enabled: row.Enabled == 1, RowVersion: row.RowVersion,
		CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
	}
}

func (r *Resolver) CreateSAMLProvider(ctx context.Context, n NewSAMLProvider) error {
	if r.sq != nil {
		return samlProviderConstraint(r.sq.InsertSAMLProvider(ctx, sqlitegen.InsertSAMLProviderParams{
			ID: n.ID, Slug: n.Slug, DisplayName: n.DisplayName, EntityID: n.EntityID,
			AcsUrl: n.ACSURL, SsoRedirectUrl: n.SSORedirectURL,
			SigningCertificates: n.SigningCertificates, AssurancePolicy: ptrNullString(n.AssurancePolicy),
			AllowEmailNameid: boolInt(n.AllowEmailNameID), ForceSignRequests: boolInt(n.ForceSignRequests),
			MetadataWantAuthnRequestsSigned: boolInt(n.MetadataWantAuthnRequestsSigned),
			MetadataSource:                  n.MetadataSource, MetadataUrl: ptrNullString(n.MetadataURL),
			MetadataSigned:             boolInt(n.MetadataSigned),
			MetadataSigningFingerprint: ptrNullString(n.MetadataSigningFingerprint),
			MetadataValidUntil:         optionalSQLiteTime(n.MetadataValidUntil), Enabled: boolInt(n.Enabled),
			CreatedAt: encodeTime(n.CreatedAt), UpdatedAt: encodeTime(n.UpdatedAt),
		}))
	}
	return samlProviderConstraint(r.pg.InsertSAMLProvider(ctx, pggen.InsertSAMLProviderParams{
		ID: n.ID, Slug: n.Slug, DisplayName: n.DisplayName, EntityID: n.EntityID,
		AcsUrl: n.ACSURL, SsoRedirectUrl: n.SSORedirectURL,
		SigningCertificates: n.SigningCertificates, AssurancePolicy: ptrPgTextIn(n.AssurancePolicy),
		AllowEmailNameid: boolInt(n.AllowEmailNameID), ForceSignRequests: boolInt(n.ForceSignRequests),
		MetadataWantAuthnRequestsSigned: boolInt(n.MetadataWantAuthnRequestsSigned),
		MetadataSource:                  n.MetadataSource, MetadataUrl: ptrPgTextIn(n.MetadataURL),
		MetadataSigned:             boolInt(n.MetadataSigned),
		MetadataSigningFingerprint: ptrPgTextIn(n.MetadataSigningFingerprint),
		MetadataValidUntil:         optionalPGTime(n.MetadataValidUntil), Enabled: boolInt(n.Enabled),
		CreatedAt: pgTime(n.CreatedAt), UpdatedAt: pgTime(n.UpdatedAt),
	}))
}

// samlProviderConstraint gives the provider administration surface one stable
// cross-engine refusal for duplicate slugs and enabled entity IDs. Other
// constraint classes remain faults: a NOT NULL or foreign-key violation here
// is an implementation defect, not an operator conflict.
func samlProviderConstraint(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: duplicate SAML provider", domain.ErrConflict)
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && (sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_UNIQUE || sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY) {
		return fmt.Errorf("%w: duplicate SAML provider", domain.ErrConflict)
	}
	return err
}

func (r *Resolver) SAMLProviderBySlug(ctx context.Context, slug string) (SAMLProvider, error) {
	if r.sq != nil {
		row, err := r.sq.GetSAMLProviderBySlug(ctx, slug)
		if err != nil {
			return SAMLProvider{}, notFoundOr(err)
		}
		return sqliteSAMLProvider(row)
	}
	row, err := r.pg.GetSAMLProviderBySlug(ctx, slug)
	if err != nil {
		return SAMLProvider{}, notFoundOr(err)
	}
	return pgSAMLProvider(row), nil
}

func (r *Resolver) SAMLProviderForCallback(ctx context.Context, id string) (SAMLProvider, error) {
	if r.sq != nil {
		row, err := r.sq.GetSAMLProviderForCallback(ctx, id)
		if err != nil {
			return SAMLProvider{}, notFoundOr(err)
		}
		return sqliteSAMLProvider(row)
	}
	row, err := r.pg.GetSAMLProviderForCallback(ctx, id)
	if err != nil {
		return SAMLProvider{}, notFoundOr(err)
	}
	return pgSAMLProvider(row), nil
}

func (r *Resolver) ListSAMLProviders(ctx context.Context) ([]SAMLProvider, error) {
	if r.sq != nil {
		rows, err := r.sq.ListSAMLProviders(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]SAMLProvider, 0, len(rows))
		for _, row := range rows {
			provider, err := sqliteSAMLProvider(row)
			if err != nil {
				return nil, err
			}
			out = append(out, provider)
		}
		return out, nil
	}
	rows, err := r.pg.ListSAMLProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SAMLProvider, 0, len(rows))
	for _, row := range rows {
		out = append(out, pgSAMLProvider(row))
	}
	return out, nil
}

func (r *Resolver) UpdateSAMLProvider(ctx context.Context, u SAMLProviderUpdate) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.UpdateSAMLProviderCAS(ctx, sqlitegen.UpdateSAMLProviderCASParams{
			DisplayName: u.DisplayName, AcsUrl: u.ACSURL, SsoRedirectUrl: u.SSORedirectURL,
			SigningCertificates: u.SigningCertificates, AssurancePolicy: ptrNullString(u.AssurancePolicy),
			AllowEmailNameid: boolInt(u.AllowEmailNameID), ForceSignRequests: boolInt(u.ForceSignRequests),
			MetadataWantAuthnRequestsSigned: boolInt(u.MetadataWantAuthnRequestsSigned),
			MetadataSource:                  u.MetadataSource, MetadataUrl: ptrNullString(u.MetadataURL),
			MetadataSigned:             boolInt(u.MetadataSigned),
			MetadataSigningFingerprint: ptrNullString(u.MetadataSigningFingerprint),
			MetadataValidUntil:         optionalSQLiteTime(u.MetadataValidUntil), Enabled: boolInt(u.Enabled),
			UpdatedAt: encodeTime(u.UpdatedAt), ID: u.ID, RowVersion: u.RowVersion,
		})
		return n == 1, samlProviderConstraint(err)
	}
	n, err := r.pg.UpdateSAMLProviderCAS(ctx, pggen.UpdateSAMLProviderCASParams{
		DisplayName: u.DisplayName, AcsUrl: u.ACSURL, SsoRedirectUrl: u.SSORedirectURL,
		SigningCertificates: u.SigningCertificates, AssurancePolicy: ptrPgTextIn(u.AssurancePolicy),
		AllowEmailNameid: boolInt(u.AllowEmailNameID), ForceSignRequests: boolInt(u.ForceSignRequests),
		MetadataWantAuthnRequestsSigned: boolInt(u.MetadataWantAuthnRequestsSigned),
		MetadataSource:                  u.MetadataSource, MetadataUrl: ptrPgTextIn(u.MetadataURL),
		MetadataSigned:             boolInt(u.MetadataSigned),
		MetadataSigningFingerprint: ptrPgTextIn(u.MetadataSigningFingerprint),
		MetadataValidUntil:         optionalPGTime(u.MetadataValidUntil), Enabled: boolInt(u.Enabled),
		UpdatedAt: pgTime(u.UpdatedAt), ID: u.ID, RowVersion: u.RowVersion,
	})
	return n == 1, samlProviderConstraint(err)
}

func (r *Resolver) LockSAMLProviderForDelete(ctx context.Context, id string) error {
	if r.sq != nil {
		_, err := r.sq.LockSAMLProviderForDelete(ctx, id)
		return notFoundOr(err)
	}
	_, err := r.pg.LockSAMLProviderForDelete(ctx, id)
	return notFoundOr(err)
}

func (r *Resolver) DeleteSAMLProvider(ctx context.Context, id string) error {
	if r.sq != nil {
		return r.sq.DeleteSAMLProvider(ctx, id)
	}
	return r.pg.DeleteSAMLProvider(ctx, id)
}

func (r *Resolver) GuardSAMLProviderForMint(ctx context.Context, id string, rowVersion int64, entityID string) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.GuardSAMLProviderForMint(ctx, sqlitegen.GuardSAMLProviderForMintParams{
			ID: id, RowVersion: rowVersion, EntityID: entityID,
		})
		return n == 1, err
	}
	n, err := r.pg.GuardSAMLProviderForMint(ctx, pggen.GuardSAMLProviderForMintParams{
		ID: id, RowVersion: rowVersion, EntityID: entityID,
	})
	return n == 1, err
}

// SAMLTransaction is a server-side, request/RelayState/purpose-bound flow.
type SAMLTransaction struct {
	ID                  string
	RequestID           string
	RelayStateVerifier  []byte
	InitiatorVerifier   []byte
	ProviderID          string
	EntityID            string
	ACSURL              string
	Purpose             string
	InitiatingSessionID string
	AccountID           string
	EnvironmentID       string
	CeremonyID          string
	CredentialEpoch     int64
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Consumed            bool
}

type NewSAMLTransaction struct {
	ID                  string
	RequestID           string
	RelayStateVerifier  []byte
	InitiatorVerifier   []byte
	ProviderID          string
	EntityID            string
	ACSURL              string
	Purpose             string
	InitiatingSessionID string
	AccountID           string
	EnvironmentID       string
	CeremonyID          string
	CredentialEpoch     int64
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

func (r *Resolver) CreateSAMLTransaction(ctx context.Context, t NewSAMLTransaction) error {
	if r.sq != nil {
		return r.sq.InsertSAMLTransaction(ctx, sqlitegen.InsertSAMLTransactionParams{
			ID: t.ID, RequestID: t.RequestID, RelayStateVerifier: t.RelayStateVerifier,
			InitiatorVerifier: t.InitiatorVerifier, ProviderID: t.ProviderID,
			EntityID: t.EntityID, AcsUrl: t.ACSURL, Purpose: t.Purpose,
			InitiatingSessionID: nullString(t.InitiatingSessionID), AccountID: nullString(t.AccountID),
			EnvironmentID: nullString(t.EnvironmentID), CeremonyID: nullString(t.CeremonyID),
			CredentialEpoch: t.CredentialEpoch,
			CreatedAt:       encodeTime(t.CreatedAt), ExpiresAt: encodeTime(t.ExpiresAt),
		})
	}
	return r.pg.InsertSAMLTransaction(ctx, pggen.InsertSAMLTransactionParams{
		ID: t.ID, RequestID: t.RequestID, RelayStateVerifier: t.RelayStateVerifier,
		InitiatorVerifier: t.InitiatorVerifier, ProviderID: t.ProviderID,
		EntityID: t.EntityID, AcsUrl: t.ACSURL, Purpose: t.Purpose,
		InitiatingSessionID: pgText(t.InitiatingSessionID), AccountID: pgText(t.AccountID),
		EnvironmentID: pgText(t.EnvironmentID), CeremonyID: pgText(t.CeremonyID),
		CredentialEpoch: t.CredentialEpoch,
		CreatedAt:       pgTime(t.CreatedAt), ExpiresAt: pgTime(t.ExpiresAt),
	})
}

// SAMLTransactionByRelayState resolves the server-minted RelayState verifier
// before parsing the response. This supplies the expected request, provider
// and ACS to the wrapper's single validation pass.
func (r *Resolver) SAMLTransactionByRelayState(ctx context.Context, verifier []byte) (SAMLTransaction, error) {
	if r.sq != nil {
		row, err := r.sq.GetSAMLTransactionByRelayState(ctx, verifier)
		if err != nil {
			return SAMLTransaction{}, notFoundOr(err)
		}
		if !verifierMatches(row.RelayStateVerifier, verifier) {
			return SAMLTransaction{}, domain.ErrNotFound
		}
		created, err := decodeTime(row.CreatedAt)
		if err != nil {
			return SAMLTransaction{}, err
		}
		expires, err := decodeTime(row.ExpiresAt)
		if err != nil {
			return SAMLTransaction{}, err
		}
		return SAMLTransaction{
			ID: row.ID, RequestID: row.RequestID, RelayStateVerifier: row.RelayStateVerifier,
			InitiatorVerifier: row.InitiatorVerifier, ProviderID: row.ProviderID,
			EntityID: row.EntityID, ACSURL: row.AcsUrl, Purpose: row.Purpose,
			InitiatingSessionID: row.InitiatingSessionID.String, AccountID: row.AccountID.String,
			EnvironmentID: row.EnvironmentID.String, CeremonyID: row.CeremonyID.String,
			CredentialEpoch: row.CredentialEpoch,
			CreatedAt:       created, ExpiresAt: expires, Consumed: row.ConsumedAt.Valid,
		}, nil
	}
	row, err := r.pg.GetSAMLTransactionByRelayState(ctx, verifier)
	if err != nil {
		return SAMLTransaction{}, notFoundOr(err)
	}
	if !verifierMatches(row.RelayStateVerifier, verifier) {
		return SAMLTransaction{}, domain.ErrNotFound
	}
	return SAMLTransaction{
		ID: row.ID, RequestID: row.RequestID, RelayStateVerifier: row.RelayStateVerifier,
		InitiatorVerifier: row.InitiatorVerifier, ProviderID: row.ProviderID,
		EntityID: row.EntityID, ACSURL: row.AcsUrl, Purpose: row.Purpose,
		InitiatingSessionID: row.InitiatingSessionID.String, AccountID: row.AccountID.String,
		EnvironmentID: row.EnvironmentID.String, CeremonyID: row.CeremonyID.String,
		CredentialEpoch: row.CredentialEpoch,
		CreatedAt:       row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time, Consumed: row.ConsumedAt.Valid,
	}, nil
}

// ConsumeSAMLTransaction claims the transaction on first presentation,
// regardless of whether later assertion validation succeeds.
func (r *Resolver) ConsumeSAMLTransaction(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeSAMLTransaction(ctx, sqlitegen.ConsumeSAMLTransactionParams{
			ConsumedAt: sql.NullString{String: encodeTime(at), Valid: true}, ID: id,
		})
		return n == 1, err
	}
	n, err := r.pg.ConsumeSAMLTransaction(ctx, pggen.ConsumeSAMLTransactionParams{
		ConsumedAt: pgTime(at), ID: id,
	})
	return n == 1, err
}

type NewSAMLReplay struct {
	Issuer      string
	AssertionID string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// ClaimSAMLReplay atomically inserts durable assertion replay state. False
// means this issuer/assertion pair has already been presented.
func (r *Resolver) ClaimSAMLReplay(ctx context.Context, replay NewSAMLReplay) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.InsertSAMLReplay(ctx, sqlitegen.InsertSAMLReplayParams{
			Issuer: replay.Issuer, AssertionID: replay.AssertionID,
			ExpiresAt: encodeTime(replay.ExpiresAt), CreatedAt: encodeTime(replay.CreatedAt),
		})
		return n == 1, err
	}
	n, err := r.pg.InsertSAMLReplay(ctx, pggen.InsertSAMLReplayParams{
		Issuer: replay.Issuer, AssertionID: replay.AssertionID,
		ExpiresAt: pgTime(replay.ExpiresAt), CreatedAt: pgTime(replay.CreatedAt),
	})
	return n == 1, err
}

func (r *Resolver) DeleteExpiredSAMLReplay(ctx context.Context, at time.Time) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteExpiredSAMLReplay(ctx, encodeTime(at))
	}
	return r.pg.DeleteExpiredSAMLReplay(ctx, pgTime(at))
}

type SAMLSPKey struct {
	ID                  string
	State               string
	EncryptedPrivateKey []byte
	CertificateDER      []byte
	Fingerprint         string
	DEKVersion          int64
	RowVersion          int64
	CreatedAt           time.Time
}

type NewSAMLSPKey struct {
	ID                  string
	State               string
	EncryptedPrivateKey []byte
	CertificateDER      []byte
	Fingerprint         string
	DEKVersion          int64
	CreatedAt           time.Time
}

func sqliteSAMLSPKey(row sqlitegen.SamlSpKey) (SAMLSPKey, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return SAMLSPKey{}, err
	}
	return SAMLSPKey{
		ID: row.ID, State: row.State, EncryptedPrivateKey: row.EncryptedPrivateKey,
		CertificateDER: row.CertificateDer, Fingerprint: row.Fingerprint,
		DEKVersion: row.DekVersion, RowVersion: row.RowVersion, CreatedAt: created,
	}, nil
}

func pgSAMLSPKey(row pggen.SamlSpKey) SAMLSPKey {
	return SAMLSPKey{
		ID: row.ID, State: row.State, EncryptedPrivateKey: row.EncryptedPrivateKey,
		CertificateDER: row.CertificateDer, Fingerprint: row.Fingerprint,
		DEKVersion: row.DekVersion, RowVersion: row.RowVersion, CreatedAt: row.CreatedAt.Time,
	}
}

func (r *Resolver) CreateSAMLSPKey(ctx context.Context, key NewSAMLSPKey) error {
	if r.sq != nil {
		return r.sq.InsertSAMLSPKey(ctx, sqlitegen.InsertSAMLSPKeyParams{
			ID: key.ID, State: key.State, EncryptedPrivateKey: key.EncryptedPrivateKey,
			CertificateDer: key.CertificateDER, Fingerprint: key.Fingerprint,
			DekVersion: key.DEKVersion, CreatedAt: encodeTime(key.CreatedAt),
		})
	}
	return r.pg.InsertSAMLSPKey(ctx, pggen.InsertSAMLSPKeyParams{
		ID: key.ID, State: key.State, EncryptedPrivateKey: key.EncryptedPrivateKey,
		CertificateDer: key.CertificateDER, Fingerprint: key.Fingerprint,
		DekVersion: key.DEKVersion, CreatedAt: pgTime(key.CreatedAt),
	})
}

func (r *Resolver) ActiveSAMLSPKey(ctx context.Context) (SAMLSPKey, error) {
	if r.sq != nil {
		row, err := r.sq.GetActiveSAMLSPKey(ctx)
		if err != nil {
			return SAMLSPKey{}, notFoundOr(err)
		}
		return sqliteSAMLSPKey(row)
	}
	row, err := r.pg.GetActiveSAMLSPKey(ctx)
	if err != nil {
		return SAMLSPKey{}, notFoundOr(err)
	}
	return pgSAMLSPKey(row), nil
}

func (r *Resolver) SAMLSPKeys(ctx context.Context) ([]SAMLSPKey, error) {
	if r.sq != nil {
		rows, err := r.sq.ListSAMLSPKeys(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]SAMLSPKey, 0, len(rows))
		for _, row := range rows {
			key, err := sqliteSAMLSPKey(row)
			if err != nil {
				return nil, err
			}
			out = append(out, key)
		}
		return out, nil
	}
	rows, err := r.pg.ListSAMLSPKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SAMLSPKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, pgSAMLSPKey(row))
	}
	return out, nil
}

func (r *Resolver) MarkSAMLSPKeyRetiring(ctx context.Context, id string, rowVersion int64) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.MarkSAMLSPKeyRetiringCAS(ctx, sqlitegen.MarkSAMLSPKeyRetiringCASParams{
			ID: id, RowVersion: rowVersion,
		})
		return n == 1, err
	}
	n, err := r.pg.MarkSAMLSPKeyRetiringCAS(ctx, pggen.MarkSAMLSPKeyRetiringCASParams{
		ID: id, RowVersion: rowVersion,
	})
	return n == 1, err
}

func (r *Resolver) DeleteRetiringSAMLSPKey(ctx context.Context, id string) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.DeleteRetiringSAMLSPKey(ctx, id)
		return n == 1, err
	}
	n, err := r.pg.DeleteRetiringSAMLSPKey(ctx, id)
	return n == 1, err
}

// BindSessionToSAMLProvider records provider provenance inside the same write
// transaction that mints the session. False means the session is missing or
// already bound to a federated provider.
func (r *Resolver) BindSessionToSAMLProvider(ctx context.Context, sessionID, providerID string) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.BindSessionToSAMLProvider(ctx, sqlitegen.BindSessionToSAMLProviderParams{
			SamlProviderID: sql.NullString{String: providerID, Valid: true}, ID: sessionID,
		})
		return n == 1, err
	}
	n, err := r.pg.BindSessionToSAMLProvider(ctx, pggen.BindSessionToSAMLProviderParams{
		SamlProviderID: pgText(providerID), ID: sessionID,
	})
	return n == 1, err
}

func (r *Resolver) DeleteSessionsForSAMLProvider(ctx context.Context, providerID string) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteSessionsForSAMLProvider(ctx, sql.NullString{String: providerID, Valid: true})
	}
	return r.pg.DeleteSessionsForSAMLProvider(ctx, pgText(providerID))
}
