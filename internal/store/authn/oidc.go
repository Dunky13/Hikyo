package authn

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// OIDC login/link/reauth resolution (#54, human-auth ADR - The OIDC
// transaction). These read providers, transactions and external identities
// with request-supplied identifiers, and write the transaction, identity and
// federated-session rows that decide who a caller is. They live on the
// proof-free resolution surface for the same reason the login writers do: the
// proof is what that answer produces. Every mutating method here is named in
// lint.ResolutionSurfaceWriters. Provider administration is a distinct,
// proof-bound surface (internal/store repos), not these.

// OIDCProvider is a resolved provider row. ClientSecret is the sealed record;
// the service opens it under the instance DEK at exchange time only.
type OIDCProvider struct {
	ID              string
	Slug            string
	DisplayName     string
	Kind            string
	Issuer          string
	ClientID        string
	ClientSecret    []byte
	Scopes          string
	RedirectURI     string
	JITPolicy       *string
	AssurancePolicy *string
	Enabled         bool
	DEKVersion      int64
	RowVersion      int64
}

func sqliteProvider(row sqlitegen.OidcProvider) OIDCProvider {
	return OIDCProvider{
		ID: row.ID, Slug: row.Slug, DisplayName: row.DisplayName, Kind: row.Kind,
		Issuer: row.Issuer, ClientID: row.ClientID, ClientSecret: row.ClientSecret,
		Scopes: row.Scopes, RedirectURI: row.RedirectUri,
		JITPolicy: nullStringPtr(row.JitPolicy), AssurancePolicy: nullStringPtr(row.AssurancePolicy),
		Enabled: row.Enabled == 1, DEKVersion: row.DekVersion, RowVersion: row.RowVersion,
	}
}

func pgProvider(row pggen.OidcProvider) OIDCProvider {
	return OIDCProvider{
		ID: row.ID, Slug: row.Slug, DisplayName: row.DisplayName, Kind: row.Kind,
		Issuer: row.Issuer, ClientID: row.ClientID, ClientSecret: row.ClientSecret,
		Scopes: row.Scopes, RedirectURI: row.RedirectUri,
		JITPolicy: pgTextPtr(row.JitPolicy), AssurancePolicy: pgTextPtr(row.AssurancePolicy),
		Enabled: row.Enabled == 1, DEKVersion: row.DekVersion, RowVersion: row.RowVersion,
	}
}

func nullStringPtr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	s := n.String
	return &s
}

func pgTextPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	s := t.String
	return &s
}

// EnabledProviderByIssuer resolves the currently enabled provider for an
// issuer, or domain.ErrNotFound when none. Login uses it to re-check that a
// linked identity's issuer still has an enabled provider (A3/A11).
func (r *Resolver) EnabledProviderByIssuer(ctx context.Context, kind, issuer string) (OIDCProvider, error) {
	if r.sq != nil {
		row, err := r.sq.GetEnabledProviderByIssuer(ctx, sqlitegen.GetEnabledProviderByIssuerParams{Kind: kind, Issuer: issuer})
		if err != nil {
			return OIDCProvider{}, notFoundOr(err)
		}
		return sqliteProvider(row), nil
	}
	row, err := r.pg.GetEnabledProviderByIssuer(ctx, pggen.GetEnabledProviderByIssuerParams{Kind: kind, Issuer: issuer})
	if err != nil {
		return OIDCProvider{}, notFoundOr(err)
	}
	return pgProvider(row), nil
}

// NewProvider is the provider create carrier (proof-free resolution surface;
// the mutation is authorized at the chokepoint before this runs).
type NewProvider struct {
	ID              string
	Slug            string
	DisplayName     string
	Kind            string
	Issuer          string
	ClientID        string
	ClientSecret    []byte
	Scopes          string
	RedirectURI     string
	JITPolicy       *string
	AssurancePolicy *string
	Enabled         bool
	DEKVersion      int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ProviderUpdate is the provider reconfigure carrier. The issuer is absent: it
// is immutable after create (A3).
type ProviderUpdate struct {
	ID              string
	DisplayName     string
	ClientID        string
	ClientSecret    []byte
	Scopes          string
	RedirectURI     string
	JITPolicy       *string
	AssurancePolicy *string
	Enabled         bool
	DEKVersion      int64
	RowVersion      int64
	UpdatedAt       time.Time
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// CreateProvider inserts a provider row.
func (r *Resolver) CreateProvider(ctx context.Context, n NewProvider) error {
	if r.sq != nil {
		return r.sq.CreateOIDCProvider(ctx, sqlitegen.CreateOIDCProviderParams{
			ID: n.ID, Slug: n.Slug, DisplayName: n.DisplayName, Kind: n.Kind, Issuer: n.Issuer,
			ClientID: n.ClientID, ClientSecret: n.ClientSecret, Scopes: n.Scopes, RedirectUri: n.RedirectURI,
			JitPolicy: ptrNullString(n.JITPolicy), AssurancePolicy: ptrNullString(n.AssurancePolicy),
			Enabled: boolInt(n.Enabled), DekVersion: n.DEKVersion,
			CreatedAt: encodeTime(n.CreatedAt), UpdatedAt: encodeTime(n.UpdatedAt),
		})
	}
	return r.pg.CreateOIDCProvider(ctx, pggen.CreateOIDCProviderParams{
		ID: n.ID, Slug: n.Slug, DisplayName: n.DisplayName, Kind: n.Kind, Issuer: n.Issuer,
		ClientID: n.ClientID, ClientSecret: n.ClientSecret, Scopes: n.Scopes, RedirectUri: n.RedirectURI,
		JitPolicy: ptrPgTextIn(n.JITPolicy), AssurancePolicy: ptrPgTextIn(n.AssurancePolicy),
		Enabled: boolInt(n.Enabled), DekVersion: n.DEKVersion,
		CreatedAt: pgTime(n.CreatedAt), UpdatedAt: pgTime(n.UpdatedAt),
	})
}

// ProviderBySlug resolves a provider by slug for administration (any enabled
// state), or domain.ErrNotFound.
func (r *Resolver) ProviderBySlug(ctx context.Context, slug string) (OIDCProvider, error) {
	if r.sq != nil {
		row, err := r.sq.GetOIDCProviderBySlug(ctx, slug)
		if err != nil {
			return OIDCProvider{}, notFoundOr(err)
		}
		return sqliteProvider(row), nil
	}
	row, err := r.pg.GetOIDCProviderBySlug(ctx, slug)
	if err != nil {
		return OIDCProvider{}, notFoundOr(err)
	}
	return pgProvider(row), nil
}

// ListProviders lists every configured provider.
func (r *Resolver) ListProviders(ctx context.Context) ([]OIDCProvider, error) {
	if r.sq != nil {
		rows, err := r.sq.ListOIDCProviders(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]OIDCProvider, 0, len(rows))
		for _, row := range rows {
			out = append(out, sqliteProvider(row))
		}
		return out, nil
	}
	rows, err := r.pg.ListOIDCProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OIDCProvider, 0, len(rows))
	for _, row := range rows {
		out = append(out, pgProvider(row))
	}
	return out, nil
}

// UpdateProvider compare-and-swaps a provider on row_version; false means the
// row moved.
func (r *Resolver) UpdateProvider(ctx context.Context, u ProviderUpdate) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.UpdateOIDCProviderCAS(ctx, sqlitegen.UpdateOIDCProviderCASParams{
			DisplayName: u.DisplayName, ClientID: u.ClientID, ClientSecret: u.ClientSecret,
			Scopes: u.Scopes, RedirectUri: u.RedirectURI,
			JitPolicy: ptrNullString(u.JITPolicy), AssurancePolicy: ptrNullString(u.AssurancePolicy),
			Enabled: boolInt(u.Enabled), DekVersion: u.DEKVersion, UpdatedAt: encodeTime(u.UpdatedAt),
			ID: u.ID, RowVersion: u.RowVersion,
		})
		return n == 1, err
	}
	n, err := r.pg.UpdateOIDCProviderCAS(ctx, pggen.UpdateOIDCProviderCASParams{
		DisplayName: u.DisplayName, ClientID: u.ClientID, ClientSecret: u.ClientSecret,
		Scopes: u.Scopes, RedirectUri: u.RedirectURI,
		JitPolicy: ptrPgTextIn(u.JITPolicy), AssurancePolicy: ptrPgTextIn(u.AssurancePolicy),
		Enabled: boolInt(u.Enabled), DekVersion: u.DEKVersion, UpdatedAt: pgTime(u.UpdatedAt),
		ID: u.ID, RowVersion: u.RowVersion,
	})
	return n == 1, err
}

// DeleteProvider removes a provider. Its transactions cascade (A14).
func (r *Resolver) DeleteProvider(ctx context.Context, id string) error {
	if r.sq != nil {
		return r.sq.DeleteOIDCProvider(ctx, id)
	}
	return r.pg.DeleteOIDCProvider(ctx, id)
}

func ptrPgTextIn(p *string) pgtype.Text {
	if p == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *p, Valid: true}
}

func ptrNullString(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

// EnabledProviderBySlug resolves an enabled provider by slug, for start.
func (r *Resolver) EnabledProviderBySlug(ctx context.Context, slug string) (OIDCProvider, error) {
	if r.sq != nil {
		row, err := r.sq.GetEnabledProviderBySlug(ctx, slug)
		if err != nil {
			return OIDCProvider{}, notFoundOr(err)
		}
		return sqliteProvider(row), nil
	}
	row, err := r.pg.GetEnabledProviderBySlug(ctx, slug)
	if err != nil {
		return OIDCProvider{}, notFoundOr(err)
	}
	return pgProvider(row), nil
}

// ProviderForCallback resolves the provider a transaction pinned, by id, so a
// callback exchanges only at the recorded provider (A11).
func (r *Resolver) ProviderForCallback(ctx context.Context, id string) (OIDCProvider, error) {
	if r.sq != nil {
		row, err := r.sq.GetProviderForCallback(ctx, id)
		if err != nil {
			return OIDCProvider{}, notFoundOr(err)
		}
		return sqliteProvider(row), nil
	}
	row, err := r.pg.GetProviderForCallback(ctx, id)
	if err != nil {
		return OIDCProvider{}, notFoundOr(err)
	}
	return pgProvider(row), nil
}

// OIDCTransaction is a resolved transaction row.
type OIDCTransaction struct {
	ID                     string
	Nonce                  []byte
	PKCEVerifier           string
	ProviderID             string
	Issuer                 string
	RedirectURI            string
	Purpose                string
	BindingKind            string
	InitiatingSessionID    string
	BrowserBindingVerifier []byte
	AccountID              string
	EnvironmentID          string
	CeremonyID             string
	CredentialEpoch        int64
	CreatedAt              time.Time
	ExpiresAt              time.Time
	Consumed               bool
}

// NewOIDCTransaction is the transaction insert carrier.
type NewOIDCTransaction struct {
	ID                     string
	StateVerifier          []byte
	Nonce                  []byte
	PKCEVerifier           string
	ProviderID             string
	Issuer                 string
	RedirectURI            string
	Purpose                string
	BindingKind            string
	InitiatingSessionID    string
	BrowserBindingVerifier []byte
	AccountID              string
	EnvironmentID          string
	CeremonyID             string
	CredentialEpoch        int64
	CreatedAt              time.Time
	ExpiresAt              time.Time
}

// CreateOIDCTransaction writes a single-use transaction row.
func (r *Resolver) CreateOIDCTransaction(ctx context.Context, t NewOIDCTransaction) error {
	if r.sq != nil {
		return r.sq.InsertOIDCTransaction(ctx, sqlitegen.InsertOIDCTransactionParams{
			ID: t.ID, StateVerifier: t.StateVerifier, Nonce: t.Nonce, PkceVerifier: t.PKCEVerifier,
			ProviderID: t.ProviderID, Issuer: t.Issuer, RedirectUri: t.RedirectURI,
			Purpose: t.Purpose, BindingKind: t.BindingKind,
			InitiatingSessionID:    nullString(t.InitiatingSessionID),
			BrowserBindingVerifier: t.BrowserBindingVerifier,
			AccountID:              nullString(t.AccountID),
			EnvironmentID:          nullString(t.EnvironmentID),
			CeremonyID:             nullString(t.CeremonyID),
			CredentialEpoch:        t.CredentialEpoch,
			CreatedAt:              encodeTime(t.CreatedAt), ExpiresAt: encodeTime(t.ExpiresAt),
		})
	}
	return r.pg.InsertOIDCTransaction(ctx, pggen.InsertOIDCTransactionParams{
		ID: t.ID, StateVerifier: t.StateVerifier, Nonce: t.Nonce, PkceVerifier: t.PKCEVerifier,
		ProviderID: t.ProviderID, Issuer: t.Issuer, RedirectUri: t.RedirectURI,
		Purpose: t.Purpose, BindingKind: t.BindingKind,
		InitiatingSessionID:    pgText(t.InitiatingSessionID),
		BrowserBindingVerifier: t.BrowserBindingVerifier,
		AccountID:              pgText(t.AccountID),
		EnvironmentID:          pgText(t.EnvironmentID),
		CeremonyID:             pgText(t.CeremonyID),
		CredentialEpoch:        t.CredentialEpoch,
		CreatedAt:              pgTime(t.CreatedAt), ExpiresAt: pgTime(t.ExpiresAt),
	})
}

// OIDCTransactionByState resolves a transaction by the SHA-256 of its state
// artifact, or domain.ErrNotFound.
func (r *Resolver) OIDCTransactionByState(ctx context.Context, stateVerifier []byte) (OIDCTransaction, error) {
	if r.sq != nil {
		row, err := r.sq.GetOIDCTransactionByState(ctx, stateVerifier)
		if err != nil {
			return OIDCTransaction{}, notFoundOr(err)
		}
		created, err := decodeTime(row.CreatedAt)
		if err != nil {
			return OIDCTransaction{}, err
		}
		expires, err := decodeTime(row.ExpiresAt)
		if err != nil {
			return OIDCTransaction{}, err
		}
		return OIDCTransaction{
			ID: row.ID, Nonce: row.Nonce, PKCEVerifier: row.PkceVerifier, ProviderID: row.ProviderID,
			Issuer: row.Issuer, RedirectURI: row.RedirectUri, Purpose: row.Purpose,
			BindingKind: row.BindingKind, InitiatingSessionID: row.InitiatingSessionID.String,
			BrowserBindingVerifier: row.BrowserBindingVerifier, AccountID: row.AccountID.String,
			EnvironmentID: row.EnvironmentID.String, CeremonyID: row.CeremonyID.String,
			CredentialEpoch: row.CredentialEpoch, CreatedAt: created, ExpiresAt: expires,
			Consumed: row.ConsumedAt.Valid,
		}, nil
	}
	row, err := r.pg.GetOIDCTransactionByState(ctx, stateVerifier)
	if err != nil {
		return OIDCTransaction{}, notFoundOr(err)
	}
	return OIDCTransaction{
		ID: row.ID, Nonce: row.Nonce, PKCEVerifier: row.PkceVerifier, ProviderID: row.ProviderID,
		Issuer: row.Issuer, RedirectURI: row.RedirectUri, Purpose: row.Purpose,
		BindingKind: row.BindingKind, InitiatingSessionID: row.InitiatingSessionID.String,
		BrowserBindingVerifier: row.BrowserBindingVerifier, AccountID: row.AccountID.String,
		EnvironmentID: row.EnvironmentID.String, CeremonyID: row.CeremonyID.String,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time,
		Consumed: row.ConsumedAt.Valid,
	}, nil
}

// ConsumeOIDCTransaction claims a transaction atomically; false means it was
// already consumed and the caller must fail closed.
func (r *Resolver) ConsumeOIDCTransaction(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeOIDCTransaction(ctx, sqlitegen.ConsumeOIDCTransactionParams{
			ConsumedAt: sql.NullString{String: encodeTime(at), Valid: true}, ID: id,
		})
		return n == 1, err
	}
	n, err := r.pg.ConsumeOIDCTransaction(ctx, pggen.ConsumeOIDCTransactionParams{
		ConsumedAt: pgTime(at), ID: id,
	})
	return n == 1, err
}

// ExternalIdentity is a resolved linked identity.
type ExternalIdentity struct {
	ID              string
	AccountID       string
	Kind            string
	Issuer          string
	Subject         string
	ProviderID      string
	CredentialEpoch int64
	CreatedAt       time.Time
}

// NewExternalIdentity is the link insert carrier.
type NewExternalIdentity struct {
	ID              string
	AccountID       string
	Kind            string
	Issuer          string
	Subject         string
	ProviderID      string
	CredentialEpoch int64
	CreatedAt       time.Time
}

func sqliteIdentity(row sqlitegen.ExternalIdentity) (ExternalIdentity, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return ExternalIdentity{}, err
	}
	return ExternalIdentity{
		ID: row.ID, AccountID: row.AccountID, Kind: row.Kind, Issuer: row.Issuer,
		Subject: row.Subject, ProviderID: row.ProviderID, CredentialEpoch: row.CredentialEpoch,
		CreatedAt: created,
	}, nil
}

func pgIdentity(row pggen.ExternalIdentity) ExternalIdentity {
	return ExternalIdentity{
		ID: row.ID, AccountID: row.AccountID, Kind: row.Kind, Issuer: row.Issuer,
		Subject: row.Subject, ProviderID: row.ProviderID, CredentialEpoch: row.CredentialEpoch,
		CreatedAt: row.CreatedAt.Time,
	}
}

// ExternalIdentityByKey resolves the byte-exact (kind, issuer, subject), or
// domain.ErrNotFound. No normalization: the key is compared as stored.
func (r *Resolver) ExternalIdentityByKey(ctx context.Context, kind, issuer, subject string) (ExternalIdentity, error) {
	if r.sq != nil {
		row, err := r.sq.GetExternalIdentity(ctx, sqlitegen.GetExternalIdentityParams{Kind: kind, Issuer: issuer, Subject: subject})
		if err != nil {
			return ExternalIdentity{}, notFoundOr(err)
		}
		return sqliteIdentity(row)
	}
	row, err := r.pg.GetExternalIdentity(ctx, pggen.GetExternalIdentityParams{Kind: kind, Issuer: issuer, Subject: subject})
	if err != nil {
		return ExternalIdentity{}, notFoundOr(err)
	}
	return pgIdentity(row), nil
}

// ExternalIdentityByID resolves a link by its id.
func (r *Resolver) ExternalIdentityByID(ctx context.Context, id string) (ExternalIdentity, error) {
	if r.sq != nil {
		row, err := r.sq.GetExternalIdentityByID(ctx, id)
		if err != nil {
			return ExternalIdentity{}, notFoundOr(err)
		}
		return sqliteIdentity(row)
	}
	row, err := r.pg.GetExternalIdentityByID(ctx, id)
	if err != nil {
		return ExternalIdentity{}, notFoundOr(err)
	}
	return pgIdentity(row), nil
}

// ExternalIdentitiesForAccount lists an account's linked identities.
func (r *Resolver) ExternalIdentitiesForAccount(ctx context.Context, accountID string) ([]ExternalIdentity, error) {
	if r.sq != nil {
		rows, err := r.sq.ListExternalIdentitiesForAccount(ctx, accountID)
		if err != nil {
			return nil, err
		}
		out := make([]ExternalIdentity, 0, len(rows))
		for _, row := range rows {
			id, err := sqliteIdentity(row)
			if err != nil {
				return nil, err
			}
			out = append(out, id)
		}
		return out, nil
	}
	rows, err := r.pg.ListExternalIdentitiesForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]ExternalIdentity, 0, len(rows))
	for _, row := range rows {
		out = append(out, pgIdentity(row))
	}
	return out, nil
}

// CreateExternalIdentity writes a link. The (kind, issuer, subject) uniqueness
// constraint makes two concurrent binds of one identity fail closed.
func (r *Resolver) CreateExternalIdentity(ctx context.Context, n NewExternalIdentity) error {
	if r.sq != nil {
		return r.sq.InsertExternalIdentity(ctx, sqlitegen.InsertExternalIdentityParams{
			ID: n.ID, AccountID: n.AccountID, Kind: n.Kind, Issuer: n.Issuer, Subject: n.Subject,
			ProviderID: n.ProviderID, CredentialEpoch: n.CredentialEpoch, CreatedAt: encodeTime(n.CreatedAt),
		})
	}
	return r.pg.InsertExternalIdentity(ctx, pggen.InsertExternalIdentityParams{
		ID: n.ID, AccountID: n.AccountID, Kind: n.Kind, Issuer: n.Issuer, Subject: n.Subject,
		ProviderID: n.ProviderID, CredentialEpoch: n.CredentialEpoch, CreatedAt: pgTime(n.CreatedAt),
	})
}

// DeleteExternalIdentity removes a link (unlink).
func (r *Resolver) DeleteExternalIdentity(ctx context.Context, id string) error {
	if r.sq != nil {
		return r.sq.DeleteExternalIdentity(ctx, id)
	}
	return r.pg.DeleteExternalIdentity(ctx, id)
}

// DeleteSessionsForProvider sweeps every session minted through a provider and
// returns the count for the audit event (A4). reauth_windows cascade with the
// sessions.
func (r *Resolver) DeleteSessionsForProvider(ctx context.Context, providerID string) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteSessionsForProvider(ctx, sql.NullString{String: providerID, Valid: true})
	}
	return r.pg.DeleteSessionsForProvider(ctx, pgText(providerID))
}

// NewReauthWindow is the reauth-window insert carrier. OIDC reauth opens one
// only where the effective window is > 0 (a 0-window gate needs WebAuthn).
type NewReauthWindow struct {
	ID              string
	SessionID       string
	EnvironmentID   string
	CeremonyID      string
	FactorClass     string
	AuthenticatedAt time.Time
	WindowExpiresAt time.Time
	HardExpiresAt   time.Time
	CredentialEpoch int64
	CreatedAt       time.Time
}

// CreateReauthWindow opens a reauthentication window over one environment.
func (r *Resolver) CreateReauthWindow(ctx context.Context, w NewReauthWindow) error {
	if r.sq != nil {
		return r.sq.InsertReauthWindow(ctx, sqlitegen.InsertReauthWindowParams{
			ID: w.ID, SessionID: w.SessionID, EnvironmentID: w.EnvironmentID, CeremonyID: w.CeremonyID,
			FactorClass: w.FactorClass, AuthenticatedAt: encodeTime(w.AuthenticatedAt),
			WindowExpiresAt: encodeTime(w.WindowExpiresAt), HardExpiresAt: encodeTime(w.HardExpiresAt),
			CredentialEpoch: w.CredentialEpoch, CreatedAt: encodeTime(w.CreatedAt),
		})
	}
	return r.pg.InsertReauthWindow(ctx, pggen.InsertReauthWindowParams{
		ID: w.ID, SessionID: w.SessionID, EnvironmentID: w.EnvironmentID, CeremonyID: w.CeremonyID,
		FactorClass: w.FactorClass, AuthenticatedAt: pgTime(w.AuthenticatedAt),
		WindowExpiresAt: pgTime(w.WindowExpiresAt), HardExpiresAt: pgTime(w.HardExpiresAt),
		CredentialEpoch: w.CredentialEpoch, CreatedAt: pgTime(w.CreatedAt),
	})
}
