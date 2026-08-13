package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// OIDC federation on the resolution surface (#62, machine-identities ADR §
// Federation). A federated binding resolves at the SAME chokepoint as a bearer
// credential — the ADR's propagation to the architecture ticket does not
// distinguish the kinds — so it rides this package for the same reason, and it
// is a ROW OF machine_credentials rather than its own table (migration 00017
// carries that reasoning).
//
// What is deliberately NOT here: any signature check, any JWT parsing, any
// JWKS fetch. This package answers "which service account does this
// `(issuer, subject)` name, and is that binding live"; internal/oidcfed
// answers "is this token genuinely from that issuer", behind go-oidc.

// Binding is a federated identity's half of a machine_credentials row. It is
// the zero value on a bearer credential.
//
// RequiredClaimsJSON is the stored JSON object verbatim, NOT a parsed map:
// this package does no policy, and the comparison semantics — byte-exact per
// JSON scalar, so `12345` never matches `"12345"` — belong with the validator
// that owns them.
type Binding struct {
	IssuerID           string
	Subject            string
	Audience           string
	RequiredClaimsJSON string
	// ReactivatedAt is the restore predicate's instant, zero while the binding
	// has never been through a restore. When set it is PERMANENT for the life
	// of the binding: a token whose `iat` is not strictly greater than this
	// plus the maximum accepted positive clock skew is refused, forever, not
	// for a quarantine window.
	ReactivatedAt time.Time
}

// FederationIssuer is one instance-scoped issuer configuration.
type FederationIssuer struct {
	ID string
	// Issuer is the byte-exact `iss` string. Nothing on any path folds case,
	// resolves a URL or strips a trailing slash.
	Issuer string
	Type   domain.IssuerType
	Mode   domain.JWKSMode
	// StaticJWKS is the air-gap alternative's key document, empty under
	// discovery. The database CHECK ties presence to the mode.
	StaticJWKS string
	// RefusedAudiences are the issuer's DEFAULT audiences, which a binding may
	// never name. This is not ceremony: a Kubernetes token minted for the
	// default API-server audience would otherwise authenticate to Hikyo, and
	// Forgejo's Actions audience defaults to `<instance>/<owner>`, shared
	// across every repository that owner has.
	RefusedAudiences []string
	CreatedAt        time.Time
	CreatedBy        domain.PrincipalID
	UpdatedAt        time.Time
	UpdatedBy        domain.PrincipalID
}

// NewFederationIssuer is one issuer configuration.
type NewFederationIssuer struct {
	ID               string
	Issuer           string
	Type             domain.IssuerType
	Mode             domain.JWKSMode
	StaticJWKS       string
	RefusedAudiences []string
	CreatedAt        time.Time
	CreatedBy        domain.PrincipalID
}

// audienceSeparator joins the refused-audience list into one column. Newline
// is the separator because an audience is a URI or an `<instance>/<owner>`
// path, and neither can contain one — a comma can appear in neither by
// convention but in both by construction, and a separator a value can contain
// is a parsing bug waiting for its first operator.
const audienceSeparator = "\n"

func joinAudiences(list []string) string { return strings.Join(list, audienceSeparator) }

func splitAudiences(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, audienceSeparator)
}

// CreateFederationIssuer configures one issuer. A duplicate `iss` is an
// operator CONFLICT: the caller is authorized, the current state refuses.
func (r *Resolver) CreateFederationIssuer(ctx context.Context, iss NewFederationIssuer) error {
	if r.sq != nil {
		return issuerConstraint(r.sq.InsertFederationIssuer(ctx, sqlitegen.InsertFederationIssuerParams{
			ID: iss.ID, Issuer: iss.Issuer, IssuerType: string(iss.Type),
			JwksMode: string(iss.Mode), StaticJwks: nullString(iss.StaticJWKS),
			RefusedAudiences: joinAudiences(iss.RefusedAudiences),
			CreatedAt:        encodeTime(iss.CreatedAt), CreatedBy: string(iss.CreatedBy),
		}))
	}
	return issuerConstraint(r.pg.InsertFederationIssuer(ctx, pggen.InsertFederationIssuerParams{
		ID: iss.ID, Issuer: iss.Issuer, IssuerType: string(iss.Type),
		JwksMode: string(iss.Mode), StaticJwks: pgText(iss.StaticJWKS),
		RefusedAudiences: joinAudiences(iss.RefusedAudiences),
		CreatedAt:        pgTime(iss.CreatedAt), CreatedBy: string(iss.CreatedBy),
	}))
}

// issuerConstraint folds a duplicate issuer onto one cross-engine refusal, by
// typed extended code rather than driver message text.
func issuerConstraint(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: this issuer is already configured", domain.ErrConflict)
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) &&
		(sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_UNIQUE ||
			sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY) {
		return fmt.Errorf("%w: this issuer is already configured", domain.ErrConflict)
	}
	return err
}

// bindingConstraint folds the LIVE-ROW partial unique index onto one refusal.
// Two live bindings claiming one external identity is the state the index
// exists to prevent, and an operator who tried is owed the reason rather than
// a driver string.
func bindingConstraint(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: a live binding already names this issuer and subject", domain.ErrConflict)
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_UNIQUE {
		return fmt.Errorf("%w: a live binding already names this issuer and subject", domain.ErrConflict)
	}
	return err
}

// FederationIssuerByIssuer resolves a configuration by its BYTE-EXACT `iss`.
// This is the authentication path's lookup: a presented token names an issuer,
// and either the instance trusts exactly that string or it does not.
func (r *Resolver) FederationIssuerByIssuer(ctx context.Context, issuer string) (FederationIssuer, error) {
	if r.sq != nil {
		row, err := r.sq.FederationIssuerByIssuer(ctx, issuer)
		if err != nil {
			return FederationIssuer{}, notFoundOr(err)
		}
		return issuerFromSQLite(sqlitegen.FederationIssuer(row))
	}
	row, err := r.pg.FederationIssuerByIssuer(ctx, issuer)
	if err != nil {
		return FederationIssuer{}, notFoundOr(err)
	}
	return issuerFromPG(pggen.FederationIssuer(row)), nil
}

// FederationIssuerByID resolves a configuration by id, for the administrative
// surface and for rendering a binding's issuer.
func (r *Resolver) FederationIssuerByID(ctx context.Context, id string) (FederationIssuer, error) {
	if r.sq != nil {
		row, err := r.sq.FederationIssuerByID(ctx, id)
		if err != nil {
			return FederationIssuer{}, notFoundOr(err)
		}
		return issuerFromSQLite(sqlitegen.FederationIssuer(row))
	}
	row, err := r.pg.FederationIssuerByID(ctx, id)
	if err != nil {
		return FederationIssuer{}, notFoundOr(err)
	}
	return issuerFromPG(pggen.FederationIssuer(row)), nil
}

// FederationIssuers lists every configured issuer.
func (r *Resolver) FederationIssuers(ctx context.Context) ([]FederationIssuer, error) {
	if r.sq != nil {
		rows, err := r.sq.ListFederationIssuers(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]FederationIssuer, 0, len(rows))
		for _, row := range rows {
			iss, err := issuerFromSQLite(sqlitegen.FederationIssuer(row))
			if err != nil {
				return nil, err
			}
			out = append(out, iss)
		}
		return out, nil
	}
	rows, err := r.pg.ListFederationIssuers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]FederationIssuer, 0, len(rows))
	for _, row := range rows {
		out = append(out, issuerFromPG(pggen.FederationIssuer(row)))
	}
	return out, nil
}

// UpdateFederationIssuer rewrites the mutable half — the JWKS source and the
// refused audiences. It cannot move `issuer` or `issuer_type`: changing either
// would silently re-point every binding underneath at a different external
// authority, which is a replacement, not an edit.
func (r *Resolver) UpdateFederationIssuer(ctx context.Context, id string, mode domain.JWKSMode, staticJWKS string, refused []string, actor domain.PrincipalID, at time.Time) (bool, error) {
	var n int64
	var err error
	if r.sq != nil {
		n, err = r.sq.UpdateFederationIssuer(ctx, sqlitegen.UpdateFederationIssuerParams{
			JwksMode: string(mode), StaticJwks: nullString(staticJWKS),
			RefusedAudiences: joinAudiences(refused),
			UpdatedAt:        nullString(encodeTime(at)), UpdatedBy: nullString(string(actor)), ID: id,
		})
	} else {
		n, err = r.pg.UpdateFederationIssuer(ctx, pggen.UpdateFederationIssuerParams{
			JwksMode: string(mode), StaticJwks: pgText(staticJWKS),
			RefusedAudiences: joinAudiences(refused),
			UpdatedAt:        pgTime(at), UpdatedBy: pgText(string(actor)), ID: id,
		})
	}
	return n > 0, err
}

// DeleteFederationIssuer removes a configuration.
func (r *Resolver) DeleteFederationIssuer(ctx context.Context, id string) (bool, error) {
	var n int64
	var err error
	if r.sq != nil {
		n, err = r.sq.DeleteFederationIssuer(ctx, id)
	} else {
		n, err = r.pg.DeleteFederationIssuer(ctx, id)
	}
	return n > 0, err
}

// BindingsForIssuer counts every binding naming an issuer, live or historical, so
// a delete that would orphan one is refused rather than cascading. Removing the
// issuer of a live binding is an authorization change wearing a configuration
// changes clothes; removing one a revoked binding names would erase what that
// binding trusted.
func (r *Resolver) BindingsForIssuer(ctx context.Context, id string) (int64, error) {
	if r.sq != nil {
		return r.sq.CountBindingsForIssuer(ctx, nullString(id))
	}
	return r.pg.CountBindingsForIssuer(ctx, pgText(id))
}

// FederatedBindingByIdentity is federated authentication's single indexed
// read: the LIVE binding naming this `(issuer, subject)` pair, matched
// byte-for-byte. domain.ErrNotFound means the identity is UNBOUND, which is not
// a login — it creates no principal and authenticates nothing.
//
// On a MISS it returns domain.ErrNotFound together with a credential whose
// Binding is the DECODED DECOY and whose every identifying field is empty. Both
// halves are deliberate. The decoy binding is there so the caller's binding
// predicate — audience, every pinned claim, the CI event rule, the restore
// predicate — performs its full comparison work on the miss path too; without
// it, an unbound identity would return early on "binding names no audience"
// while a bound one ran a JSON claim comparison per pin. The empty identifiers
// are there so the service-account read that follows resolves nothing, at the
// same cost, exactly as the bearer path does with the empty id.
func (r *Resolver) FederatedBindingByIdentity(ctx context.Context, issuerID, subject string) (MachineCredential, error) {
	if r.sq != nil {
		row, err := r.sq.FederatedBindingByIdentity(ctx, sqlitegen.FederatedBindingByIdentityParams{
			IssuerID: nullString(issuerID), Subject: nullString(subject),
		})
		if errors.Is(notFoundOr(err), domain.ErrNotFound) {
			return decoyBindingWorkSQLite()
		}
		if err != nil {
			return MachineCredential{}, err
		}
		return credentialFromSQLite(sqlitegen.ListMachineCredentialsRow(row))
	}
	row, err := r.pg.FederatedBindingByIdentity(ctx, pggen.FederatedBindingByIdentityParams{
		IssuerID: pgText(issuerID), Subject: pgText(subject),
	})
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return decoyBindingWorkPG()
	}
	if err != nil {
		return MachineCredential{}, err
	}
	return credentialFromPG(pggen.ListMachineCredentialsRow(row)), nil
}

// decoyBindingWork* performs a hit's row decode on the miss path, and hands the
// caller the decoy BINDING so the predicate work happens too. The identifying
// fields are cleared so nothing downstream can mistake the decoy for a
// resolution; the error is always domain.ErrNotFound.
func decoyBindingWorkSQLite() (MachineCredential, error) {
	c, err := credentialFromSQLite(decoyBindingRowSQLite)
	if err != nil {
		return MachineCredential{}, err
	}
	sinkDecoy(uint64(c.CredentialEpoch), false)
	return MachineCredential{Binding: c.Binding}, domain.ErrNotFound
}

func decoyBindingWorkPG() (MachineCredential, error) {
	c := credentialFromPG(decoyBindingRowPG)
	sinkDecoy(uint64(c.CredentialEpoch), false)
	return MachineCredential{Binding: c.Binding}, domain.ErrNotFound
}

// ReactivateBinding records a restore-time re-validation (§ Restore). The
// re-activation UX is #76's; the column and the refusal it drives land now,
// because a restore path arriving later cannot retrofit the predicate onto
// tokens already accepted.
func (r *Resolver) ReactivateBinding(ctx context.Context, id string, at time.Time) (bool, error) {
	var n int64
	var err error
	if r.sq != nil {
		n, err = r.sq.ReactivateFederatedBinding(ctx, sqlitegen.ReactivateFederatedBindingParams{
			ReactivatedAt: nullString(encodeTime(at)), ID: id,
		})
	} else {
		n, err = r.pg.ReactivateFederatedBinding(ctx, pggen.ReactivateFederatedBindingParams{
			ReactivatedAt: pgTime(at), ID: id,
		})
	}
	return n > 0, err
}

// PinGeneration reads the cursor's pin component for one (principal,
// environment). An ABSENT row is generation 0 — the truthful "this principal
// has never had a pin here" — so no row is not an error and materialising one
// on a read path is not the answer.
func (r *Resolver) PinGeneration(ctx context.Context, p domain.PrincipalID, env domain.EnvID) (int64, error) {
	var (
		gen int64
		err error
	)
	if r.sq != nil {
		gen, err = r.sq.GetPinGeneration(ctx, sqlitegen.GetPinGenerationParams{
			PrincipalID: string(p), EnvironmentID: string(env),
		})
	} else {
		gen, err = r.pg.GetPinGeneration(ctx, pggen.GetPinGenerationParams{
			PrincipalID: string(p), EnvironmentID: string(env),
		})
	}
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return 0, nil
	}
	return gen, err
}

// SetPinGeneration advances the cursor's pin component. #52 owns pin creation,
// reassignment and release; this is the counter each of those must move, and it
// exists now because the cursor is bound to it now.
func (r *Resolver) SetPinGeneration(ctx context.Context, p domain.PrincipalID, env domain.EnvID, generation int64) error {
	if r.sq != nil {
		return r.sq.SetPinGeneration(ctx, sqlitegen.SetPinGenerationParams{
			PrincipalID: string(p), EnvironmentID: string(env), Generation: generation,
		})
	}
	return r.pg.SetPinGeneration(ctx, pggen.SetPinGenerationParams{
		PrincipalID: string(p), EnvironmentID: string(env), Generation: generation,
	})
}

func issuerFromSQLite(row sqlitegen.FederationIssuer) (FederationIssuer, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return FederationIssuer{}, err
	}
	updated, err := decodeNullTime(row.UpdatedAt)
	if err != nil {
		return FederationIssuer{}, err
	}
	return FederationIssuer{
		ID: row.ID, Issuer: row.Issuer, Type: domain.IssuerType(row.IssuerType),
		Mode: domain.JWKSMode(row.JwksMode), StaticJWKS: row.StaticJwks.String,
		RefusedAudiences: splitAudiences(row.RefusedAudiences),
		CreatedAt:        created, CreatedBy: domain.PrincipalID(row.CreatedBy),
		UpdatedAt: updated, UpdatedBy: domain.PrincipalID(row.UpdatedBy.String),
	}, nil
}

func issuerFromPG(row pggen.FederationIssuer) FederationIssuer {
	return FederationIssuer{
		ID: row.ID, Issuer: row.Issuer, Type: domain.IssuerType(row.IssuerType),
		Mode: domain.JWKSMode(row.JwksMode), StaticJWKS: row.StaticJwks.String,
		RefusedAudiences: splitAudiences(row.RefusedAudiences),
		CreatedAt:        row.CreatedAt.Time, CreatedBy: domain.PrincipalID(row.CreatedBy),
		UpdatedAt: row.UpdatedAt.Time, UpdatedBy: domain.PrincipalID(row.UpdatedBy.String),
	}
}
