package authn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// Machine identities (#61, machine-identities ADR).
//
// Why this lives on the resolution surface and not behind the proof-carrying
// store, restated because it is the load-bearing siting decision: a machine
// credential resolves at the SAME chokepoint as authorize(), in the same
// transaction, uncached (ADR § Propagations, architecture). Deciding which
// service account a presented value belongs to is resolution — the proof is
// what that answer produces — so the credential row and the service-account
// row naming its principal are `class=authn`, exactly like sessions.
//
// The administrative reads and writes ride the same surface for a duller
// reason: they touch the same tables, and the SQL predicate analyzer refuses
// any unannotated query against a `class=authn` table. Authorization for them
// still happens at the chokepoint first — the service layer calls
// az.Authorize before any method here — so the proof is minted, it just is
// not what opens the door to these particular rows. The same is already true
// of grant administration (#55) and OIDC provider administration (#54).

// ServiceAccount is a machine principal's identity record: who it is, which
// project owns it, and which class its grants are bound by. It carries NO
// scope — authority is the union of the grants on PrincipalID and nothing
// else.
type ServiceAccount struct {
	ID          string
	PrincipalID domain.PrincipalID
	Org         domain.OrgID
	Project     domain.ProjectID
	Name        string
	// Kind is `workload` or `automation`, declared at creation and immutable.
	// No writer here names the column after the insert.
	Kind      domain.PrincipalClass
	CreatedAt time.Time
	CreatedBy domain.PrincipalID
}

// MachineCredential is one authenticator's METADATA. The value is not a
// field, on purpose: nothing in the system returns a credential value after
// mint, so there is nowhere for it to be read from.
type MachineCredential struct {
	ID               string
	ServiceAccountID string
	Kind             domain.CredentialKind
	// PrefixHint is the leading, non-secret slice of the minted value —
	// `hik_1_wl_` plus a few body characters — so an operator can tell two
	// live credentials apart in a list without either being retrievable. It is
	// EMPTY for an `oidc-federation` row, which has no minted value to hint at.
	PrefixHint string
	// Binding is the federated identity this credential is, and is the zero
	// value for a bearer credential. The kind discriminates, so there is no
	// second boolean saying which half of the row is meaningful.
	Binding  Binding
	Lifetime domain.CredentialLifetime
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

// Live reports whether the credential authenticates at `now` under `epoch`.
// It is the whole predicate in one place so the authenticating path and the
// listing path cannot answer differently about the same row.
func (c MachineCredential) Live(now time.Time, epoch int64) bool {
	if !c.RevokedAt.IsZero() || c.CredentialEpoch != epoch {
		return false
	}
	return c.Lifetime == domain.LifetimeIndefinite || now.Before(c.ExpiresAt)
}

// CredentialPolicy is the instance's lifetime governance (ADR § Lifetime),
// under `instance-config`. The two lifetime controls are SEPARATE fields
// because raising MaxFiniteLifetime must never be able to manufacture an
// indefinite credential.
type CredentialPolicy struct {
	MaxFiniteLifetime  time.Duration
	AllowIndefinite    bool
	MaxLiveCredentials int64
	// UpdatedAt is the zero time while the row is still the shipped default.
	UpdatedAt time.Time
	UpdatedBy domain.PrincipalID
}

// NewServiceAccount is one creation, all fields required.
type NewServiceAccount struct {
	ID          string
	PrincipalID domain.PrincipalID
	Org         domain.OrgID
	Project     domain.ProjectID
	Name        string
	Kind        domain.PrincipalClass
	CreatedAt   time.Time
	CreatedBy   domain.PrincipalID
}

// NewMachineCredential is one mint of EITHER kind. Verifier is the unsalted
// SHA-256 of the whole presented value; the value itself never reaches this
// package. For an `oidc-federation` mint, Verifier and PrefixHint are empty and
// Binding carries the identity instead — the table's two shape CHECKs make the
// pairing total, so a half-shaped row of either kind is unrepresentable.
type NewMachineCredential struct {
	ID               string
	ServiceAccountID string
	Kind             domain.CredentialKind
	Verifier         []byte
	PrefixHint       string
	Binding          Binding
	Lifetime         domain.CredentialLifetime
	ExpiresAt        time.Time
	CredentialEpoch  int64
	CreatedAt        time.Time
	CreatedBy        domain.PrincipalID
}

// CreateMachinePrincipal inserts the principal row a service account is. It
// is separate from CreateServiceAccount because the FK orders them and the
// class column is what the normative allowlists key on.
func (r *Resolver) CreateMachinePrincipal(ctx context.Context, id domain.PrincipalID, class domain.PrincipalClass, at time.Time) error {
	if r.sq != nil {
		return r.sq.InsertMachinePrincipal(ctx, sqlitegen.InsertMachinePrincipalParams{
			ID: string(id), Class: nullString(string(class)), CreatedAt: encodeTime(at),
		})
	}
	return r.pg.InsertMachinePrincipal(ctx, pggen.InsertMachinePrincipalParams{
		ID: string(id), Class: pgText(string(class)), CreatedAt: pgTime(at),
	})
}

// CreateServiceAccount inserts the identity record. A name already in use
// among the project's service accounts is an operator CONFLICT, not a fault:
// the caller is authorized, the current state refuses.
func (r *Resolver) CreateServiceAccount(ctx context.Context, sa NewServiceAccount) error {
	if r.sq != nil {
		return serviceAccountConstraint(r.sq.InsertServiceAccount(ctx, sqlitegen.InsertServiceAccountParams{
			ID: sa.ID, PrincipalID: string(sa.PrincipalID), OrgID: string(sa.Org),
			ProjectID: string(sa.Project), Name: sa.Name, Kind: string(sa.Kind),
			CreatedAt: encodeTime(sa.CreatedAt), CreatedBy: string(sa.CreatedBy),
		}))
	}
	return serviceAccountConstraint(r.pg.InsertServiceAccount(ctx, pggen.InsertServiceAccountParams{
		ID: sa.ID, PrincipalID: string(sa.PrincipalID), OrgID: string(sa.Org),
		ProjectID: string(sa.Project), Name: sa.Name, Kind: string(sa.Kind),
		CreatedAt: pgTime(sa.CreatedAt), CreatedBy: string(sa.CreatedBy),
	}))
}

// serviceAccountConstraint maps a duplicate name onto the one cross-engine
// refusal, by TYPED extended code rather than by matching driver message text
// — a caller-visible outcome hinging on a locale- and version-dependent
// string is a silent behaviour change waiting for a dependency bump.
//
// Only uniqueness is folded. A foreign-key or check violation here is an
// implementation defect (a chain that does not exist, a kind outside the
// CHECK the service already validated), and reporting it as a conflict would
// tell an operator to rename something that is not the problem.
func serviceAccountConstraint(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: a service account with this name already exists in this project", domain.ErrConflict)
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) &&
		(sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_UNIQUE ||
			sqliteErr.Code() == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY) {
		return fmt.Errorf("%w: a service account with this name already exists in this project", domain.ErrConflict)
	}
	return err
}

// ServiceAccountAt resolves one service account WITHIN an addressed project.
// The chain is in the predicate, so an id belonging to another project
// answers domain.ErrNotFound rather than another project's row.
func (r *Resolver) ServiceAccountAt(ctx context.Context, scope domain.Scope, id string) (ServiceAccount, error) {
	if r.sq != nil {
		row, err := r.sq.GetServiceAccount(ctx, sqlitegen.GetServiceAccountParams{
			OrgID: string(scope.Org), ProjectID: string(scope.Project), ID: id,
		})
		if err != nil {
			return ServiceAccount{}, notFoundOr(err)
		}
		return serviceAccountFromSQLite(row)
	}
	row, err := r.pg.GetServiceAccount(ctx, pggen.GetServiceAccountParams{
		OrgID: string(scope.Org), ProjectID: string(scope.Project), ID: id,
	})
	if err != nil {
		return ServiceAccount{}, notFoundOr(err)
	}
	return serviceAccountFromPG(row), nil
}

// ServiceAccountByID resolves a service account by id alone. The single
// caller is authentication, where the id came from the credential row the
// presented verifier resolved to — never from a request.
func (r *Resolver) ServiceAccountByID(ctx context.Context, id string) (ServiceAccount, error) {
	if r.sq != nil {
		row, err := r.sq.GetServiceAccountByID(ctx, id)
		if errors.Is(notFoundOr(err), domain.ErrNotFound) {
			return ServiceAccount{}, decoyServiceAccountWorkSQLite()
		}
		if err != nil {
			return ServiceAccount{}, err
		}
		return serviceAccountFromSQLite(row)
	}
	row, err := r.pg.GetServiceAccountByID(ctx, id)
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return ServiceAccount{}, decoyServiceAccountWorkPG()
	}
	if err != nil {
		return ServiceAccount{}, err
	}
	return serviceAccountFromPG(row), nil
}

// ServiceAccountByPrincipal resolves the service account a machine principal
// IS, so the grant surface can confine its grants to the project that owns
// it. domain.ErrNotFound means the principal is a machine that is not a
// service account — the provisioning and instance connections (#73/#71), and
// any machine principal predating this table.
func (r *Resolver) ServiceAccountByPrincipal(ctx context.Context, p domain.PrincipalID) (ServiceAccount, error) {
	if r.sq != nil {
		row, err := r.sq.GetServiceAccountByPrincipal(ctx, string(p))
		if err != nil {
			return ServiceAccount{}, notFoundOr(err)
		}
		return serviceAccountFromSQLite(row)
	}
	row, err := r.pg.GetServiceAccountByPrincipal(ctx, string(p))
	if err != nil {
		return ServiceAccount{}, notFoundOr(err)
	}
	return serviceAccountFromPG(row), nil
}

// ServiceAccountsIn lists a project's service accounts.
func (r *Resolver) ServiceAccountsIn(ctx context.Context, scope domain.Scope) ([]ServiceAccount, error) {
	if r.sq != nil {
		rows, err := r.sq.ListServiceAccounts(ctx, sqlitegen.ListServiceAccountsParams{
			OrgID: string(scope.Org), ProjectID: string(scope.Project),
		})
		if err != nil {
			return nil, err
		}
		out := make([]ServiceAccount, 0, len(rows))
		for _, row := range rows {
			sa, err := serviceAccountFromSQLite(row)
			if err != nil {
				return nil, err
			}
			out = append(out, sa)
		}
		return out, nil
	}
	rows, err := r.pg.ListServiceAccounts(ctx, pggen.ListServiceAccountsParams{
		OrgID: string(scope.Org), ProjectID: string(scope.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ServiceAccount, 0, len(rows))
	for _, row := range rows {
		out = append(out, serviceAccountFromPG(row))
	}
	return out, nil
}

// DeleteServiceAccount removes the identity record. It is the last statement
// of the deletion sequence — credentials and grants go first — so the
// foreign keys pointing here are already gone.
func (r *Resolver) DeleteServiceAccount(ctx context.Context, scope domain.Scope, id string) (int64, error) {
	if r.sq != nil {
		return r.sq.DeleteServiceAccount(ctx, sqlitegen.DeleteServiceAccountParams{
			OrgID: string(scope.Org), ProjectID: string(scope.Project), ID: id,
		})
	}
	return r.pg.DeleteServiceAccount(ctx, pggen.DeleteServiceAccountParams{
		OrgID: string(scope.Org), ProjectID: string(scope.Project), ID: id,
	})
}

// DeleteMachinePrincipal removes the principal row and its whole grant set,
// origins first because the origin FK is RESTRICT. Every statement runs in
// the caller's transaction, which is what makes "deleting a service account
// revokes every credential and every grant in one transaction" true.
func (r *Resolver) DeleteMachinePrincipal(ctx context.Context, p domain.PrincipalID) error {
	// The principal-row lock, taken before the grant reads and writes below,
	// exactly as every other grant writer does: a concurrent grant landing on
	// this principal must serialize against its deprovisioning rather than
	// insert a row into a principal that is on its way out.
	if err := r.LockPrincipalRow(ctx, p); err != nil {
		return err
	}
	if r.sq != nil {
		if _, err := r.sq.DeleteGrantOriginsForPrincipal(ctx, string(p)); err != nil {
			return err
		}
		if _, err := r.sq.DeleteGrantsForPrincipal(ctx, string(p)); err != nil {
			return err
		}
		_, err := r.sq.DeletePrincipal(ctx, string(p))
		return err
	}
	if _, err := r.pg.DeleteGrantOriginsForPrincipal(ctx, string(p)); err != nil {
		return err
	}
	if _, err := r.pg.DeleteGrantsForPrincipal(ctx, string(p)); err != nil {
		return err
	}
	_, err := r.pg.DeletePrincipal(ctx, string(p))
	return err
}

// CreateMachineCredential persists one mint.
func (r *Resolver) CreateMachineCredential(ctx context.Context, c NewMachineCredential) error {
	if r.sq != nil {
		return bindingConstraint(r.sq.InsertMachineCredential(ctx, sqlitegen.InsertMachineCredentialParams{
			ID: c.ID, ServiceAccountID: c.ServiceAccountID, Kind: string(c.Kind),
			Verifier: c.Verifier, PrefixHint: nullString(c.PrefixHint), Lifetime: string(c.Lifetime),
			ExpiresAt: nullTimeString(c.ExpiresAt), CredentialEpoch: c.CredentialEpoch,
			CreatedAt: encodeTime(c.CreatedAt), CreatedBy: string(c.CreatedBy),
			IssuerID: nullString(c.Binding.IssuerID), Subject: nullString(c.Binding.Subject),
			Audience: nullString(c.Binding.Audience), RequiredClaims: nullString(c.Binding.RequiredClaimsJSON),
		}))
	}
	return bindingConstraint(r.pg.InsertMachineCredential(ctx, pggen.InsertMachineCredentialParams{
		ID: c.ID, ServiceAccountID: c.ServiceAccountID, Kind: string(c.Kind),
		Verifier: c.Verifier, PrefixHint: pgText(c.PrefixHint), Lifetime: string(c.Lifetime),
		ExpiresAt: nullPGTime(c.ExpiresAt), CredentialEpoch: c.CredentialEpoch,
		CreatedAt: pgTime(c.CreatedAt), CreatedBy: string(c.CreatedBy),
		IssuerID: pgText(c.Binding.IssuerID), Subject: pgText(c.Binding.Subject),
		Audience: pgText(c.Binding.Audience), RequiredClaims: pgText(c.Binding.RequiredClaimsJSON),
	}))
}

// The decoy row and verifier the MISS paths do their work against.
//
// Equal SQL statement counts close the query-count oracle but not the work
// shape above it: an index miss would otherwise skip the row decode and the
// constant-time compare that a hit performs, so an unknown credential and a
// revoked one would differ by a timestamp parse and a 32-byte compare. The
// tenant-isolation propagation asks for indistinguishability "in responses
// AND timing", so the miss paths run the same decode and the same compare
// against these fixed values and throw the result away.
//
// Fixed constants, not synthetic randomness: the work is the point, and a
// value that varies per call would add a second thing to reason about. The
// decoy verifier is 32 bytes so the compare does the same number of byte
// operations a real one does, and it is deliberately not a value any mint can
// produce (a real verifier is SHA-256 of an `hik_` artifact).
//
// KNOWN CEILING, stated rather than papered over: this equalises the work
// ABOVE the storage engine. The B-tree probe itself still differs between a
// hit and a miss, and no application-level code can change that — the
// tenant-isolation ADR already records engine-internal microtiming as the
// accepted residual. What this removes is the part that was ours.
// The decoys are ENGINE-MATCHED, and that is not tidiness. The two decoders
// do different amounts of work: the sqlite one parses timestamps out of
// fixed-width strings, the postgres one copies pgtype values the driver
// already decoded. A single sqlite-shaped decoy would make a postgres MISS
// cost more than a postgres HIT — the asymmetry inverted rather than closed.
// So each engine's miss path decodes its own decoy through the same function
// its hit path uses.
var (
	decoyVerifier = make([]byte, 32)

	decoyCredentialRowSQLite = sqlitegen.ListMachineCredentialsRow{
		ID: "mcr_decoy", ServiceAccountID: "sa_decoy", Kind: string(domain.CredentialHikyoToken),
		PrefixHint:      sql.NullString{String: "hik_1_wl_000000", Valid: true},
		Lifetime:        string(domain.LifetimeFinite),
		ExpiresAt:       sql.NullString{String: decoyTime, Valid: true},
		CredentialEpoch: 1, CreatedAt: decoyTime, CreatedBy: "usr_decoy",
	}

	decoyCredentialRowPG = pggen.ListMachineCredentialsRow{
		ID: "mcr_decoy", ServiceAccountID: "sa_decoy", Kind: string(domain.CredentialHikyoToken),
		PrefixHint:      pgtype.Text{String: "hik_1_wl_000000", Valid: true},
		Lifetime:        string(domain.LifetimeFinite),
		ExpiresAt:       pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		CredentialEpoch: 1,
		CreatedAt:       pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		CreatedBy:       "usr_decoy",
	}

	// The BINDING decoy is its own row rather than the bearer one, and the
	// difference is the point: the two kinds decode different column sets — a
	// bearer row parses no `reactivated_at`, a binding row parses no
	// verifier — so reusing one decoy would make a miss on the federated path
	// cost less than a hit on it. Same reasoning as the engine-matched split
	// above, one axis further in.
	decoyBindingRowSQLite = sqlitegen.ListMachineCredentialsRow{
		ID: "mcr_decoy", ServiceAccountID: "sa_decoy", Kind: string(domain.CredentialOIDCFederation),
		Lifetime:        string(domain.LifetimeFinite),
		ExpiresAt:       sql.NullString{String: decoyTime, Valid: true},
		CredentialEpoch: 1, CreatedAt: decoyTime, CreatedBy: "usr_decoy",
		IssuerID: sql.NullString{String: "fis_decoy", Valid: true},
		Subject:  sql.NullString{String: "system:serviceaccount:decoy:decoy", Valid: true},
		Audience: sql.NullString{String: "hikyo", Valid: true},
		// A PLAUSIBLE pinned set, not `{}`: the caller's binding predicate parses
		// this document and compares each pin, so an empty object would make the
		// miss path skip the JSON work a hit performs.
		RequiredClaims: sql.NullString{String: decoyRequiredClaims, Valid: true},
		ReactivatedAt:  sql.NullString{String: decoyTime, Valid: true},
	}

	decoyBindingRowPG = pggen.ListMachineCredentialsRow{
		ID: "mcr_decoy", ServiceAccountID: "sa_decoy", Kind: string(domain.CredentialOIDCFederation),
		Lifetime:        string(domain.LifetimeFinite),
		ExpiresAt:       pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		CredentialEpoch: 1,
		CreatedAt:       pgtype.Timestamptz{Time: decoyInstant, Valid: true},
		CreatedBy:       "usr_decoy",
		IssuerID:        pgtype.Text{String: "fis_decoy", Valid: true},
		Subject:         pgtype.Text{String: "system:serviceaccount:decoy:decoy", Valid: true},
		Audience:        pgtype.Text{String: "hikyo", Valid: true},
		RequiredClaims:  pgtype.Text{String: decoyRequiredClaims, Valid: true},
		ReactivatedAt:   pgtype.Timestamptz{Time: decoyInstant, Valid: true},
	}

	decoyServiceAccountRowSQLite = sqlitegen.ServiceAccount{
		ID: "sa_decoy", PrincipalID: "mch_decoy", OrgID: "org_decoy", ProjectID: "prj_decoy",
		Name: "decoy", Kind: string(domain.ClassWorkload), CreatedAt: decoyTime, CreatedBy: "usr_decoy",
	}

	decoyServiceAccountRowPG = pggen.ServiceAccount{
		ID: "sa_decoy", PrincipalID: "mch_decoy", OrgID: "org_decoy", ProjectID: "prj_decoy",
		Name: "decoy", Kind: string(domain.ClassWorkload),
		CreatedAt: pgtype.Timestamptz{Time: decoyInstant, Valid: true}, CreatedBy: "usr_decoy",
	}

	// decoySink consumes the decoy work. Without an observable use the
	// compiler may legally discard a pure decode and a pure comparison, which
	// would silently delete the property this whole block exists for — the
	// code would still read correctly and do nothing. An atomic store is the
	// cheapest thing the optimiser is not allowed to remove.
	decoySink atomic.Uint64
)

// decoyTime is a real timestamp in this package's fixed-width layout, so the
// sqlite decoy decode costs exactly what a live one costs rather than failing
// early; decoyInstant is the same moment for the postgres shape.
const decoyTime = "1970-01-01T00:00:00.000000Z"

// decoyRequiredClaims is a three-pin document in the shape a real CI binding
// carries, so the miss path's predicate parses and compares rather than
// returning early on an empty set.
const decoyRequiredClaims = `{"event_name":"push","repository":"decoy/decoy","workflow_ref":"decoy/decoy/.forgejo/workflows/decoy.yaml@refs/heads/main"}`

var decoyInstant = time.Unix(0, 0).UTC()

// MachineCredentialByVerifier is authentication's single indexed read. It
// returns revoked, expired and epoch-superseded rows unchanged: the caller
// evaluates every predicate after a fixed number of reads, so an unknown
// credential and a revoked one cost the same queries.
func (r *Resolver) MachineCredentialByVerifier(ctx context.Context, verifier []byte) (MachineCredential, error) {
	if r.sq != nil {
		row, err := r.sq.MachineCredentialByVerifier(ctx, verifier)
		if errors.Is(notFoundOr(err), domain.ErrNotFound) {
			return MachineCredential{}, decoyCredentialWorkSQLite(verifier)
		}
		if err != nil {
			return MachineCredential{}, err
		}
		if !verifierMatches(row.Verifier, verifier) {
			return MachineCredential{}, domain.ErrNotFound
		}
		return credentialFromSQLite(sqlitegen.ListMachineCredentialsRow{
			ID: row.ID, ServiceAccountID: row.ServiceAccountID, Kind: row.Kind,
			PrefixHint: row.PrefixHint, Lifetime: row.Lifetime, ExpiresAt: row.ExpiresAt,
			CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt,
			CreatedBy: row.CreatedBy, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
			IssuerID: row.IssuerID, Subject: row.Subject, Audience: row.Audience,
			RequiredClaims: row.RequiredClaims, ReactivatedAt: row.ReactivatedAt,
		})
	}
	row, err := r.pg.MachineCredentialByVerifier(ctx, verifier)
	if errors.Is(notFoundOr(err), domain.ErrNotFound) {
		return MachineCredential{}, decoyCredentialWorkPG(verifier)
	}
	if err != nil {
		return MachineCredential{}, err
	}
	if !verifierMatches(row.Verifier, verifier) {
		return MachineCredential{}, domain.ErrNotFound
	}
	return credentialFromPG(pggen.ListMachineCredentialsRow{
		ID: row.ID, ServiceAccountID: row.ServiceAccountID, Kind: row.Kind,
		PrefixHint: row.PrefixHint, Lifetime: row.Lifetime, ExpiresAt: row.ExpiresAt,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt,
		CreatedBy: row.CreatedBy, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
		IssuerID: row.IssuerID, Subject: row.Subject, Audience: row.Audience,
		RequiredClaims: row.RequiredClaims, ReactivatedAt: row.ReactivatedAt,
	}), nil
}

// decoyCredentialWork* performs a hit's decode and compare on the miss path
// and always answers domain.ErrNotFound.
//
// The comparison's result reaches decoySink rather than the return value: the
// outcome must not depend on it (the decoy is not a mintable verifier, so a
// match is impossible in fact), but the work must still happen, and only an
// observable side effect guarantees that.
func decoyCredentialWorkSQLite(verifier []byte) error {
	c, err := credentialFromSQLite(decoyCredentialRowSQLite)
	if err != nil {
		return err
	}
	sinkDecoy(uint64(c.CredentialEpoch), verifierMatches(decoyVerifier, verifier))
	return domain.ErrNotFound
}

func decoyCredentialWorkPG(verifier []byte) error {
	c := credentialFromPG(decoyCredentialRowPG)
	sinkDecoy(uint64(c.CredentialEpoch), verifierMatches(decoyVerifier, verifier))
	return domain.ErrNotFound
}

// decoyServiceAccountWork* is the same idea for the second of the three reads:
// a missing service account decodes a decoy rather than returning early, so an
// unknown credential and a live one cost the same decode here too.
func decoyServiceAccountWorkSQLite() error {
	sa, err := serviceAccountFromSQLite(decoyServiceAccountRowSQLite)
	if err != nil {
		return err
	}
	sinkDecoy(uint64(len(sa.ID)), false)
	return domain.ErrNotFound
}

func decoyServiceAccountWorkPG() error {
	sa := serviceAccountFromPG(decoyServiceAccountRowPG)
	sinkDecoy(uint64(len(sa.ID)), false)
	return domain.ErrNotFound
}

// sinkDecoy makes the decoy decode and the decoy comparison observable, so
// neither can be optimised away. Nothing reads decoySink and nothing should:
// its only job is to be a side effect the compiler must keep.
func sinkDecoy(n uint64, matched bool) {
	if matched {
		n++
	}
	decoySink.Add(n)
}

// MachineCredentialsFor lists one service account's credentials — metadata
// only, because that is all the row holds.
func (r *Resolver) MachineCredentialsFor(ctx context.Context, serviceAccountID string) ([]MachineCredential, error) {
	if r.sq != nil {
		rows, err := r.sq.ListMachineCredentials(ctx, serviceAccountID)
		if err != nil {
			return nil, err
		}
		out := make([]MachineCredential, 0, len(rows))
		for _, row := range rows {
			c, err := credentialFromSQLite(row)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, nil
	}
	rows, err := r.pg.ListMachineCredentials(ctx, serviceAccountID)
	if err != nil {
		return nil, err
	}
	out := make([]MachineCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, credentialFromPG(row))
	}
	return out, nil
}

// LiveMachineCredentialCount is the concurrent-credential cap's census,
// counted in the database so a mint racing another mint cannot both read a
// count below the cap.
func (r *Resolver) LiveMachineCredentialCount(ctx context.Context, serviceAccountID string, epoch int64, now time.Time) (int64, error) {
	if r.sq != nil {
		return r.sq.CountLiveMachineCredentials(ctx, sqlitegen.CountLiveMachineCredentialsParams{
			ServiceAccountID: serviceAccountID, CredentialEpoch: epoch,
			ExpiresAt: nullString(encodeTime(now)),
		})
	}
	return r.pg.CountLiveMachineCredentials(ctx, pggen.CountLiveMachineCredentialsParams{
		ServiceAccountID: serviceAccountID, CredentialEpoch: epoch, Now: pgTime(now),
	})
}

// LiveMachineCredentialCounts is the project's whole census in one query, so
// an administrative list does not cost a count per service account.
func (r *Resolver) LiveMachineCredentialCounts(ctx context.Context, scope domain.Scope, epoch int64, now time.Time) (map[string]int64, error) {
	out := map[string]int64{}
	if r.sq != nil {
		rows, err := r.sq.CountLiveMachineCredentialsInProject(ctx, sqlitegen.CountLiveMachineCredentialsInProjectParams{
			OrgID: string(scope.Org), ProjectID: string(scope.Project),
			CredentialEpoch: epoch, ExpiresAt: nullString(encodeTime(now)),
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out[row.ServiceAccountID] = row.Live
		}
		return out, nil
	}
	rows, err := r.pg.CountLiveMachineCredentialsInProject(ctx, pggen.CountLiveMachineCredentialsInProjectParams{
		OrgID: string(scope.Org), ProjectID: string(scope.Project),
		CredentialEpoch: epoch, Now: pgTime(now),
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.ServiceAccountID] = row.Live
	}
	return out, nil
}

// RevokeMachineCredential marks one credential revoked, reporting whether
// this call is the one that did it. The `revoked_at IS NULL` guard lives in
// the statement, so two concurrent revokes cannot both claim the transition.
func (r *Resolver) RevokeMachineCredential(ctx context.Context, serviceAccountID, id string, at time.Time) (bool, error) {
	var n int64
	var err error
	if r.sq != nil {
		n, err = r.sq.RevokeMachineCredential(ctx, sqlitegen.RevokeMachineCredentialParams{
			RevokedAt: nullString(encodeTime(at)), ID: id, ServiceAccountID: serviceAccountID,
		})
	} else {
		n, err = r.pg.RevokeMachineCredential(ctx, pggen.RevokeMachineCredentialParams{
			RevokedAt: nullPGTime(at), ID: id, ServiceAccountID: serviceAccountID,
		})
	}
	return n > 0, err
}

// RevokeAllMachineCredentials revokes every live credential of one service
// account, returning how many it killed. Deletion calls it before removing
// the rows, so the count is the blast radius the audit event records.
func (r *Resolver) RevokeAllMachineCredentials(ctx context.Context, serviceAccountID string, at time.Time) (int64, error) {
	if r.sq != nil {
		return r.sq.RevokeAllMachineCredentials(ctx, sqlitegen.RevokeAllMachineCredentialsParams{
			RevokedAt: nullString(encodeTime(at)), ServiceAccountID: serviceAccountID,
		})
	}
	return r.pg.RevokeAllMachineCredentials(ctx, pggen.RevokeAllMachineCredentialsParams{
		RevokedAt: nullPGTime(at), ServiceAccountID: serviceAccountID,
	})
}

// DeleteMachineCredentials removes a deleted service account's credential
// rows. It is a delete rather than a revoke because the service account is
// going away with them; the revoke ran first so the audit trail records the
// transition before the rows stop existing.
func (r *Resolver) DeleteMachineCredentials(ctx context.Context, serviceAccountID string) error {
	if r.sq != nil {
		_, err := r.sq.DeleteMachineCredentials(ctx, serviceAccountID)
		return err
	}
	_, err := r.pg.DeleteMachineCredentials(ctx, serviceAccountID)
	return err
}

// TouchMachineCredential records last use. It is observability, never an
// authorization input: nothing reads it to decide anything.
func (r *Resolver) TouchMachineCredential(ctx context.Context, id string, at time.Time) error {
	if r.sq != nil {
		return r.sq.TouchMachineCredential(ctx, sqlitegen.TouchMachineCredentialParams{
			LastUsedAt: nullString(encodeTime(at)), ID: id,
		})
	}
	return r.pg.TouchMachineCredential(ctx, pggen.TouchMachineCredentialParams{
		LastUsedAt: nullPGTime(at), ID: id,
	})
}

// AffectedCredential is one row of the enumeration a lifetime tightening
// shows the actor BEFORE it commits (ADR § Lifetime: "a settings change
// never silently kills a live credential").
type AffectedCredential struct {
	ID               string
	ServiceAccountID string
	// ExpiresAt is the zero time for an indefinite credential, which is the
	// shape the allow_indefinite half of the enumeration produces.
	ExpiresAt time.Time
}

// CredentialsBeyondCeiling lists the live finite credentials a proposed
// ceiling would clamp.
func (r *Resolver) CredentialsBeyondCeiling(ctx context.Context, ceiling time.Time) ([]AffectedCredential, error) {
	if r.sq != nil {
		rows, err := r.sq.ListCredentialsBeyondCeiling(ctx, nullString(encodeTime(ceiling)))
		if err != nil {
			return nil, err
		}
		out := make([]AffectedCredential, 0, len(rows))
		for _, row := range rows {
			at, err := decodeNullTime(row.ExpiresAt)
			if err != nil {
				return nil, err
			}
			out = append(out, AffectedCredential{ID: row.ID, ServiceAccountID: row.ServiceAccountID, ExpiresAt: at})
		}
		return out, nil
	}
	rows, err := r.pg.ListCredentialsBeyondCeiling(ctx, nullPGTime(ceiling))
	if err != nil {
		return nil, err
	}
	out := make([]AffectedCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, AffectedCredential{
			ID: row.ID, ServiceAccountID: row.ServiceAccountID, ExpiresAt: row.ExpiresAt.Time,
		})
	}
	return out, nil
}

// IndefiniteCredentials lists the live indefinite credentials switching
// allow_indefinite off would strand.
func (r *Resolver) IndefiniteCredentials(ctx context.Context) ([]AffectedCredential, error) {
	if r.sq != nil {
		rows, err := r.sq.ListIndefiniteCredentials(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]AffectedCredential, 0, len(rows))
		for _, row := range rows {
			out = append(out, AffectedCredential{ID: row.ID, ServiceAccountID: row.ServiceAccountID})
		}
		return out, nil
	}
	rows, err := r.pg.ListIndefiniteCredentials(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AffectedCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, AffectedCredential{ID: row.ID, ServiceAccountID: row.ServiceAccountID})
	}
	return out, nil
}

// ClampIndefiniteCredentials converts every live INDEFINITE credential to a
// finite one expiring at the ceiling. It is what withdrawing the
// allow_indefinite opt-in actually does: enumerating them and leaving them
// alone would report the control as withdrawn while an unbounded credential
// kept working, which is the opposite of what the operator asked for.
//
// It is a clamp, not a revocation: the credential keeps working until the
// ceiling, so the fleet has the same window to rotate that every other
// tightening gives it, and the operator was shown the list first.
func (r *Resolver) ClampIndefiniteCredentials(ctx context.Context, ceiling time.Time) (int64, error) {
	if r.sq != nil {
		return r.sq.ClampIndefiniteCredentials(ctx, nullString(encodeTime(ceiling)))
	}
	return r.pg.ClampIndefiniteCredentials(ctx, nullPGTime(ceiling))
}

// ClampCredentialExpiry moves every live finite credential beyond the
// ceiling down to it. It only ever moves expiry DOWN: a credential already
// inside the ceiling is untouched, so raising the ceiling later cannot
// resurrect the window this clamp took away.
func (r *Resolver) ClampCredentialExpiry(ctx context.Context, ceiling time.Time) (int64, error) {
	if r.sq != nil {
		return r.sq.ClampCredentialExpiry(ctx, sqlitegen.ClampCredentialExpiryParams{
			ExpiresAt: nullString(encodeTime(ceiling)), ExpiresAt_2: nullString(encodeTime(ceiling)),
		})
	}
	return r.pg.ClampCredentialExpiry(ctx, nullPGTime(ceiling))
}

// LockCredentialPolicy takes the policy row's lock. Every writer of the
// ceiling and every reader that acts on it (a mint) takes it first, in that
// one order, so a credential cannot be written under a ceiling a concurrent
// tightening has already replaced. Postgres takes FOR UPDATE; sqlite's single
// writer serializes.
func (r *Resolver) LockCredentialPolicy(ctx context.Context) error {
	if r.sq != nil {
		_, err := r.sq.LockCredentialPolicy(ctx)
		return notFoundOr(err)
	}
	_, err := r.pg.LockCredentialPolicy(ctx)
	return notFoundOr(err)
}

// CredentialPolicy reads the instance lifetime governance.
func (r *Resolver) CredentialPolicy(ctx context.Context) (CredentialPolicy, error) {
	if r.sq != nil {
		row, err := r.sq.GetCredentialPolicy(ctx)
		if err != nil {
			return CredentialPolicy{}, notFoundOr(err)
		}
		at, err := decodeNullTime(row.UpdatedAt)
		if err != nil {
			return CredentialPolicy{}, err
		}
		return CredentialPolicy{
			MaxFiniteLifetime:  time.Duration(row.MaxFiniteLifetimeSeconds) * time.Second,
			AllowIndefinite:    row.AllowIndefinite == 1,
			MaxLiveCredentials: row.MaxLiveCredentials,
			UpdatedAt:          at,
			UpdatedBy:          domain.PrincipalID(row.UpdatedBy.String),
		}, nil
	}
	row, err := r.pg.GetCredentialPolicy(ctx)
	if err != nil {
		return CredentialPolicy{}, notFoundOr(err)
	}
	return CredentialPolicy{
		MaxFiniteLifetime:  time.Duration(row.MaxFiniteLifetimeSeconds) * time.Second,
		AllowIndefinite:    row.AllowIndefinite,
		MaxLiveCredentials: row.MaxLiveCredentials,
		UpdatedAt:          row.UpdatedAt.Time,
		UpdatedBy:          domain.PrincipalID(row.UpdatedBy.String),
	}, nil
}

// SetCredentialPolicy writes it, naming the acting principal and the instant.
func (r *Resolver) SetCredentialPolicy(ctx context.Context, p CredentialPolicy, actor domain.PrincipalID, at time.Time) error {
	if r.sq != nil {
		allow := int64(0)
		if p.AllowIndefinite {
			allow = 1
		}
		return r.sq.SetCredentialPolicy(ctx, sqlitegen.SetCredentialPolicyParams{
			MaxFiniteLifetimeSeconds: int64(p.MaxFiniteLifetime / time.Second),
			AllowIndefinite:          allow,
			MaxLiveCredentials:       p.MaxLiveCredentials,
			UpdatedAt:                nullString(encodeTime(at)),
			UpdatedBy:                nullString(string(actor)),
		})
	}
	return r.pg.SetCredentialPolicy(ctx, pggen.SetCredentialPolicyParams{
		MaxFiniteLifetimeSeconds: int64(p.MaxFiniteLifetime / time.Second),
		AllowIndefinite:          p.AllowIndefinite,
		MaxLiveCredentials:       p.MaxLiveCredentials,
		UpdatedAt:                pgTime(at),
		UpdatedBy:                pgText(string(actor)),
	})
}

// EnvironmentsInProject lists a project's environments for the reachability
// computation the mint and widen formulas range over. Grants on a service
// account are confined to its owning project's subtree (#55's
// checkMachineProject), so this list IS the universe of environments its
// credentials can reach — enumerating the whole instance would be both
// wasteful and a cross-tenant read.
func (r *Resolver) EnvironmentsInProject(ctx context.Context, scope domain.Scope) ([]domain.EnvID, error) {
	if r.sq != nil {
		rows, err := r.sq.ListEnvironmentIDsInProject(ctx, sqlitegen.ListEnvironmentIDsInProjectParams{
			OrgID: string(scope.Org), ProjectID: string(scope.Project),
		})
		if err != nil {
			return nil, err
		}
		out := make([]domain.EnvID, 0, len(rows))
		for _, id := range rows {
			out = append(out, domain.EnvID(id))
		}
		return out, nil
	}
	rows, err := r.pg.ListEnvironmentIDsInProject(ctx, pggen.ListEnvironmentIDsInProjectParams{
		OrgID: string(scope.Org), ProjectID: string(scope.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.EnvID, 0, len(rows))
	for _, id := range rows {
		out = append(out, domain.EnvID(id))
	}
	return out, nil
}

func serviceAccountFromSQLite(row sqlitegen.ServiceAccount) (ServiceAccount, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return ServiceAccount{}, err
	}
	return ServiceAccount{
		ID: row.ID, PrincipalID: domain.PrincipalID(row.PrincipalID),
		Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ProjectID),
		Name: row.Name, Kind: domain.PrincipalClass(row.Kind),
		CreatedAt: created, CreatedBy: domain.PrincipalID(row.CreatedBy),
	}, nil
}

func serviceAccountFromPG(row pggen.ServiceAccount) ServiceAccount {
	return ServiceAccount{
		ID: row.ID, PrincipalID: domain.PrincipalID(row.PrincipalID),
		Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ProjectID),
		Name: row.Name, Kind: domain.PrincipalClass(row.Kind),
		CreatedAt: row.CreatedAt.Time, CreatedBy: domain.PrincipalID(row.CreatedBy),
	}
}

func credentialFromSQLite(row sqlitegen.ListMachineCredentialsRow) (MachineCredential, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return MachineCredential{}, err
	}
	expires, err := decodeNullTime(row.ExpiresAt)
	if err != nil {
		return MachineCredential{}, err
	}
	revoked, err := decodeNullTime(row.RevokedAt)
	if err != nil {
		return MachineCredential{}, err
	}
	used, err := decodeNullTime(row.LastUsedAt)
	if err != nil {
		return MachineCredential{}, err
	}
	reactivated, err := decodeNullTime(row.ReactivatedAt)
	if err != nil {
		return MachineCredential{}, err
	}
	return MachineCredential{
		ID: row.ID, ServiceAccountID: row.ServiceAccountID,
		Kind: domain.CredentialKind(row.Kind), PrefixHint: row.PrefixHint.String,
		Binding: Binding{
			IssuerID: row.IssuerID.String, Subject: row.Subject.String,
			Audience: row.Audience.String, RequiredClaimsJSON: row.RequiredClaims.String,
			ReactivatedAt: reactivated,
		},
		Lifetime: domain.CredentialLifetime(row.Lifetime), ExpiresAt: expires,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: created,
		CreatedBy: domain.PrincipalID(row.CreatedBy), RevokedAt: revoked, LastUsedAt: used,
	}, nil
}

func credentialFromPG(row pggen.ListMachineCredentialsRow) MachineCredential {
	return MachineCredential{
		ID: row.ID, ServiceAccountID: row.ServiceAccountID,
		Kind: domain.CredentialKind(row.Kind), PrefixHint: row.PrefixHint.String,
		Binding: Binding{
			IssuerID: row.IssuerID.String, Subject: row.Subject.String,
			Audience: row.Audience.String, RequiredClaimsJSON: row.RequiredClaims.String,
			ReactivatedAt: row.ReactivatedAt.Time,
		},
		Lifetime: domain.CredentialLifetime(row.Lifetime), ExpiresAt: row.ExpiresAt.Time,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt.Time,
		CreatedBy: domain.PrincipalID(row.CreatedBy),
		RevokedAt: row.RevokedAt.Time, LastUsedAt: row.LastUsedAt.Time,
	}
}

// nullPGTime renders an optional instant: the zero time is SQL NULL.
func nullPGTime(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgTime(t)
}

// nullTimeString renders an optional instant for sqlite: the zero time is
// SQL NULL, which is what the lifetime CHECK pairs with `indefinite`.
func nullTimeString(t time.Time) sql.NullString {
	if t.IsZero() {
		return sql.NullString{}
	}
	return nullString(encodeTime(t))
}
