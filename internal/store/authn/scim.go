package authn

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// SCIM provisioning, resolution-surface half (#73).
//
// Two things live here and neither can hold a proof:
//
//   - the provisioning connection's credentials. A SCIM wire request presents
//     one BEFORE any operation is authorized — the credential is what decides
//     who the caller is, and the proof is what that answer produces. Same
//     circularity as the session lifecycle.
//   - the machine principal itself, created with the binding and retired with
//     it by §6's state machine, and the grant-origin read the §2.4 release
//     algorithm walks.
//
// Every mutating function below is named in lint.ResolutionSurfaceWriters.

// SCIMCredential is one stored provisioning credential. The plaintext exists
// exactly once, at mint; only the verifier is persisted.
type SCIMCredential struct {
	ID              string
	BindingID       string
	PrincipalID     domain.PrincipalID
	CredentialEpoch int64
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       time.Time
	LastUsedAt      time.Time
}

// Live reports whether the credential may authenticate a request at `now`:
// not revoked, and either indefinite or not yet past its ceiling. Revocation
// bites at the NEXT request, which is what this predicate is.
func (c SCIMCredential) Live(now time.Time) bool {
	if !c.RevokedAt.IsZero() {
		return false
	}
	if !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt) {
		return false
	}
	return true
}

// SCIMCredentialByVerifier resolves a presented value. This is the ONE
// credential operation that belongs on the proof-free surface, and the reason
// is the same circularity the session lifecycle has: a SCIM request presents
// the credential BEFORE any operation is authorized, so there is no proof to
// bind the lookup to.
//
// Everything else a credential surface does — mint, list, show, revoke,
// delete — runs AFTER `manage-members(org)` has been proved and therefore
// lives on the proof-carrying repository, where the org predicate comes from
// the proof and a credential id from another org matches no row. Exposing
// those here with caller-controlled ids would put the whole administrative
// surface one forgotten Go check away from cross-org access.
//
// Nothing inside the presented value is trusted: binding, principal, epoch and
// expiry all come from this row.
func (r *Resolver) SCIMCredentialByVerifier(ctx context.Context, presented []byte) (SCIMCredential, error) {
	if r.sq != nil {
		row, err := r.sq.GetSCIMCredentialByVerifier(ctx, presented)
		if err != nil {
			return SCIMCredential{}, notFoundOr(err)
		}
		if subtle.ConstantTimeCompare(row.Verifier, presented) != 1 {
			return SCIMCredential{}, domain.ErrNotFound
		}
		return sqliteSCIMCredential(sqlitegen.GetSCIMCredentialRow{
			ID: row.ID, BindingID: row.BindingID, PrincipalID: row.PrincipalID,
			CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt,
			ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
		})
	}
	row, err := r.pg.GetSCIMCredentialByVerifier(ctx, presented)
	if err != nil {
		return SCIMCredential{}, notFoundOr(err)
	}
	if subtle.ConstantTimeCompare(row.Verifier, presented) != 1 {
		return SCIMCredential{}, domain.ErrNotFound
	}
	return pgSCIMCredential(pggen.GetSCIMCredentialRow{
		ID: row.ID, BindingID: row.BindingID, PrincipalID: row.PrincipalID,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt, RevokedAt: row.RevokedAt, LastUsedAt: row.LastUsedAt,
	}), nil
}

// TouchSCIMCredential records last use. It runs inside authentication, before
// any proof exists, and its id comes from the verifier lookup above rather than
// from the caller.
func (r *Resolver) TouchSCIMCredential(ctx context.Context, id string, at time.Time) error {
	if r.sq != nil {
		return r.sq.TouchSCIMCredential(ctx, sqlitegen.TouchSCIMCredentialParams{
			LastUsedAt: nullTime(at), ID: id,
		})
	}
	return r.pg.TouchSCIMCredential(ctx, pggen.TouchSCIMCredentialParams{
		LastUsedAt: pgNullTime(at), ID: id,
	})
}

// CreateProvisioningPrincipal creates the machine principal a binding's
// provisioning connection is, carrying its class at INSERT. A two-step
// create-then-classify would leave a window in which the connection is an
// unclassified machine principal, which fails closed at every allowlist path.
// The class is HARDCODED, not a parameter. This writer exists for exactly one
// principal class; taking the class from a caller would make it a general
// machine-principal factory on the proof-free surface, which is a different and
// much larger thing than "create the connection this binding needs".
func (r *Resolver) CreateProvisioningPrincipal(ctx context.Context, id domain.PrincipalID, at time.Time) error {
	class := string(domain.ClassProvisioning)
	if r.sq != nil {
		return r.sq.InsertMachinePrincipal(ctx, sqlitegen.InsertMachinePrincipalParams{
			ID: string(id), Class: nullString(class), CreatedAt: encodeTime(at),
		})
	}
	return r.pg.InsertMachinePrincipal(ctx, pggen.InsertMachinePrincipalParams{
		ID: string(id), Class: pgNullString(class), CreatedAt: pgTime(at),
	})
}

// GrantOriginRow is one (grant row, origin) pair: what the §2.4 release
// algorithm walks.
type GrantOriginRow struct {
	GrantRow
	Origin Origin
}

// GrantOriginsForPrincipal returns every origin holding every grant row of one
// principal, read at one instant. The release algorithm decides per origin and
// then counts what remains per row, so seeing the two tables at different
// instants would let a row be judged against origins that had already moved.
func (r *Resolver) GrantOriginsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]GrantOriginRow, error) {
	out := []GrantOriginRow{}
	if r.sq != nil {
		rows, err := r.sq.ListGrantOriginsForPrincipal(ctx, string(p))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
			if err != nil {
				return nil, err
			}
			out = append(out, GrantOriginRow{
				GrantRow: GrantRow{ID: row.ID, Grant: g},
				Origin:   Origin{Kind: domain.OriginKind(row.Kind), Subject: row.Subject},
			})
		}
		return out, nil
	}
	rows, err := r.pg.ListGrantOriginsForPrincipal(ctx, string(p))
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
		if err != nil {
			return nil, err
		}
		out = append(out, GrantOriginRow{
			GrantRow: GrantRow{ID: row.ID, Grant: g},
			Origin:   Origin{Kind: domain.OriginKind(row.Kind), Subject: row.Subject},
		})
	}
	return out, nil
}

// nullTime and pgNullTime encode "absent" for the three optional timestamps a
// credential carries. The zero time.Time is the absent value on the Go side —
// an indefinite credential has no ceiling, a live one has no revocation, an
// unused one has no last use — and collapsing any of them onto a real instant
// would make "never revoked" indistinguishable from "revoked at the epoch".
func nullTime(t time.Time) sql.NullString {
	if t.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: encodeTime(t), Valid: true}
}

func pgNullTime(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgTime(t)
}

func pgNullString(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func sqliteSCIMCredential(row sqlitegen.GetSCIMCredentialRow) (SCIMCredential, error) {
	created, err := decodeTime(row.CreatedAt)
	if err != nil {
		return SCIMCredential{}, err
	}
	out := SCIMCredential{
		ID: row.ID, BindingID: row.BindingID,
		PrincipalID:     domain.PrincipalID(row.PrincipalID),
		CredentialEpoch: row.CredentialEpoch,
		CreatedAt:       created,
	}
	for _, f := range []struct {
		src sql.NullString
		dst *time.Time
	}{
		{row.ExpiresAt, &out.ExpiresAt},
		{row.RevokedAt, &out.RevokedAt},
		{row.LastUsedAt, &out.LastUsedAt},
	} {
		if !f.src.Valid {
			continue
		}
		t, err := decodeTime(f.src.String)
		if err != nil {
			return SCIMCredential{}, err
		}
		*f.dst = t
	}
	return out, nil
}

func pgSCIMCredential(row pggen.GetSCIMCredentialRow) SCIMCredential {
	out := SCIMCredential{
		ID: row.ID, BindingID: row.BindingID,
		PrincipalID:     domain.PrincipalID(row.PrincipalID),
		CredentialEpoch: row.CredentialEpoch,
		CreatedAt:       row.CreatedAt.Time.UTC(),
	}
	if row.ExpiresAt.Valid {
		out.ExpiresAt = row.ExpiresAt.Time.UTC()
	}
	if row.RevokedAt.Valid {
		out.RevokedAt = row.RevokedAt.Time.UTC()
	}
	if row.LastUsedAt.Valid {
		out.LastUsedAt = row.LastUsedAt.Time.UTC()
	}
	return out
}

// LockoutRetention is one row held alive by a `lockout-retention` origin.
type LockoutRetention struct {
	GrantRow
	Principal domain.PrincipalID
	// Binding and Cause are what the origin's `subject` column carries for this
	// kind. The binding is recorded rather than joined because a retention
	// origin outlives its binding (§6 step 2).
	Binding string
	Cause   domain.SCIMCause
}

// LockoutRetentionsInOrg lists the retention origins of ONE org. An org-scope
// `manage-members` grant cures that org and nothing else, so this is the query
// that sweep uses: loading and locking every retention in the instance to then
// discard all but one org's is tenant-triggerable O(instance) work and a
// cross-tenant timing signal, both for a set the caller may not observe.
func (r *Resolver) LockoutRetentionsInOrg(ctx context.Context, org domain.OrgID) ([]LockoutRetention, error) {
	out := []LockoutRetention{}
	id := sql.NullString{String: string(org), Valid: org != ""}
	if r.sq != nil {
		rows, err := r.sq.ListLockoutRetentionOriginsInOrg(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			ret, err := retentionFrom(row.ID, row.PrincipalID, row.Capability,
				row.OrgID.String, row.ProjectID.String, row.EnvID.String, row.Subject)
			if err != nil {
				return nil, err
			}
			out = append(out, ret)
		}
		return out, nil
	}
	rows, err := r.pg.ListLockoutRetentionOriginsInOrg(ctx, pgNullString(string(org)))
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		ret, err := retentionFrom(row.ID, row.PrincipalID, row.Capability,
			row.OrgID.String, row.ProjectID.String, row.EnvID.String, row.Subject)
		if err != nil {
			return nil, err
		}
		out = append(out, ret)
	}
	return out, nil
}

// retentionFrom builds one retention from a row of either dialect, so the four
// readers cannot drift on the parse or the fail-closed refusal.
func retentionFrom(id, principal, capability, org, project, env, subject string) (LockoutRetention, error) {
	g, err := grantFrom(capability, org, project, env)
	if err != nil {
		return LockoutRetention{}, err
	}
	key, ok := domain.ParseSCIMRetentionSubject(subject)
	if !ok {
		return LockoutRetention{}, fmt.Errorf(
			"authn: grant %s carries an unparseable lockout-retention subject %q", id, subject)
	}
	return LockoutRetention{
		GrantRow:  GrantRow{ID: id, Grant: g},
		Principal: domain.PrincipalID(principal),
		Binding:   key.Binding, Cause: key.Cause,
	}, nil
}

// LockoutRetentions lists every retention origin in the instance. Only an
// INSTANCE-scope `manage-members` grant needs this unbounded walk, because only
// it cures every org at once (§2.4's "the moment a transaction leaves the org
// with another manage-members holder"). Every org-scope cure uses
// LockoutRetentionsInOrg.
func (r *Resolver) LockoutRetentions(ctx context.Context) ([]LockoutRetention, error) {
	out := []LockoutRetention{}
	if r.sq != nil {
		rows, err := r.sq.ListLockoutRetentionOrigins(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
			if err != nil {
				return nil, err
			}
			key, ok := domain.ParseSCIMRetentionSubject(row.Subject)
			if !ok {
				return nil, fmt.Errorf(
					"authn: grant %s carries an unparseable lockout-retention subject %q", row.ID, row.Subject)
			}
			out = append(out, LockoutRetention{
				GrantRow:  GrantRow{ID: row.ID, Grant: g},
				Principal: domain.PrincipalID(row.PrincipalID),
				Binding:   key.Binding, Cause: key.Cause,
			})
		}
		return out, nil
	}
	rows, err := r.pg.ListLockoutRetentionOrigins(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
		if err != nil {
			return nil, err
		}
		key, ok := domain.ParseSCIMRetentionSubject(row.Subject)
		if !ok {
			return nil, fmt.Errorf(
				"authn: grant %s carries an unparseable lockout-retention subject %q", row.ID, row.Subject)
		}
		out = append(out, LockoutRetention{
			GrantRow:  GrantRow{ID: row.ID, Grant: g},
			Principal: domain.PrincipalID(row.PrincipalID),
			Binding:   key.Binding, Cause: key.Cause,
		})
	}
	return out, nil
}
