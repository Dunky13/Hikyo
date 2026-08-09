package authn

import (
	"context"
	"fmt"
	"time"

	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// The grant surface (#55, permission-model ADR). It lives on the enumerated
// resolution surface for the same reason the session lifecycle does:
// authorize() reads the grant table to mint a proof, so a grant write cannot
// itself be gated behind one without a cycle. The authorization gate for
// these writes is the ordinary chokepoint operation the service calls first
// (grant.create / grant.revoke / ...); what happens here is the write.
//
// Every mutating method is named in lint.ResolutionSurfaceWriters, and every
// one takes the principal-row lock (lint.CheckGrantLock).

// GrantRow is one stored grant with its row id, so origins can be attached
// and the row revoked individually.
type GrantRow struct {
	ID    string
	Grant domain.Grant
}

// Origin is one origin holding a grant row alive.
type Origin struct {
	Kind    domain.OriginKind
	Subject string
}

// GrantLine is the membership surface's unit: one capability line for one
// principal at one scope, with its origin chips.
type GrantLine struct {
	GrantRow
	Principal domain.PrincipalID
	CreatedAt time.Time
	Origins   []Origin
}

// GrantRowsForPrincipal lists the principal's grants WITH their row ids. It
// is a separate name from Grants (which authorize() calls) so the grant
// surface's read is visible in the trusted-query registry as its own entry.
func (r *Resolver) GrantRowsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]GrantRow, error) {
	var out []GrantRow
	if r.sq != nil {
		rows, err := r.sq.ListGrantRowsForPrincipal(ctx, string(p))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
			if err != nil {
				return nil, err
			}
			out = append(out, GrantRow{ID: row.ID, Grant: g})
		}
		return out, nil
	}
	rows, err := r.pg.ListGrantRowsForPrincipal(ctx, string(p))
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		g, err := grantFrom(row.Capability, row.OrgID.String, row.ProjectID.String, row.EnvID.String)
		if err != nil {
			return nil, err
		}
		out = append(out, GrantRow{ID: row.ID, Grant: g})
	}
	return out, nil
}

// AddGrantOrigin attaches one origin to a grant row. Attaching an origin that
// already holds the row is the dedup case and is a no-op, not an error: the
// UNIQUE key makes the second attach a conflict, so the caller checks first
// (the same transaction and the same principal-row lock make that safe).
func (r *Resolver) AddGrantOrigin(ctx context.Context, id, grantID string, p domain.PrincipalID, o Origin, at time.Time) error {
	if !domain.IsMintableOrigin(o.Kind) {
		return fmt.Errorf("authn: origin kind %q is not mintable by the grant surface", o.Kind)
	}
	if o.Subject == "" {
		return fmt.Errorf("authn: origin %q carries no subject", o.Kind)
	}
	if err := r.LockPrincipalRow(ctx, p); err != nil {
		return err
	}
	if r.sq != nil {
		return r.sq.InsertGrantOrigin(ctx, sqlitegen.InsertGrantOriginParams{
			ID: id, GrantID: grantID, Kind: string(o.Kind), Subject: o.Subject,
			CreatedAt: encodeTime(at),
		})
	}
	return r.pg.InsertGrantOrigin(ctx, pggen.InsertGrantOriginParams{
		ID: id, GrantID: grantID, Kind: string(o.Kind), Subject: o.Subject,
		CreatedAt: pgTime(at),
	})
}

// ReleaseGrantOrigin releases one origin and reports whether it held the row.
func (r *Resolver) ReleaseGrantOrigin(ctx context.Context, grantID string, p domain.PrincipalID, o Origin) (bool, error) {
	if err := r.LockPrincipalRow(ctx, p); err != nil {
		return false, err
	}
	if r.sq != nil {
		n, err := r.sq.DeleteGrantOrigin(ctx, sqlitegen.DeleteGrantOriginParams{
			GrantID: grantID, Kind: string(o.Kind), Subject: o.Subject,
		})
		return n == 1, err
	}
	n, err := r.pg.DeleteGrantOrigin(ctx, pggen.DeleteGrantOriginParams{
		GrantID: grantID, Kind: string(o.Kind), Subject: o.Subject,
	})
	return n == 1, err
}

// GrantOriginCount reports how many origins still hold a grant row.
func (r *Resolver) GrantOriginCount(ctx context.Context, grantID string) (int64, error) {
	if r.sq != nil {
		return r.sq.CountGrantOrigins(ctx, grantID)
	}
	return r.pg.CountGrantOrigins(ctx, grantID)
}

// DeleteGrantRow removes the grant row once its last origin is released. The
// database refuses it while an origin still holds the row (RESTRICT FK), so
// this cannot silently orphan the invariant.
func (r *Resolver) DeleteGrantRow(ctx context.Context, grantID string, p domain.PrincipalID) (bool, error) {
	if err := r.LockPrincipalRow(ctx, p); err != nil {
		return false, err
	}
	if r.sq != nil {
		n, err := r.sq.DeleteGrantRow(ctx, grantID)
		return n == 1, err
	}
	n, err := r.pg.DeleteGrantRow(ctx, grantID)
	return n == 1, err
}

// GrantLinesInOrg lists every grant row scoped INSIDE one org, with origins.
// Instance-scope grants are deliberately absent: they reach into the org by
// inheritance but they are not membership of it, and showing them on an org's
// member list would invite revoking an instance operator from an org page.
// The org id is a plain string, not domain.OrgID: the proof-signature rule
// bans tenant-typed values from store signatures, and the resolution surface
// is outside the analyzer's Repos/ReadRepos walk — so it holds the rule by
// construction rather than by being caught.
func (r *Resolver) GrantLinesInOrg(ctx context.Context, org string) ([]GrantLine, error) {
	if r.sq != nil {
		rows, err := r.sq.ListGrantsWithOriginsForOrg(ctx, nullString(org))
		if err != nil {
			return nil, err
		}
		lines := make([]rawGrantLine, 0, len(rows))
		for _, row := range rows {
			at, err := decodeTime(row.CreatedAt)
			if err != nil {
				return nil, err
			}
			lines = append(lines, rawGrantLine{
				id: row.ID, principal: row.PrincipalID, capability: row.Capability,
				org: row.OrgID.String, project: row.ProjectID.String, env: row.EnvID.String,
				at: at, kind: row.Kind, subject: row.Subject,
			})
		}
		return foldGrantLines(lines)
	}
	rows, err := r.pg.ListGrantsWithOriginsForOrg(ctx, pgText(org))
	if err != nil {
		return nil, err
	}
	lines := make([]rawGrantLine, 0, len(rows))
	for _, row := range rows {
		lines = append(lines, rawGrantLine{
			id: row.ID, principal: row.PrincipalID, capability: row.Capability,
			org: row.OrgID.String, project: row.ProjectID.String, env: row.EnvID.String,
			at: row.CreatedAt.Time, kind: row.Kind, subject: row.Subject,
		})
	}
	return foldGrantLines(lines)
}

// GrantLinesInProject lists the grant rows scoped inside ONE project, with
// origins. It is a separate query rather than a filter over the org's rows
// because a project member manager authorizes for one project: reading the
// org's and discarding the rest makes the work scale with sibling-project
// membership, which a caller can observe.
func (r *Resolver) GrantLinesInProject(ctx context.Context, org, project string) ([]GrantLine, error) {
	if r.sq != nil {
		rows, err := r.sq.ListGrantsWithOriginsForProject(ctx, sqlitegen.ListGrantsWithOriginsForProjectParams{
			OrgID: nullString(org), ProjectID: nullString(project),
		})
		if err != nil {
			return nil, err
		}
		lines := make([]rawGrantLine, 0, len(rows))
		for _, row := range rows {
			at, err := decodeTime(row.CreatedAt)
			if err != nil {
				return nil, err
			}
			lines = append(lines, rawGrantLine{
				id: row.ID, principal: row.PrincipalID, capability: row.Capability,
				org: row.OrgID.String, project: row.ProjectID.String, env: row.EnvID.String,
				at: at, kind: row.Kind, subject: row.Subject,
			})
		}
		return foldGrantLines(lines)
	}
	rows, err := r.pg.ListGrantsWithOriginsForProject(ctx, pggen.ListGrantsWithOriginsForProjectParams{
		OrgID: pgText(org), ProjectID: pgText(project),
	})
	if err != nil {
		return nil, err
	}
	lines := make([]rawGrantLine, 0, len(rows))
	for _, row := range rows {
		lines = append(lines, rawGrantLine{
			id: row.ID, principal: row.PrincipalID, capability: row.Capability,
			org: row.OrgID.String, project: row.ProjectID.String, env: row.EnvID.String,
			at: row.CreatedAt.Time, kind: row.Kind, subject: row.Subject,
		})
	}
	return foldGrantLines(lines)
}

// GrantLinesAtInstance lists the instance-scope grant rows with origins.
func (r *Resolver) GrantLinesAtInstance(ctx context.Context) ([]GrantLine, error) {
	if r.sq != nil {
		rows, err := r.sq.ListGrantsWithOriginsAtInstance(ctx)
		if err != nil {
			return nil, err
		}
		lines := make([]rawGrantLine, 0, len(rows))
		for _, row := range rows {
			at, err := decodeTime(row.CreatedAt)
			if err != nil {
				return nil, err
			}
			lines = append(lines, rawGrantLine{
				id: row.ID, principal: row.PrincipalID, capability: row.Capability,
				at: at, kind: row.Kind, subject: row.Subject,
			})
		}
		return foldGrantLines(lines)
	}
	rows, err := r.pg.ListGrantsWithOriginsAtInstance(ctx)
	if err != nil {
		return nil, err
	}
	lines := make([]rawGrantLine, 0, len(rows))
	for _, row := range rows {
		lines = append(lines, rawGrantLine{
			id: row.ID, principal: row.PrincipalID, capability: row.Capability,
			at: row.CreatedAt.Time, kind: row.Kind, subject: row.Subject,
		})
	}
	return foldGrantLines(lines)
}

// rawGrantLine is one (grant, origin) join row before folding.
type rawGrantLine struct {
	id, principal, capability string
	org, project, env         string
	at                        time.Time
	kind, subject             string
}

// foldGrantLines collapses the join back into one line per grant row with its
// origin chips. The query orders by grant id, so the fold is a single pass.
func foldGrantLines(rows []rawGrantLine) ([]GrantLine, error) {
	var out []GrantLine
	index := map[string]int{}
	for _, row := range rows {
		i, seen := index[row.id]
		if !seen {
			g, err := grantFrom(row.capability, row.org, row.project, row.env)
			if err != nil {
				return nil, err
			}
			out = append(out, GrantLine{
				GrantRow:  GrantRow{ID: row.id, Grant: g},
				Principal: domain.PrincipalID(row.principal),
				CreatedAt: row.at,
			})
			i = len(out) - 1
			index[row.id] = i
		}
		out[i].Origins = append(out[i].Origins, Origin{
			Kind: domain.OriginKind(row.kind), Subject: row.subject,
		})
	}
	return out, nil
}

// ManageMembersHolders lists the principals holding `manage-members` at or
// above the given org — the lockout invariant's census. A zero org asks the
// instance-scope question.
func (r *Resolver) ManageMembersHolders(ctx context.Context, org string) ([]domain.PrincipalID, error) {
	var ids []string
	var err error
	switch {
	case org == "" && r.sq != nil:
		ids, err = r.sq.ListManageMembersHoldersAtInstance(ctx)
	case org == "":
		ids, err = r.pg.ListManageMembersHoldersAtInstance(ctx)
	case r.sq != nil:
		ids, err = r.sq.ListManageMembersHoldersForOrg(ctx, nullString(org))
	default:
		ids, err = r.pg.ListManageMembersHoldersForOrg(ctx, pgText(org))
	}
	if err != nil {
		return nil, err
	}
	out := make([]domain.PrincipalID, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.PrincipalID(id))
	}
	return out, nil
}

// EnvironmentSettings is the per-environment half of `project-settings`.
type EnvironmentSettings struct {
	Protected bool
	// Window is the environment's own reauthentication window. HasWindow
	// false means the environment inherits the instance default — a stored
	// copy of that default would freeze it at creation time.
	HasWindow bool
	Window    time.Duration
}

// EnvironmentReauthSettings reads an environment's protection state and
// window during resolution, before any operation proof exists — the reveal
// guard runs beside session resolution, not inside a tenant operation.
func (r *Resolver) EnvironmentReauthSettings(ctx context.Context, envID string) (EnvironmentSettings, error) {
	if r.sq != nil {
		row, err := r.sq.EnvironmentReauthSettings(ctx, envID)
		if err != nil {
			return EnvironmentSettings{}, notFoundOr(err)
		}
		return EnvironmentSettings{
			Protected: row.Protected == 1,
			HasWindow: row.ReauthWindowSeconds.Valid,
			Window:    time.Duration(row.ReauthWindowSeconds.Int64) * time.Second,
		}, nil
	}
	row, err := r.pg.EnvironmentReauthSettings(ctx, envID)
	if err != nil {
		return EnvironmentSettings{}, notFoundOr(err)
	}
	return EnvironmentSettings{
		Protected: row.Protected,
		HasWindow: row.ReauthWindowSeconds.Valid,
		Window:    time.Duration(row.ReauthWindowSeconds.Int64) * time.Second,
	}, nil
}

// PrincipalClass resolves a principal's class for the normative machine
// allowlists. A human answers domain.ClassHuman; a machine answers its stored
// class, and an unclassified machine answers the empty class, which every
// allowlist refuses — fail-closed, never widened by omission.
func (r *Resolver) PrincipalClass(ctx context.Context, p domain.PrincipalID) (domain.PrincipalClass, error) {
	var kind, class string
	if r.sq != nil {
		row, err := r.sq.GetPrincipalClass(ctx, string(p))
		if err != nil {
			return "", notFoundOr(err)
		}
		kind, class = row.Kind, row.Class.String
	} else {
		row, err := r.pg.GetPrincipalClass(ctx, string(p))
		if err != nil {
			return "", notFoundOr(err)
		}
		kind, class = row.Kind, row.Class.String
	}
	if kind == "human" {
		return domain.ClassHuman, nil
	}
	return domain.PrincipalClass(class), nil
}

// GrantOriginsFor lists the origins holding one grant row. It is the dedup
// read (does this grantor's origin already hold it?) and the revocation read
// (which origins may this surface release?).
func (r *Resolver) GrantOriginsFor(ctx context.Context, grantID string) ([]Origin, error) {
	var out []Origin
	if r.sq != nil {
		rows, err := r.sq.ListGrantOriginsForGrant(ctx, grantID)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, Origin{Kind: domain.OriginKind(row.Kind), Subject: row.Subject})
		}
		return out, nil
	}
	rows, err := r.pg.ListGrantOriginsForGrant(ctx, grantID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, Origin{Kind: domain.OriginKind(row.Kind), Subject: row.Subject})
	}
	return out, nil
}
