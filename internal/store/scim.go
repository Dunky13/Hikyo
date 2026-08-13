package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// The SCIM repository (#73, scim-provisioning ADR §7-8).
//
// Everything a binding owns — the binding row, its mapping table, its
// provisioned directory and its attention states — is ORG TENANT DATA, so it
// rides this proof-carrying surface: `authorize()` mints an operation- and
// transaction-bound proof for `scim-provision(org)` (wire) or
// `manage-members(org)` (administration), and every statement below binds
// `org_id` from that proof's resolved chain. A caller argument cannot reach a
// chain predicate here any more than it can in repos.go.
//
// One structural difference from repos.go, stated because it is visible: the
// two dialects share ONE implementation struct with two query handles (exactly
// as internal/store/authn's Resolver does) rather than one struct per engine.
// The SCIM surface is roughly forty methods; two parallel structs would be
// eighty method bodies that must never drift, and the drift is precisely what
// the shared body removes. The proof verification, which is the security
// property, happens once per method either way.

// SCIMBinding is one stored binding (ADR §1).
type SCIMBinding struct {
	ID           string
	OrgID        string
	ProviderKind string
	// ProviderID is the provider's immutable ROW id. The slug beside it is a
	// mutable address kept for rendering; liveness, the audit trail's
	// `provider_ref` and the identity link's recorded provider all resolve by
	// THIS, so a provider deleted and recreated under the same slug is a
	// different provider — which it is.
	ProviderID               string
	ProviderSlug             string
	ProviderIssuer           string
	SubjectSource            string
	NameIDFormat             string
	NameIDQualifier          string
	NameIDQualifierPresent   bool
	NameIDSPQualifier        string
	NameIDSPQualifierPresent bool
	ConnectionPrincipalID    string
	LastContactAt            time.Time
	CreatedAt                time.Time
}

// NewSCIMBinding is the insert carrier. It deliberately has no OrgID: the
// chain column is bound from the proof.
type NewSCIMBinding struct {
	ID                       string
	ProviderKind             string
	ProviderID               string
	ProviderSlug             string
	ProviderIssuer           string
	SubjectSource            string
	NameIDFormat             string
	NameIDQualifier          string
	NameIDQualifierPresent   bool
	NameIDSPQualifier        string
	NameIDSPQualifierPresent bool
	ConnectionPrincipalID    string
	CreatedAt                time.Time
}

// SCIMMapping is one `(IdP group -> role template @ scope)` row (ADR §3).
type SCIMMapping struct {
	ID             string
	OrgID          string
	BindingID      string
	GroupID        string
	Template       string
	ScopeProjectID string
	ScopeEnvID     string
	Inert          bool
	CreatedAt      time.Time
}

// NewSCIMMapping is the mapping insert carrier.
type NewSCIMMapping struct {
	ID             string
	BindingID      string
	GroupID        string
	Template       string
	ScopeProjectID string
	ScopeEnvID     string
	CreatedAt      time.Time
}

// SCIMUser is one provisioned directory entry (ADR §5).
type SCIMUser struct {
	ID            string
	OrgID         string
	BindingID     string
	AccountID     string
	UserName      string
	UserNameLower string
	ExternalID    string
	Subject       string
	Active        bool
	Attributes    string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewSCIMUser is the user insert carrier.
type NewSCIMUser struct {
	ID            string
	BindingID     string
	AccountID     string
	UserName      string
	UserNameLower string
	ExternalID    string
	Subject       string
	Active        bool
	Attributes    string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SCIMUserUpdate is the mutable half of a user resource. `Subject` is absent
// on purpose: it is write-once per resource (ADR §5.1), so there is no
// statement here that could change it.
type SCIMUserUpdate struct {
	ID            string
	BindingID     string
	UserName      string
	UserNameLower string
	ExternalID    string
	Active        bool
	Attributes    string
	UpdatedAt     time.Time
}

// SCIMGroup is one provisioned group (ADR §6).
type SCIMGroup struct {
	ID               string
	OrgID            string
	BindingID        string
	DisplayName      string
	DisplayNameLower string
	ExternalID       string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// NewSCIMGroup is the group insert carrier.
type NewSCIMGroup struct {
	ID               string
	BindingID        string
	DisplayName      string
	DisplayNameLower string
	ExternalID       string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// SCIMGroupUpdate is the mutable half of a group resource.
type SCIMGroupUpdate struct {
	ID               string
	BindingID        string
	DisplayName      string
	DisplayNameLower string
	ExternalID       string
	UpdatedAt        time.Time
}

// SCIMGroupMember is one member reference.
type SCIMGroupMember struct {
	ID        string
	BindingID string
	GroupID   string
	UserID    string
	CreatedAt time.Time
}

// SCIMAttentionRow is one stored attention state (ADR §9). Stored, not
// derived: each state is audited on entry AND exit, and a state computed at
// read time cannot emit a transition.
type SCIMAttentionRow struct {
	ID         string
	BindingID  string
	State      string
	SubjectRef string
	Cause      string
	EnteredAt  time.Time
}

// SCIMReader is the read half of the SCIM surface.
type SCIMReader interface {
	Binding(ctx context.Context, p authz.Proof, id string) (SCIMBinding, error)
	Bindings(ctx context.Context, p authz.Proof) ([]SCIMBinding, error)

	Mapping(ctx context.Context, p authz.Proof, id string) (SCIMMapping, error)
	Mappings(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMMapping, error)
	MappingsForGroup(ctx context.Context, p authz.Proof, bindingID, groupID string) ([]SCIMMapping, error)

	User(ctx context.Context, p authz.Proof, bindingID, id string) (SCIMUser, error)
	UserByUserName(ctx context.Context, p authz.Proof, bindingID, folded string) (SCIMUser, error)
	UsersByExternalID(ctx context.Context, p authz.Proof, bindingID, externalID string) ([]SCIMUser, error)
	UserBySubject(ctx context.Context, p authz.Proof, bindingID, subject string) (SCIMUser, error)
	UserByAccount(ctx context.Context, p authz.Proof, bindingID, accountID string) (SCIMUser, error)
	Users(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMUser, error)
	// PageUsers and PageGroups are the WIRE's reads: bounded in SQL, with a
	// separate count, so a page costs a page rather than the whole directory.
	PageUsers(ctx context.Context, p authz.Proof, bindingID string, limit, offset int64) ([]SCIMUser, int64, error)

	Group(ctx context.Context, p authz.Proof, bindingID, id string) (SCIMGroup, error)
	GroupsByDisplayName(ctx context.Context, p authz.Proof, bindingID, folded string) ([]SCIMGroup, error)
	GroupsByExternalID(ctx context.Context, p authz.Proof, bindingID, externalID string) ([]SCIMGroup, error)
	Groups(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMGroup, error)
	PageGroups(ctx context.Context, p authz.Proof, bindingID string, limit, offset int64) ([]SCIMGroup, int64, error)

	// Every membership method carries the bindingID. Without it an org-scoped
	// proof for one binding could address group and user ids belonging to
	// another binding in the same org: the proof binds the ORG, and the org is
	// not the tenancy here — the binding is.
	GroupMembers(ctx context.Context, p authz.Proof, bindingID, groupID string) ([]SCIMGroupMember, error)
	MembershipsForUser(ctx context.Context, p authz.Proof, bindingID, userID string) ([]SCIMGroupMember, error)

	Attention(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMAttentionRow, error)
}

// SCIMCredential is one provisioning credential as the ADMINISTRATION surface
// sees it. Token material is absent because it was never stored.
type SCIMCredential struct {
	ID          string
	BindingID   string
	PrincipalID string
	// CredentialEpoch is the instance epoch this credential was minted under.
	// A row whose epoch is behind the instance's is a credential a RESTORE
	// brought back: permanently dead by presentation (§9.1), and the only
	// observable trace of the restore this tree has.
	CredentialEpoch int64
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       time.Time
	LastUsedAt      time.Time
}

// NewSCIMCredential is the mint carrier. It has no OrgID: the chain column is
// bound from the proof.
type NewSCIMCredential struct {
	ID              string
	BindingID       string
	PrincipalID     string
	Verifier        []byte
	CredentialEpoch int64
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// SCIMRepo is the full SCIM surface bound to one write transaction.
type SCIMRepo interface {
	SCIMReader

	// Credential administration. It lives HERE and not on the proof-free
	// resolver — where only the pre-auth verifier lookup belongs — because
	// every one of these runs after `manage-members(org)` is proved, and the
	// org predicate must come from that proof rather than from a Go check
	// beside a caller-controlled id.
	CreateCredential(ctx context.Context, p authz.Proof, c NewSCIMCredential) error
	Credential(ctx context.Context, p authz.Proof, bindingID, id string) (SCIMCredential, error)
	Credentials(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMCredential, error)
	RevokeCredential(ctx context.Context, p authz.Proof, bindingID, id string, at time.Time) (bool, error)
	RevokeCredentialsForBinding(ctx context.Context, p authz.Proof, bindingID string, at time.Time) (int64, error)
	DeleteCredentialsForBinding(ctx context.Context, p authz.Proof, bindingID string) error

	// LockBinding is the FIRST statement of every mutation on a binding's
	// subtree (ADR §9: per-binding writes serialize). It is a no-op CAS write,
	// not a read — a SELECT takes no row lock — following this repo's own
	// GuardProviderForMint precedent.
	LockBinding(ctx context.Context, p authz.Proof, id string) error
	CreateBinding(ctx context.Context, p authz.Proof, b NewSCIMBinding) error
	TouchBinding(ctx context.Context, p authz.Proof, id string, at time.Time) error
	DeleteBinding(ctx context.Context, p authz.Proof, id string) error
	// RetireConnectionPrincipal removes an ORPHANED provisioning connection
	// under a proof; a connection any binding still owns is unmatched.
	RetireConnectionPrincipal(ctx context.Context, p authz.Proof, principal domain.PrincipalID) (bool, error)

	CreateMapping(ctx context.Context, p authz.Proof, m NewSCIMMapping) error
	SetMappingInert(ctx context.Context, p authz.Proof, bindingID, groupID string, inert bool) (int64, error)
	UpdateMappingTemplate(ctx context.Context, p authz.Proof, id, template string) error
	DeleteMapping(ctx context.Context, p authz.Proof, id string) error
	DeleteMappingsForBinding(ctx context.Context, p authz.Proof, bindingID string) error

	CreateUser(ctx context.Context, p authz.Proof, u NewSCIMUser) error
	UpdateUser(ctx context.Context, p authz.Proof, u SCIMUserUpdate) error
	DeleteUser(ctx context.Context, p authz.Proof, bindingID, id string) error
	DeleteUsersForBinding(ctx context.Context, p authz.Proof, bindingID string) error

	CreateGroup(ctx context.Context, p authz.Proof, g NewSCIMGroup) error
	UpdateGroup(ctx context.Context, p authz.Proof, g SCIMGroupUpdate) error
	DeleteGroup(ctx context.Context, p authz.Proof, bindingID, id string) error
	DeleteGroupsForBinding(ctx context.Context, p authz.Proof, bindingID string) error

	AddGroupMember(ctx context.Context, p authz.Proof, m SCIMGroupMember) error
	RemoveGroupMember(ctx context.Context, p authz.Proof, bindingID, groupID, userID string) error
	ClearGroupMembers(ctx context.Context, p authz.Proof, bindingID, groupID string) error
	RemoveMembershipsForUser(ctx context.Context, p authz.Proof, bindingID, userID string) error
	DeleteGroupMembersForBinding(ctx context.Context, p authz.Proof, bindingID string) error

	EnterAttention(ctx context.Context, p authz.Proof, a SCIMAttentionRow) error
	ClearAttention(ctx context.Context, p authz.Proof, bindingID, state, subjectRef string) (int64, error)
	DeleteAttentionForBinding(ctx context.Context, p authz.Proof, bindingID string) error
}

type scimRepo struct {
	sq  *sqlitegen.Queries
	pg  *pggen.Queries
	tok *authz.TxToken
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

func (r scimRepo) LockBinding(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMLockBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.LockSCIMBinding(ctx, sqlitegen.LockSCIMBindingParams{
			OrgID: string(chain.Org), ID: id, // chain column: proof-bound
		}))
	}
	return affected(r.pg.LockSCIMBinding(ctx, pggen.LockSCIMBindingParams{
		ChainOrgID: string(chain.Org), ID: id, // chain column: proof-bound
	}))
}

func (r scimRepo) CreateBinding(ctx context.Context, p authz.Proof, b NewSCIMBinding) error {
	chain, err := authz.Verify(p, authz.StoreSCIMCreateBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.CreateSCIMBinding(ctx, sqlitegen.CreateSCIMBindingParams{
			ID:                       b.ID,
			OrgID:                    string(chain.Org), // chain column: proof-bound
			ProviderKind:             b.ProviderKind,
			ProviderID:               b.ProviderID,
			ProviderSlug:             b.ProviderSlug,
			ProviderIssuer:           b.ProviderIssuer,
			SubjectSource:            b.SubjectSource,
			NameidFormat:             b.NameIDFormat,
			NameidQualifier:          b.NameIDQualifier,
			NameidQualifierPresent:   boolInt(b.NameIDQualifierPresent),
			NameidSpQualifier:        b.NameIDSPQualifier,
			NameidSpQualifierPresent: boolInt(b.NameIDSPQualifierPresent),
			ConnectionPrincipalID:    b.ConnectionPrincipalID,
			CreatedAt:                CanonTime(b.CreatedAt).Format(timeFormat),
		}))
	}
	return constraint(r.pg.CreateSCIMBinding(ctx, pggen.CreateSCIMBindingParams{
		ID:                       b.ID,
		ChainOrgID:               string(chain.Org), // chain column: proof-bound
		ProviderKind:             b.ProviderKind,
		ProviderID:               b.ProviderID,
		ProviderSlug:             b.ProviderSlug,
		ProviderIssuer:           b.ProviderIssuer,
		SubjectSource:            b.SubjectSource,
		NameidFormat:             b.NameIDFormat,
		NameidQualifier:          b.NameIDQualifier,
		NameidQualifierPresent:   b.NameIDQualifierPresent,
		NameidSpQualifier:        b.NameIDSPQualifier,
		NameidSpQualifierPresent: b.NameIDSPQualifierPresent,
		ConnectionPrincipalID:    b.ConnectionPrincipalID,
		CreatedAt:                pgtype.Timestamptz{Time: CanonTime(b.CreatedAt), Valid: true},
	}))
}

func (r scimRepo) Binding(ctx context.Context, p authz.Proof, id string) (SCIMBinding, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMBinding, r.tok)
	if err != nil {
		return SCIMBinding{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMBinding(ctx, sqlitegen.GetSCIMBindingParams{
			OrgID: string(chain.Org), ID: id, // chain column: proof-bound
		})
		if errors.Is(err, sql.ErrNoRows) {
			return SCIMBinding{}, ErrNotFound
		}
		if err != nil {
			return SCIMBinding{}, err
		}
		return sqliteBinding(row)
	}
	row, err := r.pg.GetSCIMBinding(ctx, pggen.GetSCIMBindingParams{
		ChainOrgID: string(chain.Org), ID: id, // chain column: proof-bound
	})
	if noRows(err) {
		return SCIMBinding{}, ErrNotFound
	}
	if err != nil {
		return SCIMBinding{}, err
	}
	return pgBinding(row), nil
}

func (r scimRepo) Bindings(ctx context.Context, p authz.Proof) ([]SCIMBinding, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMBindings, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMBinding{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMBindings(ctx, string(chain.Org)) // chain column: proof-bound
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			b, err := sqliteBinding(row)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMBindings(ctx, string(chain.Org)) // chain column: proof-bound
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgBinding(row))
	}
	return out, nil
}

func (r scimRepo) TouchBinding(ctx context.Context, p authz.Proof, id string, at time.Time) error {
	chain, err := authz.Verify(p, authz.StoreSCIMTouchBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.TouchSCIMBinding(ctx, sqlitegen.TouchSCIMBindingParams{
			LastContactAt: sql.NullString{String: CanonTime(at).Format(timeFormat), Valid: true},
			OrgID:         string(chain.Org), // chain column: proof-bound
			ID:            id,
		}))
	}
	return affected(r.pg.TouchSCIMBinding(ctx, pggen.TouchSCIMBindingParams{
		LastContactAt: pgtype.Timestamptz{Time: CanonTime(at), Valid: true},
		ChainOrgID:    string(chain.Org), // chain column: proof-bound
		ID:            id,
	}))
}

// RetireConnectionPrincipal is §6 step (3). It moved off the proof-free
// resolution surface, where a caller-controlled principal id was the entire
// predicate: it now takes a proof and can only remove a provisioning connection
// that NO binding still owns, addressed by an id the caller read from its own
// proof-scoped binding row. The statement runs after the binding row is gone,
// because that row references this principal.
func (r scimRepo) RetireConnectionPrincipal(ctx context.Context, p authz.Proof, principal domain.PrincipalID) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreSCIMRetireConnection, r.tok); err != nil {
		return false, err
	}
	if r.sq != nil {
		n, err := r.sq.RetireSCIMConnectionPrincipal(ctx, string(principal))
		return n == 1, err
	}
	n, err := r.pg.RetireSCIMConnectionPrincipal(ctx, string(principal))
	return n == 1, err
}

func (r scimRepo) DeleteBinding(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.DeleteSCIMBinding(ctx, sqlitegen.DeleteSCIMBindingParams{
			OrgID: string(chain.Org), ID: id, // chain column: proof-bound
		}))
	}
	return affected(r.pg.DeleteSCIMBinding(ctx, pggen.DeleteSCIMBindingParams{
		ChainOrgID: string(chain.Org), ID: id, // chain column: proof-bound
	}))
}

// ---------------------------------------------------------------------------
// Mappings
// ---------------------------------------------------------------------------

func (r scimRepo) CreateMapping(ctx context.Context, p authz.Proof, m NewSCIMMapping) error {
	chain, err := authz.Verify(p, authz.StoreSCIMCreateMapping, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.CreateSCIMMapping(ctx, sqlitegen.CreateSCIMMappingParams{
			ID:             m.ID,
			OrgID:          string(chain.Org), // chain column: proof-bound
			BindingID:      m.BindingID,
			GroupID:        m.GroupID,
			Template:       m.Template,
			ScopeProjectID: m.ScopeProjectID,
			ScopeEnvID:     m.ScopeEnvID,
			Inert:          0,
			CreatedAt:      CanonTime(m.CreatedAt).Format(timeFormat),
		}))
	}
	return constraint(r.pg.CreateSCIMMapping(ctx, pggen.CreateSCIMMappingParams{
		ID:             m.ID,
		ChainOrgID:     string(chain.Org), // chain column: proof-bound
		BindingID:      m.BindingID,
		GroupID:        m.GroupID,
		Template:       m.Template,
		ScopeProjectID: m.ScopeProjectID,
		ScopeEnvID:     m.ScopeEnvID,
		Inert:          false,
		CreatedAt:      pgtype.Timestamptz{Time: CanonTime(m.CreatedAt), Valid: true},
	}))
}

func (r scimRepo) Mapping(ctx context.Context, p authz.Proof, id string) (SCIMMapping, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMMapping, r.tok)
	if err != nil {
		return SCIMMapping{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMMapping(ctx, sqlitegen.GetSCIMMappingParams{
			OrgID: string(chain.Org), ID: id, // chain column: proof-bound
		})
		if errors.Is(err, sql.ErrNoRows) {
			return SCIMMapping{}, ErrNotFound
		}
		if err != nil {
			return SCIMMapping{}, err
		}
		return sqliteMapping(row)
	}
	row, err := r.pg.GetSCIMMapping(ctx, pggen.GetSCIMMappingParams{
		ChainOrgID: string(chain.Org), ID: id, // chain column: proof-bound
	})
	if noRows(err) {
		return SCIMMapping{}, ErrNotFound
	}
	if err != nil {
		return SCIMMapping{}, err
	}
	return pgMapping(row), nil
}

func (r scimRepo) Mappings(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMMapping, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMMappings, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMMapping{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMMappings(ctx, sqlitegen.ListSCIMMappingsParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			m, err := sqliteMapping(row)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMMappings(ctx, pggen.ListSCIMMappingsParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgMapping(row))
	}
	return out, nil
}

func (r scimRepo) MappingsForGroup(ctx context.Context, p authz.Proof, bindingID, groupID string) ([]SCIMMapping, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMMappingsForGroup, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMMapping{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMMappingsForGroup(ctx, sqlitegen.ListSCIMMappingsForGroupParams{
			OrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			m, err := sqliteMapping(row)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMMappingsForGroup(ctx, pggen.ListSCIMMappingsForGroupParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgMapping(row))
	}
	return out, nil
}

func (r scimRepo) SetMappingInert(ctx context.Context, p authz.Proof, bindingID, groupID string, inert bool) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMSetMappingInert, r.tok)
	if err != nil {
		return 0, err
	}
	if r.sq != nil {
		return r.sq.SetSCIMMappingInert(ctx, sqlitegen.SetSCIMMappingInertParams{
			Inert: boolInt(inert),
			OrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
		})
	}
	return r.pg.SetSCIMMappingInert(ctx, pggen.SetSCIMMappingInertParams{
		Inert:      inert,
		ChainOrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
	})
}

func (r scimRepo) UpdateMappingTemplate(ctx context.Context, p authz.Proof, id, template string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMUpdateMappingTemplate, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.UpdateSCIMMappingTemplate(ctx, sqlitegen.UpdateSCIMMappingTemplateParams{
			Template: template,
			OrgID:    string(chain.Org), ID: id, // chain column: proof-bound
		}))
	}
	return affected(r.pg.UpdateSCIMMappingTemplate(ctx, pggen.UpdateSCIMMappingTemplateParams{
		Template:   template,
		ChainOrgID: string(chain.Org), ID: id, // chain column: proof-bound
	}))
}

func (r scimRepo) DeleteMapping(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteMapping, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.DeleteSCIMMapping(ctx, sqlitegen.DeleteSCIMMappingParams{
			OrgID: string(chain.Org), ID: id, // chain column: proof-bound
		}))
	}
	return affected(r.pg.DeleteSCIMMapping(ctx, pggen.DeleteSCIMMappingParams{
		ChainOrgID: string(chain.Org), ID: id, // chain column: proof-bound
	}))
}

func (r scimRepo) DeleteMappingsForBinding(ctx context.Context, p authz.Proof, bindingID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteMappingsForBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMMappingsForBinding(ctx, sqlitegen.DeleteSCIMMappingsForBindingParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMMappingsForBinding(ctx, pggen.DeleteSCIMMappingsForBindingParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	return err
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func (r scimRepo) CreateUser(ctx context.Context, p authz.Proof, u NewSCIMUser) error {
	chain, err := authz.Verify(p, authz.StoreSCIMCreateUser, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.CreateSCIMUser(ctx, sqlitegen.CreateSCIMUserParams{
			ID:            u.ID,
			OrgID:         string(chain.Org), // chain column: proof-bound
			BindingID:     u.BindingID,
			AccountID:     u.AccountID,
			UserName:      u.UserName,
			UserNameLower: u.UserNameLower,
			ExternalID:    u.ExternalID,
			Subject:       u.Subject,
			Active:        boolInt(u.Active),
			Attributes:    u.Attributes,
			CreatedAt:     CanonTime(u.CreatedAt).Format(timeFormat),
			UpdatedAt:     CanonTime(u.UpdatedAt).Format(timeFormat),
		}))
	}
	return constraint(r.pg.CreateSCIMUser(ctx, pggen.CreateSCIMUserParams{
		ID:            u.ID,
		ChainOrgID:    string(chain.Org), // chain column: proof-bound
		BindingID:     u.BindingID,
		AccountID:     u.AccountID,
		UserName:      u.UserName,
		UserNameLower: u.UserNameLower,
		ExternalID:    u.ExternalID,
		Subject:       u.Subject,
		Active:        u.Active,
		Attributes:    u.Attributes,
		CreatedAt:     pgtype.Timestamptz{Time: CanonTime(u.CreatedAt), Valid: true},
		UpdatedAt:     pgtype.Timestamptz{Time: CanonTime(u.UpdatedAt), Valid: true},
	}))
}

func (r scimRepo) User(ctx context.Context, p authz.Proof, bindingID, id string) (SCIMUser, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMUser, r.tok)
	if err != nil {
		return SCIMUser{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMUser(ctx, sqlitegen.GetSCIMUserParams{
			OrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
		})
		return sqliteUserOrNotFound(row, err)
	}
	row, err := r.pg.GetSCIMUser(ctx, pggen.GetSCIMUserParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
	})
	return pgUserOrNotFound(row, err)
}

func (r scimRepo) UserByUserName(ctx context.Context, p authz.Proof, bindingID, folded string) (SCIMUser, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMUserByUserName, r.tok)
	if err != nil {
		return SCIMUser{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMUserByUserName(ctx, sqlitegen.GetSCIMUserByUserNameParams{
			OrgID: string(chain.Org), BindingID: bindingID, UserNameLower: folded, // chain column: proof-bound
		})
		return sqliteUserOrNotFound(row, err)
	}
	row, err := r.pg.GetSCIMUserByUserName(ctx, pggen.GetSCIMUserByUserNameParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, UserNameLower: folded, // chain column: proof-bound
	})
	return pgUserOrNotFound(row, err)
}

func (r scimRepo) UsersByExternalID(ctx context.Context, p authz.Proof, bindingID, externalID string) ([]SCIMUser, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMUsersByExternalID, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMUser{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMUsersByExternalID(ctx, sqlitegen.ListSCIMUsersByExternalIDParams{
			OrgID: string(chain.Org), BindingID: bindingID, ExternalID: externalID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			u, err := sqliteUser(row)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMUsersByExternalID(ctx, pggen.ListSCIMUsersByExternalIDParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, ExternalID: externalID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgUser(row))
	}
	return out, nil
}

func (r scimRepo) UserBySubject(ctx context.Context, p authz.Proof, bindingID, subject string) (SCIMUser, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMUserBySubject, r.tok)
	if err != nil {
		return SCIMUser{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMUserBySubject(ctx, sqlitegen.GetSCIMUserBySubjectParams{
			OrgID: string(chain.Org), BindingID: bindingID, Subject: subject, // chain column: proof-bound
		})
		return sqliteUserOrNotFound(row, err)
	}
	row, err := r.pg.GetSCIMUserBySubject(ctx, pggen.GetSCIMUserBySubjectParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, Subject: subject, // chain column: proof-bound
	})
	return pgUserOrNotFound(row, err)
}

func (r scimRepo) UserByAccount(ctx context.Context, p authz.Proof, bindingID, accountID string) (SCIMUser, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMUserByAccount, r.tok)
	if err != nil {
		return SCIMUser{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMUserByAccount(ctx, sqlitegen.GetSCIMUserByAccountParams{
			OrgID: string(chain.Org), BindingID: bindingID, AccountID: accountID, // chain column: proof-bound
		})
		return sqliteUserOrNotFound(row, err)
	}
	row, err := r.pg.GetSCIMUserByAccount(ctx, pggen.GetSCIMUserByAccountParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, AccountID: accountID, // chain column: proof-bound
	})
	return pgUserOrNotFound(row, err)
}

func (r scimRepo) Users(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMUser, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMUsers, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMUser{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMUsers(ctx, sqlitegen.ListSCIMUsersParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			u, err := sqliteUser(row)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMUsers(ctx, pggen.ListSCIMUsersParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgUser(row))
	}
	return out, nil
}

func (r scimRepo) PageUsers(ctx context.Context, p authz.Proof, bindingID string, limit, offset int64) ([]SCIMUser, int64, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMPageUsers, r.tok)
	if err != nil {
		return nil, 0, err
	}
	out := []SCIMUser{}
	if r.sq != nil {
		total, err := r.sq.CountSCIMUsers(ctx, sqlitegen.CountSCIMUsersParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, 0, err
		}
		rows, err := r.sq.PageSCIMUsers(ctx, sqlitegen.PageSCIMUsersParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
			Limit: limit, Offset: offset,
		})
		if err != nil {
			return nil, 0, err
		}
		for _, row := range rows {
			u, err := sqliteUser(row)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, u)
		}
		return out, total, nil
	}
	total, err := r.pg.CountSCIMUsers(ctx, pggen.CountSCIMUsersParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.pg.PageSCIMUsers(ctx, pggen.PageSCIMUsersParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		PageLimit: int32(limit), PageOffset: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	for _, row := range rows {
		out = append(out, pgUser(row))
	}
	return out, total, nil
}

func (r scimRepo) PageGroups(ctx context.Context, p authz.Proof, bindingID string, limit, offset int64) ([]SCIMGroup, int64, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMPageGroups, r.tok)
	if err != nil {
		return nil, 0, err
	}
	out := []SCIMGroup{}
	if r.sq != nil {
		total, err := r.sq.CountSCIMGroups(ctx, sqlitegen.CountSCIMGroupsParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, 0, err
		}
		rows, err := r.sq.PageSCIMGroups(ctx, sqlitegen.PageSCIMGroupsParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
			Limit: limit, Offset: offset,
		})
		if err != nil {
			return nil, 0, err
		}
		for _, row := range rows {
			g, err := sqliteGroup(row)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, g)
		}
		return out, total, nil
	}
	total, err := r.pg.CountSCIMGroups(ctx, pggen.CountSCIMGroupsParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.pg.PageSCIMGroups(ctx, pggen.PageSCIMGroupsParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		PageLimit: int32(limit), PageOffset: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	for _, row := range rows {
		out = append(out, pgGroup(row))
	}
	return out, total, nil
}

func (r scimRepo) UpdateUser(ctx context.Context, p authz.Proof, u SCIMUserUpdate) error {
	chain, err := authz.Verify(p, authz.StoreSCIMUpdateUser, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.UpdateSCIMUser(ctx, sqlitegen.UpdateSCIMUserParams{
			UserName: u.UserName, UserNameLower: u.UserNameLower, ExternalID: u.ExternalID,
			Active: boolInt(u.Active), Attributes: u.Attributes,
			UpdatedAt: CanonTime(u.UpdatedAt).Format(timeFormat),
			OrgID:     string(chain.Org), BindingID: u.BindingID, ID: u.ID, // chain column: proof-bound
		}))
	}
	return affected(r.pg.UpdateSCIMUser(ctx, pggen.UpdateSCIMUserParams{
		UserName: u.UserName, UserNameLower: u.UserNameLower, ExternalID: u.ExternalID,
		Active: u.Active, Attributes: u.Attributes,
		UpdatedAt:  pgtype.Timestamptz{Time: CanonTime(u.UpdatedAt), Valid: true},
		ChainOrgID: string(chain.Org), BindingID: u.BindingID, ID: u.ID, // chain column: proof-bound
	}))
}

func (r scimRepo) DeleteUser(ctx context.Context, p authz.Proof, bindingID, id string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteUser, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.DeleteSCIMUser(ctx, sqlitegen.DeleteSCIMUserParams{
			OrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
		}))
	}
	return affected(r.pg.DeleteSCIMUser(ctx, pggen.DeleteSCIMUserParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
	}))
}

func (r scimRepo) DeleteUsersForBinding(ctx context.Context, p authz.Proof, bindingID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteUsersForBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMUsersForBinding(ctx, sqlitegen.DeleteSCIMUsersForBindingParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMUsersForBinding(ctx, pggen.DeleteSCIMUsersForBindingParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	return err
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func (r scimRepo) CreateGroup(ctx context.Context, p authz.Proof, g NewSCIMGroup) error {
	chain, err := authz.Verify(p, authz.StoreSCIMCreateGroup, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.CreateSCIMGroup(ctx, sqlitegen.CreateSCIMGroupParams{
			ID:        g.ID,
			OrgID:     string(chain.Org), // chain column: proof-bound
			BindingID: g.BindingID, DisplayName: g.DisplayName,
			DisplayNameLower: g.DisplayNameLower, ExternalID: g.ExternalID,
			CreatedAt: CanonTime(g.CreatedAt).Format(timeFormat),
			UpdatedAt: CanonTime(g.UpdatedAt).Format(timeFormat),
		}))
	}
	return constraint(r.pg.CreateSCIMGroup(ctx, pggen.CreateSCIMGroupParams{
		ID:         g.ID,
		ChainOrgID: string(chain.Org), // chain column: proof-bound
		BindingID:  g.BindingID, DisplayName: g.DisplayName,
		DisplayNameLower: g.DisplayNameLower, ExternalID: g.ExternalID,
		CreatedAt: pgtype.Timestamptz{Time: CanonTime(g.CreatedAt), Valid: true},
		UpdatedAt: pgtype.Timestamptz{Time: CanonTime(g.UpdatedAt), Valid: true},
	}))
}

func (r scimRepo) Group(ctx context.Context, p authz.Proof, bindingID, id string) (SCIMGroup, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMGroup, r.tok)
	if err != nil {
		return SCIMGroup{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMGroup(ctx, sqlitegen.GetSCIMGroupParams{
			OrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
		})
		return sqliteGroupOrNotFound(row, err)
	}
	row, err := r.pg.GetSCIMGroup(ctx, pggen.GetSCIMGroupParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
	})
	return pgGroupOrNotFound(row, err)
}

func (r scimRepo) GroupsByDisplayName(ctx context.Context, p authz.Proof, bindingID, folded string) ([]SCIMGroup, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMGroupsByDisplayName, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMGroup{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMGroupsByDisplayName(ctx, sqlitegen.ListSCIMGroupsByDisplayNameParams{
			OrgID: string(chain.Org), BindingID: bindingID, DisplayNameLower: folded, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			g, err := sqliteGroup(row)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMGroupsByDisplayName(ctx, pggen.ListSCIMGroupsByDisplayNameParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, DisplayNameLower: folded, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgGroup(row))
	}
	return out, nil
}

func (r scimRepo) GroupsByExternalID(ctx context.Context, p authz.Proof, bindingID, externalID string) ([]SCIMGroup, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMGroupsByExternalID, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMGroup{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMGroupsByExternalID(ctx, sqlitegen.ListSCIMGroupsByExternalIDParams{
			OrgID: string(chain.Org), BindingID: bindingID, ExternalID: externalID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			g, err := sqliteGroup(row)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMGroupsByExternalID(ctx, pggen.ListSCIMGroupsByExternalIDParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, ExternalID: externalID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgGroup(row))
	}
	return out, nil
}

func (r scimRepo) Groups(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMGroup, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMGroups, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMGroup{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMGroups(ctx, sqlitegen.ListSCIMGroupsParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			g, err := sqliteGroup(row)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMGroups(ctx, pggen.ListSCIMGroupsParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgGroup(row))
	}
	return out, nil
}

func (r scimRepo) UpdateGroup(ctx context.Context, p authz.Proof, g SCIMGroupUpdate) error {
	chain, err := authz.Verify(p, authz.StoreSCIMUpdateGroup, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.UpdateSCIMGroup(ctx, sqlitegen.UpdateSCIMGroupParams{
			DisplayName: g.DisplayName, DisplayNameLower: g.DisplayNameLower,
			ExternalID: g.ExternalID,
			UpdatedAt:  CanonTime(g.UpdatedAt).Format(timeFormat),
			OrgID:      string(chain.Org), BindingID: g.BindingID, ID: g.ID, // chain column: proof-bound
		}))
	}
	return affected(r.pg.UpdateSCIMGroup(ctx, pggen.UpdateSCIMGroupParams{
		DisplayName: g.DisplayName, DisplayNameLower: g.DisplayNameLower,
		ExternalID: g.ExternalID,
		UpdatedAt:  pgtype.Timestamptz{Time: CanonTime(g.UpdatedAt), Valid: true},
		ChainOrgID: string(chain.Org), BindingID: g.BindingID, ID: g.ID, // chain column: proof-bound
	}))
}

func (r scimRepo) DeleteGroup(ctx context.Context, p authz.Proof, bindingID, id string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteGroup, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return affected(r.sq.DeleteSCIMGroup(ctx, sqlitegen.DeleteSCIMGroupParams{
			OrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
		}))
	}
	return affected(r.pg.DeleteSCIMGroup(ctx, pggen.DeleteSCIMGroupParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
	}))
}

func (r scimRepo) DeleteGroupsForBinding(ctx context.Context, p authz.Proof, bindingID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteGroupsForBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMGroupsForBinding(ctx, sqlitegen.DeleteSCIMGroupsForBindingParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMGroupsForBinding(ctx, pggen.DeleteSCIMGroupsForBindingParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	return err
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

func (r scimRepo) AddGroupMember(ctx context.Context, p authz.Proof, m SCIMGroupMember) error {
	chain, err := authz.Verify(p, authz.StoreSCIMAddGroupMember, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.AddSCIMGroupMember(ctx, sqlitegen.AddSCIMGroupMemberParams{
			ID:        m.ID,
			OrgID:     string(chain.Org), // chain column: proof-bound
			BindingID: m.BindingID, GroupID: m.GroupID, UserID: m.UserID,
			CreatedAt: CanonTime(m.CreatedAt).Format(timeFormat),
		}))
	}
	return constraint(r.pg.AddSCIMGroupMember(ctx, pggen.AddSCIMGroupMemberParams{
		ID:         m.ID,
		ChainOrgID: string(chain.Org), // chain column: proof-bound
		BindingID:  m.BindingID, GroupID: m.GroupID, UserID: m.UserID,
		CreatedAt: pgtype.Timestamptz{Time: CanonTime(m.CreatedAt), Valid: true},
	}))
}

func (r scimRepo) GroupMembers(ctx context.Context, p authz.Proof, bindingID, groupID string) ([]SCIMGroupMember, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMGroupMembers, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMGroupMember{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMGroupMembers(ctx, sqlitegen.ListSCIMGroupMembersParams{
			OrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			m, err := sqliteGroupMember(row)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMGroupMembers(ctx, pggen.ListSCIMGroupMembersParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgMember(row))
	}
	return out, nil
}

func (r scimRepo) MembershipsForUser(ctx context.Context, p authz.Proof, bindingID, userID string) ([]SCIMGroupMember, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMMembershipsForUser, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMGroupMember{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMGroupMembershipsForUser(ctx, sqlitegen.ListSCIMGroupMembershipsForUserParams{
			OrgID: string(chain.Org), BindingID: bindingID, UserID: userID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			m, err := sqliteGroupMember(row)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMGroupMembershipsForUser(ctx, pggen.ListSCIMGroupMembershipsForUserParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, UserID: userID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgMember(row))
	}
	return out, nil
}

func (r scimRepo) RemoveGroupMember(ctx context.Context, p authz.Proof, bindingID, groupID, userID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMRemoveGroupMember, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMGroupMember(ctx, sqlitegen.DeleteSCIMGroupMemberParams{
			OrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, UserID: userID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMGroupMember(ctx, pggen.DeleteSCIMGroupMemberParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, UserID: userID, // chain column: proof-bound
	})
	return err
}

func (r scimRepo) ClearGroupMembers(ctx context.Context, p authz.Proof, bindingID, groupID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMClearGroupMembers, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.ClearSCIMGroupMembers(ctx, sqlitegen.ClearSCIMGroupMembersParams{
			OrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.ClearSCIMGroupMembers(ctx, pggen.ClearSCIMGroupMembersParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, GroupID: groupID, // chain column: proof-bound
	})
	return err
}

func (r scimRepo) RemoveMembershipsForUser(ctx context.Context, p authz.Proof, bindingID, userID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMRemoveMembershipsForUser, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMGroupMembershipsForUser(ctx, sqlitegen.DeleteSCIMGroupMembershipsForUserParams{
			OrgID: string(chain.Org), BindingID: bindingID, UserID: userID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMGroupMembershipsForUser(ctx, pggen.DeleteSCIMGroupMembershipsForUserParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, UserID: userID, // chain column: proof-bound
	})
	return err
}

func (r scimRepo) DeleteGroupMembersForBinding(ctx context.Context, p authz.Proof, bindingID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteGroupMembersForBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMGroupMembersForBinding(ctx, sqlitegen.DeleteSCIMGroupMembersForBindingParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMGroupMembersForBinding(ctx, pggen.DeleteSCIMGroupMembersForBindingParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	return err
}

// ---------------------------------------------------------------------------
// Attention states
// ---------------------------------------------------------------------------

func (r scimRepo) EnterAttention(ctx context.Context, p authz.Proof, a SCIMAttentionRow) error {
	chain, err := authz.Verify(p, authz.StoreSCIMEnterAttention, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.EnterSCIMAttention(ctx, sqlitegen.EnterSCIMAttentionParams{
			ID:        a.ID,
			OrgID:     string(chain.Org), // chain column: proof-bound
			BindingID: a.BindingID, State: a.State, SubjectRef: a.SubjectRef, Cause: a.Cause,
			EnteredAt: CanonTime(a.EnteredAt).Format(timeFormat),
		}))
	}
	return constraint(r.pg.EnterSCIMAttention(ctx, pggen.EnterSCIMAttentionParams{
		ID:         a.ID,
		ChainOrgID: string(chain.Org), // chain column: proof-bound
		BindingID:  a.BindingID, State: a.State, SubjectRef: a.SubjectRef, Cause: a.Cause,
		EnteredAt: pgtype.Timestamptz{Time: CanonTime(a.EnteredAt), Valid: true},
	}))
}

func (r scimRepo) Attention(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMAttentionRow, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMAttention, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMAttentionRow{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMAttention(ctx, sqlitegen.ListSCIMAttentionParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			at, err := parseTime("scim_attention", row.ID, row.EnteredAt)
			if err != nil {
				return nil, err
			}
			out = append(out, SCIMAttentionRow{
				ID: row.ID, BindingID: row.BindingID, State: row.State,
				SubjectRef: row.SubjectRef, Cause: row.Cause, EnteredAt: at,
			})
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMAttention(ctx, pggen.ListSCIMAttentionParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, SCIMAttentionRow{
			ID: row.ID, BindingID: row.BindingID, State: row.State,
			SubjectRef: row.SubjectRef, Cause: row.Cause,
			EnteredAt: row.EnteredAt.Time.UTC(),
		})
	}
	return out, nil
}

func (r scimRepo) ClearAttention(ctx context.Context, p authz.Proof, bindingID, state, subjectRef string) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMClearAttention, r.tok)
	if err != nil {
		return 0, err
	}
	if r.sq != nil {
		return r.sq.ClearSCIMAttention(ctx, sqlitegen.ClearSCIMAttentionParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
			State: state, SubjectRef: subjectRef,
		})
	}
	return r.pg.ClearSCIMAttention(ctx, pggen.ClearSCIMAttentionParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		State: state, SubjectRef: subjectRef,
	})
}

func (r scimRepo) DeleteAttentionForBinding(ctx context.Context, p authz.Proof, bindingID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteAttentionForBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		_, err := r.sq.DeleteSCIMAttentionForBinding(ctx, sqlitegen.DeleteSCIMAttentionForBindingParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		return err
	}
	_, err = r.pg.DeleteSCIMAttentionForBinding(ctx, pggen.DeleteSCIMAttentionForBindingParams{
		ChainOrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	return err
}

// ---------------------------------------------------------------------------
// Credential administration
// ---------------------------------------------------------------------------

func (r scimRepo) CreateCredential(ctx context.Context, p authz.Proof, c NewSCIMCredential) error {
	chain, err := authz.Verify(p, authz.StoreSCIMCreateCredential, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return constraint(r.sq.InsertSCIMCredential(ctx, sqlitegen.InsertSCIMCredentialParams{
			ID: c.ID, OrgID: string(chain.Org), // chain column: proof-bound
			BindingID: c.BindingID, PrincipalID: c.PrincipalID, Verifier: c.Verifier,
			CredentialEpoch: c.CredentialEpoch,
			CreatedAt:       CanonTime(c.CreatedAt).Format(scimCredentialTime),
			ExpiresAt:       nullTimeString(c.ExpiresAt),
		}))
	}
	return constraint(r.pg.InsertSCIMCredential(ctx, pggen.InsertSCIMCredentialParams{
		ID: c.ID, OrgID: string(chain.Org), // chain column: proof-bound
		BindingID: c.BindingID, PrincipalID: c.PrincipalID, Verifier: c.Verifier,
		CredentialEpoch: c.CredentialEpoch,
		CreatedAt:       pgtype.Timestamptz{Time: CanonTime(c.CreatedAt), Valid: true},
		ExpiresAt:       pgNullTimestamp(c.ExpiresAt),
	}))
}

func (r scimRepo) Credential(ctx context.Context, p authz.Proof, bindingID, id string) (SCIMCredential, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMCredential, r.tok)
	if err != nil {
		return SCIMCredential{}, err
	}
	if r.sq != nil {
		row, err := r.sq.GetSCIMCredential(ctx, sqlitegen.GetSCIMCredentialParams{
			OrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
		})
		if errors.Is(err, sql.ErrNoRows) {
			return SCIMCredential{}, ErrNotFound
		}
		if err != nil {
			return SCIMCredential{}, err
		}
		return sqliteCredential(row)
	}
	row, err := r.pg.GetSCIMCredential(ctx, pggen.GetSCIMCredentialParams{
		OrgID: string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
	})
	if noRows(err) {
		return SCIMCredential{}, ErrNotFound
	}
	if err != nil {
		return SCIMCredential{}, err
	}
	return pgCredential(row), nil
}

func (r scimRepo) Credentials(ctx context.Context, p authz.Proof, bindingID string) ([]SCIMCredential, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMCredentials, r.tok)
	if err != nil {
		return nil, err
	}
	out := []SCIMCredential{}
	if r.sq != nil {
		rows, err := r.sq.ListSCIMCredentials(ctx, sqlitegen.ListSCIMCredentialsParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			c, err := sqliteCredential(sqlitegen.GetSCIMCredentialRow(row))
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, nil
	}
	rows, err := r.pg.ListSCIMCredentials(ctx, pggen.ListSCIMCredentialsParams{
		OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, pgCredential(pggen.GetSCIMCredentialRow(row)))
	}
	return out, nil
}

func (r scimRepo) RevokeCredential(ctx context.Context, p authz.Proof, bindingID, id string, at time.Time) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMRevokeCredential, r.tok)
	if err != nil {
		return false, err
	}
	if r.sq != nil {
		n, err := r.sq.RevokeSCIMCredential(ctx, sqlitegen.RevokeSCIMCredentialParams{
			RevokedAt: nullTimeString(at),
			OrgID:     string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
		})
		return n == 1, err
	}
	n, err := r.pg.RevokeSCIMCredential(ctx, pggen.RevokeSCIMCredentialParams{
		RevokedAt: pgNullTimestamp(at),
		OrgID:     string(chain.Org), BindingID: bindingID, ID: id, // chain column: proof-bound
	})
	return n == 1, err
}

func (r scimRepo) RevokeCredentialsForBinding(ctx context.Context, p authz.Proof, bindingID string, at time.Time) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreSCIMRevokeCredentialsForBinding, r.tok)
	if err != nil {
		return 0, err
	}
	if r.sq != nil {
		return r.sq.RevokeSCIMCredentialsForBinding(ctx, sqlitegen.RevokeSCIMCredentialsForBindingParams{
			RevokedAt: nullTimeString(at),
			OrgID:     string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
	}
	return r.pg.RevokeSCIMCredentialsForBinding(ctx, pggen.RevokeSCIMCredentialsForBindingParams{
		RevokedAt: pgNullTimestamp(at),
		OrgID:     string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
}

func (r scimRepo) DeleteCredentialsForBinding(ctx context.Context, p authz.Proof, bindingID string) error {
	chain, err := authz.Verify(p, authz.StoreSCIMDeleteCredentialsForBinding, r.tok)
	if err != nil {
		return err
	}
	if r.sq != nil {
		return r.sq.DeleteSCIMCredentialsForBinding(ctx, sqlitegen.DeleteSCIMCredentialsForBindingParams{
			OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
		})
	}
	return r.pg.DeleteSCIMCredentialsForBinding(ctx, pggen.DeleteSCIMCredentialsForBindingParams{
		OrgID: string(chain.Org), BindingID: bindingID, // chain column: proof-bound
	})
}

// nullTimeString and pgNullTimestamp encode "absent" for the optional
// timestamps a credential carries: an indefinite one has no ceiling, a live one
// no revocation. The zero time is the absent value, so "never revoked" cannot
// be confused with "revoked at the epoch".
// scimCredentialTime is the layout the AUTHN resolver parses this table with
// (internal/store/authn's fixed-width `timeLayout`). The credential row is read
// pre-auth by that resolver and written post-auth by this repository, so the
// two must agree — RFC3339Nano's variable-width fraction does not parse under a
// fixed-width layout, and the mismatch only shows up once a fraction happens to
// be short.
const scimCredentialTime = "2006-01-02T15:04:05.000000Z"

func nullTimeString(t time.Time) sql.NullString {
	if t.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: CanonTime(t).Format(scimCredentialTime), Valid: true}
}

func pgNullTimestamp(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: CanonTime(t), Valid: true}
}

func sqliteCredential(row sqlitegen.GetSCIMCredentialRow) (SCIMCredential, error) {
	created, err := time.Parse(scimCredentialTime, row.CreatedAt)
	if err != nil {
		return SCIMCredential{}, err
	}
	out := SCIMCredential{
		ID: row.ID, BindingID: row.BindingID, PrincipalID: row.PrincipalID,
		CredentialEpoch: row.CredentialEpoch, CreatedAt: created,
	}
	for _, f := range []struct {
		src sql.NullString
		dst *time.Time
	}{{row.ExpiresAt, &out.ExpiresAt}, {row.RevokedAt, &out.RevokedAt}, {row.LastUsedAt, &out.LastUsedAt}} {
		if !f.src.Valid {
			continue
		}
		t, err := time.Parse(scimCredentialTime, f.src.String)
		if err != nil {
			return SCIMCredential{}, err
		}
		*f.dst = t
	}
	return out, nil
}

func pgCredential(row pggen.GetSCIMCredentialRow) SCIMCredential {
	out := SCIMCredential{
		ID: row.ID, BindingID: row.BindingID, PrincipalID: row.PrincipalID,
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

// Live reports whether the credential may authenticate at `now`: not revoked,
// and either indefinite or not past its ceiling. Revocation bites at the NEXT
// request, which is what this predicate is.
func (c SCIMCredential) Live(now time.Time) bool {
	if !c.RevokedAt.IsZero() {
		return false
	}
	return c.ExpiresAt.IsZero() || now.Before(c.ExpiresAt)
}

// ---------------------------------------------------------------------------
// Row conversion
// ---------------------------------------------------------------------------

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func sqliteBinding(row sqlitegen.ScimBinding) (SCIMBinding, error) {
	created, err := parseTime("scim_binding", row.ID, row.CreatedAt)
	if err != nil {
		return SCIMBinding{}, err
	}
	out := SCIMBinding{
		ID: row.ID, OrgID: row.OrgID, ProviderKind: row.ProviderKind,
		ProviderID: row.ProviderID, ProviderSlug: row.ProviderSlug,
		ProviderIssuer:           row.ProviderIssuer,
		SubjectSource:            row.SubjectSource,
		NameIDFormat:             row.NameidFormat,
		NameIDQualifier:          row.NameidQualifier,
		NameIDQualifierPresent:   row.NameidQualifierPresent == 1,
		NameIDSPQualifier:        row.NameidSpQualifier,
		NameIDSPQualifierPresent: row.NameidSpQualifierPresent == 1,
		ConnectionPrincipalID:    row.ConnectionPrincipalID,
		CreatedAt:                created,
	}
	if row.LastContactAt.Valid {
		last, err := parseTime("scim_binding", row.ID, row.LastContactAt.String)
		if err != nil {
			return SCIMBinding{}, err
		}
		out.LastContactAt = last
	}
	return out, nil
}

func pgBinding(row pggen.ScimBinding) SCIMBinding {
	out := SCIMBinding{
		ID: row.ID, OrgID: row.OrgID, ProviderKind: row.ProviderKind,
		ProviderID: row.ProviderID, ProviderSlug: row.ProviderSlug,
		ProviderIssuer:           row.ProviderIssuer,
		SubjectSource:            row.SubjectSource,
		NameIDFormat:             row.NameidFormat,
		NameIDQualifier:          row.NameidQualifier,
		NameIDQualifierPresent:   row.NameidQualifierPresent,
		NameIDSPQualifier:        row.NameidSpQualifier,
		NameIDSPQualifierPresent: row.NameidSpQualifierPresent,
		ConnectionPrincipalID:    row.ConnectionPrincipalID,
		CreatedAt:                row.CreatedAt.Time.UTC(),
	}
	if row.LastContactAt.Valid {
		out.LastContactAt = row.LastContactAt.Time.UTC()
	}
	return out
}

func sqliteMapping(row sqlitegen.ScimMapping) (SCIMMapping, error) {
	created, err := parseTime("scim_mapping", row.ID, row.CreatedAt)
	if err != nil {
		return SCIMMapping{}, err
	}
	return SCIMMapping{
		ID: row.ID, OrgID: row.OrgID, BindingID: row.BindingID, GroupID: row.GroupID,
		Template: row.Template, ScopeProjectID: row.ScopeProjectID,
		ScopeEnvID: row.ScopeEnvID, Inert: row.Inert == 1, CreatedAt: created,
	}, nil
}

func pgMapping(row pggen.ScimMapping) SCIMMapping {
	return SCIMMapping{
		ID: row.ID, OrgID: row.OrgID, BindingID: row.BindingID, GroupID: row.GroupID,
		Template: row.Template, ScopeProjectID: row.ScopeProjectID,
		ScopeEnvID: row.ScopeEnvID, Inert: row.Inert, CreatedAt: row.CreatedAt.Time.UTC(),
	}
}

func sqliteUser(row sqlitegen.ScimUser) (SCIMUser, error) {
	created, err := parseTime("scim_user", row.ID, row.CreatedAt)
	if err != nil {
		return SCIMUser{}, err
	}
	updated, err := parseTime("scim_user", row.ID, row.UpdatedAt)
	if err != nil {
		return SCIMUser{}, err
	}
	return SCIMUser{
		ID: row.ID, OrgID: row.OrgID, BindingID: row.BindingID, AccountID: row.AccountID,
		UserName: row.UserName, UserNameLower: row.UserNameLower, ExternalID: row.ExternalID,
		Subject: row.Subject, Active: row.Active == 1, Attributes: row.Attributes,
		CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func pgUser(row pggen.ScimUser) SCIMUser {
	return SCIMUser{
		ID: row.ID, OrgID: row.OrgID, BindingID: row.BindingID, AccountID: row.AccountID,
		UserName: row.UserName, UserNameLower: row.UserNameLower, ExternalID: row.ExternalID,
		Subject: row.Subject, Active: row.Active, Attributes: row.Attributes,
		CreatedAt: row.CreatedAt.Time.UTC(), UpdatedAt: row.UpdatedAt.Time.UTC(),
	}
}

func sqliteUserOrNotFound(row sqlitegen.ScimUser, err error) (SCIMUser, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMUser{}, ErrNotFound
	}
	if err != nil {
		return SCIMUser{}, err
	}
	return sqliteUser(row)
}

func pgUserOrNotFound(row pggen.ScimUser, err error) (SCIMUser, error) {
	if noRows(err) {
		return SCIMUser{}, ErrNotFound
	}
	if err != nil {
		return SCIMUser{}, err
	}
	return pgUser(row), nil
}

func sqliteGroup(row sqlitegen.ScimGroup) (SCIMGroup, error) {
	created, err := parseTime("scim_group", row.ID, row.CreatedAt)
	if err != nil {
		return SCIMGroup{}, err
	}
	updated, err := parseTime("scim_group", row.ID, row.UpdatedAt)
	if err != nil {
		return SCIMGroup{}, err
	}
	return SCIMGroup{
		ID: row.ID, OrgID: row.OrgID, BindingID: row.BindingID,
		DisplayName: row.DisplayName, DisplayNameLower: row.DisplayNameLower,
		ExternalID: row.ExternalID, CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func pgGroup(row pggen.ScimGroup) SCIMGroup {
	return SCIMGroup{
		ID: row.ID, OrgID: row.OrgID, BindingID: row.BindingID,
		DisplayName: row.DisplayName, DisplayNameLower: row.DisplayNameLower,
		ExternalID: row.ExternalID,
		CreatedAt:  row.CreatedAt.Time.UTC(), UpdatedAt: row.UpdatedAt.Time.UTC(),
	}
}

func sqliteGroupOrNotFound(row sqlitegen.ScimGroup, err error) (SCIMGroup, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMGroup{}, ErrNotFound
	}
	if err != nil {
		return SCIMGroup{}, err
	}
	return sqliteGroup(row)
}

func pgGroupOrNotFound(row pggen.ScimGroup, err error) (SCIMGroup, error) {
	if noRows(err) {
		return SCIMGroup{}, ErrNotFound
	}
	if err != nil {
		return SCIMGroup{}, err
	}
	return pgGroup(row), nil
}

func sqliteGroupMember(row sqlitegen.ScimGroupMember) (SCIMGroupMember, error) {
	created, err := parseTime("scim_group_member", row.ID, row.CreatedAt)
	if err != nil {
		return SCIMGroupMember{}, err
	}
	return SCIMGroupMember{
		ID: row.ID, BindingID: row.BindingID, GroupID: row.GroupID,
		UserID: row.UserID, CreatedAt: created,
	}, nil
}

func pgMember(row pggen.ScimGroupMember) SCIMGroupMember {
	return SCIMGroupMember{
		ID: row.ID, BindingID: row.BindingID, GroupID: row.GroupID,
		UserID: row.UserID, CreatedAt: row.CreatedAt.Time.UTC(),
	}
}
