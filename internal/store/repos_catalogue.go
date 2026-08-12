package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// The key catalogue's binding layer (#49). Same discipline as repos.go: every
// method verifies the proof at the boundary against its own registered store
// operation, and binds every chain parameter exclusively from the verified
// proof's resolved chain. The caller-facing signatures expose no chain
// parameter at all.

type sqliteCatalogue struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteCatalogue) Create(ctx context.Context, p authz.Proof, key NewCatalogueKey) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateKey(ctx, sqlitegen.CreateKeyParams{
		ID:              key.ID,
		OrgID:           string(chain.Org),     // chain column: proof-bound
		ProjectID:       string(chain.Project), // chain column: proof-bound
		Name:            key.Name,
		FolderPath:      key.FolderPath,
		Classification:  key.Classification,
		Description:     key.Description,
		Deprecated:      boolToInt(key.Deprecated),
		DeprecationNote: key.DeprecationNote,
		Declaration:     key.Declaration,
		RequiredMode:    key.RequiredMode,
		ForbiddenMode:   key.ForbiddenMode,
		GroupID:         nullString(key.GroupID),
		CreatedAt:       CanonTime(key.CreatedAt).Format(timeFormat),
	}))
}

func (r sqliteCatalogue) Get(ctx context.Context, p authz.Proof, id string) (CatalogueKey, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGet, r.tok)
	if err != nil {
		return CatalogueKey{}, err
	}
	row, err := r.q.GetKey(ctx, sqlitegen.GetKeyParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return CatalogueKey{}, ErrNotFound
	}
	if err != nil {
		return CatalogueKey{}, err
	}
	return keyFromSQLite(row)
}

func (r sqliteCatalogue) List(ctx context.Context, p authz.Proof) ([]CatalogueKey, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListKeys(ctx, sqlitegen.ListKeysParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]CatalogueKey, 0, len(rows))
	for _, row := range rows {
		key, err := keyFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func (r sqliteCatalogue) Count(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueCount, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountKeys(ctx, sqlitegen.CountKeysParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
}

func (r sqliteCatalogue) Rename(ctx context.Context, p authz.Proof, id, name string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameKey(ctx, sqlitegen.RenameKeyParams{
		Name:      name,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func (r sqliteCatalogue) UpdateMetadata(ctx context.Context, p authz.Proof, id string, m KeyMetadata) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueUpdateMetadata, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.UpdateKeyMetadata(ctx, sqlitegen.UpdateKeyMetadataParams{
		FolderPath:      m.FolderPath,
		Description:     m.Description,
		Deprecated:      boolToInt(m.Deprecated),
		DeprecationNote: m.DeprecationNote,
		OrgID:           string(chain.Org),
		ProjectID:       string(chain.Project),
		ID:              id,
	}))
}

func (r sqliteCatalogue) UpdateDeclaration(ctx context.Context, p authz.Proof, id string, d KeyDeclaration) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueUpdateDeclaration, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.UpdateKeyDeclaration(ctx, sqlitegen.UpdateKeyDeclarationParams{
		Declaration:   d.Declaration,
		RequiredMode:  d.RequiredMode,
		ForbiddenMode: d.ForbiddenMode,
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		ID:            id,
	}))
}

func (r sqliteCatalogue) SetClassification(ctx context.Context, p authz.Proof, id, classification string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueSetClassification, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.SetKeyClassification(ctx, sqlitegen.SetKeyClassificationParams{
		Classification: classification,
		OrgID:          string(chain.Org),
		ProjectID:      string(chain.Project),
		ID:             id,
	}))
}

func (r sqliteCatalogue) SetGroup(ctx context.Context, p authz.Proof, id, groupID string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueSetGroup, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.SetKeyGroup(ctx, sqlitegen.SetKeyGroupParams{
		GroupID:   nullString(groupID),
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func (r sqliteCatalogue) Delete(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteKey(ctx, sqlitegen.DeleteKeyParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func (r sqliteCatalogue) CreateGroup(ctx context.Context, p authz.Proof, group NewCatalogueGroup) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateKeyGroup(ctx, sqlitegen.CreateKeyGroupParams{
		ID:        group.ID,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		Name:      group.Name,
		CreatedAt: CanonTime(group.CreatedAt).Format(timeFormat),
	}))
}

func (r sqliteCatalogue) GetGroup(ctx context.Context, p authz.Proof, id string) (CatalogueGroup, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupGet, r.tok)
	if err != nil {
		return CatalogueGroup{}, err
	}
	row, err := r.q.GetKeyGroup(ctx, sqlitegen.GetKeyGroupParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return CatalogueGroup{}, ErrNotFound
	}
	if err != nil {
		return CatalogueGroup{}, err
	}
	return groupFromSQLite(row)
}

func (r sqliteCatalogue) ListGroups(ctx context.Context, p authz.Proof) ([]CatalogueGroup, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListKeyGroups(ctx, sqlitegen.ListKeyGroupsParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]CatalogueGroup, 0, len(rows))
	for _, row := range rows {
		group, err := groupFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, group)
	}
	return out, nil
}

func (r sqliteCatalogue) CountGroups(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupCount, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountKeyGroups(ctx, sqlitegen.CountKeyGroupsParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
}

func (r sqliteCatalogue) RenameGroup(ctx context.Context, p authz.Proof, id, name string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameKeyGroup(ctx, sqlitegen.RenameKeyGroupParams{
		Name:      name,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func (r sqliteCatalogue) DeleteGroup(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteKeyGroup(ctx, sqlitegen.DeleteKeyGroupParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func (r sqliteCatalogue) ClearGroupMembers(ctx context.Context, p authz.Proof, groupID string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupClearMembers, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.ClearKeyGroupMembers(ctx, sqlitegen.ClearKeyGroupMembersParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		GroupID:   nullString(groupID),
	}))
}

func (r sqliteCatalogue) ListPresence(ctx context.Context, p authz.Proof) ([]KeyPresence, error) {
	chain, err := authz.Verify(p, authz.StoreCataloguePresenceList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListKeyPresence(ctx, sqlitegen.ListKeyPresenceParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]KeyPresence, 0, len(rows))
	for _, row := range rows {
		out = append(out, KeyPresence{KeyID: row.KeyID, EnvironmentID: row.EnvironmentID, Rule: row.Rule})
	}
	return out, nil
}

func (r sqliteCatalogue) ReplacePresence(ctx context.Context, p authz.Proof, keyID string, rows []KeyPresence) error {
	chain, err := authz.Verify(p, authz.StoreCataloguePresenceReplace, r.tok)
	if err != nil {
		return err
	}
	if err := r.q.DeleteKeyPresence(ctx, sqlitegen.DeleteKeyPresenceParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		KeyID:     keyID,
	}); err != nil {
		return constraint(err)
	}
	for _, row := range rows {
		if err := r.q.InsertKeyPresence(ctx, sqlitegen.InsertKeyPresenceParams{
			OrgID:         string(chain.Org),
			ProjectID:     string(chain.Project),
			KeyID:         keyID,
			EnvironmentID: row.EnvironmentID,
			Rule:          row.Rule,
		}); err != nil {
			// A foreign environment id lands here as a foreign-key violation,
			// which is the conflict the service turns into its fixed refusal.
			return constraint(err)
		}
	}
	return nil
}

func (r sqliteCatalogue) DeletePresenceForEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreCataloguePresenceCascade, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.DeleteEnvironmentPresence(ctx, sqlitegen.DeleteEnvironmentPresenceParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: string(chain.Env), // chain column: proof-bound
	}))
}

func (r sqliteCatalogue) SchemaRevision(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueRevisionGet, r.tok)
	if err != nil {
		return 0, err
	}
	rev, err := r.q.GetProjectSchemaRevision(ctx, sqlitegen.GetProjectSchemaRevisionParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return rev, err
}

func (r sqliteCatalogue) BumpSchemaRevision(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueRevisionBump, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.BumpProjectSchemaRevision(ctx, sqlitegen.BumpProjectSchemaRevisionParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	}))
}

func keyFromSQLite(row sqlitegen.Key) (CatalogueKey, error) {
	created, err := parseTime("key", row.ID, row.CreatedAt)
	if err != nil {
		return CatalogueKey{}, err
	}
	return CatalogueKey{
		ID:              row.ID,
		OrgID:           row.OrgID,
		ProjectID:       row.ProjectID,
		Name:            row.Name,
		FolderPath:      row.FolderPath,
		Classification:  row.Classification,
		Description:     row.Description,
		Deprecated:      row.Deprecated != 0,
		DeprecationNote: row.DeprecationNote,
		Declaration:     row.Declaration,
		RequiredMode:    row.RequiredMode,
		ForbiddenMode:   row.ForbiddenMode,
		GroupID:         row.GroupID.String,
		CreatedAt:       created,
	}, nil
}

func groupFromSQLite(row sqlitegen.KeyGroup) (CatalogueGroup, error) {
	created, err := parseTime("key group", row.ID, row.CreatedAt)
	if err != nil {
		return CatalogueGroup{}, err
	}
	return CatalogueGroup{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, CreatedAt: created,
	}, nil
}

// boolToInt is sqlite's canonical boolean encoding (system-architecture ADR:
// booleans as integers), fixed in one place so the two engines cannot drift.
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// nullString maps the empty string to SQL NULL for the one nullable column in
// this aggregate. "" and NULL both mean "belongs to no group"; collapsing them
// at the boundary keeps the two representations from ever both existing.
func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func pgNullText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

// --- postgres ---

type pgCatalogue struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgCatalogue) Create(ctx context.Context, p authz.Proof, key NewCatalogueKey) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateKey(ctx, pggen.CreateKeyParams{
		ID:              key.ID,
		ChainOrgID:      string(chain.Org),     // chain column: proof-bound
		ChainProjectID:  string(chain.Project), // chain column: proof-bound
		Name:            key.Name,
		FolderPath:      key.FolderPath,
		Classification:  key.Classification,
		Description:     key.Description,
		Deprecated:      key.Deprecated,
		DeprecationNote: key.DeprecationNote,
		Declaration:     key.Declaration,
		RequiredMode:    key.RequiredMode,
		ForbiddenMode:   key.ForbiddenMode,
		GroupID:         pgNullText(key.GroupID),
		CreatedAt:       pgtype.Timestamptz{Time: CanonTime(key.CreatedAt), Valid: true},
	}))
}

func (r pgCatalogue) Get(ctx context.Context, p authz.Proof, id string) (CatalogueKey, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGet, r.tok)
	if err != nil {
		return CatalogueKey{}, err
	}
	row, err := r.q.GetKey(ctx, pggen.GetKeyParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CatalogueKey{}, ErrNotFound
	}
	if err != nil {
		return CatalogueKey{}, err
	}
	return keyFromPG(row)
}

func (r pgCatalogue) List(ctx context.Context, p authz.Proof) ([]CatalogueKey, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListKeys(ctx, pggen.ListKeysParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]CatalogueKey, 0, len(rows))
	for _, row := range rows {
		key, err := keyFromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func (r pgCatalogue) Count(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueCount, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountKeys(ctx, pggen.CountKeysParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
}

func (r pgCatalogue) Rename(ctx context.Context, p authz.Proof, id, name string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameKey(ctx, pggen.RenameKeyParams{
		Name:           name,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) UpdateMetadata(ctx context.Context, p authz.Proof, id string, m KeyMetadata) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueUpdateMetadata, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.UpdateKeyMetadata(ctx, pggen.UpdateKeyMetadataParams{
		FolderPath:      m.FolderPath,
		Description:     m.Description,
		Deprecated:      m.Deprecated,
		DeprecationNote: m.DeprecationNote,
		ChainOrgID:      string(chain.Org),
		ChainProjectID:  string(chain.Project),
		ID:              id,
	}))
}

func (r pgCatalogue) UpdateDeclaration(ctx context.Context, p authz.Proof, id string, d KeyDeclaration) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueUpdateDeclaration, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.UpdateKeyDeclaration(ctx, pggen.UpdateKeyDeclarationParams{
		Declaration:    d.Declaration,
		RequiredMode:   d.RequiredMode,
		ForbiddenMode:  d.ForbiddenMode,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) SetClassification(ctx context.Context, p authz.Proof, id, classification string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueSetClassification, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.SetKeyClassification(ctx, pggen.SetKeyClassificationParams{
		Classification: classification,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) SetGroup(ctx context.Context, p authz.Proof, id, groupID string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueSetGroup, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.SetKeyGroup(ctx, pggen.SetKeyGroupParams{
		GroupID:        pgNullText(groupID),
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) Delete(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteKey(ctx, pggen.DeleteKeyParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) CreateGroup(ctx context.Context, p authz.Proof, group NewCatalogueGroup) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateKeyGroup(ctx, pggen.CreateKeyGroupParams{
		ID:             group.ID,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		Name:           group.Name,
		CreatedAt:      pgtype.Timestamptz{Time: CanonTime(group.CreatedAt), Valid: true},
	}))
}

func (r pgCatalogue) GetGroup(ctx context.Context, p authz.Proof, id string) (CatalogueGroup, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupGet, r.tok)
	if err != nil {
		return CatalogueGroup{}, err
	}
	row, err := r.q.GetKeyGroup(ctx, pggen.GetKeyGroupParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CatalogueGroup{}, ErrNotFound
	}
	if err != nil {
		return CatalogueGroup{}, err
	}
	return groupFromPG(row)
}

func (r pgCatalogue) ListGroups(ctx context.Context, p authz.Proof) ([]CatalogueGroup, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListKeyGroups(ctx, pggen.ListKeyGroupsParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]CatalogueGroup, 0, len(rows))
	for _, row := range rows {
		group, err := groupFromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, group)
	}
	return out, nil
}

func (r pgCatalogue) CountGroups(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupCount, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountKeyGroups(ctx, pggen.CountKeyGroupsParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
}

func (r pgCatalogue) RenameGroup(ctx context.Context, p authz.Proof, id, name string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameKeyGroup(ctx, pggen.RenameKeyGroupParams{
		Name:           name,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) DeleteGroup(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteKeyGroup(ctx, pggen.DeleteKeyGroupParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgCatalogue) ClearGroupMembers(ctx context.Context, p authz.Proof, groupID string) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueGroupClearMembers, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.ClearKeyGroupMembers(ctx, pggen.ClearKeyGroupMembersParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		GroupID:        pgNullText(groupID),
	}))
}

func (r pgCatalogue) ListPresence(ctx context.Context, p authz.Proof) ([]KeyPresence, error) {
	chain, err := authz.Verify(p, authz.StoreCataloguePresenceList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListKeyPresence(ctx, pggen.ListKeyPresenceParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]KeyPresence, 0, len(rows))
	for _, row := range rows {
		out = append(out, KeyPresence{KeyID: row.KeyID, EnvironmentID: row.EnvironmentID, Rule: row.Rule})
	}
	return out, nil
}

func (r pgCatalogue) ReplacePresence(ctx context.Context, p authz.Proof, keyID string, rows []KeyPresence) error {
	chain, err := authz.Verify(p, authz.StoreCataloguePresenceReplace, r.tok)
	if err != nil {
		return err
	}
	if err := r.q.DeleteKeyPresence(ctx, pggen.DeleteKeyPresenceParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		KeyID:          keyID,
	}); err != nil {
		return constraint(err)
	}
	for _, row := range rows {
		if err := r.q.InsertKeyPresence(ctx, pggen.InsertKeyPresenceParams{
			ChainOrgID:     string(chain.Org),
			ChainProjectID: string(chain.Project),
			KeyID:          keyID,
			EnvironmentID:  row.EnvironmentID,
			Rule:           row.Rule,
		}); err != nil {
			return constraint(err)
		}
	}
	return nil
}

func (r pgCatalogue) DeletePresenceForEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreCataloguePresenceCascade, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.DeleteEnvironmentPresence(ctx, pggen.DeleteEnvironmentPresenceParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		EnvironmentID:  string(chain.Env), // chain column: proof-bound
	}))
}

func (r pgCatalogue) SchemaRevision(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreCatalogueRevisionGet, r.tok)
	if err != nil {
		return 0, err
	}
	rev, err := r.q.GetProjectSchemaRevision(ctx, pggen.GetProjectSchemaRevisionParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return rev, err
}

func (r pgCatalogue) BumpSchemaRevision(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreCatalogueRevisionBump, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.BumpProjectSchemaRevision(ctx, pggen.BumpProjectSchemaRevisionParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	}))
}

func keyFromPG(row pggen.Key) (CatalogueKey, error) {
	if !row.CreatedAt.Valid {
		return CatalogueKey{}, errors.New("store: key " + row.ID + ": null created_at")
	}
	return CatalogueKey{
		ID:              row.ID,
		OrgID:           row.OrgID,
		ProjectID:       row.ProjectID,
		Name:            row.Name,
		FolderPath:      row.FolderPath,
		Classification:  row.Classification,
		Description:     row.Description,
		Deprecated:      row.Deprecated,
		DeprecationNote: row.DeprecationNote,
		Declaration:     row.Declaration,
		RequiredMode:    row.RequiredMode,
		ForbiddenMode:   row.ForbiddenMode,
		GroupID:         row.GroupID.String,
		CreatedAt:       row.CreatedAt.Time.UTC(),
	}, nil
}

func groupFromPG(row pggen.KeyGroup) (CatalogueGroup, error) {
	if !row.CreatedAt.Valid {
		return CatalogueGroup{}, errors.New("store: key group " + row.ID + ": null created_at")
	}
	return CatalogueGroup{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, CreatedAt: row.CreatedAt.Time.UTC(),
	}, nil
}
