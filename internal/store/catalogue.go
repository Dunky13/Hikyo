package store

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
)

// The key catalogue's storage shapes (#49). "Catalogue" rather than "Keys":
// this package already owns a KeyRepo, which is the KEYRING — wrapped crypto
// material (#43). The two senses of "key" are unrelated and never share a
// name here.
//
// Everything in this file is addressed WITHIN a project: the scope lattice has
// no key level (permission-model ADR: no key-scoped grants in v1), so a key id
// is an ordinary argument that can only resolve inside the project the proof
// already authorized. An id from another project simply misses the chain
// predicate, which is the uniform nonexistent outcome.

// CatalogueKey is one declared Key: a tenant-owned aggregate (chain: org,
// project) whose identity is the immutable id and whose name is a mutable
// label on it.
//
// Declaration holds the canonical JSON of the value-dependent rules
// (internal/schema); this package stores and returns it verbatim and does not
// interpret it — parsing rules is the schema package's authority, and a second
// interpreter is a second set of semantics.
type CatalogueKey struct {
	ID              string
	OrgID           string
	ProjectID       string
	Name            string
	FolderPath      string
	Classification  string
	Description     string
	Deprecated      bool
	DeprecationNote string
	Declaration     string
	RequiredMode    string
	ForbiddenMode   string
	// GroupID is "" when the key belongs to no group. A key belongs to at most
	// one, so this is a column rather than a join table.
	GroupID   string
	CreatedAt time.Time
}

// NewCatalogueKey carries the caller-suppliable fields of a key insert; chain
// columns are bound from the proof, as with every other aggregate.
type NewCatalogueKey struct {
	ID              string
	Name            string
	FolderPath      string
	Classification  string
	Description     string
	Deprecated      bool
	DeprecationNote string
	Declaration     string
	RequiredMode    string
	ForbiddenMode   string
	GroupID         string
	CreatedAt       time.Time
}

// KeyMetadata is exactly the NON-semantic field set: it cannot change what any
// environment delivers or whether it validates, which is why the schema ADR
// exempts it from per-environment publish authorization. Its own type so a
// semantic field cannot be smuggled into a metadata write.
type KeyMetadata struct {
	FolderPath      string
	Description     string
	Deprecated      bool
	DeprecationNote string
}

// KeyDeclaration is the semantic half: the value-dependent rules plus the two
// presence modes, replaced as one unit.
type KeyDeclaration struct {
	Declaration   string
	RequiredMode  string
	ForbiddenMode string
}

// CatalogueGroup is a named, project-level key group.
type CatalogueGroup struct {
	ID        string
	OrgID     string
	ProjectID string
	Name      string
	CreatedAt time.Time
}

// NewCatalogueGroup carries the caller-suppliable fields of a group insert.
type NewCatalogueGroup struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// KeyPresence is one row of an explicit presence set: this key is required (or
// forbidden) in this environment. `mode: all` and `mode: none` produce no rows
// at all — `all` is symbolic and must keep covering environments created
// later, so expanding it into ids here would silently exempt them.
type KeyPresence struct {
	KeyID         string
	EnvironmentID string
	Rule          string // required | forbidden
}

// Presence rule values, fixed here because they are a stored enum.
const (
	PresenceRuleRequired  = "required"
	PresenceRuleForbidden = "forbidden"
)

// CatalogueReader is the read side of the catalogue.
type CatalogueReader interface {
	Get(ctx context.Context, p authz.Proof, id string) (CatalogueKey, error)
	List(ctx context.Context, p authz.Proof) ([]CatalogueKey, error)
	// Count is the per-project key cap's input, read inside the same
	// transaction as the insert it bounds.
	Count(ctx context.Context, p authz.Proof) (int64, error)
	GetGroup(ctx context.Context, p authz.Proof, id string) (CatalogueGroup, error)
	ListGroups(ctx context.Context, p authz.Proof) ([]CatalogueGroup, error)
	CountGroups(ctx context.Context, p authz.Proof) (int64, error)
	// ListPresence returns every explicit presence row in the project. It is
	// project-wide rather than per-key because the group conflict check is a
	// property of a SET of keys, and one read is both cheaper and impossible
	// to get half-right.
	ListPresence(ctx context.Context, p authz.Proof) ([]KeyPresence, error)
	// SchemaRevision is the project's monotonic key-catalogue revision.
	SchemaRevision(ctx context.Context, p authz.Proof) (int64, error)
}

// CatalogueRepo is the full catalogue aggregate.
type CatalogueRepo interface {
	CatalogueReader
	Create(ctx context.Context, p authz.Proof, key NewCatalogueKey) error
	// Rename touches the mutable label only — identity is the immutable id, so
	// a rename never breaks a reference. It IS a content-affecting schema
	// change, because it changes the delivered payload's key set.
	Rename(ctx context.Context, p authz.Proof, id, name string) error
	UpdateMetadata(ctx context.Context, p authz.Proof, id string, m KeyMetadata) error
	UpdateDeclaration(ctx context.Context, p authz.Proof, id string, d KeyDeclaration) error
	// SetClassification is reached only by the reclassification ceremony; no
	// ordinary update path writes this column.
	SetClassification(ctx context.Context, p authz.Proof, id, classification string) error
	// SetGroup moves a key into a group, or out of every group when groupID is
	// "". A key belongs to at most one group, so this is a set, not an append.
	SetGroup(ctx context.Context, p authz.Proof, id, groupID string) error
	Delete(ctx context.Context, p authz.Proof, id string) error

	CreateGroup(ctx context.Context, p authz.Proof, group NewCatalogueGroup) error
	RenameGroup(ctx context.Context, p authz.Proof, id, name string) error
	DeleteGroup(ctx context.Context, p authz.Proof, id string) error
	// ClearGroupMembers takes a group's members out of it. Deleting a group
	// dissolves the coupling; it never deletes the keys it coupled.
	ClearGroupMembers(ctx context.Context, p authz.Proof, groupID string) error

	// ReplacePresence rewrites one key's explicit sets whole, so a partial
	// presence set cannot be observed.
	ReplacePresence(ctx context.Context, p authz.Proof, keyID string, rows []KeyPresence) error
	// DeletePresenceForEnvironment cascades a deleted environment's id out of
	// every explicit presence set. It addresses the environment through the
	// proof's chain, so it runs in the same transaction as the delete that
	// earned it.
	DeletePresenceForEnvironment(ctx context.Context, p authz.Proof) error

	// BumpSchemaRevision advances the project's key-catalogue revision. It is
	// called exactly where a SEMANTIC declaration change commits: metadata
	// moves nothing, so it moves no revision.
	BumpSchemaRevision(ctx context.Context, p authz.Proof) error
}
