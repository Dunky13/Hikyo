package store

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
)

// Revisions, drafts and publishing storage shapes (#51, revision-model ADR).
//
// This package never sees plaintext here either: a pending change's material
// and a snapshot entry's material both arrive sealed under the project DEK and
// leave sealed. A draft is stored exactly like a published value because the
// permission-model ADR treats it exactly like one -- "a pending secret's plaintext
// remains reveal-gated exactly as a published one is".

// PendingOperation is what a draft does to its cell. Two states, because
// presence is two states: `set` carries material, `unset` carries none.
type PendingOperation string

const (
	PendingSet   PendingOperation = "set"
	PendingUnset PendingOperation = "unset"
)

type PendingSource string

const (
	PendingSourceValues  PendingSource = "values"
	PendingSourceRestore PendingSource = "restore"
)

// PendingChange is one immutable draft version owned by one principal.
type PendingChange struct {
	// ID is the immutable version id a publish names. Editing the cell mints a
	// new one; this row is collected rather than mutated.
	ID            string
	OrgID         string
	ProjectID     string
	EnvironmentID string
	KeyID         string
	OwnerID       string
	Operation     PendingOperation
	// Ciphertext is nil exactly when Operation is PendingUnset.
	Ciphertext []byte
	// StagedFromRevision is the environment's published revision at staging
	// time. Provenance a client shows, never a check.
	StagedFromRevision int64
	// StagedFromEntry is the published value-entry row id this cell held when
	// the draft was staged, "" when the cell was absent. THIS is the freshness
	// check: the rule is stated per entry, not per environment.
	StagedFromEntry string
	CreatedAt       time.Time
	Source          PendingSource
	// Secret is sticky occurrence metadata retained with the draft even after
	// historical payload collection.
	Secret bool
	// MaterialSecret classifies the value being staged, independently from a
	// secret current-side comparison that may only make the preview sensitive.
	MaterialSecret bool
}

// PendingMarker is a pending change stripped of its material: what another
// principal may learn about a draft is write-presence, and this type is that
// rule in the type system rather than in a review comment.
type PendingMarker struct {
	ID            string
	EnvironmentID string
	KeyID         string
	OwnerID       string
	Operation     PendingOperation
}

// NewPendingChange carries the caller-suppliable fields of a draft write; the
// chain columns and the environment are bound from the proof.
type NewPendingChange struct {
	ID                 string
	KeyID              string
	OwnerID            string
	Operation          PendingOperation
	Ciphertext         []byte
	StagedFromRevision int64
	StagedFromEntry    string
	CreatedAt          time.Time
	Source             PendingSource
	Secret             bool
	MaterialSecret     bool
}

// Snapshot is the immutable per-(project, environment) materialization's
// header. It carries the pinned schema revision; it deliberately carries no
// change token, which is derived from the current root token key at read.
type Snapshot struct {
	ID              string
	OrgID           string
	ProjectID       string
	EnvironmentID   string
	Revision        int64
	SchemaRevision  int64
	PublishedBy     string
	PublishedAt     time.Time
	PayloadPresent  bool
	CollectedAt     *time.Time
	CollectedPolicy string
}

// NewSnapshot carries the caller-suppliable fields of a snapshot insert.
type NewSnapshot struct {
	ID             string
	Revision       int64
	SchemaRevision int64
	PublishedBy    string
	PublishedAt    time.Time
}

// SnapshotEntry is one delivered key of one snapshot. Name and classification
// are the snapshot's own copies: the delivered key set is a property of the
// pinned schema revision, not of the live catalogue.
type SnapshotEntry struct {
	ID             string
	OrgID          string
	ProjectID      string
	EnvironmentID  string
	SnapshotID     string
	KeyID          string
	KeyName        string
	Classification string
	Ciphertext     []byte
	// ValueEntryID is the pinned value-entry revision this entry materialized
	// from. Metadata, not a reference -- the cell is delete-then-insert, and
	// the snapshot must keep answering after the cell moves on.
	ValueEntryID string
}

// NewSnapshotEntry carries the caller-suppliable fields of an entry insert.
type NewSnapshotEntry struct {
	ID             string
	SnapshotID     string
	KeyID          string
	KeyName        string
	Classification string
	Ciphertext     []byte
	ValueEntryID   string
}

// RevisionChange is one lineage row: which key changed how, in which revision.
// It never holds a value, and that is what makes payload collection real.
type RevisionChange string

const (
	RevisionChangeAdded   RevisionChange = "added"
	RevisionChangeEdited  RevisionChange = "edited"
	RevisionChangeRemoved RevisionChange = "removed"
)

// RevisionKeyChange is one lineage row.
type RevisionKeyChange struct {
	EnvironmentID string
	Revision      int64
	KeyID         string
	KeyName       string
	Change        RevisionChange
}

// PendingReader is the read side of the draft model.
type PendingReader interface {
	// ListForOwner returns one principal's whole working state in the proof's
	// project, material included. There is deliberately no statement that
	// returns another principal's material.
	ListForOwner(ctx context.Context, p authz.Proof, ownerID string) ([]PendingChange, error)
	// ListForOwnerInEnvironment is the pending-draft preview read. Owner and
	// environment are both bound into its SQL predicate; no post-query filter
	// is trusted with another principal's ciphertext.
	ListForOwnerInEnvironment(ctx context.Context, p authz.Proof, ownerID string) ([]PendingChange, error)
	// ListMarkers returns every principal's drafts in the proof's project,
	// without material.
	ListMarkers(ctx context.Context, p authz.Proof) ([]PendingMarker, error)
}

// PendingRepo is the full draft aggregate.
type PendingRepo interface {
	PendingReader
	// Stage collects the owner's superseded version for the cell and writes the
	// new one, in that order and in one transaction.
	Stage(ctx context.Context, p authz.Proof, change NewPendingChange) error
	// Discard removes one version by id from the proof's environment. It
	// reports whether a row existed, so a publish can tell "published it" from
	// "it was already gone".
	Discard(ctx context.Context, p authz.Proof, id string) (bool, error)
	// DiscardEnvironment removes the proof's environment's whole draft set, in
	// the transaction that deletes the environment.
	DiscardEnvironment(ctx context.Context, p authz.Proof) error
	// DiscardKey removes every draft referencing one key across the proof's
	// project, in the transaction that deletes the key.
	DiscardKey(ctx context.Context, p authz.Proof, keyID string) (int64, error)
	// CountForProjectExcludingCell counts the project's pending rows other than
	// the (env, key, owner) cell about to be staged — under the stage proof,
	// since the count is part of admitting a stage. Stage is delete-then-insert,
	// so excluding the cell makes the count the size the project would have
	// AROUND the new row: the caller refuses when it has reached the per-project
	// pending cap.
	CountForProjectExcludingCell(ctx context.Context, p authz.Proof, keyID, ownerID string) (int64, error)
	// ListForReencrypt / Reencrypt are the reencrypt walk's page + in-place
	// re-seal of pending-draft ciphertext (project-wide, keyset by id). Unset
	// drafts (NULL ciphertext) are skipped by the query.
	ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptFieldRow, error)
	Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error)
}

// ReencryptFieldRow is one project_field row the reencrypt walk considers.
// SnapshotID is set for snapshot entries and empty for pending drafts, matching
// each table's AAD (the snapshot AAD binds it; the pending AAD does not). Owner
// is the AAD's owner_row_id where it differs from the primary key: an adapter
// route move is keyed by its own id but its credential AAD binds the ADAPTER's
// id, so Owner carries the adapter_id while ID (used for the CAS and cursor)
// stays the move's id. Empty Owner means "same as ID".
type ReencryptFieldRow struct {
	ID            string
	EnvironmentID string
	KeyID         string
	SnapshotID    string
	Owner         string
	Ciphertext    []byte
}

// SnapshotReader is the read side of the published state.
type SnapshotReader interface {
	// Latest returns the proof's environment's newest snapshot, or ErrNotFound
	// when the environment has never been materialized.
	Latest(ctx context.Context, p authz.Proof) (Snapshot, error)
	// AtRevision returns one named revision, or ErrNotFound.
	AtRevision(ctx context.Context, p authz.Proof, revision int64) (Snapshot, error)
	// List returns the environment's revision history, newest first.
	List(ctx context.Context, p authz.Proof) ([]Snapshot, error)
	// Entries returns one snapshot's resolved map, ordered by key name.
	Entries(ctx context.Context, p authz.Proof, snapshot Snapshot) ([]SnapshotEntry, error)
	// SecretValueOccurrenceIDs returns the payload-free sticky sensitivity
	// lineage for this environment.
	SecretValueOccurrenceIDs(ctx context.Context, p authz.Proof) ([]string, error)
	// Changes returns one revision's lineage rows.
	Changes(ctx context.Context, p authz.Proof, revision int64) ([]RevisionKeyChange, error)
	// ProjectRevisions returns the latest published revision per environment
	// across the whole project, under a PROJECT proof — the definitions
	// plan/apply value-snapshot pin (#70). Environments with no snapshot are
	// absent from the map (revision 0).
	ProjectRevisions(ctx context.Context, p authz.Proof) (map[string]int64, error)
	// PayloadBytesForProject sums the ciphertext bytes of the proof's project's
	// published snapshot entries across every environment and revision — the
	// other half of the per-project storage high-water accounting (#185).
	PayloadBytesForProject(ctx context.Context, p authz.Proof) (int64, error)
	// InstancePayloadByProject sums published snapshot-entry ciphertext bytes
	// grouped by owning project across the whole instance — the operator storage
	// surface (doctor warn, metric). Instance-scoped, cross-tenant by definition.
	InstancePayloadByProject(ctx context.Context, p authz.Proof) ([]ProjectPayloadBytes, error)
}

// SnapshotRepo is the full published-state aggregate. There is no update and
// no delete-by-revision: a snapshot is immutable, and history is never
// rewritten. The only removal is the environment cascade, and payload
// retention (#52) will add its own collection path beside it.
type SnapshotRepo interface {
	SnapshotReader
	Insert(ctx context.Context, p authz.Proof, snapshot NewSnapshot) error
	InsertEntry(ctx context.Context, p authz.Proof, entry NewSnapshotEntry) error
	RecordSecretValueOccurrence(ctx context.Context, p authz.Proof, valueEntryID string) error
	InsertChange(ctx context.Context, p authz.Proof, revision int64, keyID, keyName string, change RevisionChange) error
	// DeleteEnvironment removes the environment's snapshots, their entries and
	// their lineage, in the transaction that deletes the environment.
	DeleteEnvironment(ctx context.Context, p authz.Proof) error
	// ListForReencrypt / Reencrypt are the reencrypt walk's page + in-place
	// re-seal of snapshot-entry ciphertext (project-wide, keyset by id).
	ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptFieldRow, error)
	Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error)
}

// RevisionPin is one durable delivery route and retention reference.
type RevisionPin struct {
	ID                   string
	OrgID                string
	ProjectID            string
	EnvironmentID        string
	WorkloadPrincipalID  string
	SnapshotID           string
	Revision             int64
	AuthorityPrincipalID string
	ExpiresAt            time.Time
	CreatedAt            time.Time
	AuthorizedAt         time.Time
	HistoryAuthorized    bool
	SchemaOverride       bool
}

type NewRevisionPin struct {
	ID                   string
	WorkloadPrincipalID  string
	SnapshotID           string
	Revision             int64
	AuthorityPrincipalID string
	ExpiresAt            time.Time
	CreatedAt            time.Time
	AuthorizedAt         time.Time
	HistoryAuthorized    bool
	SchemaOverride       bool
}

type RevisionPinReader interface {
	GetForWorkload(ctx context.Context, p authz.Proof, workloadPrincipalID string) (RevisionPin, error)
	List(ctx context.Context, p authz.Proof) ([]RevisionPin, error)
}

type RevisionPinRepo interface {
	RevisionPinReader
	CountProject(ctx context.Context, p authz.Proof) (int64, error)
	Insert(ctx context.Context, p authz.Proof, pin NewRevisionPin) error
	Delete(ctx context.Context, p authz.Proof, workloadPrincipalID string) (bool, error)
	DeleteEnvironment(ctx context.Context, p authz.Proof) error
}
