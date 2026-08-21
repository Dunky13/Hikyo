package store

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
)

// The flat value model's storage shapes (#50, flat-model ADR).
//
// A ValueEntry is one `(key, environment)` cell that is `set`. There is no
// presence field and no `absent` row: PRESENCE IS THE ROW'S EXISTENCE, and the
// deleted `masked` state has no representation anywhere in this package. That
// is not a shortcut — it is what makes "no fallback source exists" a property
// of the schema instead of a promise the service layer has to keep.
//
// This package never sees plaintext. Ciphertext arrives sealed by the caller
// under the project DEK and leaves sealed; the AAD that binds it to this row
// is the service layer's to build, from the same columns stored here.

// ValueEntry is a stored value cell.
type ValueEntry struct {
	// ID is bound into the ciphertext's AAD, so it is immutable and never
	// reused: a rewrite of the same cell mints a new id.
	ID            string
	OrgID         string
	ProjectID     string
	EnvironmentID string
	KeyID         string
	Ciphertext    []byte
	UpdatedAt     time.Time
	// UpdatedBy is the principal whose act produced this occurrence — the
	// supply record the re-delivery gate reasons about.
	UpdatedBy string
}

// NewValueEntry carries the caller-suppliable fields of a value write. The
// chain columns and the environment are bound from the proof.
type NewValueEntry struct {
	ID         string
	KeyID      string
	Ciphertext []byte
	UpdatedAt  time.Time
	UpdatedBy  string
}

// ValueReader is the read side of the value model.
type ValueReader interface {
	// Get returns one cell of the proof's environment, or ErrNotFound — which
	// IS `absent`, the only non-`set` state there is.
	Get(ctx context.Context, p authz.Proof, keyID string) (ValueEntry, error)
	// List returns the proof's environment's entire set, ordered by key id.
	// This is the delivery-shaped read and the diff's per-side read.
	List(ctx context.Context, p authz.Proof) ([]ValueEntry, error)
	// EnvironmentsWithValue names the environments in the proof's PROJECT that
	// hold a value for one key. It spans environments deliberately: deleting a
	// key must be able to say which environments still deliver material for
	// it, and that answer cannot be assembled one authorized environment at a
	// time without becoming a different (and racier) question.
	EnvironmentsWithValue(ctx context.Context, p authz.Proof, keyID string) ([]string, error)
	// CountEnvironmentValues counts one environment's live occurrences under a
	// PROJECT proof — environment_id is an ordinary column, so the
	// definitions-apply path (project-scoped) can ask it of an environment it is
	// about to delete. Any count above zero is the unconditional
	// environment-delete refusal (#70).
	CountEnvironmentValues(ctx context.Context, p authz.Proof, environmentID string) (int64, error)
	// PayloadBytesForProject sums the ciphertext bytes of the proof's project's
	// live value cells across every environment — half of the per-project
	// storage high-water accounting refused at publish (#185, ops-spec section 8).
	PayloadBytesForProject(ctx context.Context, p authz.Proof) (int64, error)
	// InstancePayloadByProject sums live value-cell ciphertext bytes grouped by
	// owning project across the whole instance — the operator storage surface
	// (doctor warn, metric). Cross-tenant by definition, so its query is
	// instance-scoped; the proof licenses the read, not a tenant chain.
	InstancePayloadByProject(ctx context.Context, p authz.Proof) ([]ProjectPayloadBytes, error)
}

// ProjectPayloadBytes is one project's stored ciphertext-byte total, from the
// instance-scoped storage sweep behind the high-water operator surface (#185).
type ProjectPayloadBytes struct {
	OrgID     string
	ProjectID string
	Bytes     int64
}

// ValueRepo is the full value aggregate.
type ValueRepo interface {
	ValueReader
	// Put writes one cell of the proof's environment. It is delete-then-insert
	// rather than an upsert because the row id is bound into the AAD: reusing
	// the id of a superseded occurrence is the one thing the encryption-model ADR
	// forbids outright.
	Put(ctx context.Context, p authz.Proof, entry NewValueEntry) error
	// Clear removes one cell — the `set` → `absent` transition, which with no
	// inheritance leaves nothing behind to fall back to. Removing a cell that
	// is already absent is not an error: absence is the state, not the act. It
	// reports whether a row actually existed, so the caller emits the
	// value.cleared event only for a transition that really happened.
	Clear(ctx context.Context, p authz.Proof, keyID string) (bool, error)
	// ClearEnvironment removes the proof's environment's whole set, in the
	// transaction that deletes the environment itself.
	ClearEnvironment(ctx context.Context, p authz.Proof) error
	// ClearKey removes a key's occurrences across every environment under a
	// PROJECT proof, in the definitions-apply transaction that deletes the key
	// with --allow-delete (#70). Returns the number of occurrences removed.
	ClearKey(ctx context.Context, p authz.Proof, keyID string) (int64, error)
	// ListForReencrypt pages a project's entire value set by id (keyset cursor,
	// "" for the first page), for the reencrypt walk. Project-scoped: spans every
	// environment.
	ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptValueRow, error)
	// Reencrypt re-seals one value row's ciphertext in place (same id, same AAD,
	// new DEK version), compare-and-swapping on the old ciphertext. Reports
	// whether the row moved (false = a concurrent write already replaced it).
	Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error)
}

// ReencryptValueRow is one value row the reencrypt walk considers: its id, the
// AAD-reconstruction fields, and the current ciphertext (whose header names the
// DEK version it is sealed under).
type ReencryptValueRow struct {
	ID            string
	EnvironmentID string
	KeyID         string
	Ciphertext    []byte
}
