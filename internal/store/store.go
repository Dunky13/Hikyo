// Package store owns datastore access. All generated query code sits behind
// per-aggregate repository interfaces here — no service code ever sees a pgx
// or sqlite type. Canonical cross-engine semantics are fixed in this package:
// timestamps UTC (RFC 3339 text on sqlite, timestamptz on postgres, both
// truncated to microseconds), booleans as integers on sqlite, JSON as text
// validated at the boundary.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

type Engine string

const (
	EngineSQLite   Engine = "sqlite"
	EnginePostgres Engine = "postgres"
)

// Config selects and locates the datastore. Exactly one of Path (sqlite) or
// DSN (postgres) is used, per Engine.
type Config struct {
	Engine Engine
	Path   string
	DSN    string
}

// Org is the tenancy boundary. Creation, listing and counting are
// instance-scoped (cross-tenant by definition: a create has no parent tenant
// and an enumeration spans all of them). Every BY-ID operation is tenant-owned
// at org depth — the addressed id comes from the proof's chain like any other
// tenant address, which is what makes an org the caller may not reach
// indistinguishable from one that does not exist (#48, mvp-boundary C1).
type Org struct {
	ID        string
	Name      string
	Active    bool
	Metadata  json.RawMessage
	CreatedAt time.Time
	Retention RetentionPolicy
}

// Project is a tenant-owned aggregate (chain: org). OrgID appears on reads
// only; writes bind it from the proof.
type Project struct {
	ID                string
	OrgID             string
	Name              string
	CreatedAt         time.Time
	RetentionOverride *RetentionPolicy
	// DefinitionsSource is `db` or `git` (#70). In `git` the definition-write
	// chokepoint refuses every ordinary edit and only definitions apply writes.
	DefinitionsSource string
}

// RetentionPolicy is the stored keep-if-either payload policy. Unlimited is
// valid only on an organization row; project overrides are always bounded.
type RetentionPolicy struct {
	Unlimited     bool
	MaxAge        time.Duration
	LastRevisions int64
}

// NewProject carries the caller-suppliable fields of a project insert. It
// deliberately has no chain fields: the org id is bound from the proof by
// the repository layer, so caller arguments structurally cannot reach the
// chain columns (tenant-isolation ADR § row shape and lookup discipline).
type NewProject struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Environment is a tenant-owned aggregate (chain: org, project).
//
// DisplayOrder is the user-defined display position within the project. There
// is deliberately no `base` field and no defaults layer of any kind: the
// flat-model ADR deletes both, and a dormant column would be the structure it
// forbids.
type Environment struct {
	ID           string
	OrgID        string
	ProjectID    string
	Name         string
	Note         string
	DisplayOrder int64
	CreatedAt    time.Time
}

// NewEnvironment carries the caller-suppliable fields of an environment
// insert; chain columns are bound from the proof, as with NewProject.
type NewEnvironment struct {
	ID           string
	Name         string
	Note         string
	DisplayOrder int64
	CreatedAt    time.Time
}

// Folder is a tenant-owned aggregate (chain: org, project), organizational
// only: namespace + display grouping. No folder-scoped grants exist
// (permission-model ADR) and no value ever attaches to one (domain-model), so
// the row carries its path and nothing else.
type Folder struct {
	ID        string
	OrgID     string
	ProjectID string
	Path      string
	CreatedAt time.Time
}

// NewFolder carries the caller-suppliable fields of a folder insert; chain
// columns are bound from the proof, as with NewProject.
type NewFolder struct {
	ID        string
	Path      string
	CreatedAt time.Time
}

// Every repository method takes a proof as its first argument (after ctx)
// and verifies it at the store boundary before touching any query — nil,
// foreign-transaction, ended-transaction and operation-mismatched proofs are
// rejected fail-closed. Tenant-owned aggregates take no identifiers at all:
// the addressed chain comes out of the proof, which authorize() resolved
// in this same transaction.

// OrgReader is the read side of the orgs aggregate. Get takes no id: the org
// it returns is the one the proof's chain addresses. List and Count are the
// instance-scoped enumerations and carry no address at all.
type OrgReader interface {
	Get(ctx context.Context, p authz.Proof) (Org, error)
	List(ctx context.Context, p authz.Proof) ([]Org, error)
	Count(ctx context.Context, p authz.Proof) (int64, error)
}

// OrgRepo is the full per-aggregate repository interface. Only transaction
// closures (internal/store/tx) ever hold one.
type OrgRepo interface {
	OrgReader
	Create(ctx context.Context, p authz.Proof, org Org) error
	// Rename and Delete address the org through the proof's chain. Rename
	// touches the mutable name only — identity is the immutable id, so a
	// rename never breaks a reference.
	Rename(ctx context.Context, p authz.Proof, name string) error
	Lock(ctx context.Context, p authz.Proof) error
	SetRetention(ctx context.Context, p authz.Proof, policy RetentionPolicy) error
	Delete(ctx context.Context, p authz.Proof) error
}

// ProjectReader is the read side of the projects aggregate.
type ProjectReader interface {
	// Get returns the project addressed by the proof's resolved chain.
	Get(ctx context.Context, p authz.Proof) (Project, error)
	// List returns every project in the org the proof addresses.
	List(ctx context.Context, p authz.Proof) ([]Project, error)
	// ListAll returns (org id, name) for every project on the instance,
	// under an instance-scope proof addressing no tenant. It exists for the
	// multi-instance directory (#71), whose served listing is org/project
	// names and counts across org boundaries by design. It is deliberately
	// NOT List in a loop: N tenant proofs for one operation would misreport
	// the operation in the boundary check.
	ListAll(ctx context.Context, p authz.Proof) ([]ProjectName, error)
}

// ProjectName is the directory listing's project row: the two fields the
// served listing may carry, and nothing more. A full Project would hand the
// caller an id and a creation time the directory has no licence to publish.
type ProjectName struct {
	OrgID string
	Name  string
}

// ProjectRepo is the full projects aggregate.
type ProjectRepo interface {
	ProjectReader
	Create(ctx context.Context, p authz.Proof, proj NewProject) error
	Rename(ctx context.Context, p authz.Proof, name string) error
	SetRetention(ctx context.Context, p authz.Proof, policy *RetentionPolicy) error
	// SetDefinitionsSource writes the git/db definitions mode (#70). It is a
	// project-settings write, off the definitions-edit path.
	SetDefinitionsSource(ctx context.Context, p authz.Proof, source string) error
	Delete(ctx context.Context, p authz.Proof) error
	// Lock takes the project row for the rest of the transaction, so every
	// mutation of that project's environment SET serializes: the cap check and
	// the append position are both read-then-write, and postgres would
	// otherwise let two transactions at cap-1 both pass. ErrNotFound when the
	// project is gone — the uniform outcome, as everywhere.
	Lock(ctx context.Context, p authz.Proof) error
}

// EnvironmentReader is the read side of the environments aggregate.
type EnvironmentReader interface {
	// Get returns the environment addressed by the proof's resolved chain.
	Get(ctx context.Context, p authz.Proof) (Environment, error)
	// List returns the project's environments in display order.
	List(ctx context.Context, p authz.Proof) ([]Environment, error)
	// Count is the environment-count cap's input, read inside the same
	// transaction as the insert it bounds.
	Count(ctx context.Context, p authz.Proof) (int64, error)
	// NextOrder is the append position: one past the highest display order in
	// use. It is NOT the count — deleting an environment leaves a gap on
	// purpose, so a count would hand the next create a position another row
	// already holds.
	NextOrder(ctx context.Context, p authz.Proof) (int64, error)
	// Settings reads the environment's protection state and its own
	// reauthentication window (#55). The proof addresses the environment.
	Settings(ctx context.Context, p authz.Proof) (EnvironmentSettings, error)
	// ListProtection reads every environment's protected flag under a PROJECT
	// proof — the definitions plan/apply protected-set pin (#70).
	ListProtection(ctx context.Context, p authz.Proof) ([]EnvironmentProtection, error)
}

// EnvironmentProtection is one environment's identity and protected flag.
type EnvironmentProtection struct {
	ID        string
	Protected bool
}

// EnvironmentSettings is the per-environment half of `project-settings`.
// HasWindow false means the environment inherits the instance default: a
// stored copy of that default would freeze it at creation time.
type EnvironmentSettings struct {
	Protected bool
	HasWindow bool
	Window    time.Duration
}

// EnvironmentRepo is the full environments aggregate.
type EnvironmentRepo interface {
	EnvironmentReader
	// SetSettings writes the protection state and window together: marking
	// an environment protected CAPS its window, so the two are one fact and
	// must not be writable apart.
	SetSettings(ctx context.Context, p authz.Proof, s EnvironmentSettings) error
	Create(ctx context.Context, p authz.Proof, env NewEnvironment) error
	// UpdateNote mutates the non-chain note column of the environment
	// addressed by the proof's chain. Chain columns are immutable —
	// re-parenting is a new row (tenant-isolation ADR).
	UpdateNote(ctx context.Context, p authz.Proof, note string) error
	Rename(ctx context.Context, p authz.Proof, name string) error
	// SetOrder writes one environment's display position. The whole ordered
	// set is rewritten by one authorized operation in one transaction, so a
	// partial reorder cannot be observed.
	SetOrder(ctx context.Context, p authz.Proof, id string, order int64) error
	Delete(ctx context.Context, p authz.Proof) error
}

// FolderReader is the read side of the folders aggregate. A folder is
// addressed by (proof chain, id): the scope lattice has no folder level, so
// the id is an ordinary argument that can only ever resolve inside the
// project the proof already authorized.
type FolderReader interface {
	Get(ctx context.Context, p authz.Proof, id string) (Folder, error)
	List(ctx context.Context, p authz.Proof) ([]Folder, error)
}

// FolderRepo is the full folders aggregate.
type FolderRepo interface {
	FolderReader
	Create(ctx context.Context, p authz.Proof, folder NewFolder) error
	Rename(ctx context.Context, p authz.Proof, id, path string) error
	Delete(ctx context.Context, p authz.Proof, id string) error
}

// Remote is one connection entry: this instance's named pointer at another
// one (#71, multi-instance ADR § The connection entry).
//
// There is deliberately NO credential field. URL and pin are immutable and the
// sealed credential is write-only after storage, so the ordinary read cannot
// hand it out by accident — reaching it is the separate, greppable
// SealedCredential call, and that call exists so the fetch path can PRESENT the
// value, never so a surface can display it.
type Remote struct {
	ID   string
	Name string
	URL  string
	// SPKIPin is base64(sha256(SubjectPublicKeyInfo)), verified on every
	// connection before any request is written.
	SPKIPin   string
	CreatedAt time.Time
	CreatedBy domain.PrincipalID
}

// NewRemote is one entry insert. It is the only carrier that names the sealed
// credential, and it names it once.
type NewRemote struct {
	ID               string
	Name             string
	URL              string
	SPKIPin          string
	CredentialSealed []byte
	CreatedAt        time.Time
	CreatedBy        domain.PrincipalID
}

// RemoteSnapshot is one entry's last-known directory listing.
//
// TWO CLOCKS, deliberately separate. LastAttemptAt/LastOutcome record the most
// recent FETCH; ObservedAt and the listing fields record the most recent
// SUCCESS. That split is the whole freshness model: an unreachable remote
// serves its last-known listing marked stale with its age, never silently as
// current, and a credential rejection is a distinct loud state because the
// operator's fix differs.
//
// LastOutcome is a plain string here rather than remotefetch.Outcome: the
// store must not depend on the outbound client, and the column's own CHECK is
// what makes the enum total. A value outside it fails loud at the write.
type RemoteSnapshot struct {
	RemoteID      string
	LastAttemptAt time.Time
	LastOutcome   string
	// ObservedAt is the zero time until the first successful fetch. The
	// listing fields are meaningful IFF it is non-zero — the table's CHECK
	// makes the pairing total, so a zero-count "listing" cannot be stored.
	ObservedAt       time.Time
	InstanceIdentity string
	Version          string
	OrgCount         int64
	ProjectCount     int64
	// Listing is the org/project names as fetched, stored as JSON. It is
	// foreign structure at rest and holds nothing value-bearing: the
	// credential that produced it may read nothing else.
	Listing json.RawMessage
}

// RemoteReader is the read side of the remotes aggregate (viewing side).
// Every method takes an instance-scope proof: remotes address no tenant.
type RemoteReader interface {
	List(ctx context.Context, p authz.Proof) ([]Remote, error)
	Get(ctx context.Context, p authz.Proof, id string) (Remote, error)
	// GetByName is the CLI's addressing mode — `remote show <name>`,
	// `remote remove <name>` — and the uniqueness the schema already enforces
	// is what makes it single-valued.
	GetByName(ctx context.Context, p authz.Proof, name string) (Remote, error)
	// Count is the RemoteCount cap's input, read inside the same transaction
	// as the insert it bounds.
	Count(ctx context.Context, p authz.Proof) (int64, error)
	Snapshots(ctx context.Context, p authz.Proof) ([]RemoteSnapshot, error)
	Snapshot(ctx context.Context, p authz.Proof, remoteID string) (RemoteSnapshot, error)
	// SealedCredential is the ONLY reader of the stored credential. It is a
	// distinct method rather than a field on Remote so that reaching the
	// credential is a greppable act, and it carries its own StoreOp so an
	// operation licensed to LIST remotes is not thereby licensed to present
	// one. It is on the READ side because the on-view fetch reads it in a read
	// transaction — a network fan-out must not hold the write connection.
	SealedCredential(ctx context.Context, p authz.Proof, id string) ([]byte, error)
}

// RemoteRepo is the full remotes aggregate.
type RemoteRepo interface {
	RemoteReader
	Create(ctx context.Context, p authz.Proof, r NewRemote) error
	// Rename touches the display name, the ADR's one mutable field. There is
	// no Repoint: re-pointing a stored credential at a different host is the
	// credential-redirect attack, so it is remove + add, which re-runs the
	// full ceremony including the human fingerprint confirmation.
	Rename(ctx context.Context, p authz.Proof, id, name string) error
	Delete(ctx context.Context, p authz.Proof, id string) error
	// WriteSnapshot records a SUCCESSFUL fetch, listing and all.
	WriteSnapshot(ctx context.Context, p authz.Proof, s RemoteSnapshot) error
	// RecordFetchFailure records the attempt and its outcome and PRESERVES the
	// last known listing — that preservation is what makes "unreachable 2h,
	// last known state shown" possible, and it is why failure is its own
	// method rather than WriteSnapshot with empty fields.
	RecordFetchFailure(ctx context.Context, p authz.Proof, remoteID string, at time.Time, outcome string) error
}

// Repos bundles the full repositories bound to one write transaction.
//
// Keys() is the KEYRING (#43, wrapped crypto material); Catalogue() is the KEY
// CATALOGUE (#49, the project's schema). The two are unrelated senses of the
// word and the accessors keep them apart, so no caller can reach one meaning
// to while holding the other.
type Repos interface {
	Orgs() OrgRepo
	Keys() KeyRepo
	Catalogue() CatalogueRepo
	Values() ValueRepo
	Pending() PendingRepo
	Snapshots() SnapshotRepo
	Pins() RevisionPinRepo
	Retention() RetentionRepo
	Projects() ProjectRepo
	Environments() EnvironmentRepo
	Folders() FolderRepo
	Audit() AuditRepo
	// SCIM is the provisioning surface (#73). It is on the WRITE bundle only:
	// every SCIM read the product performs happens inside a transaction that
	// also writes — the wire reads emit `scim.directory_read`, and the
	// administration reads run beside their own lifecycle events — so a
	// read-only twin would be a surface with no caller.
	SCIM() SCIMRepo
	// Remotes is the multi-instance directory's viewing side (#71).
	Remotes() RemoteRepo
	Adapters() AdapterRepo
	// Definitions is the plan ledger behind definitions plan/apply (#70).
	Definitions() DefinitionsRepo
	// ScanningDismissals is the secret-scanning "keep as config" dismissal
	// surface (#74). It is on the WRITE bundle only: the sticky-match lookup
	// (Exists) runs inside the same value-write transaction that may record a
	// dismissal, so a read-only twin would have no caller — the shape SCIM took
	// for the same reason.
	ScanningDismissals() ScanningDismissalRepo
}

// ScanningDismissalRepo is the proof-bound dismissal-row surface (#74,
// secret-scanning ADR section 4). Every method is authorized against its own
// registered store operation and binds its chain from the proof.
type ScanningDismissalRepo interface {
	// Insert records one "keep as config" acknowledgement. A second insert of
	// the identical (org, project, env, key, rule digest, fingerprint) tuple
	// hits the UNIQUE constraint and surfaces as ErrConflict — the dismissal is
	// already sticky.
	Insert(ctx context.Context, p authz.Proof, d NewDismissal) error
	// Exists is the sticky-match lookup that suppresses a re-warn on a value
	// already accepted for this (key, rule digest, fingerprint) in the proof's
	// environment.
	Exists(ctx context.Context, p authz.Proof, keyID, ruleDigest string, fingerprint []byte) (bool, error)
	// DeleteByKey drops one key's dismissals across every environment
	// (reclassification-to-secret and key deletion; ADR section 4 lifecycle).
	DeleteByKey(ctx context.Context, p authz.Proof, keyID string) (int64, error)
	// DeleteByProject drops a project's dismissals (project deletion; ADR
	// section 4 lifecycle).
	DeleteByProject(ctx context.Context, p authz.Proof) (int64, error)
	// DeleteAll drops every dismissal instance-wide for scanning-key rotation:
	// old fingerprints become unrecomputable and must die.
	DeleteAll(ctx context.Context, p authz.Proof) (int64, error)
}

// ReadRepos bundles the read-only repositories bound to one read
// transaction. There is no proof-free read path: authorization is evaluated
// in-transaction, so reads run under internal/store/tx too.
type ReadRepos interface {
	Orgs() OrgReader
	Keys() KeyReader
	Catalogue() CatalogueReader
	Values() ValueReader
	Pending() PendingReader
	Snapshots() SnapshotReader
	Pins() RevisionPinReader
	Retention() RetentionReader
	Projects() ProjectReader
	Environments() EnvironmentReader
	Folders() FolderReader
	Audit() AuditReader
	Remotes() RemoteReader
	Adapters() AdapterReader
	Definitions() DefinitionsReader
}

// DefinitionsPlan is a stored plan row (#70). Bundle holds the canonical bundle
// bytes; EnvRevisions, ProtectedEnvs and Diff hold canonical JSON. Applied is
// false until a successful apply stamps AppliedAt/AppliedBy and the display-only
// provenance strings.
type DefinitionsPlan struct {
	ID                 string
	OrgID              string
	ProjectID          string
	CreatedBy          string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	Bundle             string
	Digest             string
	BaseSchemaRevision int64
	EnvRevisions       string
	ProtectedEnvs      string
	Diff               string
	Additive           bool
	// ScanSnapshot is the secret-scanning ruleset SnapshotVersion the plan was
	// scanned under (#74 SS3). Apply re-scans iff it differs from the running
	// ruleset's; empty means scanning was off at plan time.
	ScanSnapshot     string
	Applied          bool
	AppliedAt        time.Time
	AppliedBy        string
	ProvenanceCommit string
	ProvenanceRef    string
	ProvenanceActor  string
}

// NewDefinitionsPlan carries the caller-suppliable fields of a plan insert;
// chain columns are bound from the proof.
type NewDefinitionsPlan struct {
	ID                 string
	CreatedBy          string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	Bundle             string
	Digest             string
	BaseSchemaRevision int64
	EnvRevisions       string
	ProtectedEnvs      string
	Diff               string
	Additive           bool
	ScanSnapshot       string
}

// PlanApplyStamp is the one-shot apply record. Commit/Ref/Actor are the
// length-bounded, sanitized display-only provenance labels.
type PlanApplyStamp struct {
	AppliedAt time.Time
	AppliedBy string
	Commit    string
	Ref       string
	Actor     string
}

// DefinitionsReader is the read side of the plan ledger.
type DefinitionsReader interface {
	// GetPlan returns the plan addressed by (proof chain, id). ErrNotFound when
	// absent — the uniform outcome, so unauthorized ≡ nonexistent on the wire.
	GetPlan(ctx context.Context, p authz.Proof, id string) (DefinitionsPlan, error)
	// LatestAppliedPlan returns the project's most recently applied plan, or
	// ErrNotFound when none has ever been applied.
	LatestAppliedPlan(ctx context.Context, p authz.Proof) (DefinitionsPlan, error)
	// CountOpenPlans is the open-plan quota input: unapplied and unexpired at now.
	CountOpenPlans(ctx context.Context, p authz.Proof, now time.Time) (int64, error)
}

// DefinitionsRepo is the full plan ledger.
type DefinitionsRepo interface {
	DefinitionsReader
	CreatePlan(ctx context.Context, p authz.Proof, plan NewDefinitionsPlan) error
	// MarkPlanApplied stamps the apply record. It returns false when the plan was
	// already applied (the guarded update affected no row), which the service
	// maps to the already-applied conflict.
	MarkPlanApplied(ctx context.Context, p authz.Proof, id string, stamp PlanApplyStamp) (bool, error)
	// PruneExpiredPlans deletes expired, unapplied plans across the instance
	// under an instance-scope proof (the hourly GC).
	PruneExpiredPlans(ctx context.Context, p authz.Proof, now time.Time) (int64, error)
}

type AdapterConflictEntry struct {
	Surface       string
	EffectiveName string
}

type AdapterConflictArtifact struct {
	ID               string
	TargetID         string
	JobID            string
	DestinationID    int64
	RepositoryID     int64
	TargetGeneration int64
	Entries          []AdapterConflictEntry
	CreatedAt        time.Time
}

type AdapterTarget struct {
	ID                     string
	AdapterID              string
	Provider               string
	EnvironmentID          string
	Origin                 string
	DestinationKind        string
	DestinationOwner       string
	DestinationName        string
	DestinationEnvironment string
	DestinationID          int64
	RepositoryID           int64
	Visibility             string
	SelectedRepositoryIDs  []int64
	NamePrefix             string
	Generation             int64
	State                  string
	SyncStatus             string
	ConvergedRevision      *int64
	FailureNames           []string
	Warnings               []string
	AuthorityPrincipalID   string
}

type AdapterRecord struct {
	ID                   string
	Provider             string
	Origin               string
	CredentialPresent    bool
	CredentialSetAt      string
	CredentialExpiresAt  string
	AuthorityPrincipalID string
	State                string
	CreatedAt            string
}

type AdapterTargetMutation struct {
	ID                     string
	AdapterID              string
	EnvironmentID          string
	DestinationKind        string
	DestinationOwner       string
	DestinationName        string
	DestinationEnvironment string
	DestinationID          int64
	RepositoryID           int64
	Visibility             string
	SelectedRepositoryIDs  []int64
	NamePrefix             string
	KeyIDs                 []string
}

type AdapterCreate struct {
	ID                   string
	Provider             string
	Origin               string
	CredentialCiphertext []byte
	CredentialExpiresAt  time.Time
	AuthorityPrincipalID string
	Target               AdapterTargetMutation
	At                   time.Time
}

type AdapterConfigureFence struct {
	TargetID               string
	EnvironmentID          string
	DestinationKind        string
	DestinationOwner       string
	DestinationName        string
	DestinationEnvironment string
	Generation             int64
	EffectID               string
	LeaseExpiresAt         time.Time
	At                     time.Time
}

type AdapterTargetUpdate struct {
	Target               AdapterTargetMutation
	ExpectedGeneration   int64
	CredentialExpiresAt  time.Time
	AuthorityPrincipalID string
	At                   time.Time
}

type AdapterTargetUpdateResult struct {
	Target                       AdapterTarget
	Enqueue                      AdapterEnqueueResult
	PreviousAuthorityPrincipalID string
	AuthorityPrincipalID         string
}

type AdapterTargetAddResult struct {
	Target                       AdapterTarget
	PreviousAuthorityPrincipalID string
	AuthorityPrincipalID         string
}

type AdapterRouteMoveMutation struct {
	MoveID               string
	Target               AdapterTargetMutation
	ExpectedGeneration   int64
	AuthorityPrincipalID string
	KeepRemote           bool
	At                   time.Time
}

type AdapterRouteMoveResult struct {
	MoveID          string
	TargetID        string
	JobID           string
	SupersededJobID string
	Generation      int64
	Orphaned        []string
}

type AdapterOriginMoveMutation struct {
	MoveID                      string
	AdapterID                   string
	Origin                      string
	PendingCredentialCiphertext []byte
	AuthorityPrincipalID        string
	KeepRemote                  bool
	At                          time.Time
}

type AdapterRouteMoveBatch struct {
	MoveID   string
	Targets  []AdapterRouteMoveResult
	Orphaned []string
}

type AdapterMoveJob struct {
	ID, TargetID, Kind, State string
}

type AdapterMoveTarget struct {
	TargetID, EnvironmentID, DestinationKind, DestinationOwner, DestinationName, DestinationEnvironment, Visibility, NamePrefix string
	DestinationID, RepositoryID                                                                                                 int64
	SelectedRepositoryIDs                                                                                                       []int64
	Orphaned                                                                                                                    []string
	Jobs                                                                                                                        []AdapterMoveJob
}

type AdapterMove struct {
	ID, AdapterID, Kind, State, PendingOrigin, CreatedAt string
	KeepRemote                                           bool
	Targets                                              []AdapterMoveTarget
	PreviousAuthorityPrincipalID                         string
	AuthorityPrincipalID                                 string
}

type AdapterAdoption struct {
	TargetID             string
	ArtifactID           string
	Entries              []AdapterConflictEntry
	AuthorityPrincipalID string
	LedgerIDs            []string
	JobID                string
	AuditAt              time.Time
}

type AdapterAdoptionResult struct {
	Generation      int64
	JobID           string
	SupersededJobID string
}

type AdapterReader interface {
	Get(ctx context.Context, p authz.Proof, adapterID string) (AdapterRecord, error)
	Configuration(ctx context.Context, p authz.Proof, adapterID string) (AdapterRecord, []byte, error)
	List(ctx context.Context, p authz.Proof) ([]AdapterRecord, error)
	ListTargets(ctx context.Context, p authz.Proof, adapterID string) ([]AdapterTarget, error)
	TargetKeyIDs(ctx context.Context, p authz.Proof, targetID string) ([]string, error)
	Target(ctx context.Context, p authz.Proof, targetID string) (AdapterTarget, error)
	Mapping(ctx context.Context, p authz.Proof, targetID string) ([]adapter.ManifestEntry, error)
	PlanMaterial(ctx context.Context, p authz.Proof, targetID string) (AdapterPlanMaterial, error)
	TargetEnvironments(ctx context.Context, p authz.Proof, targetID string) ([]string, error)
	Environments(ctx context.Context, p authz.Proof, adapterID string) ([]string, error)
	Conflicts(ctx context.Context, p authz.Proof, targetID string) ([]AdapterConflictArtifact, error)
	Move(ctx context.Context, p authz.Proof, moveID string) (AdapterMove, error)
}

type AdapterPlanMaterial struct {
	Target               AdapterTarget
	CredentialCiphertext []byte
	Manifest             []adapter.ManifestEntry
	Ledger               []adapter.LedgerEntry
}

type AdapterRepo interface {
	AdapterReader
	Create(ctx context.Context, p authz.Proof, mutation AdapterCreate) (AdapterRecord, AdapterTarget, error)
	BeginConfigureEffect(ctx context.Context, p authz.Proof, fence AdapterConfigureFence) error
	FinishConfigureEffect(ctx context.Context, p authz.Proof, targetID, effectID, outcome string, at time.Time) error
	AddTarget(ctx context.Context, p authz.Proof, mutation AdapterTargetUpdate) (AdapterTargetAddResult, error)
	RecordCredentialExpiry(ctx context.Context, p authz.Proof, adapterID string, expiresAt time.Time) error
	UpdateTarget(ctx context.Context, p authz.Proof, mutation AdapterTargetUpdate) (AdapterTargetUpdateResult, error)
	MoveTarget(ctx context.Context, p authz.Proof, mutation AdapterRouteMoveMutation) (AdapterRouteMoveResult, error)
	MoveOrigin(ctx context.Context, p authz.Proof, mutation AdapterOriginMoveMutation) (AdapterRouteMoveBatch, error)
	CancelMove(ctx context.Context, p authz.Proof, moveID, authorityPrincipalID string, at time.Time) (AdapterMove, error)
	ReplaceMoveTarget(ctx context.Context, p authz.Proof, moveID string, target AdapterTargetMutation, authorityPrincipalID string, at time.Time) (AdapterMove, error)
	ReplaceMoveOrigin(ctx context.Context, p authz.Proof, moveID, origin string, pendingCredential []byte, authorityPrincipalID string, at time.Time) (AdapterMove, error)
	RecordPlan(ctx context.Context, p authz.Proof, targetID, artifactID string, expectedGeneration, expectedRepositoryID, expectedDestinationID int64, entries []AdapterConflictEntry, at time.Time) error
	Adopt(ctx context.Context, p authz.Proof, adoption AdapterAdoption) (AdapterAdoptionResult, error)
	EnqueuePublished(ctx context.Context, p authz.Proof, at time.Time) ([]AdapterEnqueueResult, error)
	TeardownTarget(ctx context.Context, p authz.Proof, targetID string, keepRemote bool, at time.Time) (AdapterTeardownResult, error)
	TeardownAdapter(ctx context.Context, p authz.Proof, adapterID string, keepRemote bool, at time.Time) (AdapterTeardownBatch, error)
	ReplaceCredential(ctx context.Context, p authz.Proof, mutation AdapterCredentialMutation) (AdapterCredentialResult, error)
	RevokeCredential(ctx context.Context, p authz.Proof, adapterID string, at time.Time) (AdapterCredentialResult, error)
	EnqueueManual(ctx context.Context, p authz.Proof, targetID, authorityPrincipalID string, at time.Time) (AdapterEnqueueResult, error)
}

type AdapterEnqueueResult struct {
	TargetID             string
	JobID                string
	SupersededJobID      string
	AuthorityPrincipalID string
	Generation           int64
}

type AdapterTeardownResult struct {
	TargetID             string
	JobID                string
	SupersededJobID      string
	AuthorityPrincipalID string
	Generation           int64
	Orphaned             []string
}

type AdapterTeardownBatch struct {
	AuthorityPrincipalID string
	Targets              []AdapterTeardownResult
}

type AdapterCredentialMutation struct {
	AdapterID            string
	CredentialCiphertext []byte
	AuthorityPrincipalID string
	At                   time.Time
}

type AdapterCredentialResult struct {
	PreviousAuthorityPrincipalID string
	AuthorityPrincipalID         string
	TargetCount                  int
}

// ErrNotFound is the canonical cross-engine "no such row" — aliased from
// domain so every layer shares one sentinel for the unauthorized ≡
// nonexistent rule without importing the store.
// ErrRetrySerialization marks an error a caller has classified as a TRANSIENT
// race that the bounded retry loop should re-run the whole transaction for.
//
// It exists because the engine-level classifier cannot tell a race from a real
// conflict: postgres answers both with 23505. The SCIM provisioning create is
// the one caller today — §5.2's "the loser retries and attaches" — and the
// loser cannot simply re-read, because its failed statement has already
// aborted the transaction.
var ErrRetrySerialization = errors.New("store: transient race; retry the transaction")

var ErrNotFound = domain.ErrNotFound

// ErrConflict is the canonical cross-engine constraint refusal — a duplicate
// name among live siblings, or a parent still referenced by children.
var ErrConflict = domain.ErrConflict

// DB holds the open datastore. SQLite keeps a single write connection
// (pool of one) and a separate read pool, per the boot-enforced connection
// policy; postgres uses one pgx pool.
type DB struct {
	engine Engine

	sqWrite *sql.DB // sqlite only, MaxOpenConns(1), BEGIN IMMEDIATE via _txlock
	sqRead  *sql.DB // sqlite only
	pool    *pgxpool.Pool
}

// Engine, SQLiteWrite, SQLiteRead, and PG are the doors internal/store/tx
// and the test harness need; Go has no friend packages, so the "service
// never sees a pgx or sqlite type" rule is carried by the import-boundary
// test and review, not the type system.
func (d *DB) Engine() Engine       { return d.engine }
func (d *DB) SQLiteWrite() *sql.DB { return d.sqWrite }
func (d *DB) SQLiteRead() *sql.DB  { return d.sqRead }
func (d *DB) PG() *pgxpool.Pool    { return d.pool }

// AuditExportSnapshotTime returns the authoritative upper time bound for an
// unbounded audit export. Postgres event inserts use the same server clock, so
// a transaction that inserted before this cutoff remains in the snapshot even
// when it commits after paging starts. The fixed bound also keeps live writes
// from turning an export into an endless chase.
func (d *DB) AuditExportSnapshotTime(ctx context.Context) (time.Time, error) {
	switch d.engine {
	case EnginePostgres:
		var now time.Time
		if err := d.pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return time.Time{}, fmt.Errorf("store: postgres audit export snapshot time: %w", err)
		}
		return CanonTime(now), nil
	case EngineSQLite:
		return CanonTime(time.Now()), nil
	default:
		return time.Time{}, fmt.Errorf("store: audit export snapshot time for unknown engine %q", d.engine)
	}
}

// AwaitAuditExportWriters is the final-page barrier for a fixed audit
// snapshot. Postgres writers acquire the shared side of this lock before
// INSERT; taking the exclusive side waits until every pre-cutoff writer has
// committed. The autocommit statement releases the transaction lock after it
// establishes that barrier. sqlite's single writer needs no extra barrier.
func (d *DB) AwaitAuditExportWriters(ctx context.Context) error {
	switch d.engine {
	case EnginePostgres:
		if _, err := d.pool.Exec(ctx, "SELECT pg_advisory_xact_lock(1464159830, 85)"); err != nil {
			return fmt.Errorf("store: postgres audit export writer barrier: %w", err)
		}
		return nil
	case EngineSQLite:
		return nil
	default:
		return fmt.Errorf("store: audit export writer barrier for unknown engine %q", d.engine)
	}
}

// sqlitePragmas is the boot-enforced connection policy
// (system-architecture ADR § Data layer). _pragma parameters apply on every
// new connection.
const sqlitePragmas = "_pragma=foreign_keys(1)" +
	"&_pragma=journal_mode(wal)" +
	"&_pragma=synchronous(FULL)" +
	"&_pragma=busy_timeout(5000)"

// SQLiteDSN builds the canonical WRITE connection string for a database
// file: _txlock=immediate makes write transactions BEGIN IMMEDIATE, so
// write intent is acquired before any read.
func SQLiteDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?_txlock=immediate&" + sqlitePragmas
}

// sqliteReadDSN is the read-pool connection string: same enforced pragmas,
// but NO _txlock=immediate — read transactions open plain deferred BEGINs,
// and under WAL a reader never blocks the writer. With the write-pool DSN a
// held read transaction would take sqlite's write intent and starve the
// single writer through its whole busy_timeout.
func sqliteReadDSN(path string) string {
	return "file:" + url.PathEscape(path) + "?" + sqlitePragmas
}

// Open opens the datastore and, for sqlite, verifies the pragma policy took
// effect — if any pragma cannot be established, boot refuses (no silent
// downgrade).
func Open(ctx context.Context, cfg Config) (*DB, error) {
	switch cfg.Engine {
	case EngineSQLite:
		return openSQLite(ctx, cfg.Path)
	case EnginePostgres:
		return openPostgres(ctx, cfg.DSN)
	default:
		return nil, fmt.Errorf("store: unknown engine %q", cfg.Engine)
	}
}

func openSQLite(ctx context.Context, path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("store: sqlite path is empty")
	}
	write, err := sql.Open("sqlite", SQLiteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite write pool: %w", err)
	}
	write.SetMaxOpenConns(1)
	read, err := sql.Open("sqlite", sqliteReadDSN(path))
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("store: open sqlite read pool: %w", err)
	}
	d := &DB{engine: EngineSQLite, sqWrite: write, sqRead: read}
	for name, pool := range map[string]*sql.DB{"write": write, "read": read} {
		if err := verifySQLitePragmas(ctx, pool); err != nil {
			d.Close()
			return nil, fmt.Errorf("store: sqlite %s pool: %w", name, err)
		}
	}
	return d, nil
}

// verifySQLitePragmas re-reads the policy pragmas and refuses on mismatch.
// Pragmas are per-connection; the DSN applies them to every new connection,
// so verifying one connection per pool proves the DSN is effective.
func verifySQLitePragmas(ctx context.Context, db *sql.DB) error {
	checks := []struct {
		query string
		want  string
	}{
		{"PRAGMA foreign_keys", "1"},
		{"PRAGMA journal_mode", "wal"},
		{"PRAGMA synchronous", "2"}, // FULL
		{"PRAGMA busy_timeout", "5000"},
		{"PRAGMA read_uncommitted", "0"}, // prohibited by the tx boundary contract
	}
	for _, c := range checks {
		var got string
		if err := db.QueryRowContext(ctx, c.query).Scan(&got); err != nil {
			return fmt.Errorf("%s: %w", c.query, err)
		}
		if got != c.want {
			return fmt.Errorf("%s = %q, want %q — refusing to boot without the enforced pragma policy", c.query, got, c.want)
		}
	}
	return nil
}

func openPostgres(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: postgres ping: %w", err)
	}
	if err := verifyPGDurability(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{engine: EnginePostgres, pool: pool}, nil
}

// pgSettingQuerier is the seam verifyPGDurability tests through: the fsync
// leg cannot be exercised against a live server without restarting it, so
// the unit test injects a fake.
type pgSettingQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// verifyPGDurability is the audit-model ADR's boot check (CI invariant 7):
// sqlite runs synchronous=FULL precisely so audit commits are durable, and
// postgres gets the same no-silent-downgrade posture — a server with
// fsync=off or synchronous_commit=off would make "denial durable before the
// response" a fiction, so boot refuses. A deployment wanting async commit
// for other workloads runs Hikyo against a database configured for durable
// commits or does not run it. The store never issues SET synchronous_commit
// at any level (lint-banned).
func verifyPGDurability(ctx context.Context, q pgSettingQuerier) error {
	for _, setting := range []string{"fsync", "synchronous_commit"} {
		var v string
		if err := q.QueryRow(ctx, "SHOW "+setting).Scan(&v); err != nil {
			return fmt.Errorf("store: postgres SHOW %s: %w", setting, err)
		}
		if v != "on" {
			return fmt.Errorf("store: postgres %s = %q — audit durability requires it on; refusing to boot without durable commits (audit-model ADR)", setting, v)
		}
	}
	return nil
}

func (d *DB) Ping(ctx context.Context) error {
	if d.engine == EnginePostgres {
		return d.pool.Ping(ctx)
	}
	return d.sqRead.PingContext(ctx)
}

func (d *DB) Close() error {
	var errs []error
	if d.sqWrite != nil {
		errs = append(errs, d.sqWrite.Close())
	}
	if d.sqRead != nil {
		errs = append(errs, d.sqRead.Close())
	}
	if d.pool != nil {
		d.pool.Close()
	}
	return errors.Join(errs...)
}
