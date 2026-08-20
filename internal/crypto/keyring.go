package crypto

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Purpose distinguishes the tier-3 keys: one DEK per project, one instance
// DEK for rows belonging to no project, the root token key (derivation
// only, never encryption), and the scanning-fingerprint key (secret-scanning
// amendment — derivation only, one instance-scoped key for dismissal
// fingerprints).
type Purpose string

const (
	PurposeProject  Purpose = "project"
	PurposeInstance Purpose = "instance"
	PurposeToken    Purpose = "token"
	// PurposeScanning is the instance-scoped scanning-fingerprint key
	// (secret-scanning ADR §4, encryption-model amendment): a tier-3 sibling of
	// the instance DEK and token key, used only to compute dismissal-row value
	// fingerprints and for nothing else. Like the token key it is derivation
	// material, never an envelope key, and it wraps under the existing
	// wrapped_dek kind.
	PurposeScanning Purpose = "scanning"
)

// WrappedKey is a stored, wrapped key row. Blob is a versioned ciphertext
// envelope — the repository layer stores and returns ciphertext only, never
// unwrapped key material.
type WrappedKey struct {
	ID               string  // tier-3 key id; empty for the master key
	Purpose          Purpose // tier-3 only
	OrgID, ProjectID string  // empty for instance-scoped keys and the master
	Version          uint32
	MasterKeyVersion uint32 // tier-3 only: the master version that wraps it
	RootKeyEpoch     uint32 // master only: the root epoch that wraps it
	Blob             []byte
	CreatedAt        time.Time
}

// ErrNoKey reports that no active key exists for the requested scope.
var ErrNoKey = errors.New("crypto: no active key for scope")

// ErrKeyExists reports a uniqueness conflict on key creation — two writers
// racing to mint the same scope's key. Callers re-read the winner.
var ErrKeyExists = errors.New("crypto: key already exists for scope")

// ErrStaleMaster reports a tier-3 key creation carrying a master version
// that is no longer the active master: the writer sealed under a master a
// rotation has since retired. Unreachable until the rotations ticket lands;
// the fence check exists so the race of CI invariant 9 is structurally
// refused rather than silently committed.
var ErrStaleMaster = errors.New("crypto: wrapping master key version is no longer active")

// ErrMasterRotationBlocked reports that rotate-master-key cannot proceed: the
// datastore holds no active master (corrupted hierarchy) or more than one (the
// root is mid dual-wrapped rotation). The two operations are mutually exclusive
// — dual-wrapping the new master under both roots is the four-way state the ADR
// refuses — so master rotation waits for `rotate-root-key --finalize`.
var ErrMasterRotationBlocked = errors.New("crypto: master rotation blocked; the root key is dual-wrapped, finalize the root rotation first")

// ErrRootRotationBlocked reports that rotate-root-key --prepare cannot proceed:
// the datastore is already dual-wrapped (a prepare is in flight) or the
// hierarchy is missing. The operator verifies and finalizes the pending
// rotation, or the instance is unbooted.
var ErrRootRotationBlocked = errors.New("crypto: root rotation blocked; a rotation is already in flight, verify and finalize it first")

// ErrNotDualWrapped reports a verify or finalize with no pending root rotation:
// there is a single active master wrapper, so there is nothing to confirm or
// retire. Prepare first.
var ErrNotDualWrapped = errors.New("crypto: no root rotation in flight; run --prepare first")

// KeyStore is the persistence seam. internal/store/keyring implements it;
// every method that creates keys must run in one transaction, acquire the
// hierarchy generation (the fence that serializes tier-3 key creation
// against master rotation — encryption-model ADR § Rotation), and for tier-3
// creation verify the key's MasterKeyVersion is still the active master
// inside that fence (ErrStaleMaster otherwise).
type KeyStore interface {
	// ActiveMasterWrappers returns every active wrapper of the master key —
	// one per root epoch; two during a dual-wrapped root rotation; empty at
	// first boot.
	ActiveMasterWrappers(ctx context.Context) ([]WrappedKey, error)
	ActiveTier3(ctx context.Context, p Purpose, orgID, projectID string) (WrappedKey, error)
	// Tier3Versions returns every still-openable version of one scope's key —
	// the active version plus every retiring version a reencrypt has not yet
	// walked — newest first. Empty (not ErrNoKey) when the scope has no key.
	// The keyring loads all of them so a sealer can open ciphertext written
	// under a superseded DEK version while sealing new writes under the active.
	Tier3Versions(ctx context.Context, p Purpose, orgID, projectID string) ([]WrappedKey, error)
	// AllOpenableTier3 returns every still-openable tier-3 key (active +
	// retiring) across every scope, for rotate-master-key to re-wrap them all
	// under a new master.
	AllOpenableTier3(ctx context.Context) ([]WrappedKey, error)
	// CreateHierarchy persists the first-boot key set (master + tier-3 keys)
	// atomically. A concurrent first boot returns ErrKeyExists.
	CreateHierarchy(ctx context.Context, master WrappedKey, tier3 []WrappedKey) error
	// CreateTier3 persists one new tier-3 key. Same-scope race returns
	// ErrKeyExists; a retired MasterKeyVersion returns ErrStaleMaster.
	CreateTier3(ctx context.Context, key WrappedKey) error
}

// masterKeyID is the wrapping_key_id naming the master key in tier-3
// envelopes; there is one master lineage, so the version disambiguates.
var masterKeyID = []byte("master")

// masterSet is the unwrapped master key across every version a tier-3 row may
// still name. During `rotate-master-key` the store re-wraps every tier-3 key
// under the new master version and retires the old master in one transaction;
// between that commit and the in-memory adopt, a tier-3 cache miss would unwrap
// a row already carrying the new master version. Holding both versions here
// makes that window safe — the row's master version resolves its unwrapping
// key — instead of failing a single-version check. Built once, never mutated;
// adopt installs a new set.
type masterSet struct {
	redactor
	active uint32
	byVer  map[uint32][]byte
}

func (m *masterSet) activeVersion() uint32 { return m.active }
func (m *masterSet) activeKey() []byte     { return m.byVer[m.active] }

func (m *masterSet) at(v uint32) ([]byte, bool) {
	k, ok := m.byVer[v]
	return k, ok
}

func singleMaster(version uint32, key []byte) *masterSet {
	return &masterSet{active: version, byVer: map[uint32][]byte{version: key}}
}

// addMaster makes a new master version resolvable WITHOUT changing which one is
// active. Master rotation calls it before the store transaction so that during
// the window between commit (rows re-wrapped to the new version) and adopt (the
// in-memory switch), a tier-3 cache miss resolves the new version by `at(v)`
// rather than failing. Idempotent under concurrent rotations.
func (k *Keyring) addMaster(version uint32, key []byte) {
	for {
		old := k.master.Load()
		if _, ok := old.byVer[version]; ok {
			return
		}
		byVer := make(map[uint32][]byte, len(old.byVer)+1)
		for v, kk := range old.byVer {
			byVer[v] = kk
		}
		byVer[version] = key
		if k.master.CompareAndSwap(old, &masterSet{active: old.active, byVer: byVer}) {
			return
		}
	}
}

// activateMaster switches the active master forward, monotonically. Adopt calls
// it only after the store transaction commits; a late or losing adopt whose
// version does not advance the active is a no-op.
func (k *Keyring) activateMaster(version uint32) {
	for {
		old := k.master.Load()
		if version <= old.active {
			return
		}
		if k.master.CompareAndSwap(old, &masterSet{active: version, byVer: old.byVer}) {
			return
		}
	}
}

// removeMaster drops a never-activated master version and returns its key bytes
// to zero. Abort calls it when a rotation fails before adoption: no committed
// tier-3 row references the version, so nothing can be mid-unwrap under it. It
// refuses to remove the active version, a safety invariant.
func (k *Keyring) removeMaster(version uint32) []byte {
	for {
		old := k.master.Load()
		if old.active == version {
			return nil
		}
		key, ok := old.byVer[version]
		if !ok {
			return nil
		}
		byVer := make(map[uint32][]byte, len(old.byVer))
		for v, kk := range old.byVer {
			if v != version {
				byVer[v] = kk
			}
		}
		if k.master.CompareAndSwap(old, &masterSet{active: old.active, byVer: byVer}) {
			return key
		}
	}
}

// dekCacheSize bounds the unwrapped project-DEK LRU cache. Ops-spec § 9 value
// (LRU 1 024 entries — effectively every DEK at the envelope, but a declared
// bound; eviction is a re-unwrap, not a failure).
const dekCacheSize = 1024

type keyHandle struct {
	redactor
	id      string
	version uint32
	key     []byte
}

// versionSet is the unwrapped key material for one tier-3 scope across every
// still-openable version: the active version new writes seal under, plus every
// retiring version whose ciphertext a reencrypt has not yet moved. It is built
// once and never mutated — rotation installs a NEW set rather than editing this
// one, so a reader holding a set never sees a torn update.
type versionSet struct {
	redactor
	active uint32
	byVer  map[uint32]keyHandle
}

// activeHandle is the handle new writes seal under.
func (vs *versionSet) activeHandle() keyHandle { return vs.byVer[vs.active] }

// at returns the handle for a specific version, or false if this set does not
// carry it — a record naming a version already retired to zero references, or
// one this set was built before.
func (vs *versionSet) at(v uint32) (keyHandle, bool) {
	h, ok := vs.byVer[v]
	return h, ok
}

// Keyring holds the unwrapped key hierarchy for the server process — the
// only mode that ever constructs one. Master key, instance DEK and root
// token key live unwrapped for the process lifetime; project DEKs are
// unwrapped on demand into a bounded LRU.
type Keyring struct {
	redactor
	ks  KeyStore
	rnd io.Reader

	// master holds the unwrapped master key(s), swapped atomically by
	// `rotate-master-key`. A tier-3 unwrap resolves its master by the row's
	// version, so the brief rotation window (rows re-wrapped, adopt pending) is
	// safe.
	master atomic.Pointer[masterSet]

	// instance is the instance DEK's version set, swapped atomically by
	// `rotate-dek --instance`. An atomic pointer, not a mutex: instance-field
	// opens are on the hot auth path, and every read is a single load of an
	// immutable set.
	instance atomic.Pointer[versionSet]

	// tokenMu guards the root token key handle against `rotate-token-key`
	// swapping it under a concurrent derivation. It is separate from mu (the
	// DEK cache's lock) so a rotation's datastore write never holds the lock
	// every value read needs.
	tokenMu sync.Mutex
	token   keyHandle

	// scanningMu guards the scanning-fingerprint key handle against
	// `rotate-scanning-key` swapping it under a concurrent fingerprint
	// computation, exactly as tokenMu guards the token key.
	scanningMu sync.Mutex
	scanning   keyHandle

	mu   sync.Mutex
	deks map[string]*list.Element // scope → *list.Element holding *dekEntry
	lru  *list.List               // front = most recently used

	// hierarchyRotationMu serializes the tier-1/tier-2 rotations (master and
	// root) process-wide. It lives on the Keyring — the single object every
	// service shares — rather than on any one caller, so two callers sharing this
	// keyring cannot prepare the same master version concurrently (which would
	// mint two different keys for one version and let a version-keyed adopt
	// activate or zero the wrong one). Held by the service across the whole
	// rotation: prepare → commit → adopt/abort. Tier-3 DEK rotations are
	// scope-fenced in the store and never take it.
	hierarchyRotationMu sync.Mutex

	// rootRotationPending records whether load saw more than one active master
	// wrapper — the dual-wrapped transition state of an unfinished root
	// rotation. Boot warns on it every start until finalize (encryption-model
	// ADR § Rotation). Set once at load.
	rootRotationPending bool
}

// RootRotationPending reports whether this instance booted with a root rotation
// half-done (the master dual-wrapped under two roots). Boot warns on it every
// start until `rotate-root-key --finalize` — a rotation half-done must be
// visible, not silent.
func (k *Keyring) RootRotationPending() bool { return k.rootRotationPending }

// LockHierarchyRotation / UnlockHierarchyRotation serialize master and root
// rotations process-wide (see hierarchyRotationMu). The caller holds the lock
// across the entire rotation — prepare, the store transaction, and adopt/abort.
func (k *Keyring) LockHierarchyRotation()   { k.hierarchyRotationMu.Lock() }
func (k *Keyring) UnlockHierarchyRotation() { k.hierarchyRotationMu.Unlock() }

type dekEntry struct {
	redactor
	scope string
	set   *versionSet
}

func dekScope(orgID, projectID string) string {
	// LP-composed for the same injectivity reason as everywhere else.
	return string(appendLP(appendLP(nil, []byte(orgID)), []byte(projectID)))
}

// LoadKeyring unwraps (or, at first startup, mints) the key hierarchy.
// It consumes root: the root key is zeroed before returning, success or
// failure — it is re-read from its source when rotation needs it again.
func LoadKeyring(ctx context.Context, ks KeyStore, root []byte) (*Keyring, error) {
	defer Zero(root)
	if len(root) != KeySize {
		return nil, ErrRootKeyFormat
	}
	k := &Keyring{
		ks:   ks,
		rnd:  rand.Reader,
		deks: make(map[string]*list.Element),
		lru:  list.New(),
	}

	wrappers, err := ks.ActiveMasterWrappers(ctx)
	if err != nil {
		return nil, fmt.Errorf("crypto: load master key: %w", err)
	}
	if len(wrappers) == 0 {
		switch err := k.mintHierarchy(ctx, root); {
		case err == nil:
			return k, nil
		case !errors.Is(err, ErrKeyExists):
			return nil, err
		}
		// Lost a first-boot race: the winner's hierarchy is in the store.
		if wrappers, err = ks.ActiveMasterWrappers(ctx); err != nil {
			return nil, fmt.Errorf("crypto: load master key: %w", err)
		}
	}

	// Startup accepts any root key that unwraps any present wrapper, so a
	// crash mid root-rotation (dual-wrapped state) boots with either root
	// (encryption-model ADR § Rotation). A wrapper at an unknown format version
	// aborts rather than guessing — refusal 5 — even if another opens.
	// More than one active wrapper is the dual-wrapped transition of an
	// unfinished root rotation: bootable under either root, warned on every
	// start until finalized.
	k.rootRotationPending = len(wrappers) > 1

	master, err := k.unwrapMaster(root, wrappers)
	if err != nil {
		return nil, err
	}
	k.master.Store(singleMaster(master.version, master.key))

	instance, err := k.loadTier3Versions(ctx, PurposeInstance, "", "")
	if err != nil {
		return nil, err
	}
	k.instance.Store(instance)
	if k.token, err = k.loadTier3(ctx, PurposeToken, "", ""); err != nil {
		return nil, err
	}
	if k.scanning, err = k.loadOrMintScanning(ctx); err != nil {
		return nil, err
	}
	return k, nil
}

// loadOrMintScanning loads the instance-scoped scanning-fingerprint key,
// minting it on absence. It is deliberately NOT loadTier3's die-on-missing:
// the scanning key joined the hierarchy with the secret-scanning ADR, so any
// hierarchy minted before it — including a restored pre-#74 backup — has no
// scanning row, and a hard failure there would brick boot on upgrade. A fresh
// first boot mints it in mintHierarchy; this path covers the upgrade, with the
// same ErrKeyExists convergence a concurrent minter needs (projectDEK's shape).
func (k *Keyring) loadOrMintScanning(ctx context.Context) (keyHandle, error) {
	row, err := k.ks.ActiveTier3(ctx, PurposeScanning, "", "")
	if errors.Is(err, ErrNoKey) {
		handle, newRow, mintErr := k.mintTier3(PurposeScanning, "", "")
		if mintErr != nil {
			return keyHandle{}, mintErr
		}
		switch createErr := k.ks.CreateTier3(ctx, newRow); {
		case createErr == nil:
			return handle, nil
		case errors.Is(createErr, ErrKeyExists):
			Zero(handle.key)
			row, err = k.ks.ActiveTier3(ctx, PurposeScanning, "", "")
		default:
			Zero(handle.key)
			return keyHandle{}, createErr
		}
	}
	if err != nil {
		return keyHandle{}, fmt.Errorf("crypto: load scanning key: %w", err)
	}
	return k.unwrapTier3(row)
}

func (k *Keyring) unwrapMaster(root []byte, wrappers []WrappedKey) (keyHandle, error) {
	// Refusal 5 is checked over EVERY wrapper before any unwrap is accepted:
	// a datastore carrying an unknown-format master wrapper aborts even when
	// another wrapper would open — never a partial boot over a record this
	// build cannot read.
	for _, w := range wrappers {
		if _, _, err := parseHeader(w.Blob); errors.Is(err, ErrUnknownFormat) {
			return keyHandle{}, fmt.Errorf("crypto: master key: %w", err)
		}
	}
	for _, w := range wrappers {
		master, err := open(root, be32(w.RootKeyEpoch), 0,
			WrappedMasterAAD{MasterKeyVersion: w.Version, RootKeyEpoch: w.RootKeyEpoch}, w.Blob)
		if err == nil {
			return keyHandle{version: w.Version, key: master}, nil
		}
	}
	return keyHandle{}, ErrRootKeyMismatch
}

// mintHierarchy is first startup: generate master, instance DEK and root
// token key, persist all wrapped in one transaction. The root key is present
// and operator-held — the server never generates a root key.
func (k *Keyring) mintHierarchy(ctx context.Context, root []byte) error {
	master, err := k.newKey()
	if err != nil {
		return err
	}
	const epoch, version = 1, 1
	masterBlob, err := seal(k.rnd, root, be32(epoch), 0,
		WrappedMasterAAD{MasterKeyVersion: version, RootKeyEpoch: epoch}, master)
	if err != nil {
		return err
	}
	k.master.Store(singleMaster(version, master))

	instance, instanceRow, err := k.mintTier3(PurposeInstance, "", "")
	if err != nil {
		return err
	}
	token, tokenRow, err := k.mintTier3(PurposeToken, "", "")
	if err != nil {
		return err
	}
	scanning, scanningRow, err := k.mintTier3(PurposeScanning, "", "")
	if err != nil {
		return err
	}

	err = k.ks.CreateHierarchy(ctx, WrappedKey{
		Version:      version,
		RootKeyEpoch: epoch,
		Blob:         masterBlob,
	}, []WrappedKey{instanceRow, tokenRow, scanningRow})
	if err != nil {
		Zero(master)
		Zero(instance.key)
		Zero(token.key)
		Zero(scanning.key)
		k.master.Store(nil)
		return err
	}
	k.instance.Store(&versionSet{
		active: instance.version,
		byVer:  map[uint32]keyHandle{instance.version: instance},
	})
	k.token = token
	k.scanning = scanning
	return nil
}

// mintTier3 generates a tier-3 key and its wrapped row under the current
// master. The caller persists the row.
func (k *Keyring) mintTier3(p Purpose, orgID, projectID string) (keyHandle, WrappedKey, error) {
	return k.mintTier3At(p, orgID, projectID, 1)
}

// mintTier3At is mintTier3 at an explicit version. Rotation is the only
// caller that supplies one: the version is bound into the wrapping AAD, so a
// rotated key must be sealed under the version it will be stored at, not
// resealed afterwards.
func (k *Keyring) mintTier3At(p Purpose, orgID, projectID string, version uint32) (keyHandle, WrappedKey, error) {
	key, err := k.newKey()
	if err != nil {
		return keyHandle{}, WrappedKey{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return keyHandle{}, WrappedKey{}, fmt.Errorf("crypto: generate key id: %w", err)
	}
	m := k.master.Load()
	row := WrappedKey{
		ID:               "dek_" + id.String(),
		Purpose:          p,
		OrgID:            orgID,
		ProjectID:        projectID,
		Version:          version,
		MasterKeyVersion: m.activeVersion(),
	}
	if row.Blob, err = seal(k.rnd, m.activeKey(), masterKeyID, m.activeVersion(), tier3AAD(row), key); err != nil {
		return keyHandle{}, WrappedKey{}, err
	}
	return keyHandle{id: row.ID, version: row.Version, key: key}, row, nil
}

// tier3AAD is the one place the tier-3 row → AAD mapping lives: the token
// key wraps under wrapped_token_key, every DEK-shaped key (project,
// instance, scanning) under wrapped_dek.
func tier3AAD(row WrappedKey) AAD {
	if row.Purpose == PurposeToken {
		return WrappedTokenKeyAAD{TokenKeyVersion: row.Version, MasterKeyVersion: row.MasterKeyVersion}
	}
	return WrappedDEKAAD{
		OrgID: row.OrgID, ProjectID: row.ProjectID, DEKID: row.ID,
		DEKVersion: row.Version, MasterKeyVersion: row.MasterKeyVersion,
	}
}

func (k *Keyring) loadTier3(ctx context.Context, p Purpose, orgID, projectID string) (keyHandle, error) {
	row, err := k.ks.ActiveTier3(ctx, p, orgID, projectID)
	if err != nil {
		// A present master with a missing instance DEK or token key is a
		// corrupted hierarchy, not a first boot — refuse loudly.
		return keyHandle{}, fmt.Errorf("crypto: load %s key: %w", p, err)
	}
	return k.unwrapTier3(row)
}

// loadTier3Versions unwraps every still-openable version of one tier-3 scope
// into a versionSet. A present master with no version at all for the instance
// DEK or token key is a corrupted hierarchy, not a first boot — refuse loudly.
func (k *Keyring) loadTier3Versions(ctx context.Context, p Purpose, orgID, projectID string) (*versionSet, error) {
	rows, err := k.ks.Tier3Versions(ctx, p, orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("crypto: load %s key versions: %w", p, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("crypto: load %s key: %w", p, ErrNoKey)
	}
	return k.buildVersionSet(rows)
}

// buildVersionSet unwraps a scope's rows into a versionSet. The active version
// is the highest one present: rotation always appends a higher version as the
// new active and demotes the previous active to retiring, so max(version) is
// active by construction, with no state column to carry.
func (k *Keyring) buildVersionSet(rows []WrappedKey) (*versionSet, error) {
	vs := &versionSet{byVer: make(map[uint32]keyHandle, len(rows))}
	for _, row := range rows {
		h, err := k.unwrapTier3(row)
		if err != nil {
			return nil, err
		}
		vs.byVer[row.Version] = h
		if row.Version > vs.active {
			vs.active = row.Version
		}
	}
	return vs, nil
}

func (k *Keyring) unwrapTier3(row WrappedKey) (keyHandle, error) {
	mkey, ok := k.master.Load().at(row.MasterKeyVersion)
	if !ok {
		// The master version the row names is not held: a corrupted hierarchy,
		// or a master retired before its tier-3 keys were re-wrapped (which
		// rotate-master-key does atomically, so this is corruption in practice).
		return keyHandle{}, fmt.Errorf("crypto: %s key %s wrapped under master v%d, which is not held",
			row.Purpose, row.ID, row.MasterKeyVersion)
	}
	key, err := open(mkey, masterKeyID, row.MasterKeyVersion, tier3AAD(row), row.Blob)
	if err != nil {
		return keyHandle{}, fmt.Errorf("crypto: unwrap %s key %s: %w", row.Purpose, row.ID, err)
	}
	return keyHandle{id: row.ID, version: row.Version, key: key}, nil
}

func (k *Keyring) newKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(k.rnd, key); err != nil {
		return nil, fmt.Errorf("crypto: randomness unavailable, refusing to generate key: %w", err)
	}
	return key, nil
}

// ForProject returns the sealer for one project's key domain, minting the
// project DEK on first use. The sealer only accepts value and project_field
// envelopes whose AAD names exactly this org and project — a project-owned
// secret can never land under the instance DEK (CI invariant 16).
func (k *Keyring) ForProject(ctx context.Context, orgID, projectID string) (*ProjectSealer, error) {
	if orgID == "" || projectID == "" {
		return nil, errors.New("crypto: project scope requires org and project ids")
	}
	set, err := k.projectDEKSet(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}
	return &ProjectSealer{kr: k, orgID: orgID, projectID: projectID, deks: set}, nil
}

func (k *Keyring) projectDEKSet(ctx context.Context, orgID, projectID string) (*versionSet, error) {
	scope := dekScope(orgID, projectID)
	k.mu.Lock()
	defer k.mu.Unlock()
	if el, ok := k.deks[scope]; ok {
		k.lru.MoveToFront(el)
		return el.Value.(*dekEntry).set, nil
	}

	rows, err := k.ks.Tier3Versions(ctx, PurposeProject, orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("crypto: load project key: %w", err)
	}
	if len(rows) == 0 {
		// First use of this project: mint version 1. A concurrent first use
		// races on CreateTier3; the loser re-reads the winner's key.
		handle, newRow, mintErr := k.mintTier3(PurposeProject, orgID, projectID)
		if mintErr != nil {
			return nil, mintErr
		}
		switch createErr := k.ks.CreateTier3(ctx, newRow); {
		case createErr == nil:
			set := &versionSet{active: handle.version, byVer: map[uint32]keyHandle{handle.version: handle}}
			k.cacheDEK(scope, set)
			return set, nil
		case errors.Is(createErr, ErrKeyExists):
			Zero(handle.key)
			if rows, err = k.ks.Tier3Versions(ctx, PurposeProject, orgID, projectID); err != nil {
				return nil, fmt.Errorf("crypto: load project key: %w", err)
			}
		default:
			Zero(handle.key)
			return nil, createErr
		}
	}
	set, err := k.buildVersionSet(rows)
	if err != nil {
		return nil, err
	}
	k.cacheDEK(scope, set)
	return set, nil
}

// EvictProjectDEK drops a project scope from the DEK cache so the next
// ForProject rebuilds its version set from the store. reencrypt calls it after
// retiring the scope's retiring versions, so a cached sealer stops offering
// them. Not zeroed: a concurrent sealer built before the retire may still alias
// the buffers, and a zeroed-key open would be a silent failure — the Go GC
// reclaims them.
func (k *Keyring) EvictProjectDEK(orgID, projectID string) { k.evictProjectDEK(orgID, projectID) }

// evictProjectDEK drops one project scope from the cache. Rotation calls it
// after installing a new DEK version so the next ForProject rebuilds the set
// with the new active version and the demoted retiring one — the one place
// eviction is safe to pair with zeroing is rotation and project delete, where
// the fence guarantees no live sealer still aliases the old buffers.
func (k *Keyring) evictProjectDEK(orgID, projectID string) {
	scope := dekScope(orgID, projectID)
	k.mu.Lock()
	defer k.mu.Unlock()
	if el, ok := k.deks[scope]; ok {
		k.lru.Remove(el)
		delete(k.deks, scope)
	}
}

// cacheDEK inserts under k.mu, evicting the least recently used entry past
// the bound. Evicted keys are NOT zeroed here: a live ProjectSealer may
// still alias the buffer, and sealing under a zeroed key would be a silent
// confidentiality break. Zeroing happens only where fencing guarantees no
// live holder — rotation and project delete, with their tickets.
func (k *Keyring) cacheDEK(scope string, set *versionSet) {
	k.deks[scope] = k.lru.PushFront(&dekEntry{scope: scope, set: set})
	if k.lru.Len() > dekCacheSize {
		oldest := k.lru.Back()
		k.lru.Remove(oldest)
		delete(k.deks, oldest.Value.(*dekEntry).scope)
	}
}

// ForInstance returns the sealer for instance-scoped sensitive fields. It
// snapshots the active write-handle now, so the sealer keeps sealing under the
// version live at this moment even across a concurrent rotate-dek adoption —
// the writer fence rejects that stale write at commit.
func (k *Keyring) ForInstance() *InstanceSealer {
	return &InstanceSealer{kr: k, wh: k.instance.Load().activeHandle()}
}

// PrepareRootKeyRotation seals the active master under a new root at the next
// epoch, producing the second wrapper of the dual-wrapped transition. The
// master is already unwrapped in memory, so this needs only the NEW root (the
// operator's new-root source) — no current root, and no data is touched.
//
// It refuses unless there is exactly one active master wrapper: a second
// prepare while one is pending, or master rotation mid-flight, would build the
// four-way root×master matrix the ADR refuses.
func (k *Keyring) PrepareRootKeyRotation(ctx context.Context, newRoot []byte) (WrappedKey, error) {
	if len(newRoot) != KeySize {
		return WrappedKey{}, ErrRootKeyFormat
	}
	wrappers, err := k.ks.ActiveMasterWrappers(ctx)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("crypto: load master wrappers: %w", err)
	}
	if len(wrappers) != 1 {
		return WrappedKey{}, ErrRootRotationBlocked
	}
	cur := wrappers[0]
	m := k.master.Load()
	newEpoch := cur.RootKeyEpoch + 1
	blob, err := seal(k.rnd, newRoot, be32(newEpoch), 0,
		WrappedMasterAAD{MasterKeyVersion: cur.Version, RootKeyEpoch: newEpoch}, m.activeKey())
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{Version: cur.Version, RootKeyEpoch: newEpoch, Blob: blob}, nil
}

// VerifyRootKeyRotation confirms the operator has installed the new root at the
// PRIMARY source: primaryRoot (re-read from that source) must unwrap the
// new-epoch wrapper to the live master. It reads and decides only — the dual
// wrapper is already committed by prepare — so a failed verify is safe to
// retry after the operator fixes the source.
func (k *Keyring) VerifyRootKeyRotation(ctx context.Context, primaryRoot []byte) (uint32, error) {
	if len(primaryRoot) != KeySize {
		return 0, ErrRootKeyFormat
	}
	wrappers, err := k.ks.ActiveMasterWrappers(ctx)
	if err != nil {
		return 0, fmt.Errorf("crypto: load master wrappers: %w", err)
	}
	if len(wrappers) < 2 {
		return 0, ErrNotDualWrapped
	}
	newest := wrappers[0]
	for _, w := range wrappers[1:] {
		if w.RootKeyEpoch > newest.RootKeyEpoch {
			newest = w
		}
	}
	master, err := open(primaryRoot, be32(newest.RootKeyEpoch), 0,
		WrappedMasterAAD{MasterKeyVersion: newest.Version, RootKeyEpoch: newest.RootKeyEpoch}, newest.Blob)
	if err != nil {
		return 0, ErrRootKeyMismatch
	}
	// Defence in depth against a stale wrapper: the new wrapper must unwrap to the
	// ACTIVE master, not merely to some retained (retired) master. A prepare that
	// raced a master rotation could seal a now-retired master version under the
	// new root — a valid AEAD open that wraps the wrong key. Requiring the
	// wrapper's version to be the active one, and comparing against the active
	// key, rejects that; the store's in-fence version pin prevents it being
	// written in the first place.
	m := k.master.Load()
	same := newest.Version == m.activeVersion() &&
		subtle.ConstantTimeCompare(master, m.activeKey()) == 1
	Zero(master)
	if !same {
		return 0, ErrRootKeyMismatch
	}
	return newest.RootKeyEpoch, nil
}

// ClearRootRotationPending records that the pending root rotation has been
// finalized in this process, so RootRotationPending stops reporting the
// dual-wrapped state without waiting for a reboot.
func (k *Keyring) ClearRootRotationPending() { k.rootRotationPending = false }

// PrepareMasterKeyRotation generates a new master key, re-wraps every openable
// tier-3 key under it, and returns the new master row, the re-wrapped tier-3
// rows, and the adopt function. root is the current operator root, re-read from
// its source (the master is wrapped by the root, and the root is zeroed after
// boot); the caller zeroes it after this returns.
//
// It refuses while the root is dual-wrapped (more than one active master
// wrapper): the two rotations are mutually exclusive per the ADR, and the store
// re-checks the count inside the hierarchy fence. Key bytes are unchanged — only
// the wrapping master and the wrapping AAD move — so cached DEK handles stay
// valid and adoption swaps only the master, never the DEK caches.
//
// The new master is made RESOLVABLE (but not active) here, before the store
// transaction, so a tier-3 cache miss in the window between the store commit
// and adopt() resolves the new master version rather than failing. adopt()
// switches active forward after the commit; abort() removes and zeroes the new
// master if the transaction never commits — the caller defers abort and cancels
// it on success.
func (k *Keyring) PrepareMasterKeyRotation(ctx context.Context, root []byte) (newRow WrappedKey, rewrapped []WrappedKey, adopt, abort func(), err error) {
	fail := func(e error) (WrappedKey, []WrappedKey, func(), func(), error) {
		return WrappedKey{}, nil, nil, nil, e
	}
	if len(root) != KeySize {
		return fail(ErrRootKeyFormat)
	}
	wrappers, err := k.ks.ActiveMasterWrappers(ctx)
	if err != nil {
		return fail(fmt.Errorf("crypto: load master wrappers: %w", err))
	}
	if len(wrappers) != 1 {
		return fail(ErrMasterRotationBlocked)
	}
	cur := wrappers[0]
	// Fail fast if the re-read root does not match this datastore, before minting
	// anything: sealing a new master under a wrong root would only surface at the
	// next boot as an unbootable instance.
	curMaster, err := open(root, be32(cur.RootKeyEpoch), 0,
		WrappedMasterAAD{MasterKeyVersion: cur.Version, RootKeyEpoch: cur.RootKeyEpoch}, cur.Blob)
	if err != nil {
		return fail(ErrRootKeyMismatch)
	}
	Zero(curMaster)

	newVersion := cur.Version + 1
	newMaster, err := k.newKey()
	if err != nil {
		return fail(err)
	}
	newMasterBlob, err := seal(k.rnd, root, be32(cur.RootKeyEpoch), 0,
		WrappedMasterAAD{MasterKeyVersion: newVersion, RootKeyEpoch: cur.RootKeyEpoch}, newMaster)
	if err != nil {
		Zero(newMaster)
		return fail(err)
	}

	tier3, err := k.ks.AllOpenableTier3(ctx)
	if err != nil {
		Zero(newMaster)
		return fail(fmt.Errorf("crypto: load tier-3 keys for rewrap: %w", err))
	}
	rewrapped = make([]WrappedKey, 0, len(tier3))
	for _, row := range tier3 {
		// Unwrap under the row's CURRENT master (resolved by row.MasterKeyVersion),
		// then re-seal the same key bytes under the new master with the new
		// master version bound into the AAD.
		h, uerr := k.unwrapTier3(row)
		if uerr != nil {
			Zero(newMaster)
			return fail(uerr)
		}
		row.MasterKeyVersion = newVersion
		blob, sealErr := seal(k.rnd, newMaster, masterKeyID, newVersion, tier3AAD(row), h.key)
		Zero(h.key)
		if sealErr != nil {
			Zero(newMaster)
			return fail(sealErr)
		}
		row.Blob = blob
		rewrapped = append(rewrapped, row)
	}

	// Make the new master resolvable (active stays old) so the commit→adopt
	// window is safe; adopt activates it, abort removes and zeroes it.
	k.addMaster(newVersion, newMaster)
	newRow = WrappedKey{Version: newVersion, RootKeyEpoch: cur.RootKeyEpoch, Blob: newMasterBlob}
	adopt = func() { k.activateMaster(newVersion) }
	abort = func() { Zero(k.removeMaster(newVersion)) }
	return newRow, rewrapped, adopt, abort, nil
}

// PrepareProjectDEKRotation mints the next version of a project DEK and returns
// its wrapped row plus the adopt function. Like the token rotation, the split
// exists because the persistence closure runs in a retryable transaction: only
// the attempt that commits may adopt. Project DEK adoption is a cache eviction
// — the next ForProject rebuilds the version set from the store, picking up the
// new active version and the demoted retiring one — so a rolled-back attempt
// that never adopts leaves nothing behind.
func (k *Keyring) PrepareProjectDEKRotation(ctx context.Context, orgID, projectID string) (WrappedKey, func(), error) {
	if orgID == "" || projectID == "" {
		return WrappedKey{}, nil, errors.New("crypto: project scope requires org and project ids")
	}
	// projectDEKSet mints version 1 if this project has never sealed anything,
	// so rotating a pristine project produces v1 (immediately retiring, with no
	// ciphertext) and v2 active. Harmless — reencrypt retires the empty v1
	// trivially — and simpler than a special "nothing to rotate" path.
	set, err := k.projectDEKSet(ctx, orgID, projectID)
	if err != nil {
		return WrappedKey{}, nil, err
	}
	handle, row, err := k.mintTier3At(PurposeProject, orgID, projectID, set.active+1)
	if err != nil {
		return WrappedKey{}, nil, err
	}
	// The freshly minted key material is not cached — eviction rebuilds the set
	// from the store — so zero it now; the sealed blob in row is all that is
	// needed past commit.
	Zero(handle.key)
	return row, func() { k.evictProjectDEK(orgID, projectID) }, nil
}

// ReloadInstanceDEK rebuilds the instance DEK version set from the store,
// dropping versions no longer openable. reencrypt --instance calls it after
// retiring the instance scope's retiring versions, so the held set stops
// offering them.
func (k *Keyring) ReloadInstanceDEK(ctx context.Context) error {
	set, err := k.loadTier3Versions(ctx, PurposeInstance, "", "")
	if err != nil {
		return err
	}
	k.instance.Store(set)
	return nil
}

// PrepareInstanceDEKRotation mints the next instance DEK version and returns the
// adopt function that installs it. Unlike a project DEK the instance set is held
// for the process lifetime, so adoption swaps in a new set carrying the new
// active version alongside every still-openable retiring version. Monotonic: a
// late or losing adopt whose version does not advance the live set is a no-op.
func (k *Keyring) PrepareInstanceDEKRotation() (WrappedKey, func(), error) {
	cur := k.instance.Load()
	handle, row, err := k.mintTier3At(PurposeInstance, "", "", cur.active+1)
	if err != nil {
		return WrappedKey{}, nil, err
	}
	return row, func() {
		for {
			old := k.instance.Load()
			if handle.version <= old.active {
				return
			}
			byVer := make(map[uint32]keyHandle, len(old.byVer)+1)
			for v, h := range old.byVer {
				byVer[v] = h
			}
			byVer[handle.version] = handle
			next := &versionSet{active: handle.version, byVer: byVer}
			if k.instance.CompareAndSwap(old, next) {
				return
			}
		}
	}, nil
}

// ProjectSealer seals and opens ciphertext in one project's key domain. It
// holds every still-openable DEK version for the scope: new writes seal under
// the active version, reads resolve the version named in the record's header,
// so a sealer opens ciphertext a reencrypt has not yet moved off a superseded
// version. The set is fixed at construction — a rotation that lands after this
// sealer is built is picked up by the next ForProject, not by this instance.
type ProjectSealer struct {
	redactor
	kr               *Keyring
	orgID, projectID string
	deks             *versionSet
}

func (s *ProjectSealer) checkScope(orgID, projectID string) error {
	if orgID != s.orgID || projectID != s.projectID {
		return fmt.Errorf("crypto: AAD names %s/%s, sealer is scoped to %s/%s",
			orgID, projectID, s.orgID, s.projectID)
	}
	return nil
}

// openVersioned resolves the DEK version named in the record header and opens
// under it. A record naming a version this sealer does not hold — retired to
// zero references, or minted after this sealer was built — fails closed as a
// decrypt error rather than opening under the wrong key.
func (s *ProjectSealer) openVersioned(a AAD, record []byte) ([]byte, error) {
	h, _, err := parseHeader(record)
	if err != nil {
		return nil, err
	}
	dek, ok := s.deks.at(h.keyVersion)
	if !ok {
		return nil, ErrDecrypt
	}
	return open(dek.key, []byte(dek.id), dek.version, a, record)
}

// ActiveVersion is the DEK version new writes seal under. reencrypt compares it
// against a record's header version to decide whether the row is already
// current and can be skipped.
func (s *ProjectSealer) ActiveVersion() uint32 { return s.deks.active }

// Open and Seal are the AAD-kind-generic forms of OpenValue/OpenField and
// SealValue/SealField, for reencrypt's table-agnostic walk. They dispatch on the
// AAD's concrete type to apply the scope check, then resolve the record's
// version (Open) or seal under the active version (Seal). A sealer built for one
// project rejects an AAD naming another.
func (s *ProjectSealer) Open(a AAD, record []byte) ([]byte, error) {
	if err := s.checkAADScope(a); err != nil {
		return nil, err
	}
	return s.openVersioned(a, record)
}

func (s *ProjectSealer) Seal(a AAD, plaintext []byte) ([]byte, error) {
	if err := s.checkAADScope(a); err != nil {
		return nil, err
	}
	d := s.deks.activeHandle()
	return seal(s.kr.rnd, d.key, []byte(d.id), d.version, a, plaintext)
}

func (s *ProjectSealer) checkAADScope(a AAD) error {
	switch v := a.(type) {
	case ValueAAD:
		return s.checkScope(v.OrgID, v.ProjectID)
	case ProjectFieldAAD:
		return s.checkScope(v.OrgID, v.ProjectID)
	default:
		return fmt.Errorf("crypto: project sealer cannot handle AAD kind %d", a.kind())
	}
}

func (s *ProjectSealer) SealValue(a ValueAAD, plaintext []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	d := s.deks.activeHandle()
	return seal(s.kr.rnd, d.key, []byte(d.id), d.version, a, plaintext)
}

func (s *ProjectSealer) OpenValue(a ValueAAD, record []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	return s.openVersioned(a, record)
}

func (s *ProjectSealer) SealField(a ProjectFieldAAD, plaintext []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	d := s.deks.activeHandle()
	return seal(s.kr.rnd, d.key, []byte(d.id), d.version, a, plaintext)
}

func (s *ProjectSealer) OpenField(a ProjectFieldAAD, record []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	return s.openVersioned(a, record)
}

// InstanceSealer seals and opens instance-scoped fields under the instance
// DEK. It accepts only instance_field envelopes — the type system, not a
// runtime branch, keeps project-owned material out of the instance domain.
//
// Like ProjectSealer, it captures its write-side handle at construction (a
// point-in-time snapshot of the active version) so Version() and the writer
// fence agree on the version a row was actually sealed under, even if a
// rotate-dek adopts a new active between ForInstance and the fenced commit. The
// old key buffer is never zeroed on instance-DEK adoption (ReloadInstanceDEK /
// the rotation adopt swap the atomic set and let the GC reclaim it), so a
// captured handle stays usable — which is exactly the stale write the fence
// then rejects. Reads (OpenField) resolve every version live and are unaffected.
type InstanceSealer struct {
	redactor
	kr *Keyring
	wh keyHandle
}

func (s *InstanceSealer) SealField(a InstanceFieldAAD, plaintext []byte) ([]byte, error) {
	d := s.wh
	return seal(s.kr.rnd, d.key, []byte(d.id), d.version, a, plaintext)
}

func (s *InstanceSealer) OpenField(a InstanceFieldAAD, record []byte) ([]byte, error) {
	h, _, err := parseHeader(record)
	if err != nil {
		return nil, err
	}
	d, ok := s.kr.instance.Load().at(h.keyVersion)
	if !ok {
		return nil, ErrDecrypt
	}
	return open(d.key, []byte(d.id), d.version, a, record)
}

// Version reports the instance DEK version this sealer writes under — the
// active version captured when the sealer was built. Credential rows record it
// so `reencrypt` knows which rows it has already moved, and so the writer
// fence's compare-and-swap has the sealed version, not a live re-read, to check.
func (s *InstanceSealer) Version() uint32 { return s.wh.version }
