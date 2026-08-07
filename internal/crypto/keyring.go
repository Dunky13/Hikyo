package crypto

import (
	"container/list"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Purpose distinguishes the tier-3 keys: one DEK per project, one instance
// DEK for rows belonging to no project, and the root token key (derivation
// only, never encryption). The scanning-fingerprint key (secret-scanning
// amendment) lands with its ticket; the column set already carries it.
type Purpose string

const (
	PurposeProject  Purpose = "project"
	PurposeInstance Purpose = "instance"
	PurposeToken    Purpose = "token"
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

// KeyStore is the persistence seam. internal/store/keyring implements it;
// every method that creates keys must run in one transaction, acquire the
// hierarchy generation (the fence that serializes tier-3 key creation
// against master rotation — encryption ADR § Rotation), and for tier-3
// creation verify the key's MasterKeyVersion is still the active master
// inside that fence (ErrStaleMaster otherwise).
type KeyStore interface {
	// ActiveMasterWrappers returns every active wrapper of the master key —
	// one per root epoch; two during a dual-wrapped root rotation; empty at
	// first boot.
	ActiveMasterWrappers(ctx context.Context) ([]WrappedKey, error)
	ActiveTier3(ctx context.Context, p Purpose, orgID, projectID string) (WrappedKey, error)
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

// dekCacheSize bounds the unwrapped project-DEK LRU cache. Ops-spec value;
// far above the v1 scale envelope either way.
const dekCacheSize = 128

type keyHandle struct {
	redactor
	id      string
	version uint32
	key     []byte
}

// Keyring holds the unwrapped key hierarchy for the server process — the
// only mode that ever constructs one. Master key, instance DEK and root
// token key live unwrapped for the process lifetime; project DEKs are
// unwrapped on demand into a bounded LRU.
type Keyring struct {
	redactor
	ks  KeyStore
	rnd io.Reader

	master   keyHandle
	instance keyHandle
	token    keyHandle

	mu   sync.Mutex
	deks map[string]*list.Element // scope → *list.Element holding *dekEntry
	lru  *list.List               // front = most recently used
}

type dekEntry struct {
	redactor
	scope  string
	handle keyHandle
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
	// (encryption ADR § Rotation). A wrapper at an unknown format version
	// aborts rather than guessing — refusal 5 — even if another opens.
	master, err := k.unwrapMaster(root, wrappers)
	if err != nil {
		return nil, err
	}
	k.master = master

	if k.instance, err = k.loadTier3(ctx, PurposeInstance, "", ""); err != nil {
		return nil, err
	}
	if k.token, err = k.loadTier3(ctx, PurposeToken, "", ""); err != nil {
		return nil, err
	}
	return k, nil
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
	k.master = keyHandle{version: version, key: master}

	instance, instanceRow, err := k.mintTier3(PurposeInstance, "", "")
	if err != nil {
		return err
	}
	token, tokenRow, err := k.mintTier3(PurposeToken, "", "")
	if err != nil {
		return err
	}

	err = k.ks.CreateHierarchy(ctx, WrappedKey{
		Version:      version,
		RootKeyEpoch: epoch,
		Blob:         masterBlob,
	}, []WrappedKey{instanceRow, tokenRow})
	if err != nil {
		Zero(master)
		Zero(instance.key)
		Zero(token.key)
		k.master = keyHandle{}
		return err
	}
	k.instance, k.token = instance, token
	return nil
}

// mintTier3 generates a tier-3 key and its wrapped row under the current
// master. The caller persists the row.
func (k *Keyring) mintTier3(p Purpose, orgID, projectID string) (keyHandle, WrappedKey, error) {
	key, err := k.newKey()
	if err != nil {
		return keyHandle{}, WrappedKey{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return keyHandle{}, WrappedKey{}, fmt.Errorf("crypto: generate key id: %w", err)
	}
	row := WrappedKey{
		ID:               "dek_" + id.String(),
		Purpose:          p,
		OrgID:            orgID,
		ProjectID:        projectID,
		Version:          1,
		MasterKeyVersion: k.master.version,
	}
	if row.Blob, err = seal(k.rnd, k.master.key, masterKeyID, k.master.version, tier3AAD(row), key); err != nil {
		return keyHandle{}, WrappedKey{}, err
	}
	return keyHandle{id: row.ID, version: row.Version, key: key}, row, nil
}

// tier3AAD is the one place the tier-3 row → AAD mapping lives: the token
// key wraps under wrapped_token_key, every DEK-shaped key (project,
// instance, future scanning) under wrapped_dek.
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

func (k *Keyring) unwrapTier3(row WrappedKey) (keyHandle, error) {
	if row.MasterKeyVersion != k.master.version {
		// Scaffolding honesty: multi-version masters arrive with the
		// rotations ticket; until then a mismatch is corruption.
		return keyHandle{}, fmt.Errorf("crypto: %s key %s wrapped under master v%d, active is v%d",
			row.Purpose, row.ID, row.MasterKeyVersion, k.master.version)
	}
	key, err := open(k.master.key, masterKeyID, row.MasterKeyVersion, tier3AAD(row), row.Blob)
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
	dek, err := k.projectDEK(ctx, orgID, projectID)
	if err != nil {
		return nil, err
	}
	return &ProjectSealer{kr: k, orgID: orgID, projectID: projectID, dek: dek}, nil
}

func (k *Keyring) projectDEK(ctx context.Context, orgID, projectID string) (keyHandle, error) {
	scope := dekScope(orgID, projectID)
	k.mu.Lock()
	defer k.mu.Unlock()
	if el, ok := k.deks[scope]; ok {
		k.lru.MoveToFront(el)
		return el.Value.(*dekEntry).handle, nil
	}

	row, err := k.ks.ActiveTier3(ctx, PurposeProject, orgID, projectID)
	if errors.Is(err, ErrNoKey) {
		handle, newRow, mintErr := k.mintTier3(PurposeProject, orgID, projectID)
		if mintErr != nil {
			return keyHandle{}, mintErr
		}
		switch createErr := k.ks.CreateTier3(ctx, newRow); {
		case createErr == nil:
			k.cacheDEK(scope, handle)
			return handle, nil
		case errors.Is(createErr, ErrKeyExists):
			Zero(handle.key)
			row, err = k.ks.ActiveTier3(ctx, PurposeProject, orgID, projectID)
		default:
			Zero(handle.key)
			return keyHandle{}, createErr
		}
	}
	if err != nil {
		return keyHandle{}, fmt.Errorf("crypto: load project key: %w", err)
	}
	handle, err := k.unwrapTier3(row)
	if err != nil {
		return keyHandle{}, err
	}
	k.cacheDEK(scope, handle)
	return handle, nil
}

// cacheDEK inserts under k.mu, evicting the least recently used entry past
// the bound. Evicted keys are NOT zeroed here: a live ProjectSealer may
// still alias the buffer, and sealing under a zeroed key would be a silent
// confidentiality break. Zeroing happens only where fencing guarantees no
// live holder — rotation and project delete, with their tickets.
func (k *Keyring) cacheDEK(scope string, h keyHandle) {
	k.deks[scope] = k.lru.PushFront(&dekEntry{scope: scope, handle: h})
	if k.lru.Len() > dekCacheSize {
		oldest := k.lru.Back()
		k.lru.Remove(oldest)
		delete(k.deks, oldest.Value.(*dekEntry).scope)
	}
}

// ForInstance returns the sealer for instance-scoped sensitive fields.
func (k *Keyring) ForInstance() *InstanceSealer {
	return &InstanceSealer{kr: k}
}

// ProjectSealer seals and opens ciphertext in one project's key domain.
type ProjectSealer struct {
	redactor
	kr               *Keyring
	orgID, projectID string
	dek              keyHandle
}

func (s *ProjectSealer) checkScope(orgID, projectID string) error {
	if orgID != s.orgID || projectID != s.projectID {
		return fmt.Errorf("crypto: AAD names %s/%s, sealer is scoped to %s/%s",
			orgID, projectID, s.orgID, s.projectID)
	}
	return nil
}

func (s *ProjectSealer) SealValue(a ValueAAD, plaintext []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	return seal(s.kr.rnd, s.dek.key, []byte(s.dek.id), s.dek.version, a, plaintext)
}

func (s *ProjectSealer) OpenValue(a ValueAAD, record []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	return open(s.dek.key, []byte(s.dek.id), s.dek.version, a, record)
}

func (s *ProjectSealer) SealField(a ProjectFieldAAD, plaintext []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	return seal(s.kr.rnd, s.dek.key, []byte(s.dek.id), s.dek.version, a, plaintext)
}

func (s *ProjectSealer) OpenField(a ProjectFieldAAD, record []byte) ([]byte, error) {
	if err := s.checkScope(a.OrgID, a.ProjectID); err != nil {
		return nil, err
	}
	return open(s.dek.key, []byte(s.dek.id), s.dek.version, a, record)
}

// InstanceSealer seals and opens instance-scoped fields under the instance
// DEK. It accepts only instance_field envelopes — the type system, not a
// runtime branch, keeps project-owned material out of the instance domain.
type InstanceSealer struct {
	redactor
	kr *Keyring
}

func (s *InstanceSealer) SealField(a InstanceFieldAAD, plaintext []byte) ([]byte, error) {
	d := s.kr.instance
	return seal(s.kr.rnd, d.key, []byte(d.id), d.version, a, plaintext)
}

func (s *InstanceSealer) OpenField(a InstanceFieldAAD, record []byte) ([]byte, error) {
	d := s.kr.instance
	return open(d.key, []byte(d.id), d.version, a, record)
}

// Version reports the instance DEK version a row was (or will be) sealed
// under. Credential rows record it so `reencrypt` knows which rows it has
// already moved, and so the compare-and-swap rule has something to compare.
func (s *InstanceSealer) Version() uint32 { return s.kr.instance.version }
