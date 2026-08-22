package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// memStore is an in-memory KeyStore for keyring tests. tier3 holds every
// version of each scope's key (active + retiring); the highest version is the
// active one, mirroring the store's one-active-per-scope semantics.
type memStore struct {
	mu           sync.Mutex
	master       *WrappedKey
	extraMasters []WrappedKey            // additional wrappers, returned after master
	tier3        map[string][]WrappedKey // scope key purpose|org|project → versions
}

func newMemStore() *memStore { return &memStore{tier3: map[string][]WrappedKey{}} }

func t3key(p Purpose, org, proj string) string { return string(p) + "|" + org + "|" + proj }

// activeOf returns the highest-version row for a scope, or false if none.
func activeOf(rows []WrappedKey) (WrappedKey, bool) {
	var out WrappedKey
	var found bool
	for _, r := range rows {
		if !found || r.Version > out.Version {
			out, found = r, true
		}
	}
	return out, found
}

func (m *memStore) ActiveMasterWrappers(context.Context) ([]WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.master == nil {
		return nil, nil
	}
	return append([]WrappedKey{*m.master}, m.extraMasters...), nil
}

func (m *memStore) ActiveTier3(_ context.Context, p Purpose, org, proj string) (WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := activeOf(m.tier3[t3key(p, org, proj)])
	if !ok {
		return WrappedKey{}, ErrNoKey
	}
	return k, nil
}

func (m *memStore) Tier3Versions(_ context.Context, p Purpose, org, proj string) ([]WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.tier3[t3key(p, org, proj)]
	out := make([]WrappedKey, len(rows))
	copy(out, rows)
	return out, nil
}

func (m *memStore) AllOpenableTier3(_ context.Context) ([]WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []WrappedKey
	for _, rows := range m.tier3 {
		out = append(out, rows...)
	}
	return out, nil
}

func (m *memStore) CreateHierarchy(_ context.Context, master WrappedKey, tier3 []WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.master != nil {
		return ErrKeyExists
	}
	m.master = &master
	for _, k := range tier3 {
		key := t3key(k.Purpose, k.OrgID, k.ProjectID)
		m.tier3[key] = append(m.tier3[key], k)
	}
	return nil
}

func (m *memStore) CreateTier3(_ context.Context, k WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := t3key(k.Purpose, k.OrgID, k.ProjectID)
	if _, ok := activeOf(m.tier3[key]); ok {
		return ErrKeyExists
	}
	m.tier3[key] = append(m.tier3[key], k)
	return nil
}

func newRoot(t *testing.T) []byte {
	t.Helper()
	root := make([]byte, KeySize)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFirstBootMintsAndReboots(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	rootCopy := bytes.Clone(root)

	kr, err := LoadKeyring(ctx, ks, root)
	if err != nil {
		t.Fatal(err)
	}
	// LoadKeyring consumes (zeroes) the root key it was handed.
	if !bytes.Equal(root, make([]byte, KeySize)) {
		t.Error("root key not zeroed after load")
	}
	if ks.master == nil || len(ks.tier3) != 3 {
		t.Fatalf("first boot minted master=%v tier3=%d, want master + instance + token + scanning", ks.master != nil, len(ks.tier3))
	}

	// Seal in boot one, open after reboot: the persisted hierarchy is real.
	sealer, err := kr.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	aad := testValueAAD()
	ct, err := sealer.SealValue(aad, []byte("survives reboot"))
	if err != nil {
		t.Fatal(err)
	}

	kr2, err := LoadKeyring(ctx, ks, bytes.Clone(rootCopy))
	if err != nil {
		t.Fatalf("reboot with same root: %v", err)
	}
	sealer2, err := kr2.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sealer2.OpenValue(aad, ct)
	if err != nil || string(pt) != "survives reboot" {
		t.Fatalf("open after reboot: %q, %v", pt, err)
	}
}

func TestWrongRootKeyRefused(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	if _, err := LoadKeyring(ctx, ks, newRoot(t)); err != nil {
		t.Fatal(err)
	}
	_, err := LoadKeyring(ctx, ks, newRoot(t))
	if !errors.Is(err, ErrRootKeyMismatch) {
		t.Errorf("err = %v, want ErrRootKeyMismatch", err)
	}
}

// Refusal 5 must hold across the whole wrapper set: a valid wrapper first
// in order must not mask an unknown-format wrapper behind it.
func TestUnknownFormatWrapperRefusedEvenWhenAnotherOpens(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	kr, err := LoadKeyring(ctx, ks, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	_ = kr
	// Second wrapper of the same master at an unknown format version,
	// ordered AFTER the valid one.
	bad := *ks.master
	bad.Blob = bytes.Clone(bad.Blob)
	bad.Blob[0] = 0x7F
	bad.RootKeyEpoch = 0 // distinct epoch, sorts after in the fake's slice
	ks.extraMasters = append(ks.extraMasters, bad)

	_, err = LoadKeyring(ctx, ks, root)
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("err = %v, want ErrUnknownFormat — a valid wrapper must not mask an unreadable one", err)
	}
}

func TestUnknownMasterFormatRefusedDistinctly(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	if _, err := LoadKeyring(ctx, ks, bytes.Clone(root)); err != nil {
		t.Fatal(err)
	}
	ks.master.Blob[0] = 0x7F
	_, err := LoadKeyring(ctx, ks, root)
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("err = %v, want ErrUnknownFormat (refusal 5, distinct from wrong-root)", err)
	}
}

func TestProjectSealerScopeEnforced(t *testing.T) {
	ctx := context.Background()
	kr, err := LoadKeyring(ctx, newMemStore(), newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	// AAD naming a different project than the sealer's scope is refused
	// before any crypto runs (invariant 16's structural half).
	_, err = sealer.SealValue(ValueAAD{OrgID: "org_1", ProjectID: "prj_2", EnvID: "e", KeyID: "k", RowID: "r", FieldTag: "f"}, []byte("x"))
	if err == nil {
		t.Error("cross-project AAD accepted")
	}
	_, err = sealer.SealField(ProjectFieldAAD{OrgID: "org_2", ProjectID: "prj_1", OwnerTable: "t", OwnerRowID: "r", FieldTag: "f"}, []byte("x"))
	if err == nil {
		t.Error("cross-org AAD accepted")
	}
	if _, err := kr.ForProject(ctx, "", "prj_1"); err == nil {
		t.Error("empty org id accepted")
	}
}

// Invariant 16, cross-domain half: a record sealed in the project domain can
// never open in the instance domain, and vice versa — different DEKs and
// different envelope kinds.
func TestProjectAndInstanceDomainsAreDisjoint(t *testing.T) {
	ctx := context.Background()
	kr, err := LoadKeyring(ctx, newMemStore(), newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.SealField(ProjectFieldAAD{
		OrgID: "org_1", ProjectID: "prj_1", OwnerTable: "adapters", OwnerRowID: "r1", FieldTag: "cred",
	}, []byte("project-owned"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.ForInstance().OpenField(InstanceFieldAAD{
		OwnerTable: "adapters", OwnerRowID: "r1", FieldTag: "cred",
	}, ct); err == nil {
		t.Error("project field opened under the instance DEK")
	}

	ict, err := kr.ForInstance().SealField(InstanceFieldAAD{
		OwnerTable: "users", OwnerRowID: "u1", FieldTag: "mfa",
	}, []byte("instance-owned"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealer.OpenField(ProjectFieldAAD{
		OrgID: "org_1", ProjectID: "prj_1", OwnerTable: "users", OwnerRowID: "u1", FieldTag: "mfa",
	}, ict); err == nil {
		t.Error("instance field opened under a project DEK")
	}
}

func TestProjectDEKsAreDistinctAndCached(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	kr, err := LoadKeyring(ctx, ks, newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	a, err := kr.ForProject(ctx, "org_1", "prj_a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := kr.ForProject(ctx, "org_1", "prj_b")
	if err != nil {
		t.Fatal(err)
	}
	ah, bh := a.deks.activeHandle(), b.deks.activeHandle()
	if ah.id == bh.id || bytes.Equal(ah.key, bh.key) {
		t.Error("two projects share a DEK")
	}
	a2, err := kr.ForProject(ctx, "org_1", "prj_a")
	if err != nil {
		t.Fatal(err)
	}
	if a2.deks.activeHandle().id != ah.id {
		t.Error("cache miss returned a different key for the same scope")
	}
}

// A sealer built after a DEK rotation opens ciphertext written under the old
// version (the retiring key is still in its version set) while sealing new
// writes under the new active version. This is the read half of `rotate-dek`:
// old versions remain readable until reencrypt walks them.
func TestProjectDEKOpensAcrossVersions(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	kr, err := LoadKeyring(ctx, ks, newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	const org, proj = "org_1", "prj_1"

	s1, err := kr.ForProject(ctx, org, proj)
	if err != nil {
		t.Fatal(err)
	}
	aad := testValueAAD()
	ctV1, err := s1.SealValue(aad, []byte("written under v1"))
	if err != nil {
		t.Fatal(err)
	}
	if s1.ActiveVersion() != 1 {
		t.Fatalf("fresh scope active version = %d, want 1", s1.ActiveVersion())
	}

	// Simulate `rotate-dek`: append a v2 active key for the scope. (The store
	// machinery that demotes v1 to retiring lands with the operation; here the
	// version set carries both, which is what matters for the read path.)
	_, v2row, err := kr.mintTier3At(PurposeProject, org, proj, 2)
	if err != nil {
		t.Fatal(err)
	}
	scope := t3key(PurposeProject, org, proj)
	ks.tier3[scope] = append(ks.tier3[scope], v2row)
	kr.evictProjectDEK(org, proj)

	s2, err := kr.ForProject(ctx, org, proj)
	if err != nil {
		t.Fatal(err)
	}
	if s2.ActiveVersion() != 2 {
		t.Fatalf("after rotation active version = %d, want 2", s2.ActiveVersion())
	}
	// Old ciphertext still opens under the retiring v1 key.
	pt, err := s2.OpenValue(aad, ctV1)
	if err != nil || string(pt) != "written under v1" {
		t.Fatalf("open v1 ciphertext after rotation: %q, %v", pt, err)
	}
	// New writes seal under v2.
	ctV2, err := s2.SealValue(aad, []byte("written under v2"))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := RecordKeyVersion(ctV2); err != nil || v != 2 {
		t.Fatalf("new write sealed under version %d (err %v), want 2", v, err)
	}
	if v, err := RecordKeyVersion(ctV1); err != nil || v != 1 {
		t.Fatalf("old record reports version %d (err %v), want 1", v, err)
	}
}

// Master rotation re-wraps every tier-3 key under a new master. Key bytes do
// not change, so ciphertext sealed before the rotation still opens — whether
// the DEK is served from cache (bytes unchanged) or reloaded from the store
// (now unwrapped under the new master version).
func TestMasterKeyRotationRewrapsTier3(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	rootCopy := bytes.Clone(root)
	kr, err := LoadKeyring(ctx, ks, root)
	if err != nil {
		t.Fatal(err)
	}
	const org, proj = "org_m", "prj_m"
	sealer, err := kr.ForProject(ctx, org, proj)
	if err != nil {
		t.Fatal(err)
	}
	aad := ValueAAD{OrgID: org, ProjectID: proj, EnvID: "env_1", KeyID: "key_1", RowID: "row_1", FieldTag: "value"}
	ct, err := sealer.SealValue(aad, []byte("under master v1"))
	if err != nil {
		t.Fatal(err)
	}
	if kr.master.Load().active != 1 {
		t.Fatalf("initial master version = %d, want 1", kr.master.Load().active)
	}

	newMaster, rewrapped, adopt, _, err := kr.PrepareMasterKeyRotation(ctx, bytes.Clone(rootCopy))
	if err != nil {
		t.Fatal(err)
	}
	if newMaster.Version != 2 {
		t.Fatalf("new master version = %d, want 2", newMaster.Version)
	}
	if len(rewrapped) < 3 {
		t.Fatalf("re-wrapped %d tier-3 keys, want at least instance+token+project", len(rewrapped))
	}
	// Simulate the store commit: new active master, every tier-3 row re-pointed.
	ks.master = &newMaster
	for _, rw := range rewrapped {
		if rw.MasterKeyVersion != 2 {
			t.Fatalf("re-wrapped %s still on master v%d", rw.ID, rw.MasterKeyVersion)
		}
		scope := t3key(rw.Purpose, rw.OrgID, rw.ProjectID)
		for i, r := range ks.tier3[scope] {
			if r.Version == rw.Version {
				ks.tier3[scope][i] = rw
			}
		}
	}
	adopt()
	if kr.master.Load().active != 2 {
		t.Fatalf("after adopt master version = %d, want 2", kr.master.Load().active)
	}

	// Cache hit: the DEK bytes did not change.
	pt, err := sealer.OpenValue(aad, ct)
	if err != nil || string(pt) != "under master v1" {
		t.Fatalf("open after master rotation (cache hit): %q, %v", pt, err)
	}
	// Reload from the store: the row now unwraps under the new master version.
	kr.evictProjectDEK(org, proj)
	sealer2, err := kr.ForProject(ctx, org, proj)
	if err != nil {
		t.Fatalf("reload DEK after master rotation: %v", err)
	}
	pt, err = sealer2.OpenValue(aad, ct)
	if err != nil || string(pt) != "under master v1" {
		t.Fatalf("open after master rotation (reload): %q, %v", pt, err)
	}

	// A fresh boot under the same root unwraps the NEW master and the re-wrapped
	// hierarchy — proving the new master blob is sealed correctly under the root.
	kr2, err := LoadKeyring(ctx, ks, bytes.Clone(rootCopy))
	if err != nil {
		t.Fatalf("reboot after master rotation: %v", err)
	}
	sealer3, err := kr2.ForProject(ctx, org, proj)
	if err != nil {
		t.Fatal(err)
	}
	pt, err = sealer3.OpenValue(aad, ct)
	if err != nil || string(pt) != "under master v1" {
		t.Fatalf("open after reboot under rotated master: %q, %v", pt, err)
	}
}

// Invariant 8: root rotation is crash-safe. After --prepare dual-wraps the
// master, the instance boots under EITHER root (a crash mid-rotation leaves the
// same persisted state as a clean stop), warns while dual-wrapped, and after
// --finalize only the new root boots — the old is refused.
func TestRootKeyRotationCrashSafe(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	rootA := newRoot(t)
	kr, err := LoadKeyring(ctx, ks, bytes.Clone(rootA))
	if err != nil {
		t.Fatal(err)
	}
	const org, proj = "org_r", "prj_r"
	sealer, err := kr.ForProject(ctx, org, proj)
	if err != nil {
		t.Fatal(err)
	}
	aad := ValueAAD{OrgID: org, ProjectID: proj, EnvID: "env_1", KeyID: "key_1", RowID: "row_1", FieldTag: "value"}
	ct, err := sealer.SealValue(aad, []byte("survives root rotation"))
	if err != nil {
		t.Fatal(err)
	}

	rootB := newRoot(t)
	wrapper, err := kr.PrepareRootKeyRotation(ctx, bytes.Clone(rootB))
	if err != nil {
		t.Fatal(err)
	}
	// Persist the dual wrapper (as RootKeyRotatePrepare would), then simulate a
	// crash: discard kr and reboot from the datastore alone.
	ks.extraMasters = append(ks.extraMasters, wrapper)

	openUnder := func(name string, root []byte) *Keyring {
		k, err := LoadKeyring(ctx, ks, bytes.Clone(root))
		if err != nil {
			t.Fatalf("dual-wrapped boot under %s: %v", name, err)
		}
		if !k.RootRotationPending() {
			t.Errorf("boot under %s did not report the pending root rotation", name)
		}
		s, err := k.ForProject(ctx, org, proj)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pt, err := s.OpenValue(aad, ct)
		if err != nil || string(pt) != "survives root rotation" {
			t.Fatalf("open under %s while dual-wrapped: %q, %v", name, pt, err)
		}
		return k
	}
	openUnder("old root", rootA)
	krB := openUnder("new root", rootB)

	// Verify: the new root (now the primary source) unwraps the new wrapper.
	if _, err := krB.VerifyRootKeyRotation(ctx, bytes.Clone(rootB)); err != nil {
		t.Fatalf("verify under new root: %v", err)
	}

	// Finalize: retire the old wrapper, leaving the new one sole active.
	ks.master = &wrapper
	ks.extraMasters = nil

	krFinal, err := LoadKeyring(ctx, ks, bytes.Clone(rootB))
	if err != nil {
		t.Fatalf("boot under new root after finalize: %v", err)
	}
	if krFinal.RootRotationPending() {
		t.Error("finalized instance still reports a pending rotation")
	}
	if _, err := LoadKeyring(ctx, ks, bytes.Clone(rootA)); !errors.Is(err, ErrRootKeyMismatch) {
		t.Errorf("old root after finalize: err = %v, want ErrRootKeyMismatch", err)
	}
}

// Prepare is refused while a root rotation is already pending (dual-wrapped):
// two pending rotations are the four-way matrix the ADR refuses.
func TestRootKeyRotationPrepareBlockedWhenPending(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	kr, err := LoadKeyring(ctx, ks, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	ks.extraMasters = append(ks.extraMasters, WrappedKey{Version: 1, RootKeyEpoch: 2, Blob: []byte{0x01}})
	if _, err := kr.PrepareRootKeyRotation(ctx, newRoot(t)); !errors.Is(err, ErrRootRotationBlocked) {
		t.Fatalf("prepare while pending: err = %v, want ErrRootRotationBlocked", err)
	}
}

// Master rotation is refused while the root is dual-wrapped (more than one
// active master wrapper): the two rotations are mutually exclusive.
func TestMasterKeyRotationBlockedWhenDualWrapped(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	kr, err := LoadKeyring(ctx, ks, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a dual-wrapped root: a second active master wrapper (same version,
	// a different epoch), as rotate-root-key --prepare would leave it.
	ks.extraMasters = append(ks.extraMasters, WrappedKey{Version: 1, RootKeyEpoch: 2, Blob: []byte{0x01}})
	if _, _, _, _, err := kr.PrepareMasterKeyRotation(ctx, bytes.Clone(root)); !errors.Is(err, ErrMasterRotationBlocked) {
		t.Fatalf("dual-wrapped master rotation: err = %v, want ErrMasterRotationBlocked", err)
	}
}

// lostRaceStore simulates losing the mint race deterministically: the first
// project-DEK read reports ErrNoKey (the rival has not committed yet), the
// subsequent CreateTier3 hits the rival's committed row (ErrKeyExists), and
// the re-read must converge on the winner.
type lostRaceStore struct {
	*memStore
	raced bool
}

func (s *lostRaceStore) Tier3Versions(ctx context.Context, p Purpose, org, proj string) ([]WrappedKey, error) {
	if p == PurposeProject && !s.raced {
		s.raced = true
		return nil, nil
	}
	return s.memStore.Tier3Versions(ctx, p, org, proj)
}

// A lost CreateTier3 race must converge on the winner's key — through the
// ErrKeyExists branch, not around it — never error, never fork the domain.
func TestProjectDEKMintRaceConverges(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	kr1, err := LoadKeyring(ctx, ks, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	s1, err := kr1.ForProject(ctx, "org_1", "prj_1") // the winner commits first
	if err != nil {
		t.Fatal(err)
	}

	racing := &lostRaceStore{memStore: ks}
	kr2, err := LoadKeyring(ctx, racing, root)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := kr2.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	if !racing.raced {
		t.Fatal("test harness bug: the race branch never ran")
	}
	h1, h2 := s1.deks.activeHandle(), s2.deks.activeHandle()
	if h1.id != h2.id {
		t.Errorf("same scope resolved to different DEKs: %s vs %s", h1.id, h2.id)
	}
	if !bytes.Equal(h1.key, h2.key) {
		t.Error("loser did not converge on the winner's key material")
	}
}

func TestDEKCacheBounded(t *testing.T) {
	ctx := context.Background()
	kr, err := LoadKeyring(ctx, newMemStore(), newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range dekCacheSize + 10 {
		if _, err := kr.ForProject(ctx, "org_1", fmt.Sprintf("prj_%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if kr.lru.Len() != dekCacheSize || len(kr.deks) != dekCacheSize {
		t.Errorf("cache size = %d/%d, want %d", kr.lru.Len(), len(kr.deks), dekCacheSize)
	}
	// An evicted scope still works: re-fetched from the store.
	if _, err := kr.ForProject(ctx, "org_1", "prj_0"); err != nil {
		t.Errorf("evicted scope unusable: %v", err)
	}
}

// Regression (code review, #43): a sealer obtained before its scope was
// evicted from the DEK cache aliases the cached buffer. Eviction must not
// zero it — a zeroed-key seal would be a silent confidentiality break.
func TestSealerSurvivesCacheEviction(t *testing.T) {
	ctx := context.Background()
	kr, err := LoadKeyring(ctx, newMemStore(), newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := kr.ForProject(ctx, "org_1", "prj_victim")
	if err != nil {
		t.Fatal(err)
	}
	for i := range dekCacheSize + 1 {
		if _, err := kr.ForProject(ctx, "org_1", fmt.Sprintf("prj_%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	aad := ValueAAD{OrgID: "org_1", ProjectID: "prj_victim", EnvID: "e", KeyID: "k", RowID: "r", FieldTag: "f"}
	ct, err := sealer.SealValue(aad, []byte("sealed after eviction"))
	if err != nil {
		t.Fatal(err)
	}
	// Open with a freshly fetched sealer: fails if the old sealer's key was
	// zeroed under it.
	fresh, err := kr.ForProject(ctx, "org_1", "prj_victim")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := fresh.OpenValue(aad, ct)
	if err != nil || string(pt) != "sealed after eviction" {
		t.Fatalf("ciphertext sealed by evicted sealer: %q, %v", pt, err)
	}
}
