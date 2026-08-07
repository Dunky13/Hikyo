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

// memStore is an in-memory KeyStore for keyring tests.
type memStore struct {
	mu     sync.Mutex
	master *WrappedKey
	tier3  map[string]WrappedKey // scope key purpose|org|project
}

func newMemStore() *memStore { return &memStore{tier3: map[string]WrappedKey{}} }

func t3key(p Purpose, org, proj string) string { return string(p) + "|" + org + "|" + proj }

func (m *memStore) ActiveMaster(context.Context) (WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.master == nil {
		return WrappedKey{}, ErrNoKey
	}
	return *m.master, nil
}

func (m *memStore) ActiveTier3(_ context.Context, p Purpose, org, proj string) (WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.tier3[t3key(p, org, proj)]
	if !ok {
		return WrappedKey{}, ErrNoKey
	}
	return k, nil
}

func (m *memStore) CreateHierarchy(_ context.Context, master WrappedKey, tier3 []WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.master != nil {
		return ErrKeyExists
	}
	m.master = &master
	for _, k := range tier3 {
		m.tier3[t3key(k.Purpose, k.OrgID, k.ProjectID)] = k
	}
	return nil
}

func (m *memStore) CreateTier3(_ context.Context, k WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := t3key(k.Purpose, k.OrgID, k.ProjectID)
	if _, ok := m.tier3[key]; ok {
		return ErrKeyExists
	}
	m.tier3[key] = k
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
	if ks.master == nil || len(ks.tier3) != 2 {
		t.Fatalf("first boot minted master=%v tier3=%d, want master + instance + token", ks.master != nil, len(ks.tier3))
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
	if a.dek.id == b.dek.id || bytes.Equal(a.dek.key, b.dek.key) {
		t.Error("two projects share a DEK")
	}
	a2, err := kr.ForProject(ctx, "org_1", "prj_a")
	if err != nil {
		t.Fatal(err)
	}
	if a2.dek.id != a.dek.id {
		t.Error("cache miss returned a different key for the same scope")
	}
}

// A lost CreateTier3 race must converge on the winner's key, not error and
// not fork the key domain.
func TestProjectDEKMintRaceConverges(t *testing.T) {
	ctx := context.Background()
	ks := newMemStore()
	root := newRoot(t)
	kr1, err := LoadKeyring(ctx, ks, bytes.Clone(root))
	if err != nil {
		t.Fatal(err)
	}
	kr2, err := LoadKeyring(ctx, ks, root)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := kr1.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	// kr2 has a cold cache; the store already holds kr1's DEK.
	s2, err := kr2.ForProject(ctx, "org_1", "prj_1")
	if err != nil {
		t.Fatal(err)
	}
	if s1.dek.id != s2.dek.id {
		t.Errorf("same scope resolved to different DEKs: %s vs %s", s1.dek.id, s2.dek.id)
	}
}

// Invariant 10: identifier tuples that differ only in where the boundary
// falls derive distinct scoped token keys.
func TestScopedTokenKeyInjective(t *testing.T) {
	ctx := context.Background()
	kr, err := LoadKeyring(ctx, newMemStore(), newRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	k1, err := kr.ScopedTokenKey("a", "bc", "e")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := kr.ScopedTokenKey("ab", "c", "e")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Error("boundary-shifted scopes derive the same token key")
	}
	// Determinism: same scope, same key.
	k1b, err := kr.ScopedTokenKey("a", "bc", "e")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k1b) {
		t.Error("scoped token key is not deterministic")
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
