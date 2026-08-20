package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/keyring"
	"github.com/Hikyo-Org/hikyo/internal/store/migrate"
)

// Secret-scanning acknowledgement token security (#74, ADR §4, SS4). These
// exercise the sealed, content-bound token directly: a token is opaque and
// unforgeable, it binds one surface/locator/rule/content/snapshot, it expires,
// and a tampered or foreign token opens to nothing.

func ackTestKeyring(t *testing.T) *crypto.Keyring {
	t.Helper()
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "ack.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func sampleBinding() ackBinding {
	return ackBinding{
		kind:       ackKindDecl,
		locator:    locDeclPattern,
		ruleDigest: "sha256:rule-digest",
		contentSHA: contentDigest([]byte("AKIAIOSFODNN7EXAMPLE")),
		snapshot:   "snap-v1",
		mintNano:   time.Unix(1_700_000_000, 0).UnixNano(),
	}
}

func TestAckTokenRoundTrip(t *testing.T) {
	kr := ackTestKeyring(t)
	b := sampleBinding()
	tok, err := sealAck(kr, b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openAck(kr, tok)
	if err != nil {
		t.Fatalf("openAck: %v", err)
	}
	if got != b {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, b)
	}
}

func TestAckTokenOpaqueNoPlaintext(t *testing.T) {
	kr := ackTestKeyring(t)
	// The token must not carry the offending value or its content in the clear.
	tok, err := sealAck(kr, ackBinding{
		kind: ackKindValue, locator: "key_1", ruleDigest: "d",
		contentSHA: contentDigest([]byte("AKIAIOSFODNN7EXAMPLE")),
		snapshot:   "snap", mintNano: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"AKIAIOSFODNN7EXAMPLE", "AKIA"} {
		if strings.Contains(tok, canary) {
			t.Fatalf("token leaks canary %q: %s", canary, tok)
		}
	}
}

func TestAckTokenTamperRejected(t *testing.T) {
	kr := ackTestKeyring(t)
	tok, err := sealAck(kr, sampleBinding())
	if err != nil {
		t.Fatal(err)
	}
	// Flip one character of the base64url ciphertext.
	b := []byte(tok)
	if b[len(b)/2] == 'A' {
		b[len(b)/2] = 'B'
	} else {
		b[len(b)/2] = 'A'
	}
	if _, err := openAck(kr, string(b)); err == nil {
		t.Fatal("a tampered token opened successfully; must be rejected")
	}
}

func TestAckTokenForeignKeyringRejected(t *testing.T) {
	kr1 := ackTestKeyring(t)
	kr2 := ackTestKeyring(t)
	tok, err := sealAck(kr1, sampleBinding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openAck(kr2, tok); err == nil {
		t.Fatal("a token from another instance's keyring opened; must be unforgeable")
	}
}

func TestAckSetCrossSurfaceReplayRejected(t *testing.T) {
	kr := ackTestKeyring(t)
	now := time.Unix(1_700_000_100, 0)
	cSHA := contentDigest([]byte("AKIAIOSFODNN7EXAMPLE"))
	// A Surface-1 (value) keep-as-config token.
	tok, err := sealAck(kr, ackBinding{
		kind: ackKindValue, locator: "key_1", ruleDigest: "d",
		contentSHA: cSHA, snapshot: "snap", mintNano: now.Add(-time.Minute).UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Presented on the Surface-2 (declaration) path with the SAME locator/rule/
	// content — must not match, because the kind differs.
	set := newAckSet([]string{tok})
	if _, matched := set.match(kr, ackKindDecl, "key_1", "d", "snap", cSHA, now); matched {
		t.Fatal("a Surface-1 token matched a Surface-2 finding; cross-surface replay must be rejected")
	}
	// It DOES match on its own surface.
	set2 := newAckSet([]string{tok})
	if _, matched := set2.match(kr, ackKindValue, "key_1", "d", "snap", cSHA, now); !matched {
		t.Fatal("a Surface-1 token did not match its own Surface-1 finding")
	}
}

func TestAckSetStaleContentAndVersionRejected(t *testing.T) {
	kr := ackTestKeyring(t)
	now := time.Unix(1_700_000_100, 0)
	cSHA := contentDigest([]byte("AKIAIOSFODNN7EXAMPLE"))
	tok, err := sealAck(kr, ackBinding{
		kind: ackKindDecl, locator: locDeclPattern, ruleDigest: "d",
		contentSHA: cSHA, snapshot: "snap-1", mintNano: now.Add(-time.Minute).UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Content changed since minting → different digest → no match (stale).
	otherSHA := contentDigest([]byte("ghp_different"))
	if _, matched := newAckSet([]string{tok}).match(kr, ackKindDecl, locDeclPattern, "d", "snap-1", otherSHA, now); matched {
		t.Fatal("a stale token (content changed) matched; must be rejected")
	}
	// Ruleset version changed → no match (version skew).
	if _, matched := newAckSet([]string{tok}).match(kr, ackKindDecl, locDeclPattern, "d", "snap-2", cSHA, now); matched {
		t.Fatal("a version-skewed token matched; must be rejected")
	}
}

func TestAckTokenExpires(t *testing.T) {
	kr := ackTestKeyring(t)
	mint := time.Unix(1_700_000_000, 0)
	cSHA := contentDigest([]byte("AKIAIOSFODNN7EXAMPLE"))
	tok, err := sealAck(kr, ackBinding{
		kind: ackKindDecl, locator: locDeclPattern, ruleDigest: "d",
		contentSHA: cSHA, snapshot: "snap", mintNano: mint.UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	within := mint.Add(ackTTL - time.Second)
	if _, matched := newAckSet([]string{tok}).match(kr, ackKindDecl, locDeclPattern, "d", "snap", cSHA, within); !matched {
		t.Fatal("a token within its TTL did not match")
	}
	expired := mint.Add(ackTTL + time.Second)
	if _, matched := newAckSet([]string{tok}).match(kr, ackKindDecl, locDeclPattern, "d", "snap", cSHA, expired); matched {
		t.Fatal("an expired token matched; must be rejected")
	}
}

func TestAckSetSurplusReported(t *testing.T) {
	kr := ackTestKeyring(t)
	now := time.Unix(1_700_000_100, 0)
	cSHA := contentDigest([]byte("AKIAIOSFODNN7EXAMPLE"))
	tok, err := sealAck(kr, ackBinding{
		kind: ackKindDecl, locator: locDeclPattern, ruleDigest: "d",
		contentSHA: cSHA, snapshot: "snap", mintNano: now.Add(-time.Minute).UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	set := newAckSet([]string{tok})
	// No finding claims it → it stays unconsumed (surplus).
	if n := set.unconsumed(); n != 1 {
		t.Fatalf("unconsumed = %d, want 1 (surplus token)", n)
	}
	// After a matching finding claims it, none remain surplus.
	set.match(kr, ackKindDecl, locDeclPattern, "d", "snap", cSHA, now)
	if n := set.unconsumed(); n != 0 {
		t.Fatalf("unconsumed = %d, want 0 after match", n)
	}
}

// TestScanRejectionsNamedByClass proves a resubmitted token that no current
// finding claims is refused BY NAME (#74, ADR §4 / SS3): each of the structural
// reason classes — stale, version-skew, surplus, expired, unreadable — is
// reported against the token's submission index and, where it decodes, its bound
// locator, and the refusal body (SafeDetail) renders it, including the
// pure-rejection case that carries no blocked finding.
func TestScanRejectionsNamedByClass(t *testing.T) {
	ctx := t.Context()
	kr := ackTestKeyring(t)
	rs, err := scanning.Load()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_100, 0)
	const cred = "AKIAIOSFODNN7EXAMPLE"  // a valid-looking, non-live AWS key id
	const cred2 = "AKIAI44QH8DHBEXAMPLE" // a different one — same rule, different content

	// Baseline scan yields the valid token and the matched rule id/digest.
	base, err := scanDeclaration(ctx, kr, rs, []scanLeaf{{Locator: locDeclPattern, Content: []byte(cred)}}, nil, now, ingressEdit)
	if err != nil || len(base.blocked) != 1 {
		t.Fatalf("baseline scan: err=%v blocked=%d, want 1 finding", err, len(base.blocked))
	}
	validTok := base.blocked[0].Acknowledgement
	ruleID := base.blocked[0].RuleID
	digest, ok := rs.SemanticDigest(ruleID)
	if !ok {
		t.Fatalf("no semantic digest for %q", ruleID)
	}
	mint := func(loc, snap string, content []byte, age time.Duration) string {
		tok, err := sealAck(kr, ackBinding{
			kind: ackKindDecl, locator: loc, ruleDigest: digest,
			contentSHA: contentDigest(content), snapshot: snap, mintNano: now.Add(-age).UnixNano(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	cases := []struct {
		name    string
		leaf    string // content the current scan sees
		token   string
		reason  string
		locator string // bound locator surfaced (empty for unreadable)
	}{
		// The field content changed since minting: same locator+rule, different content.
		{"stale", cred2, validTok, rejectStale, locDeclPattern},
		// The ruleset snapshot changed since minting.
		{"version-skew", cred, mint(locDeclPattern, "old-snapshot", []byte(cred), time.Minute), rejectVersionSkew, locDeclPattern},
		// No current finding shares the token's locator+rule.
		{"surplus", cred, mint(locKeyName, rs.SnapshotVersion(), []byte(cred), time.Minute), rejectSurplus, locKeyName},
		// Older than the TTL, otherwise an exact bind.
		{"expired", cred, mint(locDeclPattern, rs.SnapshotVersion(), []byte(cred), ackTTL+time.Minute), rejectExpired, locDeclPattern},
		// Does not decode at all.
		{"unreadable", cred, "not-a-real-token", rejectUnreadable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := scanDeclaration(ctx, kr, rs, []scanLeaf{{Locator: locDeclPattern, Content: []byte(tc.leaf)}},
				newAckSet([]string{tc.token}), now, ingressEdit)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.rejections) != 1 {
				t.Fatalf("rejections = %d, want 1", len(res.rejections))
			}
			r := res.rejections[0]
			if r.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", r.Reason, tc.reason)
			}
			if r.Index != 0 {
				t.Errorf("index = %d, want 0", r.Index)
			}
			if r.Locator != tc.locator {
				t.Errorf("locator = %q, want %q", r.Locator, tc.locator)
			}
			// The refusal body names the token (by index) and the reason class.
			refusal := &scanRefusalErr{blocked: res.blocked, rejections: res.rejections}
			detail := refusal.SafeDetail()
			if !strings.Contains(detail, "token #1") || !strings.Contains(detail, tc.reason) {
				t.Errorf("SafeDetail %q does not name the token and its reason %q", detail, tc.reason)
			}
			// A refusal carrying ONLY the rejection (no blocked finding) is still a
			// non-empty, named message — the pure-rejection bug guard.
			pure := &scanRefusalErr{rejections: res.rejections}
			if pd := pure.SafeDetail(); !strings.Contains(pd, "token #1") || !strings.Contains(pd, tc.reason) {
				t.Errorf("pure-rejection SafeDetail %q is empty or unnamed", pd)
			}
		})
	}
}

// TestFindingCapFailsClosed proves the per-request finding cap (ADR §7) fails
// CLOSED naming the cap, never a silent truncation: a declaration with more than
// maxRequestFindings offending leaves refuses the whole scan.
func TestFindingCapFailsClosed(t *testing.T) {
	kr := ackTestKeyring(t)
	rs, err := scanning.Load()
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]scanLeaf, maxRequestFindings+1)
	for i := range leaves {
		leaves[i] = scanLeaf{Locator: locDeclPattern, Content: []byte("AKIAIOSFODNN7EXAMPLE")}
	}
	_, err = scanDeclaration(t.Context(), kr, rs, leaves, nil, time.Now(), ingressEdit)
	if !errors.Is(err, errFindingCap) {
		t.Fatalf("scanDeclaration over %d findings = %v, want the fail-closed cap error", len(leaves), err)
	}
	if !strings.Contains(err.Error(), "100") {
		t.Errorf("the cap refusal does not name the cap: %v", err)
	}
}
