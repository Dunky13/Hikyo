package oidcfed

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// The pointer resolver's edge cases (#62, review round 2). They are table tests
// rather than fixtures because the interesting inputs are malformed ones, and
// minting a signed token for each would test the JWS library rather than the
// resolver.
//
// The claim document is a real Kubernetes projected ServiceAccount token's shape
// plus the two array-valued registered claims that already exist, because those
// are the two things RFC 6901 traversal has to handle and the objects-only first
// cut did not.
var pointerClaims = mustClaims(`{
  "sub": "system:serviceaccount:prod:deployer",
  "aud": ["hikyo://instance"],
  "amr": ["pwd", "mfa"],
  "repository_id": 4242,
  "kubernetes.io": {
    "namespace": "prod",
    "pod": {"name": "deployer-7d4f9", "uid": "pod-uid"},
    "serviceaccount": {"name": "deployer", "uid": "9f2c-uid"}
  },
  "weird/key": "slash",
  "weird~key": "tilde",
  "": "empty-name",
  "01": "not-an-index",
  "nested": {"": "empty-segment"}
}`)

func mustClaims(raw string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		panic(err)
	}
	return out
}

func TestResolveClaim(t *testing.T) {
	cases := []struct {
		name    string
		pointer string
		want    string
		absent  bool
	}{
		// A name without a leading slash is a TOP-LEVEL claim, byte-exact. This is
		// the discriminator, and it is what keeps every pre-pointer binding working.
		{"top-level scalar", "repository_id", "4242", false},
		{"top-level name containing a slash", "weird/key", `"slash"`, false},
		{"top-level name containing a tilde", "weird~key", `"tilde"`, false},

		// The claim this whole mechanism exists for. `kubernetes.io` contains a
		// dot, which is why a dotted path would have been ambiguous.
		{"nested kubernetes uid", "/kubernetes.io/serviceaccount/uid", `"9f2c-uid"`, false},
		{"nested kubernetes namespace", "/kubernetes.io/namespace", `"prod"`, false},
		{"nested pod uid", "/kubernetes.io/pod/uid", `"pod-uid"`, false},

		// ARRAY INDICES. The objects-only first cut could not resolve these.
		{"array element", "/amr/0", `"pwd"`, false},
		{"array element, second", "/amr/1", `"mfa"`, false},
		{"array index out of range", "/amr/2", "", true},
		// `01` is not RFC 6901 index syntax, so it addresses an object member —
		// and an array has none.
		{"leading-zero index is not an index", "/amr/01", "", true},
		{"non-numeric segment into an array", "/amr/first", "", true},
		// The RFC's "past the last element" token addresses no value, so it can
		// never satisfy a pin.
		{"dash index", "/amr/-", "", true},

		// ESCAPES. `~1` is `/` and `~0` is `~`, applied in that order, so `~01`
		// is the literal `~1` and not `/`.
		{"escaped slash", "/weird~1key", `"slash"`, false},
		{"escaped tilde", "/weird~0key", `"tilde"`, false},
		{"invalid escape is refused, not literal", "/weird~2key", "", true},
		{"trailing tilde is refused", "/weird~", "", true},
		{"invalid escape mid-path", "/kubernetes.io/~9serviceaccount/uid", "", true},

		// EMPTY SEGMENTS are legitimate RFC 6901: `/` addresses the member named
		// "".
		{"root pointer addresses the empty name", "/", `"empty-name"`, false},
		{"trailing slash addresses an empty nested name", "/nested/", `"empty-segment"`, false},

		// STRUCTURAL LEAVES are never a match: a pin must name a value, not a
		// shape.
		{"object leaf", "/kubernetes.io/serviceaccount", "", true},
		{"array leaf", "/amr", "", true},

		{"absent nested member", "/kubernetes.io/serviceaccount/missing", "", true},
		{"descend into a scalar", "/repository_id/0", "", true},
		{"absent top level", "/nope/deeper", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveClaim(pointerClaims, tc.pointer)
			if tc.absent {
				if ok {
					t.Fatalf("resolveClaim(%q) = %s, want absent", tc.pointer, got)
				}
				return
			}
			if !ok {
				t.Fatalf("resolveClaim(%q) = absent, want %s", tc.pointer, tc.want)
			}
			if string(got) != tc.want {
				t.Fatalf("resolveClaim(%q) = %s, want %s", tc.pointer, got, tc.want)
			}
		})
	}
}

// TestResolveClaimTopLevelIsNotScalarChecked records the ONE asymmetry between the
// two lookup forms, so it is a stated decision rather than an accident.
//
// A pointer's leaf must be a scalar — a structural match must never satisfy a pin.
// A TOP-LEVEL name is returned as-is, because ParseRequiredClaims has already
// refused a non-scalar pinned VALUE, so the byte comparison that follows cannot
// succeed against an object anyway. Adding the check here too would be dead.
func TestResolveClaimTopLevelIsNotScalarChecked(t *testing.T) {
	got, ok := resolveClaim(pointerClaims, "kubernetes.io")
	if !ok {
		t.Fatal("a top-level object name did not resolve")
	}
	if !sameJSONScalar(json.RawMessage(`"prod"`), json.RawMessage(`"prod"`)) {
		t.Fatal("sanity")
	}
	// It resolved, and it can never MATCH: no scalar pin equals an object's bytes.
	if sameJSONScalar(json.RawMessage(`"prod"`), got) {
		t.Fatal("an object matched a scalar pin")
	}
}

// TestValidatePointerRefusesMalformed is the creation-time half. An invalid
// escape accepted literally would be stored as a pin no token can ever satisfy —
// a binding an operator believed was strict, silently inert until someone audits
// it.
func TestValidatePointerRefusesMalformed(t *testing.T) {
	for _, name := range []string{
		"/weird~2key", "/a/~", "/~", "/a/b~9", "/~x/y",
	} {
		if err := ValidatePointer(name); !errors.Is(err, ErrClaim) {
			t.Errorf("ValidatePointer(%q) = %v, want ErrClaim", name, err)
		}
	}
	for _, name := range []string{
		"repository_id", "weird~key", "/kubernetes.io/serviceaccount/uid",
		"/weird~1key", "/weird~0key", "/", "/nested/", "/amr/0",
	} {
		if err := ValidatePointer(name); err != nil {
			t.Errorf("ValidatePointer(%q) = %v, want nil", name, err)
		}
	}
}

// TestParseRequiredClaimsRefusesMalformedPointer pins that the refusal reaches
// the ONE function both the creation path and the validation path go through, so
// neither can drift from the other's idea of a well-formed pointer.
func TestParseRequiredClaimsRefusesMalformedPointer(t *testing.T) {
	if _, err := ParseRequiredClaims(`{"/weird~2key":"x"}`); !errors.Is(err, ErrClaim) {
		t.Errorf("ParseRequiredClaims with an invalid escape = %v, want ErrClaim", err)
	}
	if _, err := ParseRequiredClaims(`{"/kubernetes.io/serviceaccount/uid":"x"}`); err != nil {
		t.Errorf("ParseRequiredClaims with a valid pointer = %v, want nil", err)
	}
	// A nested pinned VALUE stays refused: byte-exact comparison of an object
	// would make JSON key order and whitespace security-relevant.
	if _, err := ParseRequiredClaims(`{"a":{"b":1}}`); !errors.Is(err, ErrClaim) {
		t.Errorf("ParseRequiredClaims with an object value = %v, want ErrClaim", err)
	}
}

// TestEntryForIsRaceFreeUnderEviction drives the eviction path directly, and it
// exists because the isolation fixtures cannot: eviction only fires past
// maxTrackedIssuers (64) and no end-to-end test configures that many issuers, so
// `-race` on the E2E suite would never touch this code at all.
//
// Two properties. Concurrent entryFor calls across more issuers than the ceiling
// must be race-free — the first cut read `fetchedAt` under Cache.mu while it was
// written under entry.mu. And an entry with a live user must NEVER be evicted: an
// in-flight entry had a zero `fetchedAt`, so it looked like the oldest and was
// chosen FIRST, which recreated it and started a duplicate concurrent fetch for
// the same issuer — defeating the singleflight precisely when it mattered.
func TestEntryForIsRaceFreeUnderEviction(t *testing.T) {
	c := &Cache{}
	// One issuer is held in flight for the whole run, exactly as a goroutine
	// waiting on a slow fetch would be.
	const pinnedIssuer = "https://held.test"
	held := c.entryFor(pinnedIssuer)
	defer held.inflight.Add(-1)

	var wg sync.WaitGroup
	for i := range maxTrackedIssuers * 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := c.entryFor(fmt.Sprintf("https://issuer-%d.test", i))
			// What a real caller does: take the lock, touch the mutable fields,
			// release. This is the write that raced the eviction read.
			e.mu.Lock()
			e.fetchedAt = time.Unix(int64(i), 0).UTC()
			e.lastAttempt = e.fetchedAt
			e.mu.Unlock()
			e.inflight.Add(-1)
		}()
	}
	wg.Wait()

	// The in-flight entry survived, and it is still the SAME object — a
	// recreated one would be a different pointer and a second concurrent fetch.
	c.mu.Lock()
	still, ok := c.entries[pinnedIssuer]
	c.mu.Unlock()
	if !ok {
		t.Fatal("an in-flight entry was evicted")
	}
	if still != held {
		t.Fatal("an in-flight entry was replaced by a new object: the singleflight is defeated")
	}
}

// TestRequireHTTPS is C1's unit half: the scheme guard applied to the issuer, the
// discovered `jwks_uri` and every redirect target.
func TestRequireHTTPS(t *testing.T) {
	for _, raw := range []string{
		"http://issuer.test/jwks", "HTTP://issuer.test", "ftp://issuer.test",
		"//issuer.test/jwks", "issuer.test/jwks", "",
	} {
		if err := requireHTTPS(raw); !errors.Is(err, ErrInsecureTransport) {
			t.Errorf("requireHTTPS(%q) = %v, want ErrInsecureTransport", raw, err)
		}
	}
	for _, raw := range []string{
		"https://issuer.test", "https://issuer.test/jwks", "HTTPS://issuer.test/jwks",
	} {
		if err := requireHTTPS(raw); err != nil {
			t.Errorf("requireHTTPS(%q) = %v, want nil", raw, err)
		}
	}
}

// TestSameJSONScalarNeverFolds is the byte-exact rule: a GitHub `repository_id`
// is the number 4242 and the string "4242" is a different claim value, so a
// binding written one way must not be satisfiable by a token the other.
func TestSameJSONScalarNeverFolds(t *testing.T) {
	if sameJSONScalar(json.RawMessage(`4242`), json.RawMessage(`"4242"`)) {
		t.Error("a number matched a string: the type was folded")
	}
	if sameJSONScalar(json.RawMessage(`1`), json.RawMessage(`1.0`)) {
		t.Error("1 matched 1.0: numerics were normalised")
	}
	if !sameJSONScalar(json.RawMessage(` 4242 `), json.RawMessage(`4242`)) {
		t.Error("whitespace defeated the comparison")
	}
	if !sameJSONScalar(json.RawMessage(`"push"`), json.RawMessage(`"push"`)) {
		t.Error("identical strings did not match")
	}
}
