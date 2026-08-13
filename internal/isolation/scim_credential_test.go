package isolation

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/scimproto"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// TestSCIMCredentialLifecycle is SC1.n and SC1.o: the whole credential family
// in one place — the mint gate, display-once, overlap rotation, revocation
// biting at the NEXT request, the lifetime ceiling, and indefinite refused
// while the instance has not opted in.
func TestSCIMCredentialLifecycleSQLite(t *testing.T) {
	runSCIMCredentialLifecycle(t, seededDB(t, openSQLite))
}
func TestSCIMCredentialLifecyclePostgres(t *testing.T) {
	runSCIMCredentialLifecycle(t, seededDB(t, openPostgres))
}

func runSCIMCredentialLifecycle(t *testing.T, db *store.DB) {
	ctx := t.Context()
	// Pinned at the credential layout's microsecond resolution: ExpiresAt
	// round-trips through storage, so a nanosecond-bearing pin loses its
	// sub-microsecond tail there and the ceiling comparison drifts by <1µs
	// (surfaced on Linux CI; macOS clocks rarely carry nanoseconds).
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := scimSvc(db)
	s.Now = func() time.Time { return now }
	// A short instance ceiling, so "clamped to the ceiling" is observable
	// without waiting a year.
	s.CredentialTTL = 48 * time.Hour

	seedSCIMProvider(t, db, "okta", "https://okta.example.test", true)
	binding, err := s.CreateBinding(ctx, service.LocalPrincipal(orgAdmin), orgA, service.SCIMBindingInput{
		ProviderKind: domain.ProviderOIDC, ProviderSlug: "okta",
		SubjectSource: domain.SubjectSourceExternalID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// THE GATE. `manage-members` at org scope is the mint formula; a principal
	// who reads the org but does not manage its members gets the uniform
	// nonexistent answer, not a distinguishable "you may not mint".
	if _, err := s.MintCredential(ctx, service.LocalPrincipal(reader), orgA, binding.ID, false, ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("minting without manage-members must answer the uniform nonexistent outcome, got %v", err)
	}

	first, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Rotated {
		t.Fatal("the binding's FIRST credential is not a rotation")
	}

	// DISPLAY-ONCE. The token exists in the mint result and NOWHERE else: the
	// store holds a verifier, and the list surface has no field to leak it
	// through. A listed token would turn every reader of the binding page into
	// a holder of its authority.
	if !strings.HasPrefix(first.Token, "hik_1_scim_") {
		t.Fatalf("credential grammar: %q", first.Token[:12])
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM scim_credentials WHERE verifier = '`+first.Token+`'`); n != 0 {
		t.Fatal("the token itself must never be stored — only its verifier")
	}
	listed, err := s.ListCredentials(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != first.Credential.ID {
		t.Fatalf("the list must show the row, got %d rows", len(listed))
	}
	if !listed[0].Live {
		t.Fatal("a freshly minted credential is live")
	}

	// THE CEILING. Every mint is clamped to the instance's configured lifetime;
	// a credential with no expiry is a permanent bearer nobody re-reviews.
	if got := first.Credential.ExpiresAt.Sub(now); got != s.CredentialTTL {
		t.Fatalf("mint lifetime = %v, want the instance ceiling %v", got, s.CredentialTTL)
	}

	// INDEFINITE IS REFUSED while the instance has not opted in — by name, so
	// an operator can tell this from an authorization failure.
	if _, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, true, ""); !errors.Is(err, service.ErrSCIMIndefiniteRefused) {
		t.Fatalf("indefinite must be refused by name while the opt-in is off, got %v", err)
	}
	// With the opt-in, the same call succeeds and carries NO expiry.
	opted := scimSvc(db)
	opted.Now = s.Now
	opted.AllowIndefinite = true
	forever, err := opted.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, true, "")
	if err != nil {
		t.Fatalf("indefinite under the opt-in: %v", err)
	}
	if !forever.Credential.ExpiresAt.IsZero() {
		t.Fatalf("an indefinite credential carries no expiry, got %v", forever.Credential.ExpiresAt)
	}
	if err := opted.RevokeCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, forever.Credential.ID); err != nil {
		t.Fatal(err)
	}

	// OVERLAP ROTATION. The second mint JOINS the first rather than replacing
	// it: a connector cannot swap a secret atomically, so both must work while
	// it rolls over.
	second, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Rotated {
		t.Fatal("a mint beside a live credential IS the rotation, and the event differs")
	}
	if second.Token == first.Token {
		t.Fatal("two mints must not produce the same token")
	}
	for _, token := range []string{first.Token, second.Token} {
		if _, _, err := s.ListUsers(ctx, service.SCIMCredentialActor(token, binding.ID), orgA, binding.ID,
			scimproto.Filter{Shape: scimproto.FilterNone}, scimproto.Page{StartIndex: 1, Count: 10}); err != nil {
			t.Fatalf("both credentials must work during overlap: %v", err)
		}
	}
	if auditCount(t, db, "scim.credential_rotated") == 0 {
		t.Fatal("the rotation must be distinguishable in the trail from a first mint")
	}

	// REVOCATION BITES AT THE NEXT REQUEST — not at the next expiry sweep, and
	// not only for new connections. The other credential is untouched.
	if err := s.RevokeCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, first.Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ListUsers(ctx, service.SCIMCredentialActor(first.Token, binding.ID), orgA, binding.ID,
		scimproto.Filter{Shape: scimproto.FilterNone}, scimproto.Page{StartIndex: 1, Count: 10}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a revoked credential must fail the very next request, got %v", err)
	}
	if _, _, err := s.ListUsers(ctx, service.SCIMCredentialActor(second.Token, binding.ID), orgA, binding.ID,
		scimproto.Filter{Shape: scimproto.FilterNone}, scimproto.Page{StartIndex: 1, Count: 10}); err != nil {
		t.Fatalf("revoking one credential must not disturb the other: %v", err)
	}

	// EXPIRY bites the same way, from the clock alone: no sweep runs in
	// between, and the credential simply stops verifying.
	now = now.Add(s.CredentialTTL + time.Minute)
	if _, _, err := s.ListUsers(ctx, service.SCIMCredentialActor(second.Token, binding.ID), orgA, binding.ID,
		scimproto.Filter{Shape: scimproto.FilterNone}, scimproto.Page{StartIndex: 1, Count: 10}); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("an expired credential must stop verifying without any sweep, got %v", err)
	}
	// And the surface says so truthfully rather than hiding the row.
	after, err := s.ListCredentials(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range after {
		if view.Live {
			t.Fatalf("credential %s reports live past its expiry", view.ID)
		}
	}

	// THE OVERLAP BOUND. Unbounded rotation is a pile of long-lived bearers
	// nobody tracks, so the cap refuses by name.
	now = now.Add(time.Minute)
	for i := range service.MaxLiveCredentials {
		if _, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, false, ""); err != nil {
			t.Fatalf("mint %d within the cap: %v", i, err)
		}
	}
	if _, err := s.MintCredential(ctx, service.LocalPrincipal(orgAdmin), orgA, binding.ID, false, ""); !errors.Is(err, service.ErrSCIMCredentialLimit) {
		t.Fatalf("the mint past the cap must refuse by name, got %v", err)
	}
}
