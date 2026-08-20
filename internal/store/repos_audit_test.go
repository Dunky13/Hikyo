package store

import "testing"

// TestAuditPageSizeIsClampedToTheCap pins the ops-spec § 10 response cap: an
// audit page never exceeds AuditMaxPageSize rows, regardless of what the caller
// asked for. bounds() is the single chokepoint every engine's page read routes
// through, so the clamp holds for tenant and instance, sqlite and postgres.
func TestAuditPageSizeIsClampedToTheCap(t *testing.T) {
	f := AuditFilter{Limit: AuditMaxPageSize + 500}
	if _, _, err := f.bounds(); err != nil {
		t.Fatalf("bounds() on a valid filter: %v", err)
	}
	if f.Limit != AuditMaxPageSize {
		t.Fatalf("page limit = %d, want it clamped to %d", f.Limit, AuditMaxPageSize)
	}

	// A request already under the cap is left untouched.
	under := AuditFilter{Limit: 25}
	if _, _, err := under.bounds(); err != nil {
		t.Fatalf("bounds() under the cap: %v", err)
	}
	if under.Limit != 25 {
		t.Fatalf("an under-cap limit was altered to %d", under.Limit)
	}

	// The positive-limit invariant still refuses a non-positive page.
	empty := AuditFilter{Limit: 0}
	if _, _, err := empty.bounds(); err == nil {
		t.Fatal("a non-positive page limit must be refused")
	}
}
