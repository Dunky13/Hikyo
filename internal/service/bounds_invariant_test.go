package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// TestRenderTotalRefusesAnOversizedTarget pins the ops-spec § 8 per-target
// render cap: a resolved environment whose delivered bytes exceed
// MaxRenderBytesPerTarget is refused by name at publish. Absent cells and the
// under-cap case are left alone.
func TestRenderTotalRefusesAnOversizedTarget(t *testing.T) {
	big := resolvedCell{key: store.CatalogueKey{Name: "BIG"}, set: true,
		value: strings.Repeat("x", MaxRenderBytesPerTarget+1)}
	if err := checkRenderTotal([]resolvedCell{big}, "env_prod"); !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("an over-cap target must be refused with ErrLimitExceeded: %v", err)
	}

	// Two just-over-half-cap set cells cross the bound in aggregate — the cap is
	// on the summed VALUE bytes, not any single value.
	overHalf := strings.Repeat("x", MaxRenderBytesPerTarget/2+1)
	pair := []resolvedCell{
		{key: store.CatalogueKey{Name: "A"}, set: true, value: overHalf},
		{key: store.CatalogueKey{Name: "B"}, set: true, value: overHalf},
	}
	if err := checkRenderTotal(pair, "env_prod"); !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("two over-half values must sum past the target cap: %v", err)
	}

	// Exactly-at-the-cap value bytes are accepted — matching Kubernetes, which
	// charges value bytes only (key names are not counted).
	exact := []resolvedCell{
		{key: store.CatalogueKey{Name: "A-LONG-KEY-NAME"}, set: true, value: strings.Repeat("x", MaxRenderBytesPerTarget)},
	}
	if err := checkRenderTotal(exact, "env_prod"); err != nil {
		t.Fatalf("a target whose value bytes equal the cap must publish (names uncounted): %v", err)
	}

	// An absent cell of any nominal size is not delivered, so it is not charged.
	ok := []resolvedCell{
		{key: store.CatalogueKey{Name: "SET"}, set: true, value: "small"},
		{key: store.CatalogueKey{Name: "ABSENT"}, set: false, value: strings.Repeat("x", MaxRenderBytesPerTarget)},
	}
	if err := checkRenderTotal(ok, "env_prod"); err != nil {
		t.Fatalf("an under-cap target (absent cells uncharged) must publish: %v", err)
	}
}

// TestResolvedCellBudgetComposesByConstruction pins the ops-spec § 8
// composability guarantee: the per-project resolved-cell budget (environments ×
// declared keys ≤ MaxResolvedCells) cannot be exceeded by any legal
// configuration, because the two component caps multiply to less than it. This
// is why there is no runtime resolved-cell refusal — it would be unreachable.
// If either component cap is ever raised past the point where the product meets
// the budget, this fails the build instead of silently voiding the bound.
func TestResolvedCellBudgetComposesByConstruction(t *testing.T) {
	product := MaxEnvironmentsPerProject * schema.MaxKeysPerProject
	if product > MaxResolvedCells {
		t.Fatalf("environments (%d) × keys (%d) = %d exceeds the resolved-cell budget %d: "+
			"the maxima no longer compose by construction, so a runtime refusal is now required",
			MaxEnvironmentsPerProject, schema.MaxKeysPerProject, product, MaxResolvedCells)
	}
}
