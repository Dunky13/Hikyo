package service

import (
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// clock is a settable time source for the windowed-rate curves, which are
// otherwise untestable without sleeping a full window (schema-rev is 60/hour).
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
func (c *clock) add(d time.Duration) {
	c.t = c.t.Add(d)
}

func newTestBudget(c *clock) *Budget {
	b := NewBudget()
	b.now = c.now
	return b
}

func principalKeys(p, org, project string) budgetKeys {
	return budgetKeys{Principal: domain.PrincipalID(p), Org: domain.OrgID(org), Project: domain.ProjectID(project)}
}

func TestBudgetRateWindowSlides(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)
	keys := principalKeys("p1", "org1", "proj1")

	// schema-revision: 60/hour per project. 60 pass, the 61st refuses.
	for i := range BudgetSchemaRevisionPerHour {
		if _, err := b.acquire(budgetSchemaRevision, keys); err != nil {
			t.Fatalf("charge %d/%d refused early: %v", i+1, BudgetSchemaRevisionPerHour, err)
		}
	}
	_, err := b.acquire(budgetSchemaRevision, keys)
	if !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("61st schema revision = %v, want ErrOverloaded", err)
	}

	// A different project is an independent bucket.
	if _, err := b.acquire(budgetSchemaRevision, principalKeys("p1", "org1", "proj2")); err != nil {
		t.Fatalf("other project refused: %v", err)
	}

	// After the window elapses, the first project is admitted again.
	c.add(time.Hour + time.Second)
	if _, err := b.acquire(budgetSchemaRevision, keys); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestBudgetConcurrencyReleases(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)
	keys := principalKeys("p1", "org1", "proj1")

	// export: 2 concurrent per org. Hold both slots.
	rel1, err := b.acquire(budgetExport, keys)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	// A second principal in the same org takes the second org slot.
	rel2, err := b.acquire(budgetExport, principalKeys("p2", "org1", "proj1"))
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	// The third concurrent export in the org is refused on the org bound.
	if _, err := b.acquire(budgetExport, principalKeys("p3", "org1", "proj1")); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("third concurrent export = %v, want ErrOverloaded", err)
	}
	// Releasing one frees a slot.
	rel1()
	if _, err := b.acquire(budgetExport, principalKeys("p3", "org1", "proj1")); err != nil {
		t.Fatalf("after release: %v", err)
	}
	rel2()

	// release is idempotent: a double call must not under-count and let an
	// extra concurrent op slip past the bound later.
	rel1()
}

func TestBudgetInstanceConcurrencyIsSeparateFromOrg(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)

	// export instance bound is 6; org bound is 2. Six exports across three orgs
	// (two each) fill the instance bound without any org tripping first. Each
	// export uses a distinct principal so the per-principal 5/min rate never
	// fires first — this test is about the concurrency dimensions.
	var rels []func()
	for _, org := range []string{"orgA", "orgB", "orgC"} {
		for p := range BudgetExportOrgConcurrency {
			rel, err := b.acquire(budgetExport, principalKeys(org+strconv.Itoa(p), org, "proj"))
			if err != nil {
				t.Fatalf("export org=%s #%d: %v", org, p, err)
			}
			rels = append(rels, rel)
		}
	}
	if len(rels) != BudgetExportInstanceConcurrency {
		t.Fatalf("filled %d slots, want %d", len(rels), BudgetExportInstanceConcurrency)
	}
	// A fresh org with free org slots is still refused on the instance bound.
	if _, err := b.acquire(budgetExport, principalKeys("p", "orgD", "proj")); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("7th instance-wide export = %v, want ErrOverloaded", err)
	}
	for _, rel := range rels {
		rel()
	}
}

func TestBudgetInstanceExportIgnoresOrgBound(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)

	// InstanceExport carries no org, so it is bounded only by 6/instance — the
	// org bound must not collapse all instance exports into a shared "" bucket
	// of 2. Distinct principals keep the per-principal 5/min rate out of the way.
	var rels []func()
	for i := range BudgetExportInstanceConcurrency {
		rel, err := b.acquire(budgetExportInstance, budgetKeys{Principal: domain.PrincipalID("admin" + strconv.Itoa(i))})
		if err != nil {
			t.Fatalf("instance export #%d: %v", i, err)
		}
		rels = append(rels, rel)
	}
	if _, err := b.acquire(budgetExportInstance, budgetKeys{Principal: domain.PrincipalID("adminX")}); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("7th instance export = %v, want ErrOverloaded", err)
	}
	for _, rel := range rels {
		rel()
	}
}

func TestBudgetRefusalDoesNotConsumeRate(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)

	// Fill the org concurrency bound, then hammer it. A refusal on the
	// concurrency bound must not also burn the principal's rate allowance —
	// otherwise a caller blocked by a busy org would additionally be rate-locked
	// out for the window, a double penalty for one refused op.
	rel1, _ := b.acquire(budgetExport, principalKeys("p1", "org1", "proj"))
	rel2, _ := b.acquire(budgetExport, principalKeys("p2", "org1", "proj"))
	for range 100 {
		if _, err := b.acquire(budgetExport, principalKeys("p3", "org1", "proj")); !errors.Is(err, admission.ErrOverloaded) {
			t.Fatalf("expected concurrency refusal, got %v", err)
		}
	}
	rel1()
	rel2()
	// p3 never got a slot, so its 5/min rate must be untouched. Acquire+release
	// sequentially so the org concurrency slot frees each time and only the rate
	// curve is exercised: exactly 5 succeed, the 6th trips the rate.
	for i := range BudgetExportRatePerMin {
		rel, err := b.acquire(budgetExport, principalKeys("p3", "org1", "proj"))
		if err != nil {
			t.Fatalf("p3 rate charge %d refused; concurrency refusals leaked into rate: %v", i+1, err)
		}
		rel()
	}
	if _, err := b.acquire(budgetExport, principalKeys("p3", "org1", "proj")); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("p3 6th charge = %v, want rate ErrOverloaded", err)
	}
}

func TestBudgetMachineFetchAggregates(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)

	// 300/min per org. The org bound trips before the 1000/min instance bound.
	for i := range BudgetMachineFetchOrgPerMin {
		if _, err := b.acquire(budgetMachineFetch, budgetKeys{Org: domain.OrgID("org1")}); err != nil {
			t.Fatalf("machine fetch %d refused early: %v", i+1, err)
		}
	}
	if _, err := b.acquire(budgetMachineFetch, budgetKeys{Org: domain.OrgID("org1")}); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("301st org fetch = %v, want ErrOverloaded", err)
	}
}

func TestBudgetFailClosedDefault(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)
	keys := principalKeys("p1", "org1", "proj")

	// An unnamed category inherits the fail-closed default: 60/min per principal.
	// Acquire+release each so the 8/org concurrency bound never fires first.
	for i := range BudgetDefaultRatePerMin {
		rel, err := b.acquire(budgetDefault, keys)
		if err != nil {
			t.Fatalf("default charge %d refused early: %v", i+1, err)
		}
		rel()
	}
	if _, err := b.acquire(budgetDefault, keys); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("61st default = %v, want ErrOverloaded", err)
	}
}

// TestAuditExportChargesExpensiveBudget proves the WIRING (the registry fixture
// for ops-spec § 20 / § 179 "audit exports 2/org · 6/instance"): Audits.Export
// consults the shared budget before touching the store, and a caller that finds
// the org's two concurrency slots full is refused with the uniform overload
// error — so the refusal renders the same 429 + Retry-After every other
// overflow does. The DB is nil on purpose: the acquire precedes every store
// access, so reaching it would be the bug.
func TestAuditExportChargesExpensiveBudget(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newTestBudget(c)
	scope := domain.Scope{Org: "org1", Project: "proj1"}

	// Occupy the org's two export concurrency slots with other principals.
	rel1, err := b.acquire(budgetExport, budgetKeys{Principal: "other1", Org: scope.Org})
	if err != nil {
		t.Fatal(err)
	}
	rel2, err := b.acquire(budgetExport, budgetKeys{Principal: "other2", Org: scope.Org})
	if err != nil {
		t.Fatal(err)
	}

	audits := &Audits{Budget: b}
	err = audits.Export(t.Context(), "me", scope, store.AuditFilter{}, 100, io.Discard)
	if !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("audit export with a full org budget = %v, want ErrOverloaded", err)
	}

	rel1()
	rel2()

	// Instance export is bounded by 6/instance, keyed with no org: fill the six
	// instance slots and the next is refused the same way.
	var rels []func()
	for i := range BudgetExportInstanceConcurrency {
		rel, err := b.acquire(budgetExportInstance, budgetKeys{Principal: domain.PrincipalID("filler" + strconv.Itoa(i))})
		if err != nil {
			t.Fatal(err)
		}
		rels = append(rels, rel)
	}
	if err := audits.InstanceExport(t.Context(), "me", store.AuditFilter{}, 100, io.Discard); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("instance export with a full instance budget = %v, want ErrOverloaded", err)
	}
	for _, rel := range rels {
		rel()
	}
}

func TestBudgetNilIsNoop(t *testing.T) {
	var b *Budget
	rel, err := b.acquire(budgetExport, principalKeys("p", "o", "pr"))
	if err != nil {
		t.Fatalf("nil budget refused: %v", err)
	}
	rel() // must not panic
}
