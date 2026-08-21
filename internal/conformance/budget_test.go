package conformance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The ops-spec § 179 / § 151 expensive-path budget joins the cross-engine
// corpus. This proves the schema-revision rate limit (§ 151, 60/h per project)
// end to end through the service layer and both engines — the wiring the bound
// registry flips from enforcement-pending to enforced.
func init() {
	corpus = append(corpus,
		scenario{"schema_revision_rate_limit", scenarioSchemaRevisionRateLimit},
		scenario{"schema_revision_noop_does_not_charge", scenarioSchemaRevisionNoopDoesNotCharge},
		scenario{"default_budget_charged_end_to_end", scenarioDefaultBudgetChargedEndToEnd},
	)
}

// scenarioDefaultBudgetChargedEndToEnd proves the §179 fail-closed default is
// actually CHARGED at a default-expensive method, not merely classified: it
// drives Definitions.Export (a whole-project materialization, classified
// default-expensive) until the 60/min per-principal default rate refuses the
// next call with the uniform overload error. The totality test proves every
// operation is classified; this proves the classification reaches runtime.
func scenarioDefaultBudgetChargedEndToEnd(t *testing.T, db *store.DB) {
	budget := service.NewBudget()
	defs := &service.Definitions{DB: db, Keyring: sharedKeyring(t, db), Budget: budget}
	who, scope := tenantFixture(t, db, "defaultbudget")
	actor := service.LocalPrincipal(who)

	for i := range service.BudgetDefaultRatePerMin {
		if _, err := defs.Export(t.Context(), actor, scope, true); err != nil {
			t.Fatalf("definitions export %d/%d refused inside the default allowance: %v",
				i+1, service.BudgetDefaultRatePerMin, err)
		}
	}
	if _, err := defs.Export(t.Context(), actor, scope, true); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("the 61st default-expensive call = %v, want ErrOverloaded (uniform 429)", err)
	}
}

// scenarioSchemaRevisionRateLimit drives real semantic schema mutations against
// one project until the § 151 rate (60/h per project) refuses the next one with
// the uniform overload error — the same error that renders 429 + Retry-After on
// the wire. Every charge converges on prepareSchemaPublish, so a single Budget
// bounds create/rename/declaration edits alike; here the cheapest charged
// mutation (rename, no schema reparse) exhausts it. A second project is an
// independent bucket, so the bound is per-project, not instance-wide.
func scenarioSchemaRevisionRateLimit(t *testing.T, db *store.DB) {
	budget := service.NewBudget()
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db), Budget: budget}
	who, scope := tenantFixture(t, db, "schemarev")
	actor := service.LocalPrincipal(who)

	// Create the key — the first schema revision, charge #1.
	created, err := keys.Create(t.Context(), actor, scope,
		keySpec("RATE_LIMITED", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil)
	if err != nil {
		t.Fatal(err)
	}

	// The remaining allowance is the per-hour bound minus that first charge.
	// Every rename that lands inside it must succeed; the one past it must be the
	// uniform overload refusal, never a different error.
	allowed := service.BudgetSchemaRevisionPerHour - 1
	for i := range allowed {
		if _, err := keys.Rename(t.Context(), actor, scope, created.ID, fmt.Sprintf("RENAMED_%d", i), nil); err != nil {
			t.Fatalf("rename %d/%d refused inside the schema-revision allowance: %v", i+1, allowed, err)
		}
	}
	_, err = keys.Rename(t.Context(), actor, scope, created.ID, "OVER_THE_LIMIT", nil)
	if !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("the schema revision past the per-project rate = %v, want ErrOverloaded (uniform 429)", err)
	}

	// A different project shares nothing: its budget is untouched, so its first
	// schema revision succeeds even though the first project is now rate-limited.
	who2, scope2 := tenantFixture(t, db, "schemarev-other")
	if _, err := keys.Create(t.Context(), service.LocalPrincipal(who2), scope2,
		keySpec("FRESH", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil); err != nil {
		t.Fatalf("a second project's first schema revision was refused; the bound is not per-project: %v", err)
	}
}

// scenarioSchemaRevisionNoopDoesNotCharge proves the § 151 charge sits at the
// real revision bump, not at the operation's entry: a mutation that no-ops
// (nothing actually changed, no BumpSchemaRevision) consumes no budget. Without
// this, a script could exhaust the 60/h rate with idempotent no-ops that mint no
// revision at all. It runs well past the hourly bound to make the point.
func scenarioSchemaRevisionNoopDoesNotCharge(t *testing.T, db *store.DB) {
	keys := &service.Keys{DB: db, Keyring: sharedKeyring(t, db), Budget: service.NewBudget()}
	who, scope := tenantFixture(t, db, "schemarev-noop")
	actor := service.LocalPrincipal(who)

	created, err := keys.Create(t.Context(), actor, scope,
		keySpec("NOOP", string(schema.Config), decl(schema.Rule{Type: schema.TypeString})), nil)
	if err != nil {
		t.Fatal(err)
	}

	// An empty metadata update merges to the stored row unchanged, so it returns
	// early without bumping the revision. Many more than the hourly bound must all
	// pass, because none is a revision.
	for i := 0; i < service.BudgetSchemaRevisionPerHour*2; i++ {
		if _, err := keys.UpdateMetadata(t.Context(), actor, scope, created.ID, service.KeyMetadataUpdate{}, nil); err != nil {
			t.Fatalf("no-op metadata update %d charged the schema-revision budget: %v", i+1, err)
		}
	}
}

// TestBudgetClassificationIsTotal is the §179 "no path is unbudgeted by
// omission" guarantee, enforced at build time: every registered authorization
// operation must be classified in the budget totality map (named category,
// fail-closed default, or exempt-with-reason). A new operation added without a
// deliberate budget decision fails HERE — the same shape as the metrics-label
// grep and the keyword-allowlist diff.
func TestBudgetClassificationIsTotal(t *testing.T) {
	var missing []string
	for op := range (authz.RegistryFacts{}).Operations() {
		if _, known := service.BudgetClassOf(op); !known {
			missing = append(missing, string(op))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d operation(s) not classified in the §179 budget totality map (classify in internal/service/budget_classification.go):\n%s",
			len(missing), strings.Join(missing, "\n"))
	}
}
