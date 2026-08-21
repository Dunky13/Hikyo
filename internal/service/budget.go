package service

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// chargeDefaultAtEntry acquires the §179 fail-closed default (rate + concurrency)
// once at the entry of a heavy operation whose work spans MANY transactions and
// therefore has no single in-tx charge point (reencrypt). It resolves and
// authorizes the caller in one lightweight read transaction purely to key the
// per-principal rate; the operation re-authorizes in each of its own
// transactions, so this is not a cross-transaction authorization cache — the
// resolved principal is used only as a budget key, and the resolve's own
// authorization refuses an ineligible caller before any slot is taken (they
// cannot burn the org's budget by guessing its id). The returned release frees
// the concurrency slot; hold it for the whole operation.
func chargeDefaultAtEntry(ctx context.Context, db *store.DB, budget *Budget, actor Actor, op authz.Operation, scope domain.Scope, now func() time.Time) (func(), error) {
	if budget == nil {
		return noopBudgetRelease, nil
	}
	var principal domain.PrincipalID
	err := tx.Read(ctx, db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now())
		if err != nil {
			return err
		}
		if _, err := az.Authorize(ctx, caller, op, scope); err != nil {
			return err
		}
		principal = caller.Principal
		return nil
	})
	if err != nil {
		return nil, err
	}
	return budget.acquire(budgetDefault, budgetKeys{Principal: principal, Org: scope.Org})
}

// Budget is the ops-spec § 179 expensive-path availability layer plus the § 151
// (§ 8) schema-revision rate limit: a per-scope windowed rate counter and a
// per-scope concurrency semaphore, applied to the named expensive categories.
// Every refusal wraps admission.ErrOverloaded, so the server renders the
// uniform 429 + Retry-After the spec requires for all overflow, exactly as the
// pre-auth admission budget does.
//
// Deliberately in memory, single node, like admission.Limiter and the reveal
// gateLimiter: v1's locked deployment envelope is a single node with no HA
// (system-architecture ADR), so process-local state IS the whole instance's
// state. A durable rate/concurrency table would add a write per expensive
// request — amplifying exactly the load it bounds — to buy nothing this
// deployment shape can use. A multi-node build must replace this with shared
// state, which is why the constraint is written down here rather than
// discovered later.
//
// A nil *Budget is a working no-op, so a build that wires no budget (the
// isolation harness, focused unit tests) enforces no expensive-path bounds —
// the same nil-is-disabled discipline Advisory uses. The production wiring in
// internal/app always constructs one.
type Budget struct {
	// now is injectable so the windowed curves are testable without sleeping a
	// full window (schema-rev is 60/hour). Nil means time.Now.
	now func() time.Time

	mu sync.Mutex
	// rate holds sliding-window buckets, keyed by category+dimension+value. Each
	// bucket carries the window of the rule that records into it, so eviction can
	// use the bucket's OWN window — a 1-minute machine-fetch bucket is reclaimed a
	// minute after its last hit, not held for schema-rev's hour.
	rate map[string]rateBucket
	// inflight holds live concurrency counts, keyed the same way. An entry is
	// deleted when it reaches zero so the map does not accumulate dead keys.
	inflight map[string]int
}

// rateBucket is one subject's hit timestamps under one rule's window.
type rateBucket struct {
	hits   []time.Time
	window time.Duration
}

// NewBudget constructs an enabled budget on the real clock.
func NewBudget() *Budget {
	return &Budget{now: time.Now, rate: map[string]rateBucket{}, inflight: map[string]int{}}
}

// Ops-spec § 179 / § 20 / § 151 values, exported so the conformance registry's
// anti-drift test can pin the whole family to the spec in one place.
const (
	// § 179 search.
	BudgetSearchRatePerMin     = 30
	BudgetSearchOrgConcurrency = 4
	// § 179 / § 20 export — values export and audit export share this category:
	// 5/min per principal, 2 concurrent per org, 6 concurrent per instance.
	BudgetExportRatePerMin          = 5
	BudgetExportOrgConcurrency      = 2
	BudgetExportInstanceConcurrency = 6
	// § 179 publish.
	BudgetPublishRatePerMin     = 10
	BudgetPublishOrgConcurrency = 4
	// § 179 adapter sync/trigger.
	BudgetAdapterRatePerMin     = 10
	BudgetAdapterOrgConcurrency = 4
	// § 179 machine-fetch aggregates, on top of § 5's per-principal 30/min.
	BudgetMachineFetchOrgPerMin      = 300
	BudgetMachineFetchInstancePerMin = 1000
	// § 179 fail-closed default for any category not named above.
	BudgetDefaultRatePerMin     = 60
	BudgetDefaultOrgConcurrency = 8
	// § 151 (§ 8) schema-revision rate limit, per project.
	BudgetSchemaRevisionPerHour = 60

	// budgetMaxTrackedSubjects bounds how many rate buckets are remembered.
	// Rate keys carry attacker-influenced values (a principal id, an org id), so
	// without a bound the limiter becomes the memory-exhaustion vector it exists
	// to prevent. It mirrors admission.MaxTrackedSubjects.
	budgetMaxTrackedSubjects = 4096
)

// budgetDimension is the scope a bound is keyed on. The § 179 family is not
// uniformly per-principal: schema-rev is per project, machine-fetch aggregates
// are per org and per instance — so the key dimension is per rule, not fixed.
type budgetDimension uint8

const (
	dimPrincipal budgetDimension = iota
	dimProject
	dimOrg
	dimInstance
)

type budgetRateRule struct {
	dim    budgetDimension
	limit  int
	window time.Duration
}

type budgetConcRule struct {
	dim   budgetDimension
	limit int
}

// budgetCategory names one expensive path and the rate/concurrency rules that
// govern it. A category with no concurrency rules is rate-only (its release is
// a no-op).
type budgetCategory struct {
	name  string
	rates []budgetRateRule
	concs []budgetConcRule
}

// The named categories. Every category that a live call site charges is keyed
// on a dimension the caller can supply AT METHOD ENTRY (before the operation's
// own transaction), because the tx closure is retried up to four times and an
// in-closure charge would multiply. Scope-keyed dims (project / org / instance)
// come from the scope argument, so they are acquired at ENTRY and held. The
// per-principal RATE dims need the resolved principal, which only exists inside
// the operation's transaction — so those are charged there via chargeOnce,
// idempotent across the retry loop. Concurrency and the per-principal rate are
// two calls on the same shared budget, keyed on the same category name so they
// share buckets.
var (
	// budgetExport is the tenant audit export: 5/min per principal, 2 concurrent
	// per org, 6 per instance. Audit export takes the principal as a parameter,
	// so the per-principal rate is charged at entry.
	budgetExport = budgetCategory{
		name:  "export",
		rates: []budgetRateRule{{dimPrincipal, BudgetExportRatePerMin, time.Minute}},
		concs: []budgetConcRule{{dimOrg, BudgetExportOrgConcurrency}, {dimInstance, BudgetExportInstanceConcurrency}},
	}
	// budgetExportInstance is the instance-trail export: it carries no org, so it
	// is bounded only by 6/instance. Sharing budgetExport would collapse every
	// instance export into one "" org bucket of 2.
	budgetExportInstance = budgetCategory{
		name:  "export",
		rates: []budgetRateRule{{dimPrincipal, BudgetExportRatePerMin, time.Minute}},
		concs: []budgetConcRule{{dimInstance, BudgetExportInstanceConcurrency}},
	}
	// budgetValuesExport takes the "export" concurrency at entry (org + instance);
	// its 5/min per-principal rate is charged in-tx via budgetExportRate, so the
	// two share the "export" rate bucket with audit export.
	budgetValuesExport = budgetCategory{
		name:  "export",
		concs: []budgetConcRule{{dimOrg, BudgetExportOrgConcurrency}, {dimInstance, BudgetExportInstanceConcurrency}},
	}
	// budgetExportRate is the in-tx, per-principal half of the export budget, for
	// values export (whose principal resolves inside its transaction).
	budgetExportRate = budgetCategory{
		name:  "export",
		rates: []budgetRateRule{{dimPrincipal, BudgetExportRatePerMin, time.Minute}},
	}
	budgetPublish = budgetCategory{
		name:  "publish",
		concs: []budgetConcRule{{dimOrg, BudgetPublishOrgConcurrency}},
	}
	// budgetPublishRate is publish's in-tx per-principal rate (10/min).
	budgetPublishRate = budgetCategory{
		name:  "publish",
		rates: []budgetRateRule{{dimPrincipal, BudgetPublishRatePerMin, time.Minute}},
	}
	budgetAdapter = budgetCategory{
		name:  "adapter-sync",
		concs: []budgetConcRule{{dimOrg, BudgetAdapterOrgConcurrency}},
	}
	// budgetAdapterRate is adapter sync/trigger's in-tx per-principal rate (10/min).
	budgetAdapterRate = budgetCategory{
		name:  "adapter-sync",
		rates: []budgetRateRule{{dimPrincipal, BudgetAdapterRatePerMin, time.Minute}},
	}
	budgetMachineFetch = budgetCategory{
		name: "machine-fetch",
		rates: []budgetRateRule{
			{dimOrg, BudgetMachineFetchOrgPerMin, time.Minute},
			{dimInstance, BudgetMachineFetchInstancePerMin, time.Minute},
		},
	}
	budgetSchemaRevision = budgetCategory{
		name:  "schema-revision",
		rates: []budgetRateRule{{dimProject, BudgetSchemaRevisionPerHour, time.Hour}},
	}
	// budgetDefault is the §179 fail-closed default: 60/min per principal, 8
	// concurrent per org, applied to expensive operations that have no named
	// category above. There is no once-per-operation post-authorization
	// chokepoint (Authorize runs per-env/per-page), so it is charged at the
	// owning service method — concurrency at entry (budgetDefaultConc, keyed on
	// the org in scope) and the per-principal rate in-tx (budgetDefaultRate, once
	// the principal is resolved), the same split publish uses. Which operations
	// take it, which take a named category, and which are exempt is the totality
	// map in budget_classification.go; the conformance totality test fails the
	// build if any registered operation is left unclassified. THAT test is "no
	// path is unbudgeted by omission": a new operation cannot be added without a
	// deliberate budget decision.
	budgetDefaultConc = budgetCategory{
		name:  "default",
		concs: []budgetConcRule{{dimOrg, BudgetDefaultOrgConcurrency}},
	}
	budgetDefaultRate = budgetCategory{
		name:  "default",
		rates: []budgetRateRule{{dimPrincipal, BudgetDefaultRatePerMin, time.Minute}},
	}
	// budgetDefault is the combined rate+concurrency default, for a heavy
	// operation whose work spans multiple transactions and has no single in-tx
	// charge point (reencrypt): it is acquired once at entry after a lightweight
	// resolve. It shares the "default" buckets with the split halves above.
	budgetDefault = budgetCategory{
		name:  "default",
		rates: []budgetRateRule{{dimPrincipal, BudgetDefaultRatePerMin, time.Minute}},
		concs: []budgetConcRule{{dimOrg, BudgetDefaultOrgConcurrency}},
	}
)

// budgetKeys carries every scope value a category might key on. A caller
// supplies the ones its category needs; unused fields stay zero.
type budgetKeys struct {
	Principal domain.PrincipalID
	Project   domain.ProjectID
	Org       domain.OrgID
}

func (k budgetKeys) value(dim budgetDimension) string {
	switch dim {
	case dimPrincipal:
		return string(k.Principal)
	case dimProject:
		return string(k.Project)
	case dimOrg:
		return string(k.Org)
	case dimInstance:
		return "" // one bucket for the whole instance.
	default:
		// A dimension added without a case here must fail loudly, not silently
		// collapse into the instance bucket and share a bound it was never meant to.
		panic(fmt.Sprintf("service: unknown budget dimension %d", dim))
	}
}

// budgetMapKey is length-prefixed on the value, not concatenated: two subjects
// whose (dimension, value) pairs would otherwise run together must not collide.
func budgetMapKey(cat string, dim budgetDimension, value string) string {
	return cat + "\x00" + strconv.Itoa(int(dim)) + "\x00" + strconv.Itoa(len(value)) + ":" + value
}

func noopBudgetRelease() {}

// acquire charges the category's rate rules and takes its concurrency slots
// atomically: it records nothing unless every rule passes, so a refusal on one
// bound never half-charges another. It returns a release that frees the
// concurrency slots (a no-op for a rate-only category), safe to call more than
// once. Every refusal wraps admission.ErrOverloaded.
func (b *Budget) acquire(cat budgetCategory, keys budgetKeys) (func(), error) {
	if b == nil {
		return noopBudgetRelease, nil
	}
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	at := now()

	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Slide every rate window and confirm it has room — WITHOUT recording.
	// kept is built in FRESH storage, never bucket.hits[:0]: an in-place
	// compaction would mutate the map-owned backing array before every check has
	// passed, so a later concurrency/tracking refusal would leave the stored
	// bucket corrupted. Nothing here writes to b.rate; step 4 publishes.
	type slid struct {
		key    string
		kept   []time.Time
		window time.Duration
	}
	pending := make([]slid, 0, len(cat.rates))
	for _, r := range cat.rates {
		key := budgetMapKey(cat.name, r.dim, keys.value(r.dim))
		cutoff := at.Add(-r.window)
		kept := make([]time.Time, 0, len(b.rate[key].hits)+1)
		for _, t := range b.rate[key].hits {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) >= r.limit {
			return noopBudgetRelease, fmt.Errorf("%w: service: %s rate budget exhausted", admission.ErrOverloaded, cat.name)
		}
		pending = append(pending, slid{key: key, kept: kept, window: r.window})
	}

	// 2. Confirm every concurrency bound has a free slot — WITHOUT taking one.
	for _, c := range cat.concs {
		key := budgetMapKey(cat.name, c.dim, keys.value(c.dim))
		if b.inflight[key] >= c.limit {
			return noopBudgetRelease, fmt.Errorf("%w: service: %s concurrency budget exhausted", admission.ErrOverloaded, cat.name)
		}
	}

	// 3. Tracking-bound check BEFORE any mutation, so a saturation refusal never
	// leaves a partial charge (one rate rule recorded, a later one refused). If
	// the brand-new rate buckets this acquire would add overflow the bound, evict
	// stale buckets once, then RECOUNT which pending keys are still absent — an
	// eviction can drop a bucket a pending key names, making it newly absent — and
	// refuse if they no longer fit. Refusing a new subject rather than growing
	// unbounded is the safe direction under the threat model, exactly as the
	// reveal gateLimiter decides it (admission evicts the oldest live entry
	// instead — a deliberate divergence, since this map is shared across
	// categories with a one-hour widest window).
	countNew := func() int {
		n := 0
		for _, p := range pending {
			if _, ok := b.rate[p.key]; !ok {
				n++
			}
		}
		return n
	}
	if newKeys := countNew(); newKeys > 0 && len(b.rate)+newKeys > budgetMaxTrackedSubjects {
		b.evictStaleRate(at)
		if newKeys := countNew(); len(b.rate)+newKeys > budgetMaxTrackedSubjects {
			return noopBudgetRelease, fmt.Errorf("%w: service: %s budget tracking saturated", admission.ErrOverloaded, cat.name)
		}
	}

	// 4. Every rule passed: record the rate hits and take the concurrency slots.
	for _, p := range pending {
		b.rate[p.key] = rateBucket{hits: append(p.kept, at), window: p.window}
	}
	taken := make([]string, 0, len(cat.concs))
	for _, c := range cat.concs {
		key := budgetMapKey(cat.name, c.dim, keys.value(c.dim))
		b.inflight[key]++
		taken = append(taken, key)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			for _, key := range taken {
				if b.inflight[key] <= 1 {
					delete(b.inflight, key)
					continue
				}
				b.inflight[key]--
			}
		})
	}, nil
}

// chargeOnce records a rate-only budget category once per operation, from INSIDE
// a tx.Write/tx.Read closure where the per-principal key first becomes known.
// The retry loop replays the closure up to four times; *charged, owned by the
// caller outside the closure, makes the charge idempotent: the first successful
// attempt records the hit and flips the flag, later attempts skip it. A refusal
// wraps admission.ErrOverloaded, which is not a retryable transaction error, so
// the enclosing tx rolls back and the method surfaces the uniform 429. cat must
// be rate-only; any concurrency slot it took could not be released from here.
func (b *Budget) chargeOnce(charged *bool, cat budgetCategory, keys budgetKeys) error {
	if *charged {
		return nil
	}
	if _, err := b.acquire(cat, keys); err != nil {
		return err
	}
	*charged = true
	return nil
}

// evictStaleRate drops rate buckets whose windows have entirely elapsed, using
// each bucket's OWN window rather than the widest one in play. A 1-minute
// machine-fetch bucket is reclaimed a minute after its last hit, so a burst of
// one-off subjects cannot hold the tracking set full long after their short
// windows expired. A bucket with no live hit carries no information — it is
// indistinguishable from one that never existed — so this is pure reclamation.
func (b *Budget) evictStaleRate(at time.Time) {
	for key, bucket := range b.rate {
		// Hits are appended in clock order, so the last is the newest. If even it
		// is outside the bucket's window, no live hit remains.
		if len(bucket.hits) == 0 || !bucket.hits[len(bucket.hits)-1].After(at.Add(-bucket.window)) {
			delete(b.rate, key)
		}
	}
}
