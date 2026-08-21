package service

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

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
	// rate holds sliding-window hit timestamps, keyed by category+dimension+value.
	rate map[string][]time.Time
	// inflight holds live concurrency counts, keyed the same way. An entry is
	// deleted when it reaches zero so the map does not accumulate dead keys.
	inflight map[string]int
}

// NewBudget constructs an enabled budget on the real clock.
func NewBudget() *Budget {
	return &Budget{now: time.Now, rate: map[string][]time.Time{}, inflight: map[string]int{}}
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
// in-closure charge would multiply. Project / org / instance dims come from the
// scope argument; the per-principal rate is charged only where the principal is
// a method parameter already (audit export). The per-principal rate rules on
// publish / values-export / adapter are DEFERRED: their principal is resolved
// inside the operation's own transaction, so charging it at entry would need a
// second resolve — their per-org concurrency, the load-bearing availability
// control, IS enforced here, and the per-principal rate wiring is a tracked
// follow-up. search / default are reference configs: there is no search
// endpoint (SCIM search is a separate surface with its own bounds), and the
// fail-closed default is the layer's documented catch-all, not a route middleware.
var (
	budgetSearch = budgetCategory{
		name:  "search",
		rates: []budgetRateRule{{dimPrincipal, BudgetSearchRatePerMin, time.Minute}},
		concs: []budgetConcRule{{dimOrg, BudgetSearchOrgConcurrency}},
	}
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
	// budgetValuesExport shares the "export" concurrency pool but omits the
	// per-principal rate (its principal is resolved in-tx, see above).
	budgetValuesExport = budgetCategory{
		name:  "export",
		concs: []budgetConcRule{{dimOrg, BudgetExportOrgConcurrency}, {dimInstance, BudgetExportInstanceConcurrency}},
	}
	budgetPublish = budgetCategory{
		name:  "publish",
		concs: []budgetConcRule{{dimOrg, BudgetPublishOrgConcurrency}},
	}
	budgetAdapter = budgetCategory{
		name:  "adapter-sync",
		concs: []budgetConcRule{{dimOrg, BudgetAdapterOrgConcurrency}},
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
	// budgetDefault is the fail-closed catch-all: no expensive category is left
	// unbudgeted by omission.
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
	default: // dimInstance — one bucket for the whole instance.
		return ""
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
	type slid struct {
		key  string
		kept []time.Time
	}
	pending := make([]slid, 0, len(cat.rates))
	for _, r := range cat.rates {
		key := budgetMapKey(cat.name, r.dim, keys.value(r.dim))
		cutoff := at.Add(-r.window)
		hits := b.rate[key]
		kept := hits[:0]
		for _, t := range hits {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) >= r.limit {
			b.rate[key] = kept // keep the compaction; charge nothing.
			return noopBudgetRelease, fmt.Errorf("%w: service: %s rate budget exhausted", admission.ErrOverloaded, cat.name)
		}
		pending = append(pending, slid{key, kept})
	}

	// 2. Confirm every concurrency bound has a free slot — WITHOUT taking one.
	for _, c := range cat.concs {
		key := budgetMapKey(cat.name, c.dim, keys.value(c.dim))
		if b.inflight[key] >= c.limit {
			for _, p := range pending {
				b.rate[p.key] = p.kept // write back the compaction; charge nothing.
			}
			return noopBudgetRelease, fmt.Errorf("%w: service: %s concurrency budget exhausted", admission.ErrOverloaded, cat.name)
		}
	}

	// 3. Every rule passed: record the rate hits and take the concurrency slots.
	for _, p := range pending {
		if len(p.kept) == 0 && len(b.rate) >= budgetMaxTrackedSubjects {
			b.evictStaleRate(at)
			if len(b.rate) >= budgetMaxTrackedSubjects {
				// Every tracked bucket is live and the map is full: refuse a brand
				// new subject rather than grow unbounded. Availability loses to a
				// memory bound under the threat model, exactly as the reveal
				// gateLimiter and admission decide it.
				return noopBudgetRelease, fmt.Errorf("%w: service: %s budget tracking saturated", admission.ErrOverloaded, cat.name)
			}
		}
		b.rate[p.key] = append(p.kept, at)
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

// evictStaleRate drops rate buckets whose windows have entirely elapsed. A
// bucket with no live hits carries no information — it is indistinguishable from
// one that never existed — so this is pure reclamation. The cutoff is the
// widest window in play (an hour, for schema-rev), so a bucket is only dropped
// when it is stale under every category that could share the map; in practice
// each key is category-prefixed, so a bucket's own category window governs it.
func (b *Budget) evictStaleRate(at time.Time) {
	for key, hits := range b.rate {
		live := false
		for _, t := range hits {
			// The longest window is schema-rev's hour; anything older than that
			// is stale for every category.
			if t.After(at.Add(-time.Hour)) {
				live = true
				break
			}
		}
		if !live {
			delete(b.rate, key)
		}
	}
}
