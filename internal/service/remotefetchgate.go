package service

import (
	"sync"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
)

// The fan-out bounds the ADR's outbound-client control set names, and the last
// three composable-maxima constants that had no consumer: CoalesceWindow,
// ViewerTriggerRate and AggregateTriggerRate.
//
// All three are in-process and in-memory, deliberately. They bound THIS
// process's outbound behaviour, which is the thing the ADR asks them to bound;
// pushing them into the database would put a write on every card refresh to
// slow down a read, and a restart resetting a per-minute budget is not a hole
// worth a table.
//
// ponytail: one mutex over both buckets and the coalescing cache. The
// contended case is a handful of humans refreshing a card; if that ever shows
// up in a profile, shard by viewer.

// Exhausting a trigger budget DEGRADES TO THE SNAPSHOT; it is not an error to
// the caller. The bounds limit fetch TRIGGERS, not views, and the freshness
// model already owns the honest answer for "we did not refresh": serve the
// last-known listing, marked stale with its age. Failing the whole view instead
// would make a poll cadence slightly over budget look like an outage. What the
// model forbids is a card that quietly stopped fetching while claiming to be
// live — the stale label is what keeps this honest, and `settle` applies it on
// exactly this path.
//
// fetchGate holds the three bounds together because they are one decision:
// "may this view trigger a round, and if a round is already in flight or just
// finished, should it join that one instead".
//
// THE BUDGETS ARE PROCESS-LOCAL, AND THAT IS SOUND ONLY BECAUSE THIS PRODUCT
// SERVES FROM ONE PROCESS. The catalogue calls AggregateTriggerRate an
// installation-wide bound, and a second serving replica sharing this datastore
// would multiply it by the replica count while running its own coalescing round
// beside the first — fifty viewers politely under their own limits is still
// fifty times the traffic at every remote, which is the exact failure the
// aggregate bound exists to prevent.
//
// The invariant is therefore SINGLE SERVING PROCESS PER DATASTORE, and it is
// stated here, at the construction site, rather than assumed: hikyo ships as
// one multicall binary with an embedded SPA and an in-process scheduler-free
// design, so horizontal replication is not a supported deployment today. A
// distributed limiter is deliberately NOT built — it would be a datastore
// round trip on the hot path for a topology the product does not have. If
// replication is ever supported, this gate is the thing that must move into the
// datastore, and the catalogue row is the thing that must say so.
//
// ponytail: process-local budgets, single-serving-process invariant; move the
// counters into the datastore if replicas are ever supported.
type fetchGate struct {
	mu sync.Mutex

	// perViewer and aggregate are simple sliding-window counters: the
	// timestamps of triggers inside the last minute. A token bucket would be
	// smaller state; a timestamp list is smaller CODE at these rates
	// (6/min and 60/min), and correct at the window edges without a refill
	// clock to get wrong.
	perViewer map[domain.PrincipalID][]time.Time
	aggregate []time.Time

	// round is the coalescing cache: the most recent completed round and when
	// it completed. Concurrent viewers inside CoalesceWindow share it, which
	// is what makes a card open on several screens one connection per remote
	// rather than one per human.
	//
	// A round is reusable ONLY by a request every one of whose remotes the
	// round actually attempted. A `remote show A` caches
	// a one-entry round, and handing that to a `remote list` would report every
	// other entry as unreachable: there is no outcome in the closed enum for
	// "we did not look", so sharing across scopes can only fabricate one. A
	// narrower round replaces a wider one rather than merging into it, because
	// merging would serve an older fetch's result as if this round had produced
	// it.
	round   map[string]remotefetch.Result
	roundAt time.Time
	// inflight is non-nil while a round is running; a viewer arriving then
	// waits on it rather than starting a second one.
	inflight chan struct{}
}

func newFetchGate() *fetchGate {
	return &fetchGate{perViewer: map[domain.PrincipalID][]time.Time{}}
}

// admit records a trigger against both budgets, or refuses. Both are checked
// before either is charged, so a viewer refused by the aggregate does not also
// burn its own budget.
//
// The AGGREGATE is the one that actually protects the fleet: per-viewer
// limiting alone does not bound many principals, and fifty viewers each
// politely under their own limit is still fifty times the traffic at every
// remote.
func (g *fetchGate) admit(viewer domain.PrincipalID, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	mine := within(g.perViewer[viewer], cutoff)
	all := within(g.aggregate, cutoff)
	if len(mine) >= remotefetch.ViewerTriggerRate || len(all) >= remotefetch.AggregateTriggerRate {
		g.perViewer[viewer], g.aggregate = mine, all
		return false
	}
	g.perViewer[viewer] = append(mine, now)
	g.aggregate = append(all, now)
	return true
}

// coalesce returns a recent round to share, or claims the right to run one.
//
// `want` is the caller's remote ids, and it is the SCOPE TEST: a cached round
// is handed back only if it fetched every one of them. A round that covers less
// is not a partial answer, it is a different question.
//
// Exactly one of the three results is non-nil. The returned release function
// must be called with the round's results — so the claim is always released
// even if the fetch fails, and waiting viewers are never stranded.
func (g *fetchGate) coalesce(now time.Time, want []string) (shared map[string]remotefetch.Result, wait chan struct{}, release func(map[string]remotefetch.Result)) {
	g.mu.Lock()
	if covers(g.round, want) && now.Sub(g.roundAt) < remotefetch.CoalesceWindow {
		out := g.round
		g.mu.Unlock()
		return out, nil, nil
	}
	if g.inflight != nil {
		ch := g.inflight
		g.mu.Unlock()
		return nil, ch, nil
	}
	ch := make(chan struct{})
	g.inflight = ch
	g.mu.Unlock()
	return nil, nil, func(results map[string]remotefetch.Result) {
		g.mu.Lock()
		g.round, g.roundAt, g.inflight = results, time.Now().UTC(), nil
		g.mu.Unlock()
		close(ch)
	}
}

// covers reports whether a completed round fetched every requested remote. A
// nil round covers nothing, including the empty request — callers with no
// targets never reach here.
func covers(round map[string]remotefetch.Result, want []string) bool {
	if round == nil {
		return false
	}
	for _, id := range want {
		result, ok := round[id]
		if !ok {
			return false
		}
		if _, ok := attemptedFetch(result); !ok {
			return false
		}
	}
	return true
}

func within(ts []time.Time, cutoff time.Time) []time.Time {
	out := ts[:0:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}
