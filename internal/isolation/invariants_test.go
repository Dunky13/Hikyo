package isolation

// The tenant-isolation ADR's 13 CI invariants. Static invariants live here
// as TestInvariantNN; the db-backed ones (2's probes themselves, 3, 4, 5,
// 8's provenance, 10) run inside the per-engine suites in probes_test.go /
// querycount_test.go — the handoff doc carries the full invariant → test
// map. All are build-failing.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Dunky13/wenv/internal/app"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/lint"
	"github.com/Dunky13/wenv/internal/server"
	"github.com/Dunky13/wenv/internal/store"
)

var facts = authz.RegistryFacts{}

// TestInvariant01ClassificationTotality: every HTTP route, CLI verb and
// system entry point carries exactly one probe class; unclassified fails.
// System-class operations assert network unreachability: no system entry has
// an HTTP route.
func TestInvariant01ClassificationTotality(t *testing.T) {
	wire := facts.Wire()
	seen := map[string]bool{}

	// HTTP routes, from the actual router.
	router, ok := server.New(nil).(chi.Routes)
	if ok {
		err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			key := "http:" + method + " " + strings.TrimSuffix(route, "/")
			if route == "/" {
				key = "http:" + method + " /"
			}
			seen[key] = true
			if _, classified := wire[key]; !classified {
				t.Errorf("route %q has no probe classification", key)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("server.New no longer returns a chi router; the route walk must be updated")
	}

	// CLI verbs: server and migrate are system entry points; client verbs
	// are stubs (declared not-yet-operations).
	for _, verb := range append([]string{"server", "migrate"}, app.ClientVerbs...) {
		key := "cli:" + verb
		seen[key] = true
		if _, classified := wire[key]; !classified {
			t.Errorf("CLI verb %q has no probe classification", key)
		}
	}

	// Outbox job types and SSE emit sites: the registries are the wire
	// table's "job:" and "sse:" key spaces, empty today. When the outbox
	// (#65) or SSE (#51) land, their type registries join this enumeration.

	// No stale wire entries: everything classified must exist.
	for key, class := range wire {
		if strings.HasPrefix(key, "http:") || strings.HasPrefix(key, "cli:") {
			if !seen[key] {
				t.Errorf("wire registry entry %q matches no live route or verb", key)
			}
		}
		// Network unreachability for system operations: nothing classified
		// system may be an HTTP route.
		if class == authz.ClassSystem && strings.HasPrefix(key, "http:") {
			t.Errorf("%q: a system operation reachable over the network is the probe failure", key)
		}
	}

	// A stub verb must not have operations registered — the class flips
	// before the implementation can ride in.
	ops := facts.Operations()
	for key, class := range wire {
		if class != authz.ClassStub {
			continue
		}
		verb := strings.TrimPrefix(key, "cli:")
		for op := range ops {
			if strings.HasPrefix(string(op), verb+".") {
				t.Errorf("stub verb %q already has operation %q registered — reclassify the verb", verb, op)
			}
		}
	}
}

// TestInvariant02ProbeFixtureAxes: the harness's own self-check. The fixture
// set must include cross-org human probes AND cross-project machine probes;
// removing either axis fails here before any probe runs.
func TestInvariant02ProbeFixtureAxes(t *testing.T) {
	axes := map[string]int{}
	for _, p := range tenantProbes {
		axes[p.axis]++
	}
	if axes[axisCrossOrgHuman] == 0 {
		t.Error("no cross-org human probes in the fixture set")
	}
	if axes[axisCrossProjectMachine] == 0 {
		t.Error("no cross-project machine probes in the fixture set — org-level probes alone never exercise the workload-credential boundary")
	}
	mutations := 0
	for _, p := range tenantProbes {
		if p.mutation {
			mutations++
		}
	}
	if mutations == 0 {
		t.Error("no mutation probes: the no-side-effect contract (invariant 4) would be vacuous")
	}
}

// TestInvariant06OperationRegistryCompleteness: every store method is
// registered to operation(s), every operation to a non-empty formula, and
// the registry names no store method that does not exist.
func TestInvariant06OperationRegistryCompleteness(t *testing.T) {
	expected := map[string]bool{}
	collect := func(bundle reflect.Type) {
		for i := range bundle.NumMethod() {
			acc := bundle.Method(i)
			if acc.Type.NumIn() != 0 || acc.Type.NumOut() != 1 {
				continue
			}
			agg := acc.Type.Out(0)
			if agg.Kind() != reflect.Interface {
				continue
			}
			for j := range agg.NumMethod() {
				expected[strings.ToLower(acc.Name)+"."+agg.Method(j).Name] = true
			}
		}
	}
	collect(reflect.TypeOf((*store.Repos)(nil)).Elem())
	collect(reflect.TypeOf((*store.ReadRepos)(nil)).Elem())

	registered := facts.StoreOps()
	for method := range expected {
		if _, ok := registered[authz.StoreOp(method)]; !ok {
			t.Errorf("store method %q has no registered operation — it is unreachable and unauthorized by construction, register or remove it", method)
		}
	}
	for op := range registered {
		if !expected[string(op)] {
			t.Errorf("registry names store operation %q but no such store method exists", op)
		}
	}
	tenantLevels := facts.TenantOperations()
	for op, formula := range facts.Formulas() {
		if len(formula) == 0 {
			t.Errorf("operation %q has an empty formula — deny-by-default means no formula, no operation", op)
		}
		for _, atom := range formula {
			if atom.Cap == "" {
				t.Errorf("operation %q has an atom with no capability", op)
			}
			// An atom cannot sit deeper than the chain the operation
			// addresses — truncate() would have nothing to cut to.
			if level, tenant := tenantLevels[op]; tenant && atom.At > level {
				t.Errorf("operation %q (depth %d) has an atom at deeper level %d", op, level, atom.At)
			}
		}
	}
}

// TestInvariant07ProofSignatures: analyzer 1 over the real repository.
func TestInvariant07ProofSignatures(t *testing.T) {
	pkgs, err := lint.LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lint.CheckProofSignatures(pkgs, lint.Module+"/internal/store") {
		t.Error(f)
	}
}

// TestInvariant08PredicateConfinement: analyzer 2 over both engines'
// migrations and queries (per-branch chain conjuncts, no SET on chain
// columns, derived scope registry total). The binding-provenance half —
// every chain parameter maps from proof fields and nothing else — is
// asserted empirically by the positive controls in the engine suites: rows
// written through the store carry exactly the proof's resolved chain.
func TestInvariant08PredicateConfinement(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lint.CheckSQLPredicates(root) {
		t.Error(f)
	}
}

// TestInvariant09aDriverHandleConfinement: the proof boundary is only as
// strong as the narrowest path around it. Raw driver handles and the
// generated query packages are both one-line bypasses — a package holding
// either can issue tenant queries with caller-controlled chain values and no
// proof — so both carry exact allowlists, enforced across the module
// including tests.
func TestInvariant09aDriverHandleConfinement(t *testing.T) {
	pkgs, err := lint.LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lint.CheckDriverHandles(pkgs) {
		t.Error(f)
	}
}

// TestInvariant09ForgeryGuard: analyzer 3 over the real repository,
// including test packages.
func TestInvariant09ForgeryGuard(t *testing.T) {
	pkgs, err := lint.LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range lint.CheckProofForgery(pkgs) {
		t.Error(f)
	}
}

// TestInvariant11SystemProofEnumeration: the mint-site set is exactly
// {boot, migration, recovery-mode reconciliation, break-glass}, and every
// site's operation set is empty today — growth of either fails this test
// until the ADR is amended. Boundary rejection of a SystemProof outside its
// site's set is asserted in internal/authz's unit tests.
func TestInvariant11SystemProofEnumeration(t *testing.T) {
	sites := facts.SystemSites()
	want := map[authz.SystemSite]bool{
		authz.SiteBoot:              true,
		authz.SiteMigration:         true,
		authz.SiteRecoveryReconcile: true,
		authz.SiteBreakGlass:        true,
	}
	if len(sites) != len(want) {
		t.Errorf("system mint sites = %d entries, want exactly %d — amending the set reopens the tenant-isolation ADR", len(sites), len(want))
	}
	for site, ops := range sites {
		if !want[site] {
			t.Errorf("unregistered system mint site %q", site)
		}
		if len(ops) != 0 {
			t.Errorf("site %q has store operations %v — widening a site's set reopens the tenant-isolation ADR", site, ops)
		}
	}
}

// TestInvariant12CacheDiscipline: no cache holding tenant-owned data exists
// yet; when one lands it must register in the wire table's "cache:" space
// with proof-taking accessors and a single proof-consuming key constructor.
// The heuristic here forces the registration conversation: any cache-named
// type anywhere in the module fails until it is registered.
func TestInvariant12CacheDiscipline(t *testing.T) {
	for key := range facts.Wire() {
		if strings.HasPrefix(key, "cache:") {
			t.Errorf("cache %q is registered but no cache discipline checks exist yet — implement invariant 12's accessors/key-constructor assertions with the first cache", key)
		}
	}
	pkgs, err := lint.LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Types == nil || !strings.HasPrefix(p.PkgPath, lint.Module) {
			continue
		}
		// The probe harness itself names this very invariant.
		if p.PkgPath == lint.Module+"/internal/isolation" {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if strings.Contains(strings.ToLower(name), "cache") {
				t.Errorf("%s.%s: cache-named declaration with no cache registration — tenant-data caches take proofs and register in the wire table (invariant 12)", p.PkgPath, name)
			}
		}
	}
}

// TestInvariant13AllowlistPinning: the instance-scoped and authn-resolution
// annotations are content-pinned as (engine, query, annotation, SQL hash).
// Broadening an annotated query changes its hash; moving an annotation is an
// add-plus-remove — both are reviewed fixture diffs, never invisible swaps.
func TestInvariant13AllowlistPinning(t *testing.T) {
	type pin struct {
		Engine     string `json:"engine"`
		Name       string `json:"name"`
		Annotation string `json:"annotation"`
		Hash       string `json:"hash"`
	}
	var current []pin
	for _, engine := range []string{"sqlite", "postgres"} {
		dir := filepath.Join("..", "store", "queries", engine)
		queries, err := lint.ParseQueries(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range queries {
			if q.Annotation == "" {
				continue
			}
			current = append(current, pin{Engine: engine, Name: q.Name, Annotation: q.Annotation, Hash: q.Hash()})
		}
	}
	sort.Slice(current, func(i, j int) bool {
		if current[i].Engine != current[j].Engine {
			return current[i].Engine < current[j].Engine
		}
		return current[i].Name < current[j].Name
	})

	fixturePath := filepath.Join("testdata", "annotated_queries.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		got, _ := json.MarshalIndent(current, "", "  ")
		t.Fatalf("pin fixture missing (%v); review the annotated set and commit it as %s:\n%s", err, fixturePath, got)
	}
	var pinned []pin
	if err := json.Unmarshal(raw, &pinned); err != nil {
		t.Fatalf("pin fixture unreadable: %v", err)
	}
	got, _ := json.MarshalIndent(current, "", "  ")
	want, _ := json.MarshalIndent(pinned, "", "  ")
	if string(got) != string(want) {
		t.Fatalf("annotated-query allowlist drifted from its pin; re-review and update %s.\ncurrent:\n%s\npinned:\n%s", fixturePath, got, want)
	}
}

// TestInvariant06aFormulaPinning is the anti-widening half of registry
// completeness. Probes prove that the CURRENT formulas deny the principals
// they should, but a formula silently widened to a capability the fixtures
// already hold (environment.update-note from edit to read, say) can slip
// past a probe suite. The pin makes every formula change a reviewed diff.
func TestInvariant06aFormulaPinning(t *testing.T) {
	current := facts.FormulaPins()
	fixturePath := filepath.Join("testdata", "operation_formulas.json")
	got, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("formula pin missing (%v); review the registry and commit it as %s:\n%s", err, fixturePath, got)
	}
	var pinned []authz.FormulaPin
	if err := json.Unmarshal(raw, &pinned); err != nil {
		t.Fatalf("formula pin unreadable: %v", err)
	}
	want, err := json.MarshalIndent(pinned, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("the operation→formula map drifted from its pin; re-review authority changes and update %s.\ncurrent:\n%s\npinned:\n%s", fixturePath, got, want)
	}
}
