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
	"github.com/Dunky13/wenv/internal/cli"
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
	router, ok := server.New(nil, &server.API{}).(chi.Routes)
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

	// CLI verbs: server and migrate are system entry points, version (#46)
	// is a local unauthenticated print; client verbs are stubs (declared
	// not-yet-operations).
	verbs := []string{"server", "migrate", "version", "admin"}
	verbs = append(verbs, cli.Verbs...)
	verbs = append(verbs, app.ClientVerbs...)
	for _, verb := range verbs {
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
	// A store method is reachable either through an ordinary operation
	// (grant-evaluated) or through a system mint site's closed set — the
	// no-principal paths the ADR enumerates, e.g. boot's keyring checks.
	// Both are registrations; an unregistered method is unreachable and
	// unauthorized by construction.
	systemRegistered := map[authz.StoreOp]authz.SystemSite{}
	for site, ops := range facts.SystemSites() {
		for _, op := range ops {
			systemRegistered[op] = site
		}
	}
	for method := range expected {
		op := authz.StoreOp(method)
		_, viaOperation := registered[op]
		_, viaSite := systemRegistered[op]
		if !viaOperation && !viaSite {
			t.Errorf("store method %q has no registered operation and no system mint site — it is unreachable and unauthorized by construction, register or remove it", method)
		}
		if viaOperation && viaSite {
			t.Errorf("store method %q is registered both to an operation and to system site %q — a method is grant-evaluated or site-bound, never both", method, systemRegistered[op])
		}
	}
	for op := range registered {
		if !expected[string(op)] {
			t.Errorf("registry names store operation %q but no such store method exists", op)
		}
	}
	for op, site := range systemRegistered {
		if !expected[string(op)] {
			t.Errorf("system site %q names store operation %q but no such store method exists", site, op)
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
	// Boot's set is the keyring surface the ADR names verbatim ("boot to its
	// pragma/keyring checks"); the other three sites stay empty until
	// recovery mode and break-glass land (#54/#55). Both directions are
	// pinned, so widening any set fails the build.
	wantBoot := map[authz.StoreOp]bool{
		authz.StoreKeysActiveMasterWrappers:       true,
		authz.StoreKeysActiveTier3:                true,
		authz.StoreKeysAcquireHierarchyGeneration: true,
		authz.StoreKeysInsertMaster:               true,
		authz.StoreKeysInsertTier3:                true,
		authz.StoreKeysInsertScopeGeneration:      true,
	}
	for site, ops := range sites {
		if !want[site] {
			t.Errorf("unregistered system mint site %q", site)
		}
		if site == authz.SiteBoot {
			if len(ops) != len(wantBoot) {
				t.Errorf("boot's operation set = %v, want exactly the keyring surface", ops)
			}
			for _, op := range ops {
				if !wantBoot[op] {
					t.Errorf("boot's set gained %q — widening a site's set reopens the tenant-isolation ADR", op)
				}
			}
			continue
		}
		if len(ops) != 0 {
			t.Errorf("site %q has store operations %v — widening a site's set reopens the tenant-isolation ADR", site, ops)
		}
	}
}

// TestInvariant12CacheDiscipline: every cache holding derived tenant
// material is registered, with its single key constructor and the layer
// that supplies its proof named. The module is swept for cache-shaped
// declarations so a new cache cannot appear unregistered — the ADR's
// keying rule and access rule both have to be answered for it in writing.
//
// The DEK LRU (#43) is keyed by internal/crypto.dekScope, a length-prefixed
// injective encoding of (org_id, project_id) — the ADR's keying rule
// exactly. Its access rule sits one layer up: internal/crypto is a locked
// leaf package (boundary-tested) and cannot import the authorization
// package, so proof-gating is the calling seam's obligation, recorded in
// the registry entry and inherited by #50.
func TestInvariant12CacheDiscipline(t *testing.T) {
	registered := facts.Caches()
	if len(registered) == 0 {
		t.Fatal("cache registry is empty; the DEK LRU (#43) must be registered")
	}
	for name, c := range registered {
		if c.KeyConstructor == "" {
			t.Errorf("cache %q registers no key constructor — ad-hoc key construction is banned", name)
		}
		if c.ProofGatedAt == "" {
			t.Errorf("cache %q does not say which layer supplies its proof", name)
		}
	}

	// The DEK LRU's key constructor must exist and compose the full chain
	// length-prefixed, not by bare concatenation.
	src, err := os.ReadFile(filepath.Join("..", "crypto", "keyring.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "func dekScope(orgID, projectID string) string {") {
		t.Error("internal/crypto.dekScope moved or changed shape; re-verify the DEK LRU's keying against invariant 12")
	}
	if !strings.Contains(string(src), "appendLP(appendLP(nil, []byte(orgID)), []byte(projectID))") {
		t.Error("the DEK LRU is no longer keyed by a length-prefixed full chain — bare concatenation collides across scope boundaries")
	}

	// Sweep: any cache-shaped declaration must belong to a registered cache.
	pkgs, err := lint.LoadRepo()
	if err != nil {
		t.Fatal(err)
	}
	knownPkgs := map[string]bool{
		lint.Module + "/internal/crypto": true, // the DEK LRU, registered below
		lint.Module + "/internal/authz":  true, // holds the registry itself
	}
	for _, p := range pkgs {
		if p.Types == nil || !strings.HasPrefix(p.PkgPath, lint.Module) {
			continue
		}
		base := strings.TrimSuffix(p.PkgPath, ".test")
		if base == lint.Module+"/internal/isolation" || knownPkgs[base] {
			continue // the harness names the invariant; crypto's cache is registered
		}
		for _, name := range p.Types.Scope().Names() {
			if strings.Contains(strings.ToLower(name), "cache") {
				t.Errorf("%s.%s: cache-shaped declaration with no entry in the cache registry — state its key constructor and proof-gating layer (invariant 12)", base, name)
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
