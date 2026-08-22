package conformance

// The bound registry (mvp-boundary O2). Every NAMED bound in the ops-spec is a
// named, user-visible refusal when hit; this registry is the single list that
// "drives the fixture list". Each entry records the bound, its ops-spec home,
// the named refusal it fires (or why it is a clamp / unreachable / pending),
// and exact executable references plus readable evidence for the fixtures that
// prove it.
//
// The registry is a LEDGER plus a VALUE PIN, not a fixture executor. Package
// AST validation proves every typed fixture reference still has one exact
// definition, including helpers, literal subtests and build-tagged tests. The
// fixture itself proves behavior. Value drift off spec fails here too.
//
// These tests give it teeth:
//   - TestBoundRegistryIsWellFormed: every entry is complete for its status, so
//     every stable row ID has at least one executable fixture reference.
//   - TestBoundRegistryFixtureReferencesResolve: every reference has one exact
//     package-owned definition of the declared kind.
//   - TestBoundRegistryPendingBoundsAreDisposition: every pending bound is a
//     loud, owner-named human-disposition item, never a silent gap.
//   - TestReconciledBoundsMatchOpsSpecValues: every reconciled EXPORTED constant
//     equals its ops-spec value, so a future edit that drifts a bound off spec
//     fails the build here rather than silently.

import (
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/importer"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/testutil/fixtureref"
)

// BoundStatus classifies how a named bound is realized.
type BoundStatus string

const (
	// StatusEnforced: hitting the bound yields a named, user-visible refusal,
	// proven by a fixture.
	StatusEnforced BoundStatus = "enforced"
	// StatusClamp: a response-shape cap (page size, count) that clamps rather
	// than refuses, per the ops-spec's own clamp precedents (SCIM count).
	StatusClamp BoundStatus = "clamp"
	// StatusByConstruction: unreachable given other enforced caps; pinned by an
	// invariant test rather than a runtime refusal nothing can reach.
	StatusByConstruction BoundStatus = "by-construction"
	// StatusSanitize: the owning ADR fixes the mechanism as truncation/sanitize,
	// not refusal (evidence must still be written), so "hit → refusal" does not
	// apply.
	StatusSanitize BoundStatus = "sanitize"
	// StatusPending: named in spec, but its enforcement awaits an owning feature
	// that does not yet exist; PendingReason names the owner/reason. These are the
	// explicit disposition items, never silent gaps.
	StatusPending BoundStatus = "enforcement-pending"
)

// BoundID is the stable identity of one registry row. Names and descriptions
// may improve without breaking references to the obligation itself.
type BoundID string

// Bound is one row of the registry.
type Bound struct {
	ID            BoundID
	Name          string // the ops-spec name of the bound
	Spec          string // its ops-spec / ops-catalogue home
	Refusal       string // the named refusal it fires, or the clamp/invariant/reason
	Evidence      string // readable explanation retained alongside executable references
	Fixtures      []fixtureref.FixtureRef
	PendingReason string // owner and reason when Status is StatusPending
	Status        BoundStatus
}

const modulePath = "github.com/Hikyo-Org/hikyo/"

func bound(id BoundID, name, spec, refusal, evidence string, status BoundStatus, fixtures ...fixtureref.FixtureRef) Bound {
	return Bound{ID: id, Name: name, Spec: spec, Refusal: refusal, Evidence: evidence, Fixtures: fixtures, Status: status}
}

func goTest(packagePath, name string) fixtureref.FixtureRef {
	return fixtureref.FixtureRef{Package: modulePath + packagePath, TestName: name, Kind: fixtureref.KindTest}
}

func goHelper(packagePath, name string) fixtureref.FixtureRef {
	return fixtureref.FixtureRef{Package: modulePath + packagePath, TestName: name, Kind: fixtureref.KindHelper}
}

// Registry is the authoritative list that drives the fixture list: every named
// ops-spec bound appears once, with the fixture that proves its refusal (or an
// explicit clamp / invariant / owner-named deferral). Value drift off spec is
// caught by TestReconciledBoundsMatchOpsSpecValues; completeness against new
// spec rows is a review responsibility on this single source.
var Registry = []Bound{
	// §4 admission / §10 runtime.
	bound("admission-queue-depth", "Admission queue depth", "ops-spec §4 / inv.8", "admission.ErrOverloaded", "admission.TestQueueDepth", StatusEnforced,
		goTest("internal/admission", "TestQueueDepthIsBounded")),
	bound("api-response-cap", "API response cap", "ops-spec §10", "response ≤ 5 MiB / paged", "server contract tests", StatusEnforced,
		goTest("internal/isolation", "TestAuditExportDoesNotTruncateAboveThePageCap")),
	bound("audit-page-size", "Audit page size", "ops-spec §10 / §2", "clamp to store.AuditMaxPageSize", "store.TestAuditPageSizeIsClampedToTheCap", StatusClamp,
		goTest("internal/store", "TestAuditPageSizeIsClampedToTheCap")),
	bound("sse-admission-caps", "SSE admission caps", "ops-spec §10", "advisory principal/org/instance limits", "service.TestAdvisory* (advisory_test)", StatusEnforced,
		goTest("internal/service", "TestAdvisoryConnectionCaps")),

	// §5 machine identities.
	bound("machine-credentials-per-sa", "Machine credentials per SA", "ops-spec §5", "service.ErrCredentialCap", "isolation identities_e2e", StatusEnforced,
		goTest("internal/isolation", "TestMachineCredentialCapSQLite")),

	// §8 structural bounds.
	bound("environments-per-project", "Environments per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxEnvironmentsPerProject)", "conformance scenarioDeleteRefusesChildren / env cap", StatusEnforced,
		goHelper("internal/conformance", "scenarioEnvironmentCap")),
	bound("resolved-cell-budget", "Resolved-cell budget", "ops-spec §8", "envs × keys ≤ MaxResolvedCells", "service.TestResolvedCellBudgetComposesByConstruction", StatusByConstruction,
		goTest("internal/service", "TestResolvedCellBudgetComposesByConstruction")),
	bound("value-size", "Value size", "ops-spec §8", "schema value bound (MaxValueBytes)", "schema validate_test / conformance values_test", StatusEnforced,
		goTest("internal/schema", "TestInstanceByteBudget")),
	bound("key-name-length", "Key name length", "ops-catalogue §Key-name", "schema key-name bound (MaxKeyNameBytes)", "schema declare_test", StatusEnforced,
		goTest("internal/schema", "TestKeyNameGrammar")),
	bound("keys-per-project", "Keys per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxKeysPerProject)", "service definitions_test", StatusEnforced,
		goTest("internal/service", "TestValidateFinalDefinitionsNamesAndCaps")),
	bound("key-groups-per-project", "Key groups per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxKeyGroupsPerProject)", "service definitions_test", StatusEnforced,
		goHelper("internal/isolation", "runDefinitions")),
	bound("declaration-structural-bounds", "Declaration bytes / $ref depth / subschemas / enum / pattern / any_of", "ops-spec §8", "declaration-time rejection", "schema declare_test / conformance catalogue_test", StatusEnforced,
		goTest("internal/schema", "TestDeclarationRefusals")),
	bound("verdict-error-bounds", "Verdict errors / bytes", "ops-spec §8", "verdict cap (MaxVerdictErrors / MaxVerdictErrorBytes)", "schema validate_test", StatusEnforced,
		goTest("internal/schema", "TestErrorCapsHold")),
	bound("evaluation-budget", "Evaluation budget (steps + deadline)", "ops-spec §8", "step-cap at declaration + per-value wall-clock deadline (EvaluationDeadline)", "schema declare_test / deadline_internal_test", StatusEnforced,
		goTest("internal/schema", "TestJSONSchemaEvaluationFailsLoudOnTheDeadline")),
	bound("plan-expiry-open-quota", "Plan expiry / open-plan quota", "ops-spec §8 source-of-truth", "PlanTTL + MaxOpenPlansPerProject", "isolation definitions_e2e", StatusEnforced,
		goHelper("internal/isolation", "definitionsPlanLifecycle")),
	bound("per-target-render-total", "Per-target render total", "ops-spec §8", "domain.ErrLimitExceeded (MaxRenderBytesPerTarget)", "service.TestRenderTotalRefusesAnOversizedTarget", StatusEnforced,
		goTest("internal/service", "TestRenderTotalRefusesAnOversizedTarget")),
	bound("pending-versions-per-project", "Pending versions per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxPendingPerProject)", "isolation.TestPendingPerProjectCap", StatusEnforced,
		goTest("internal/isolation", "TestPendingPerProjectCapSQLite")),
	bound("bundle-bytes-entries", "Bundle bytes / entries", "ops-spec §8", "definitions.ErrLimitExceeded (MaxBundle*)", "definitions bundle_test", StatusEnforced,
		goTest("internal/definitions", "TestParseBoundsRefused")),
	bound("open-plans-per-project", "Open plans per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxOpenPlansPerProject)", "isolation definitions_e2e", StatusEnforced,
		goTest("internal/isolation", "TestDefinitionsSQLite")),
	bound("pins-quota-per-project", "Pins quota per project", "ops-spec §8", "invalidDetail (PinQuota)", "conformance revisions_test", StatusEnforced,
		goHelper("internal/conformance", "scenarioPinLifecycle")),
	bound("grants-per-org", "Grants per org", "ops-spec §8", "domain.ErrLimitExceeded (MaxGrantsPerOrg)", "isolation.TestGrantPerOrgCap", StatusEnforced,
		goTest("internal/isolation", "TestGrantPerOrgCapSQLite")),
	bound("project-storage-high-water", "Per-project storage high-water (warn 1 GiB / refuse 4 GiB)", "ops-spec §8 (§141)", "domain.ErrLimitExceeded (MaxProjectStorageBytes) at publish + doctor/metric/UI-banner warn (ProjectStorageWarnBytes)", "isolation.TestProjectStorageHighWater", StatusEnforced,
		goTest("internal/isolation", "TestProjectStorageHighWaterSQLite")),
	bound("schema-revision-rate", "Schema-revision rate 60/h per project", "ops-spec §8 (§151)", "admission.ErrOverloaded (uniform 429) via service.Budget", "conformance scenarioSchemaRevisionRateLimit + service.TestBudgetRateWindowSlides", StatusEnforced,
		goHelper("internal/conformance", "scenarioSchemaRevisionRateLimit")),

	// §9 encryption.
	bound("reencrypt-cas-no-resurrect", "Reencrypt CAS (no-resurrect)", "ops-spec §9", "row_version CAS conflict", "store authn CAS", StatusEnforced,
		goTest("internal/isolation", "TestReencryptInstanceRetrySafe")),
	bound("dek-lru-cache", "DEK LRU cache", "ops-spec §9", "declared bound, eviction re-unwraps (not a refusal)", "crypto keyring_test (dekCacheSize eviction)", StatusByConstruction,
		goTest("internal/crypto", "TestSealerSurvivesCacheEviction")),
	bound("reencrypt-chunk", "Reencrypt chunk 100 rows / 100 ms", "ops-spec §9 (§167)", "chunked background rewrap (service.Reencrypt paginates by ReencryptChunkSize, pauses ReencryptChunkPause between chunks)", "conformance boundregistry_test value-pins + isolation reencrypt_e2e (chunked resumable walk)", StatusEnforced,
		goTest("internal/isolation", "TestReencryptMultiChunkRetrySafe")),

	// §11 / §12 adapter & backup ops.
	bound("import-structural-bounds", "Import per-file / decoded / records / pages", "ops-catalogue §Import", "importer bound errors", "importer connector_test / live_test", StatusEnforced,
		goTest("internal/importer", "TestBoundsFailLoudNamingTheBound")),
	bound("provider-response-cap", "Provider / remote response cap", "ops-catalogue §GitHub/§Multi-instance", "response-cap refusal", "importer / remotefetch caps", StatusEnforced,
		goTest("internal/importer", "TestK8sLiveExecPluginCannotExceedOutputCap")),
	bound("remote-count", "Remote count", "ops-catalogue §Multi-instance", "service.ErrRemoteCap (remotefetch.RemoteCount)", "isolation remote_e2e (fixture: cap enforced at service/remotes.go)", StatusEnforced,
		goTest("internal/isolation", "TestRemoteCountCapSQLite")),
	bound("outbox-depth-per-target", "Outbox depth per target", "ops-catalogue §GitHub (row 19)", "adapter.ErrQueueFull", "store adapter_runtime (enforcement site)", StatusEnforced,
		goTest("internal/store", "TestAdapterEnqueueRefusesAtPerTargetQueueDepth")),

	// §20 audit ops.
	bound("audit-free-text", "Audit free text", "ops-spec §20", "truncation to audit.FreeTextBound", "audit audit_test", StatusSanitize,
		goTest("internal/audit", "TestSanitizeFreeText")),
	bound("audit-export-budget", "Audit exports 2/org · 6/instance", "ops-spec §20 (§179)", "admission.ErrOverloaded (uniform 429) via service.Budget", "service.TestAuditExportChargesExpensiveBudget + service.TestBudgetInstanceConcurrencyIsSeparateFromOrg", StatusEnforced,
		goTest("internal/service", "TestAuditExportChargesExpensiveBudget")),
	bound("expensive-path-default-budget", "Expensive-path fail-closed default 60/min·principal · 8/org", "ops-spec §10 (§179)", "budgetDefault charged at each default-expensive method; classification totality closes 'unbudgeted by omission' at build time", "conformance TestBudgetClassificationIsTotal (every authz op classified — build breaks on a new unclassified op) + scenarioDefaultBudgetChargedEndToEnd (a default-expensive method really trips the default 429) + service.TestBudgetDefaultEnforces (mechanism)", StatusEnforced,
		goHelper("internal/conformance", "scenarioDefaultBudgetChargedEndToEnd")),

	// SAML / SCIM wire bounds.
	bound("saml-document-bounds", "SAML document bytes / depth / tokens", "ops-catalogue §SAML", "samlsp.ErrDocument* ", "samlsp xml_test", StatusEnforced,
		goTest("internal/samlsp", "TestParseXMLRefusesPreparseThreats")),
	bound("scim-wire-body-cap", "SCIM wire body cap", "ops-catalogue §SCIM", "scimproto.ErrBodyTooLarge (api.SCIMBodyBound)", "isolation scim_provider_sequence_test", StatusEnforced,
		goTest("internal/isolation", "TestSCIMWireAdmissionOverHTTPSQLite")),

	// §6 compose client.
	bound("run-arg-max-preflight", "run-- ARG_MAX preflight", "ops-spec §6 / inv.8", "composite _SC_ARG_MAX refusal", "compose argmax_test", StatusEnforced,
		goTest("internal/cli", "TestRunArgMaxRefusal")),

	// §5 reveal / reauth.
	bound("protected-environment-reauth-window", "Protected-environment reauth window cap", "ops-spec §5", "service.ErrProtectedWindowCap", "isolation grants_e2e (ErrProtectedWindowCap)", StatusEnforced,
		goTest("internal/isolation", "TestProtectedEnvironmentSQLite")),
}

func TestBoundRegistryIsWellFormed(t *testing.T) {
	seenIDs := map[BoundID]bool{}
	seenNames := map[string]bool{}
	for _, b := range Registry {
		if !validBoundID(b.ID) || b.Name == "" || b.Spec == "" || b.Refusal == "" || b.Evidence == "" || len(b.Fixtures) == 0 {
			t.Errorf("incomplete registry row: %+v", b)
		}
		if seenIDs[b.ID] {
			t.Errorf("duplicate bound ID %q", b.ID)
		}
		seenIDs[b.ID] = true
		if seenNames[b.Name] {
			t.Errorf("duplicate bound name %q", b.Name)
		}
		seenNames[b.Name] = true
		switch b.Status {
		case StatusEnforced, StatusClamp, StatusByConstruction, StatusSanitize, StatusPending:
		default:
			t.Errorf("bound %q has unknown status %q", b.Name, b.Status)
		}
	}
}

func validBoundID(id BoundID) bool {
	value := string(id)
	if value == "" || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func TestBoundIDsAreStableSlugs(t *testing.T) {
	for id, want := range map[BoundID]bool{
		"admission-queue-depth": true,
		"bound-2":               true,
		"":                      false,
		"Uppercase":             false,
		"leading-":              false,
		"-trailing":             false,
		"has spaces":            false,
	} {
		if got := validBoundID(id); got != want {
			t.Errorf("validBoundID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestBoundRegistryFixtureReferencesResolve(t *testing.T) {
	fixtures := make([]fixtureref.FixtureRef, 0, len(Registry))
	for _, b := range Registry {
		fixtures = append(fixtures, b.Fixtures...)
	}
	if err := fixtureref.Validate(".", fixtures); err != nil {
		t.Fatal(err)
	}
}

// TestBoundRegistryPendingBoundsAreDisposition ensures every pending bound is a
// LOUD, tracked disposition item — never a silent omission. PendingReason is
// separate from executable fixture identity.
func TestBoundRegistryPendingBoundsAreDisposition(t *testing.T) {
	pending := 0
	for _, b := range Registry {
		if b.Status != StatusPending {
			if b.PendingReason != "" {
				t.Errorf("non-pending bound %q has a pending reason", b.ID)
			}
			continue
		}
		pending++
		if len(b.PendingReason) < 40 {
			t.Errorf("pending bound %q must name its owner and reason, got %q", b.ID, b.PendingReason)
		}
	}
	t.Logf("registry: %d bounds total, %d enforcement-pending (feature-absent, tracked)", len(Registry), pending)
}

// TestReconciledBoundsMatchOpsSpecValues is the anti-drift guard: every
// reconciled EXPORTED constant equals its ops-spec / ops-catalogue value. A
// later edit that drifts a bound off spec fails HERE, which is the whole point
// of a single conformance owner for the values.
func TestReconciledBoundsMatchOpsSpecValues(t *testing.T) {
	type pin struct {
		name string
		got  int
		want int
	}
	pins := []pin{
		// Reconciled this ticket.
		{"schema.MaxEnumMembers", schema.MaxEnumMembers, 256},
		{"schema.MaxJSONSchemaDepth", schema.MaxJSONSchemaDepth, 32},
		{"schema.MaxJSONSchemaBytes", schema.MaxJSONSchemaBytes, 65536},
		{"schema.MaxVerdictErrors", schema.MaxVerdictErrors, 100},
		{"schema.MaxVerdictErrorBytes", schema.MaxVerdictErrorBytes, 65536},
		{"importer.MaxFileBytes", importer.MaxFileBytes, 10 << 20},
		{"importer.MaxDecodedBytes", importer.MaxDecodedBytes, 50 << 20},
		{"importer.MaxRecords", importer.MaxRecords, 50000},
		{"remotefetch.RemoteCount", remotefetch.RemoteCount, 25},
		{"audit.FreeTextBound", audit.FreeTextBound, 1024},
		{"api.SCIMBodyBound", api.SCIMBodyBound, 256 << 10},
		// New enforcement caps this ticket.
		{"service.MaxGrantsPerOrg", service.MaxGrantsPerOrg, 1000},
		{"service.MaxPendingPerProject", service.MaxPendingPerProject, 100},
		{"service.MaxRenderBytesPerTarget", service.MaxRenderBytesPerTarget, 1 << 20},
		{"service.MaxResolvedCells", service.MaxResolvedCells, 100000},
		{"store.AuditMaxPageSize", store.AuditMaxPageSize, 1000},
		// §9 reencrypt chunk bound, enforced once the walk shipped (#187 / #192).
		{"service.ReencryptChunkSize", service.ReencryptChunkSize, 100},
		// Per-project storage high-water (#185).
		{"service.MaxProjectStorageBytes", service.MaxProjectStorageBytes, 4 << 30},
		{"service.ProjectStorageWarnBytes", service.ProjectStorageWarnBytes, 1 << 30},
		// §179 / §20 / §151 expensive-path budget family (#186). Pinned as one
		// table so a future edit that drifts any family value off spec fails here.
		{"service.BudgetSearchRatePerMin", service.BudgetSearchRatePerMin, 30},
		{"service.BudgetSearchOrgConcurrency", service.BudgetSearchOrgConcurrency, 4},
		{"service.BudgetExportRatePerMin", service.BudgetExportRatePerMin, 5},
		{"service.BudgetExportOrgConcurrency", service.BudgetExportOrgConcurrency, 2},
		{"service.BudgetExportInstanceConcurrency", service.BudgetExportInstanceConcurrency, 6},
		{"service.BudgetPublishRatePerMin", service.BudgetPublishRatePerMin, 10},
		{"service.BudgetPublishOrgConcurrency", service.BudgetPublishOrgConcurrency, 4},
		{"service.BudgetAdapterRatePerMin", service.BudgetAdapterRatePerMin, 10},
		{"service.BudgetAdapterOrgConcurrency", service.BudgetAdapterOrgConcurrency, 4},
		{"service.BudgetMachineFetchOrgPerMin", service.BudgetMachineFetchOrgPerMin, 300},
		{"service.BudgetMachineFetchInstancePerMin", service.BudgetMachineFetchInstancePerMin, 1000},
		{"service.BudgetDefaultRatePerMin", service.BudgetDefaultRatePerMin, 60},
		{"service.BudgetDefaultOrgConcurrency", service.BudgetDefaultOrgConcurrency, 8},
		{"service.BudgetSchemaRevisionPerHour", service.BudgetSchemaRevisionPerHour, 60},
		// Already-conformant bounds, pinned so they cannot drift unnoticed.
		{"schema.MaxKeysPerProject", schema.MaxKeysPerProject, 1000},
		{"schema.MaxKeyGroupsPerProject", schema.MaxKeyGroupsPerProject, 100},
		{"schema.MaxKeyNameBytes", schema.MaxKeyNameBytes, 128},
		{"schema.MaxValueBytes", schema.MaxValueBytes, 65536},
		{"schema.MaxPatternBytes", schema.MaxPatternBytes, 512},
		{"schema.MaxAnyOfAlternatives", schema.MaxAnyOfAlternatives, 8},
		{"schema.MaxJSONSchemaSubschemas", schema.MaxJSONSchemaSubschemas, 256},
		{"service.MaxEnvironmentsPerProject", service.MaxEnvironmentsPerProject, 50},
		{"service.MaxOpenPlansPerProject", service.MaxOpenPlansPerProject, 20},
		{"service.PinQuotaPerProject", service.PinQuotaPerProject, 100},
		{"admission.QueueDepth", admission.QueueDepth, 16},
		{"definitions.MaxBundleBytes", definitions.MaxBundleBytes, 1 << 20},
		{"definitions.MaxBundleEntries", definitions.MaxBundleEntries, 10000},
		{"importer.MaxDepth", importer.MaxDepth, 32},
		{"importer.MaxLivePages", importer.MaxLivePages, 1000},
	}
	for _, p := range pins {
		if p.got != p.want {
			t.Errorf("%s = %d, ops-spec requires %d", p.name, p.got, p.want)
		}
	}

	// Duration-valued bounds, pinned the same way.
	type dpin struct {
		name string
		got  time.Duration
		want time.Duration
	}
	dpins := []dpin{
		{"schema.EvaluationDeadline", schema.EvaluationDeadline, 100 * time.Millisecond},
		{"service.ReencryptChunkPause", service.ReencryptChunkPause, 100 * time.Millisecond},
		{"service.PlanTTL", service.PlanTTL, 24 * time.Hour},
		{"service.BootstrapLifetime", service.BootstrapLifetime, 24 * time.Hour},
		{"service.BrowserSessionIdle", service.BrowserSessionIdle, 7 * 24 * time.Hour},
		{"service.BrowserSessionAbsolute", service.BrowserSessionAbsolute, 30 * 24 * time.Hour},
		{"service.CLISessionIdle", service.CLISessionIdle, 30 * 24 * time.Hour},
		{"service.CLISessionAbsolute", service.CLISessionAbsolute, 90 * 24 * time.Hour},
	}
	for _, p := range dpins {
		if p.got != p.want {
			t.Errorf("%s = %v, ops-spec requires %v", p.name, p.got, p.want)
		}
	}
}
