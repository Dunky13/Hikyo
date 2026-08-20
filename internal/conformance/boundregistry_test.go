package conformance

// The bound registry (mvp-boundary O2). Every NAMED bound in the ops-spec is a
// named, user-visible refusal when hit; this registry is the single list that
// "drives the fixture list". Each entry records the bound, its ops-spec home,
// the named refusal it fires (or why it is a clamp / unreachable / pending),
// and the fixture that proves it.
//
// Two tests give it teeth:
//   - TestBoundRegistryIsWellFormed: every entry is complete for its status, so
//     a bound cannot be registered without either a fixture or an explicit,
//     owner-named deferral.
//   - TestReconciledBoundsMatchOpsSpecValues: every reconciled EXPORTED constant
//     equals its ops-spec value, so a future edit that drifts a bound off spec
//     fails the build here rather than silently.

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/importer"
	"github.com/Hikyo-Org/hikyo/internal/remotefetch"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
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
	// that does not yet exist; Fixture names the owner/reason. These are the
	// explicit disposition items, never silent gaps.
	StatusPending BoundStatus = "enforcement-pending"
)

// Bound is one row of the registry.
type Bound struct {
	Name    string // the ops-spec name of the bound
	Spec    string // its ops-spec / ops-catalogue home
	Refusal string // the named refusal it fires, or the clamp/invariant/reason
	Fixture string // the test that proves it, or the owner/reason for a pending bound
	Status  BoundStatus
}

// Registry is the authoritative list that drives the fixture list: every named
// ops-spec bound appears once, with the fixture that proves its refusal (or an
// explicit clamp / invariant / owner-named deferral). Value drift off spec is
// caught by TestReconciledBoundsMatchOpsSpecValues; completeness against new
// spec rows is a review responsibility on this single source.
var Registry = []Bound{
	// §4 admission / §10 runtime.
	{"Admission queue depth", "ops-spec §4 / inv.8", "admission.ErrOverloaded", "admission.TestQueueDepth", StatusEnforced},
	{"API response cap", "ops-spec §10", "response ≤ 5 MiB / paged", "server contract tests", StatusEnforced},
	{"Audit page size", "ops-spec §10 / §2", "clamp to store.AuditMaxPageSize", "store.TestAuditPageSizeIsClampedToTheCap", StatusClamp},
	{"SSE admission caps", "ops-spec §10", "advisory principal/org/instance limits", "service.TestAdvisory* (advisory_test)", StatusEnforced},

	// §5 machine identities.
	{"Machine credentials per SA", "ops-spec §5", "service.ErrCredentialCap", "isolation identities_e2e", StatusEnforced},

	// §8 structural bounds.
	{"Environments per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxEnvironmentsPerProject)", "conformance scenarioDeleteRefusesChildren / env cap", StatusEnforced},
	{"Resolved-cell budget", "ops-spec §8", "envs × keys ≤ MaxResolvedCells", "service.TestResolvedCellBudgetComposesByConstruction", StatusByConstruction},
	{"Value size", "ops-spec §8", "schema value bound (MaxValueBytes)", "schema validate_test / conformance values_test", StatusEnforced},
	{"Key name length", "ops-catalogue §Key-name", "schema key-name bound (MaxKeyNameBytes)", "schema declare_test", StatusEnforced},
	{"Keys per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxKeysPerProject)", "service definitions_test", StatusEnforced},
	{"Key groups per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxKeyGroupsPerProject)", "service definitions_test", StatusEnforced},
	{"Declaration bytes / $ref depth / subschemas / enum / pattern / any_of", "ops-spec §8", "declaration-time rejection", "schema declare_test / conformance catalogue_test", StatusEnforced},
	{"Verdict errors / bytes", "ops-spec §8", "verdict cap (MaxVerdictErrors / MaxVerdictErrorBytes)", "schema validate_test", StatusEnforced},
	{"Per-target render total", "ops-spec §8", "domain.ErrLimitExceeded (MaxRenderBytesPerTarget)", "service.TestRenderTotalRefusesAnOversizedTarget", StatusEnforced},
	{"Pending versions per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxPendingPerProject)", "isolation.TestPendingPerProjectCap", StatusEnforced},
	{"Bundle bytes / entries", "ops-spec §8", "definitions.ErrLimitExceeded (MaxBundle*)", "definitions bundle_test", StatusEnforced},
	{"Open plans per project", "ops-spec §8", "domain.ErrLimitExceeded (MaxOpenPlansPerProject)", "isolation definitions_e2e", StatusEnforced},
	{"Pins quota per project", "ops-spec §8", "invalidDetail (PinQuota)", "conformance revisions_test", StatusEnforced},
	{"Grants per org", "ops-spec §8", "domain.ErrLimitExceeded (MaxGrantsPerOrg)", "isolation.TestGrantPerOrgCap", StatusEnforced},
	{"Per-project storage high-water (warn 1 GiB / refuse 4 GiB)", "ops-spec §8 (§141)", "publish refusal + doctor warn + metric + UI banner", "ENFORCEMENT-PENDING: needs a per-project payload-byte accounting subsystem (SUM over value_entries+snapshot_entries) and a project-scoped store proof action; multi-surface (publish/doctor/metric/UI). Owner: retention/publish.", StatusPending},
	{"Schema-revision rate 60/h per project", "ops-spec §8 (§151)", "loud rate-limit refusal", "ENFORCEMENT-PENDING: needs the §179 expensive-path rate-limit subsystem (per-principal windowed counter), which is not yet implemented. Owner: server runtime.", StatusPending},

	// §9 encryption.
	{"Reencrypt CAS (no-resurrect)", "ops-spec §9", "row_version CAS conflict", "store authn CAS", StatusEnforced},
	{"DEK LRU cache", "ops-spec §9", "declared bound, eviction re-unwraps (not a refusal)", "crypto keyring_test (dekCacheSize eviction)", StatusByConstruction},
	{"Reencrypt chunk 100 rows / 100 ms", "ops-spec §9 (§167)", "chunked background rewrap", "ENFORCEMENT-PENDING: the reencrypt-after-rotation walk is not yet implemented (no reencrypt verb/job); the bound belongs to that feature. Owner: encryption rotation.", StatusPending},

	// §11 / §12 adapter & backup ops.
	{"Import per-file / decoded / records / pages", "ops-catalogue §Import", "importer bound errors", "importer connector_test / live_test", StatusEnforced},
	{"Provider / remote response cap", "ops-catalogue §GitHub/§Multi-instance", "response-cap refusal", "importer / remotefetch caps", StatusEnforced},
	{"Remote count", "ops-catalogue §Multi-instance", "service.ErrRemoteCap (remotefetch.RemoteCount)", "isolation remote_e2e (fixture: cap enforced at service/remotes.go)", StatusEnforced},
	{"Outbox depth per target", "ops-catalogue §GitHub (row 19)", "adapter.ErrQueueFull", "store adapter_runtime (enforcement site)", StatusEnforced},

	// §20 audit ops.
	{"Audit free text", "ops-spec §20", "truncation to audit.FreeTextBound", "audit audit_test", StatusSanitize},
	{"Audit exports 2/org · 6/instance", "ops-spec §20 (§179)", "expensive-path budget refusal", "ENFORCEMENT-PENDING: needs the §179 expensive-path concurrency/rate budget layer (search/export/publish/sync), which is not yet implemented as a general layer. Owner: server runtime.", StatusPending},

	// SAML / SCIM wire bounds.
	{"SAML document bytes / depth / tokens", "ops-catalogue §SAML", "samlsp.ErrDocument* ", "samlsp xml_test", StatusEnforced},
	{"SCIM wire body cap", "ops-catalogue §SCIM", "scimproto.ErrBodyTooLarge (api.SCIMBodyBound)", "isolation scim_provider_sequence_test", StatusEnforced},

	// §6 compose client.
	{"run-- ARG_MAX preflight", "ops-spec §6 / inv.8", "composite _SC_ARG_MAX refusal", "compose argmax_test", StatusEnforced},

	// §5 reveal / reauth.
	{"Protected-environment reauth window cap", "ops-spec §5", "service.ErrProtectedWindowCap", "isolation grants_e2e (ErrProtectedWindowCap)", StatusEnforced},
}

func TestBoundRegistryIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range Registry {
		if b.Name == "" || b.Spec == "" || b.Refusal == "" || b.Fixture == "" {
			t.Errorf("incomplete registry row: %+v", b)
		}
		if seen[b.Name] {
			t.Errorf("duplicate bound name %q", b.Name)
		}
		seen[b.Name] = true
		switch b.Status {
		case StatusEnforced, StatusClamp, StatusByConstruction, StatusSanitize, StatusPending:
		default:
			t.Errorf("bound %q has unknown status %q", b.Name, b.Status)
		}
	}
}

// TestBoundRegistryPendingBoundsAreDisposition ensures every pending bound is a
// LOUD, tracked disposition item — never a silent omission. Its Fixture must
// name the owning feature and the reason.
func TestBoundRegistryPendingBoundsAreDisposition(t *testing.T) {
	pending := 0
	for _, b := range Registry {
		if b.Status != StatusPending {
			continue
		}
		pending++
		if len(b.Fixture) < 40 || !strings.Contains(b.Fixture, "ENFORCEMENT-PENDING") {
			t.Errorf("pending bound %q must name its owner+reason in Fixture, got %q", b.Name, b.Fixture)
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
}
