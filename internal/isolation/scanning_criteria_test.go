package isolation

import (
	"path/filepath"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/testutil/fixtureref"
)

// The secret-scanning acceptance-criteria matrix (#74, SS1–SS4).
//
// Modelled on the SCIM matrix (scim_criteria_test.go): the ADR's fixture
// discipline made executable. It fails in three directions:
//
//  1. a clause with no fixture and no deferral — a clause cannot be quietly
//     unimplemented;
//  2. a qualified Go fixture whose exact package AST no longer defines the
//     named test, benchmark, helper, or subtest;
//  3. a qualified Playwright fixture whose exact file no longer defines the
//     named static test title.
//
// The three residual legs the ADR's §9 table names but this PR does not close
// carry a Blocked reason instead of a fixture, and are counted apart so "the
// matrix is complete" never silently means "except for these": the two
// definitions-ingress legs wait on #70's plan/apply verbs, and the Surface-2
// block dialog waits on a declaration-editing surface the SPA does not have
// (docs/handoff/60-chrome-surfaces.md). A deferred clause is NOT COVERED — it
// does not point at a tripwire asserting the behaviour is absent.
//
// Go fixtures live across packages (internal/scanning, .../gen, internal/crypto,
// internal/conformance, internal/service, internal/cli, and this package).
// Every reference declares that ownership directly; there is no allowlist that
// can stay green after the source fixture disappears.

type scanClause struct {
	// Text is the clause as the ADR §9 table words it.
	Text string
	// Fixtures are exact, typed source references. Go File is optional because
	// package ownership is the stable identity; Playwright File is mandatory.
	Fixtures []fixtureref.FixtureRef
	// Blocked names the reason a clause cannot yet be proved. A Blocked clause
	// is NOT COVERED and may carry no fixture; it is the honest deferral.
	Blocked string
}

const scanningModulePath = "github.com/Hikyo-Org/hikyo/"

func goTestFixture(packagePath, name string) fixtureref.FixtureRef {
	return fixtureref.FixtureRef{Package: scanningModulePath + packagePath, TestName: name, Kind: fixtureref.KindTest}
}

func goBenchmarkFixture(packagePath, name string) fixtureref.FixtureRef {
	return fixtureref.FixtureRef{Package: scanningModulePath + packagePath, TestName: name, Kind: fixtureref.KindBenchmark}
}

func goHelperFixture(packagePath, name string) fixtureref.FixtureRef {
	return fixtureref.FixtureRef{Package: scanningModulePath + packagePath, TestName: name, Kind: fixtureref.KindHelper}
}

func playwrightFixture(file, title string) fixtureref.FixtureRef {
	return fixtureref.FixtureRef{Package: "web", File: file, TestName: title, Kind: fixtureref.KindPlaywrightTest}
}

// scanningCriteria is the closed matrix. IDs are stable: SS<row>.<letter>.
var scanningCriteria = map[string]scanClause{
	// --- SS1: ruleset & corpus (ADR §3, §7) ----------------------------------
	"SS1.a": {Text: "fixture corpus green: every allowlisted rule and the `ew_` rule each exercise ≥1 true-positive and ≥1 false-positive fixture",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestCorpusCoversEveryRule")}},
	"SS1.b": {Text: "`ew_` fixtures include truncated and checksum-corrupted non-matches (procedural CRC stage exercised)",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestHikTwoStage")}},
	"SS1.c": {Text: "every §3 minimum-coverage family represented by ≥1 allowlisted fixtured rule",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestMinimumCoverageFamilies")}},
	"SS1.d": {Text: "compiled-rule manifest ≡ allowlist; a vendored rule off the allowlist is proven not compiled in",
		Fixtures: []fixtureref.FixtureRef{
			goTestFixture("internal/scanning", "TestManifestEqualsAllowlist"),
			goTestFixture("internal/scanning", "TestOffAllowlistRuleNotCompiled"),
		}},
	"SS1.e": {Text: "an allowlisted rule with unsupported fields fails generation (import contract: id/regex/keywords only)",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning/gen", "TestImportRuleContract")}},
	"SS1.f": {Text: "vendoring record complete (upstream commit, source path, license hash)",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestVendoringRecord")}},
	"SS1.g": {Text: "boot-refusal fixture (corrupt ruleset → refuse to start); the pinned ruleset compiles at boot",
		Fixtures: []fixtureref.FixtureRef{
			goTestFixture("internal/scanning", "TestLoadRejectsCorruptRuleset"),
			goTestFixture("internal/scanning", "TestLoadSucceeds"),
		}},
	"SS1.h": {Text: "ruleset size ceiling: ≤ 64 compiled rules",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestRuleCountUnderCeiling")}},
	"SS1.i": {Text: "`bench-scan` harness runs as the relative regression guard",
		Fixtures: []fixtureref.FixtureRef{goBenchmarkFixture("internal/scanning", "BenchmarkScan")}},
	"SS1.j": {Text: "artifact-validation: the committed Pi-class result parses, matches the pinned harness + ruleset versions, and reports p99 ≤ 5 ms and boot ≤ 2 s / ≤ 32 MiB",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestPiBenchArtifact")}},

	// --- SS2: config-value warn path (ADR §2, §4, §7) ------------------------
	"SS2.a": {Text: "planted credential in a config value: save succeeds with finding in response and `finding_warned` committed in the same transaction; induced post-scan commit failure leaves neither value nor event",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS2.b": {Text: "keep-as-config emits `finding_dismissed`; the identical value re-saved does not re-fire; a distinct offending value re-fires; a stale rule-digest dismissal re-fires",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS2.c": {Text: "reclassify-as-secret completes under normal edit authority and drops the key's dismissals",
		Fixtures: []fixtureref.FixtureRef{
			goHelperFixture("internal/isolation", "runScanningLifecycle"),
			goHelperFixture("internal/conformance", "scenarioScanningDismissals"),
		}},
	"SS2.d": {Text: "the same planted value arriving via `values import` surfaces the finding in the import response (surface `import_value`)",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS2.e": {Text: "declassifying a secret whose value carries a planted credential fires the warn inside the ceremony (surface `declassification`)",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS2.f": {Text: "sticky-dismissal store identity — (org, project, env, key, rule digest, value fingerprint) — and rotation re-fingerprints the same value",
		Fixtures: []fixtureref.FixtureRef{
			goHelperFixture("internal/conformance", "scenarioScanningDismissals"),
			goHelperFixture("internal/conformance", "scenarioScanningKeyRotation"),
		}},
	"SS2.ui": {Text: "[UI] warn dialog with both named actions (reclassify / keep-as-config) on the locked editing surface",
		Fixtures: []fixtureref.FixtureRef{playwrightFixture("e2e/flows/scanning.spec.ts", "warns, dismisses stickily, re-fires, and reclassifies (SS2/SS4 [UI])")}},

	// --- SS3: public free-text block path (ADR §2, §4, §7) -------------------
	"SS3.a": {Text: "direct key edit refused before any pending state persists, naming locator + rule id, with `finding_blocked` durable and nothing else written",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS3.b": {Text: "resubmission with per-finding content-bound tokens commits emitting `finding_overridden`; a token presented after the field changed is rejected by name; a surplus token is rejected by name",
		Fixtures: []fixtureref.FixtureRef{
			goHelperFixture("internal/isolation", "runScanningLifecycle"),
			goTestFixture("internal/service", "TestAckSetStaleContentAndVersionRejected"),
			goTestFixture("internal/service", "TestAckSetSurplusReported"),
		}},
	"SS3.c": {Text: "a hierarchy ingress (folder path segment) also blocks",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS3.d": {Text: "per-request finding-count cap fails closed naming the cap (no silent truncation)",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/service", "TestFindingCapFailsClosed")}},
	"SS3.e": {Text: "[CI] recursive field-coverage matrix: the reflection walk descends every nested struct/pointer/slice of the canonical model, so every author-controlled string leaf (including under Key.Declaration) has a scan-coverage fixture proven by construction; a new public field without one fails (direct-edit model and the definitions bundle model), and an anti-vacuity guard pins the deep leaves are reached",
		Fixtures: []fixtureref.FixtureRef{
			goTestFixture("internal/service", "TestSurface2FieldCoverageMatrix"),
			goTestFixture("internal/service", "TestBundleLeafCoverageMatrix"),
			goTestFixture("internal/service", "TestCoverageWalkReachesDeepLeaves"),
		}},
	"SS3.f": {Text: "[CI] API schema + CLI flag-namespace sweep proves no blanket ignore-all input exists",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/cli", "TestNoBlanketScanOverrideFlag")}},
	"SS3.plan": {Text: "[E2E] `definitions plan` refused before a plan persists; acknowledged resubmission commits with finding_overridden",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningDefinitionsPlanBlock")}},
	"SS3.apply": {Text: "[E2E] same-version `definitions apply` adds no second scan; ruleset-skewed apply re-scans and refuses, then commits on acknowledgement",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningDefinitionsApplySkew")}},
	"SS3.ui": {Text: "[UI] block dialog stating the exported-as-public consequence",
		Blocked: "no SPA declaration-editing surface (docs/handoff/60-chrome-surfaces.md); block presentation ships CLI/API and the dialog lands with that surface"},

	// --- SS4: non-disclosure invariants (ADR §2, §4, §5, §6) -----------------
	"SS4.a": {Text: "planted-canary sweep: the credential appears in no real HTTP response body (value warn + declaration block), CLI table/JSON/stderr, audit export stream, or import output — and neither does any match offset/length/excerpt, proven on the closed redacted key set (redacted DTO by construction)",
		Fixtures: []fixtureref.FixtureRef{
			goHelperFixture("internal/isolation", "runScanningLifecycle"),
			goHelperFixture("internal/isolation", "runScanningCanarySweep"),
		}},
	"SS4.b": {Text: "audit fixtures assert `scanning.*` payloads carry exactly the §5 schema (no fingerprint field exists)",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS4.c": {Text: "fingerprint construction asserted executably: HMAC known-answer vectors through the envelope-package API; scope separation",
		Fixtures: []fixtureref.FixtureRef{
			goTestFixture("internal/crypto", "TestScanningFingerprintKnownAnswer"),
			goTestFixture("internal/crypto", "TestScanningFingerprintScopeSeparation"),
		}},
	"SS4.d": {Text: "the encryption ADR's architecture test extended: scanning code imports no hash/HMAC primitive",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/scanning", "TestNoHashPrimitiveImport")}},
	"SS4.e": {Text: "stolen-dump fixture: dismissal rows from a dump plus the planted value yield no match under any unkeyed digest of the value",
		Fixtures: []fixtureref.FixtureRef{
			goHelperFixture("internal/conformance", "scenarioScanningDismissals"),
			goHelperFixture("internal/isolation", "runScanningLifecycle"),
		}},
	"SS4.f": {Text: "[E2E] planted credential in a secret-classified value → zero findings, zero `scanning.*` events (Surface-3 absence proven, not merely unimplemented)",
		Fixtures: []fixtureref.FixtureRef{goHelperFixture("internal/isolation", "runScanningLifecycle")}},
	"SS4.g": {Text: "the acknowledgement token is opaque and embeds no plaintext",
		Fixtures: []fixtureref.FixtureRef{goTestFixture("internal/service", "TestAckTokenOpaqueNoPlaintext")}},
	"SS4.ui": {Text: "[UI] planted-canary absent from DOM and browser console on the warn dialog",
		Fixtures: []fixtureref.FixtureRef{playwrightFixture("e2e/flows/scanning.spec.ts", "warns, dismisses stickily, re-fires, and reclassifies (SS2/SS4 [UI])")}},
}

// TestScanningCriteriaMatrixIsComplete is the ADR's fixture discipline as a
// build failure — see the file header for the three directions it fails in.
func TestScanningCriteriaMatrixIsComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")

	blocked := 0
	refs := make([]fixtureref.FixtureRef, 0, len(scanningCriteria))
	seen := map[fixtureref.FixtureRef]bool{}
	for id, clause := range scanningCriteria {
		if clause.Blocked != "" {
			blocked++
			t.Logf("acceptance clause %s is NOT COVERED, blocked on %s: %s", id, clause.Blocked, clause.Text)
			// A deferred clause may carry no proof; if it names any, still verify.
		} else if len(clause.Fixtures) == 0 {
			t.Errorf("acceptance clause %s (%s) has neither a qualified executable fixture nor a Blocked reason", id, clause.Text)
		}
		for _, ref := range clause.Fixtures {
			if !seen[ref] {
				seen[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	if err := fixtureref.Validate(repoRoot, refs); err != nil {
		t.Errorf("scanning criteria name invalid fixtures: %v", err)
	}

	// The blocked set is pinned: the residual leg named in the ADR §9 table that
	// this PR does not close (only SS3.ui — no SPA declaration-editing surface).
	// #74 SS3's plan/apply legs are now proven (definitions plan/apply exist and
	// scan). A clause that becomes provable must lose its Blocked marker rather
	// than keep it as cover; a new deferral must move this pin deliberately.
	const blockedClauses = 1
	if blocked != blockedClauses {
		t.Errorf("%d clauses are declared not-covered, pinned at %d — a clause was blocked or unblocked without updating the pin", blocked, blockedClauses)
	}

	// A floor on the matrix's own size: SS1–SS4 decomposed clause by clause.
	// Growing it means a clause was found; shrinking it is how a completeness
	// check is made to pass without doing the work.
	const clauses = 34
	if len(scanningCriteria) < clauses {
		t.Fatalf("the criteria matrix has %d clauses, down from %d — a clause of SS1-SS4 was dropped rather than proved", len(scanningCriteria), clauses)
	}
}
