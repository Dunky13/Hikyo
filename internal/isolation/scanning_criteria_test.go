package isolation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The secret-scanning acceptance-criteria matrix (#74, SS1–SS4).
//
// Modelled on the SCIM matrix (scim_criteria_test.go): the ADR's fixture
// discipline made executable. It fails in three directions:
//
//  1. a clause with no fixture and no deferral — a clause cannot be quietly
//     unimplemented;
//  2. a Go fixture NAMED here that no test function defines — the matrix cannot
//     be satisfied by pointing at a renamed or deleted test;
//  3. a [UI] clause whose WebSpec title is absent from the Playwright flow spec
//     — the browser leg cannot be claimed by naming a test that is not there.
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
// internal/conformance, internal/service, internal/cli) and one lives here
// (runScanningLifecycle); the cross-package ones are allowlisted below and
// checked by their own package's tests, exactly as the SCIM matrix does.

type scanClause struct {
	// Text is the clause as the ADR §9 table words it.
	Text string
	// Fixtures are Go test/helper names — in this package or in the
	// cross-package allowlist below.
	Fixtures []string
	// WebSpec, when set, is a substring of a Playwright test title in the
	// secret-scanning flow spec that proves a [UI] leg. Verified to exist.
	WebSpec string
	// Blocked names the reason a clause cannot yet be proved. A Blocked clause
	// is NOT COVERED and may carry no fixture; it is the honest deferral.
	Blocked string
}

// scanningCriteria is the closed matrix. IDs are stable: SS<row>.<letter>.
var scanningCriteria = map[string]scanClause{
	// --- SS1: ruleset & corpus (ADR §3, §7) ----------------------------------
	"SS1.a": {Text: "fixture corpus green: every allowlisted rule and the `ew_` rule each exercise ≥1 true-positive and ≥1 false-positive fixture",
		Fixtures: []string{"TestCorpusCoversEveryRule"}},
	"SS1.b": {Text: "`ew_` fixtures include truncated and checksum-corrupted non-matches (procedural CRC stage exercised)",
		Fixtures: []string{"TestHikTwoStage"}},
	"SS1.c": {Text: "every §3 minimum-coverage family represented by ≥1 allowlisted fixtured rule",
		Fixtures: []string{"TestMinimumCoverageFamilies"}},
	"SS1.d": {Text: "compiled-rule manifest ≡ allowlist; a vendored rule off the allowlist is proven not compiled in",
		Fixtures: []string{"TestManifestEqualsAllowlist", "TestOffAllowlistRuleNotCompiled"}},
	"SS1.e": {Text: "an allowlisted rule with unsupported fields fails generation (import contract: id/regex/keywords only)",
		Fixtures: []string{"TestImportRuleContract"}},
	"SS1.f": {Text: "vendoring record complete (upstream commit, source path, license hash)",
		Fixtures: []string{"TestVendoringRecord"}},
	"SS1.g": {Text: "boot-refusal fixture (corrupt ruleset → refuse to start); the pinned ruleset compiles at boot",
		Fixtures: []string{"TestLoadRejectsCorruptRuleset", "TestLoadSucceeds"}},
	"SS1.h": {Text: "ruleset size ceiling: ≤ 64 compiled rules",
		Fixtures: []string{"TestRuleCountUnderCeiling"}},
	"SS1.i": {Text: "`bench-scan` harness runs as the relative regression guard",
		Fixtures: []string{"BenchmarkScan"}},
	"SS1.j": {Text: "artifact-validation: the committed Pi-class result parses, matches the pinned harness + ruleset versions, and reports p99 ≤ 5 ms and boot ≤ 2 s / ≤ 32 MiB",
		Fixtures: []string{"TestPiBenchArtifact"}},

	// --- SS2: config-value warn path (ADR §2, §4, §7) ------------------------
	"SS2.a": {Text: "planted credential in a config value: save succeeds with finding in response and `finding_warned` committed in the same transaction; induced post-scan commit failure leaves neither value nor event",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS2.b": {Text: "keep-as-config emits `finding_dismissed`; the identical value re-saved does not re-fire; a distinct offending value re-fires; a stale rule-digest dismissal re-fires",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS2.c": {Text: "reclassify-as-secret completes under normal edit authority and drops the key's dismissals",
		Fixtures: []string{"runScanningLifecycle", "scenarioScanningDismissals"}},
	"SS2.d": {Text: "the same planted value arriving via `values import` surfaces the finding in the import response (surface `import_value`)",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS2.e": {Text: "declassifying a secret whose value carries a planted credential fires the warn inside the ceremony (surface `declassification`)",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS2.f": {Text: "sticky-dismissal store identity — (org, project, env, key, rule digest, value fingerprint) — and rotation re-fingerprints the same value",
		Fixtures: []string{"scenarioScanningDismissals", "scenarioScanningKeyRotation"}},
	"SS2.ui": {Text: "[UI] warn dialog with both named actions (reclassify / keep-as-config) on the locked editing surface",
		WebSpec: "warns, dismisses stickily, re-fires, and reclassifies"},

	// --- SS3: public free-text block path (ADR §2, §4, §7) -------------------
	"SS3.a": {Text: "direct key edit refused before any pending state persists, naming locator + rule id, with `finding_blocked` durable and nothing else written",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS3.b": {Text: "resubmission with per-finding content-bound tokens commits emitting `finding_overridden`; a token presented after the field changed is rejected by name; a surplus token is rejected by name",
		Fixtures: []string{"runScanningLifecycle", "TestAckSetStaleContentAndVersionRejected", "TestAckSetSurplusReported"}},
	"SS3.c": {Text: "a hierarchy ingress (folder path segment) also blocks",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS3.d": {Text: "per-request finding-count cap fails closed naming the cap (no silent truncation)",
		Fixtures: []string{"TestFindingCapFailsClosed"}},
	"SS3.e": {Text: "[CI] generated field-coverage matrix: every author-controlled string leaf has a scan-coverage fixture; a new public field without one fails",
		Fixtures: []string{"TestSurface2FieldCoverageMatrix"}},
	"SS3.f": {Text: "[CI] API schema + CLI flag-namespace sweep proves no blanket ignore-all input exists",
		Fixtures: []string{"TestNoBlanketScanOverrideFlag"}},
	"SS3.plan": {Text: "[E2E] `definitions plan` refused before a plan persists",
		Blocked: "#70 (the definitions plan verb does not exist yet; the scanner + ack machinery is verb-agnostic and #70 calls it before plan persistence)"},
	"SS3.apply": {Text: "[E2E] ruleset-skewed `definitions apply` re-scan refused",
		Blocked: "#70 (the definitions apply verb does not exist yet; #70 re-scans on snapshot-version skew)"},
	"SS3.ui": {Text: "[UI] block dialog stating the exported-as-public consequence",
		Blocked: "no SPA declaration-editing surface (docs/handoff/60-chrome-surfaces.md); block presentation ships CLI/API and the dialog lands with that surface"},

	// --- SS4: non-disclosure invariants (ADR §2, §4, §5, §6) -----------------
	"SS4.a": {Text: "planted-canary sweep: the credential appears in no wire response, audit row, or import output — and neither does any match offset/length/excerpt (redacted DTO by construction)",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS4.b": {Text: "audit fixtures assert `scanning.*` payloads carry exactly the §5 schema (no fingerprint field exists)",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS4.c": {Text: "fingerprint construction asserted executably: HMAC known-answer vectors through the envelope-package API; scope separation",
		Fixtures: []string{"TestScanningFingerprintKnownAnswer", "TestScanningFingerprintScopeSeparation"}},
	"SS4.d": {Text: "the encryption ADR's architecture test extended: scanning code imports no hash/HMAC primitive",
		Fixtures: []string{"TestNoHashPrimitiveImport"}},
	"SS4.e": {Text: "stolen-dump fixture: dismissal rows from a dump plus the planted value yield no match under any unkeyed digest of the value",
		Fixtures: []string{"scenarioScanningDismissals", "runScanningLifecycle"}},
	"SS4.f": {Text: "[E2E] planted credential in a secret-classified value → zero findings, zero `scanning.*` events (Surface-3 absence proven, not merely unimplemented)",
		Fixtures: []string{"runScanningLifecycle"}},
	"SS4.g": {Text: "the acknowledgement token is opaque and embeds no plaintext",
		Fixtures: []string{"TestAckTokenOpaqueNoPlaintext"}},
	"SS4.ui": {Text: "[UI] planted-canary absent from DOM and browser console on the warn dialog",
		WebSpec: "warns, dismisses stickily, re-fires, and reclassifies"},
}

// scanningCrossPackageFixtures are fixtures that live outside internal/isolation.
// Named here so the matrix can point at them; each is checked by its own
// package's tests. Every entry was confirmed present at authoring.
var scanningCrossPackageFixtures = map[string]bool{
	// internal/scanning
	"TestCorpusCoversEveryRule":       true,
	"TestHikTwoStage":                 true,
	"TestMinimumCoverageFamilies":     true,
	"TestManifestEqualsAllowlist":     true,
	"TestOffAllowlistRuleNotCompiled": true,
	"TestVendoringRecord":             true,
	"TestLoadRejectsCorruptRuleset":   true,
	"TestLoadSucceeds":                true,
	"TestRuleCountUnderCeiling":       true,
	"BenchmarkScan":                   true,
	"TestPiBenchArtifact":             true,
	"TestNoHashPrimitiveImport":       true,
	// internal/scanning/gen
	"TestImportRuleContract": true,
	// internal/crypto
	"TestScanningFingerprintKnownAnswer":     true,
	"TestScanningFingerprintScopeSeparation": true,
	// internal/conformance
	"scenarioScanningDismissals":  true,
	"scenarioScanningKeyRotation": true,
	// internal/service
	"TestSurface2FieldCoverageMatrix":          true,
	"TestAckSetStaleContentAndVersionRejected": true,
	"TestAckSetSurplusReported":                true,
	"TestFindingCapFailsClosed":                true,
	"TestAckTokenOpaqueNoPlaintext":            true,
	// internal/cli
	"TestNoBlanketScanOverrideFlag": true,
}

// TestScanningCriteriaMatrixIsComplete is the ADR's fixture discipline as a
// build failure — see the file header for the three directions it fails in.
func TestScanningCriteriaMatrixIsComplete(t *testing.T) {
	source := packageSource(t)
	webSpec := webFlowSpecSource(t)

	blocked := 0
	for id, clause := range scanningCriteria {
		if clause.Blocked != "" {
			blocked++
			t.Logf("acceptance clause %s is NOT COVERED, blocked on %s: %s", id, clause.Blocked, clause.Text)
			// A deferred clause may carry no proof; if it names any, still verify.
		} else if len(clause.Fixtures) == 0 && clause.WebSpec == "" {
			t.Errorf("acceptance clause %s (%s) has neither a fixture nor a WebSpec nor a Blocked reason", id, clause.Text)
		}
		for _, fixture := range clause.Fixtures {
			if !strings.Contains(source, "func "+fixture+"(") && !scanningCrossPackageFixtures[fixture] {
				t.Errorf("%s names fixture %q, which no test function in this package defines and which is not allowlisted cross-package", id, fixture)
			}
		}
		if clause.WebSpec != "" && !strings.Contains(webSpec, clause.WebSpec) {
			t.Errorf("%s names WebSpec title %q, absent from the secret-scanning flow spec — a renamed browser test must not keep satisfying the matrix", id, clause.WebSpec)
		}
	}

	// The blocked set is pinned: the three residual legs named in the ADR §9
	// table that this PR does not close. A clause that becomes provable must
	// lose its Blocked marker rather than keep it as cover; a new deferral must
	// move this pin deliberately.
	const blockedClauses = 3
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

// webFlowSpecSource reads the secret-scanning Playwright flow spec so a [UI]
// clause's WebSpec title is verified against the real test file, two levels up
// from this package.
func webFlowSpecSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "web", "e2e", "flows", "scanning.spec.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the secret-scanning flow spec (%s): %v", path, err)
	}
	return string(raw)
}
