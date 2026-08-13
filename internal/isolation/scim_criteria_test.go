package isolation

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The SCIM acceptance-criteria matrix (#73, SC1–SC4).
//
// The ADR's fixture discipline is normative and self-enforcing: "each fixture
// names the §-clause it proves; a clause without a fixture is a CI failure of
// the criteria matrix itself — no catch-all 'full conversation' rows." This
// file is that CI failure.
//
// Two properties are checked, and they fail in OPPOSITE directions on purpose:
//
//  1. every clause in the closed list below has at least one fixture, so a
//     clause cannot be quietly unimplemented;
//  2. every fixture NAMED here exists in this package's source, so the matrix
//     cannot be satisfied by naming a test that was renamed or deleted.
//
// The registry is STATIC rather than accumulated at run time. A run-time
// registry would make the completeness check depend on test ORDER and would
// pass vacuously under `go test -run` filters, which is exactly when somebody
// is most likely to be looking at it.

// scimClause is one acceptance-criteria clause with the fixtures proving it.
type scimClause struct {
	// Text is the clause as the ADR words it, so a reader comparing this table
	// to the ADR is comparing sentences rather than guessing at abbreviations.
	Text string
	// Fixtures are Go test or helper function names in this package.
	Fixtures []string
	// Blocked names the ticket a clause cannot be proved without. A clause with
	// a Blocked reason is NOT COVERED, and the matrix says so rather than
	// pointing at a tripwire that asserts the behaviour is absent: a passing
	// test whose own subject is "this does not work yet" is not evidence the
	// clause holds, and letting it satisfy the matrix is how a completeness
	// check turns into a completeness claim.
	Blocked string
}

// scimCriteria is the closed matrix. IDs are stable: SC<row>.<letter>, assigned
// in the order the ADR's acceptance table words them. An ID is never reused for
// a different clause — a renumbered matrix would silently re-point a fixture at
// something it does not prove.
var scimCriteria = map[string]scimClause{
	// --- SC1: the wire surface, the protocol contract, the credential --------
	"SC1.a": {Text: "discovery trio matches implemented truth",
		Fixtures: []string{"TestDiscoveryIsTheClosedTruth", "runSCIMDemo", "assertDiscoveryTrio", "runSCIMOktaSequence", "runSCIMEntraSequence", "runSCIMDeclaredExtensions"}},
	"SC1.b": {Text: "user + group CRUD over the wire",
		Fixtures: []string{"runSCIMDemo", "runSCIMUserLifecycle", "runSCIMOktaSequence", "runSCIMEntraSequence"}},
	"SC1.c": {Text: "all four filters including `displayName eq` group discovery",
		Fixtures: []string{"TestFilterGrammarIsClosed", "runSCIMDemo", "runSCIMGroupDisplayNameIsNotUnique", "runSCIMOktaSequence", "runSCIMEntraSequence"}},
	"SC1.d": {Text: "RFC ListResponse fields, 1-based paging, out-of-range page",
		Fixtures: []string{"TestPagingIsOneBasedAndBounded", "runSCIMWirePaging", "runSCIMOktaSequence"}},
	"SC1.e": {Text: "enumerated PATCH shapes incl. Entra stringified booleans, applied IN ORDER",
		Fixtures: []string{"TestPatchMatrixCells", "TestDecodeUserAcceptsStringifiedActive", "runSCIMDemo", "runSCIMPatchMatrixOverTheWire", "runSCIMEntraSequence"}},
	"SC1.f": {Text: "whole-PATCH atomicity on one invalid op",
		Fixtures: []string{"TestPatchIsAtomicOnOneInvalidOperation", "runSCIMPatchAtomicityOverTheWire", "runSCIMPatchMatrixOverTheWire"}},
	"SC1.g": {Text: "PUT clears omitted mutables, subject source exempt, `groups` ignored on input; explicit removal is not omission, and a request that changes nothing changes nothing",
		Fixtures: []string{"runSCIMPutReplacementSemantics", "runSCIMDemo", "runSCIMOktaSequence", "runSCIMPresenceAndNoOp"}},
	"SC1.h": {Text: "refusals by name: Bulk, /Me, sorting, .search",
		Fixtures: []string{"TestNamedRefusalsCarryTheirExactCodes", "runSCIMDemo", "runSCIMPatchMatrixOverTheWire", "assertDiscoveryTrio"}},
	"SC1.i": {Text: "refusals by name: unknown filter, password, nested-group member, unknown member reference",
		Fixtures: []string{"TestNamedRefusalsCarryTheirExactCodes", "runSCIMDemo", "runSCIMPatchMatrixOverTheWire"}},
	"SC1.j": {Text: "subject change refused (write-once), including by explicit removal",
		Fixtures: []string{"runSCIMUserLifecycle", "runSCIMPutReplacementSemantics", "runSCIMDemo", "runSCIMPresenceAndNoOp"}},
	"SC1.k": {Text: "`userName` refused as subject source at config time; the declared extension set is closed and discovery derives from it",
		Fixtures: []string{"runSCIMBindingLifecycle", "runSCIMDeclaredExtensions"}},
	"SC1.l": {Text: "credential presented against the wrong binding path",
		Fixtures: []string{"runSCIMBindingLifecycle", "runSCIMLifecycle", "runSCIMWireMismatchOverDiscovery"}},
	"SC1.m": {Text: "binding uniqueness race: concurrent create resolves to one row, named conflict",
		Fixtures: []string{"runSCIMBindingUniquenessRace"}},
	"SC1.n": {Text: "credential lifecycle: mint under manage-members(org) ∧ reauth (single-use evidence, consumed in the mint transaction), display-once, overlap rotation",
		Fixtures: []string{"runSCIMCredentialLifecycle", "runSCIMDemo"}},
	"SC1.o": {Text: "credential revocation bites at next request; lifetime ceiling clamp; allow_indefinite default-off",
		Fixtures: []string{"runSCIMCredentialLifecycle"}},
	"SC1.p": {Text: "restored verifier dead by presentation",
		Fixtures: []string{"runSCIMRestoreDrill"}},
	"SC1.q": {Text: "[CI] `scim` credential type rejected on every non-SCIM operation",
		Fixtures: []string{"runSCIMCredentialRejected"}},
	"SC1.r": {Text: "[CI] `scim-provision` refused to every other principal class and to human grants",
		Fixtures: []string{"TestSCIMProvisionIsUngrantableThroughTheAPI", "runMachineAllowlist"}},
	"SC1.s": {Text: "[CI] scanner fixture covers `hik_<v>_scim_`",
		Fixtures: []string{"TestRedaction", "runSCIMCredentialRejected"}},
	"SC1.t": {Text: "[CI] every SCIM operation carries formula `scim-provision(org)`",
		Fixtures: []string{"TestSCIMOperationsCarryTheirFormula"}},

	// --- SC2: provisioning lifecycle -----------------------------------------
	"SC2.a": {Text: "Okta-shaped OIDC provision-then-login; subject = sub, byte-exact; case-variant is a distinct identity",
		Fixtures: []string{"runSCIMProvisionThenLoginOIDC"}},
	"SC2.b": {Text: "Entra-shaped SAML provision-then-login; NameID profile, encoder equality, emailAddress carve",
		Fixtures: []string{"runSCIMProvisionThenLoginSAML", "runSCIMProvisionThenLoginSAMLEmailCarve"}},
	"SC2.c": {Text: "create yields an account with zero grants, no session/assurance/credential, asserted by attempted authenticated ops",
		Fixtures: []string{"runSCIMProvisionThenLoginOIDC", "runSCIMZeroAuthorityOnCreate"}},
	"SC2.d": {Text: "email/profile attributes never match or link",
		Fixtures: []string{"runSCIMEmailNeverLinks"}},
	"SC2.e": {Text: "attach cases with response byte-shape and query-path equality vs fresh create",
		Fixtures: []string{"runSCIMUserLifecycle", "runSCIMCreateIsOneQueryPath", "runSCIMWireAttachIsIndistinguishable"}},
	"SC2.f": {Text: "concurrent duplicate creates yield one account",
		Fixtures: []string{"runSCIMConcurrentDuplicateCreate", "scimBindingInOrg"}},
	"SC2.g": {Text: "every §5.4 transition row exercised, with postconditions",
		Fixtures: []string{"runSCIMUserLifecycle", "runSCIMTransitionTable"}},
	"SC2.h": {Text: "deprovision: origins released, generation advance UNCONDITIONAL (zero-grant-delta)",
		Fixtures: []string{"runSCIMUserLifecycle"}},
	"SC2.i": {Text: "deprovision: manual grants survive + attention flag + honest-remainder wording",
		Fixtures: []string{"runSCIMManualRemainsMeansManual", "runSCIMManualRemainderWording"}},
	"SC2.j": {Text: "provider disable: the whole wire surface fails closed, state preserved, attention state",
		Fixtures: []string{"runSCIMProviderFailClosed"}},

	// --- SC3: origins and reconciliation -------------------------------------
	"SC3.a": {Text: "sync expansion carries scim(binding, mapping_row, group) per capability row",
		Fixtures: []string{"runSCIMOriginTupleIsExact"}},
	"SC3.b": {Text: "overlap: hand + SCIM = one row two origins; each release direction leaves the other",
		Fixtures: []string{"runSCIMMappingReconciliation"}},
	"SC3.c": {Text: "multi-group union",
		Fixtures: []string{"runSCIMMultiGroupUnion"}},
	"SC3.d": {Text: "group delete releases members' origins and flips referencing mapping rows inert",
		Fixtures: []string{"runSCIMMappingReconciliation", "runSCIMMultiGroupUnion"}},
	"SC3.e": {Text: "mapping create/widen grants to an ALREADY-POPULATED group in the authoring transaction",
		Fixtures: []string{"runSCIMMappingReconciliation", "runSCIMMappingWidenAndNarrow"}},
	"SC3.f": {Text: "mapping narrow/delete reconciles in the authoring transaction, no sync",
		Fixtures: []string{"runSCIMMappingWidenAndNarrow"}},
	"SC3.g": {Text: "hand-revoke of a SCIM-only grant refused naming both levers",
		Fixtures: []string{"runSCIMMappingReconciliation"}},
	"SC3.h": {Text: "dual-origin hand-revoke removes the manual origin only",
		Fixtures: []string{"runSCIMMappingReconciliation"}},
	"SC3.i": {Text: "lockout family across EVERY release path, with the audit pair and the cure",
		Fixtures: []string{"runSCIMLockoutAcrossEveryReleasePath"}},
	"SC3.j": {Text: "binding delete state machine order asserted phase by phase",
		Fixtures: []string{"runSCIMTeardownPhaseOrder"}},
	"SC3.k": {Text: "two-binding race on one shared grant row: no lost origin, no premature revocation",
		Fixtures: []string{"runSCIMTwoBindingRace"}},
	"SC3.l": {Text: "[UI] origin chips per capability line; inspection and per-line revocation preserved",
		Fixtures: []string{"runSCIMDemo", "runMembershipListing"}},
	"SC3.m": {Text: "[UI] blast-consequence language on org-scope / reveal-expanding rows, narrow-default picker",
		Fixtures: []string{"runSCIMMappingReconciliation", "runSCIMDemo"}},
	"SC3.n": {Text: "[CI] authorize() provably never reads origins",
		Fixtures: []string{"TestAuthorizeNeverReadsOrigins"}},

	// --- SC4: operational posture, audit, restore -----------------------------
	"SC4.a": {Text: "staleness raises and clears attention",
		Fixtures: []string{"runSCIMStalenessThreshold"}},
	"SC4.b": {Text: "per-binding serialization under concurrent pushes",
		Fixtures: []string{"runSCIMPerBindingSerialization", "runSCIMPerBindingSerializationOrder"}},
	"SC4.c": {Text: "admission: bounded page/body refusals by name; uniform unknown-vs-revoked",
		Fixtures: []string{"runSCIMWireAdmission", "runSCIMWireAdmissionOverHTTP"}},
	"SC4.d": {Text: "grant-addition session invalidation fired by a sync",
		Fixtures: []string{"runSCIMSyncInvalidatesSessions"}},
	"SC4.e": {Text: "restore drill: dead credential; post-backup-deprovisioned user never authorized after restore",
		Fixtures: []string{"runSCIMRestoreDrill"}},
	"SC4.f": {Text: "restore drill: re-mint + re-assertion rebuilds exactly current IdP truth",
		Fixtures: []string{"runSCIMRestoreDrill"}},
	"SC4.g": {Text: "restore drill: restored identity links stay inert; re-assertion does not re-bless one",
		Fixtures: []string{"runSCIMRestoreDrill"}},
	"SC4.h": {Text: "restore drill: `scim` origins dropped at reconciliation commit",
		// NOT COVERED. The rule needs the operator's quarantine/commit flow to
		// hook into, and #55 punted that to #76, so there is no seam to drop a
		// restored origin at. TestSCIMRestoreOriginDropIsBlockedOn76 is a
		// TRIPWIRE that fails the day the flow appears; it asserts the absence,
		// which is the opposite of proving the clause.
		Fixtures: []string{"TestSCIMRestoreOriginDropIsBlockedOn76"},
		Blocked:  "#76 (restore quarantine/commit flow)"},
	"SC4.i": {Text: "every attention state entered AND cleared with its audit pair",
		Fixtures: []string{"runSCIMAttentionStatePairs", "runOneLockoutPath"}},
	"SC4.j": {Text: "[CI] registry completeness over every SCIM operation incl. directory_read on reads",
		Fixtures: []string{"TestInvariant06OperationRegistryCompleteness", "runSCIMLifecycle", "runSCIMDiscoveryIsAnnotatedNotSilent"}},
	"SC4.k": {Text: "[CI] payload-schema validation fixture per registry entry",
		Fixtures: []string{"TestSCIMPayloadSchemasAreValidatedOnWrite", "TestSCIMPayloadBoundsAreEnforcedAtWrite"}},
	"SC4.l": {Text: "[CI] 3-user push = 3 provisioned events + per-grant events, no aggregation",
		Fixtures: []string{"runSCIMPushEmitsPerEvent"}},
	"SC4.m": {Text: "[CI] `ew_` redaction on IdP-supplied strings",
		Fixtures: []string{"runSCIMRedactsIdPStrings"}},
	"SC4.n": {Text: "[CI] zero-egress invariant unchanged",
		Fixtures: []string{"TestSCIMMakesNoOutboundCalls"}},
	"SC4.o": {Text: "[CI] the discovery probe class is annotated audited-none-equivalent by explicit registry annotation, not silence",
		Fixtures: []string{"runSCIMDiscoveryIsAnnotatedNotSilent", "TestInvariantAuditCompleteness"}},
}

// TestSCIMCriteriaMatrixIsComplete is the ADR's own discipline as a build
// failure. It fails in both directions: a clause with no fixture, and a fixture
// name that does not exist in this package.
func TestSCIMCriteriaMatrixIsComplete(t *testing.T) {
	source := packageSource(t)

	var missing []string
	blocked := 0
	for id, clause := range scimCriteria {
		if clause.Blocked != "" {
			// Declared not covered. It still must name whatever tripwire or
			// partial proof exists, and those names are checked below like any
			// other — but it is counted apart, and reported, so "the matrix is
			// complete" never silently means "except for these".
			blocked++
			t.Logf("acceptance clause %s is NOT COVERED, blocked on %s: %s", id, clause.Blocked, clause.Text)
		}
		if len(clause.Fixtures) == 0 {
			missing = append(missing, id+" ("+clause.Text+")")
			continue
		}
		for _, fixture := range clause.Fixtures {
			// `func <name>(` anywhere in the package (or, for fixtures that live
			// in a sibling package like scimproto's unit tests, a comment
			// naming them is not enough — those are listed by their own package
			// and checked there).
			if !strings.Contains(source, "func "+fixture+"(") && !crossPackageFixtures[fixture] {
				t.Errorf("%s names fixture %q, which no test function in this package defines — "+
					"a renamed or deleted fixture must not keep satisfying the matrix", id, fixture)
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("acceptance clause %s has no fixture; the ADR makes that a CI failure of the matrix itself", m)
	}

	// A floor on the matrix's own size. The ADR states SC1-SC4 as four prose
	// rows; this matrix is their clause-by-clause decomposition, and deleting
	// a row is how a completeness check gets made to pass without doing the
	// work. Growing it is fine and means a clause was found; shrinking it is
	// not.
	// The blocked set is pinned too: a clause may be DECLARED not covered, but
	// the number of them may not grow quietly, and a clause that becomes
	// provable must lose its Blocked marker rather than keep it as cover.
	const blockedClauses = 1
	if blocked != blockedClauses {
		t.Errorf("%d clauses are declared not-covered, pinned at %d — a clause was blocked or unblocked "+
			"without updating the pin", blocked, blockedClauses)
	}

	const clauses = 59
	if len(scimCriteria) < clauses {
		t.Fatalf("the criteria matrix has %d clauses, down from %d — a clause of SC1-SC4 was dropped "+
			"rather than proved", len(scimCriteria), clauses)
	}
}

// crossPackageFixtures are fixtures that live outside internal/isolation. They
// are named here so the matrix can point at them, and they are checked by their
// own package's tests; listing them keeps the matrix honest about where the
// proof lives rather than pretending it is local.
var crossPackageFixtures = map[string]bool{
	// internal/scimproto
	"TestDiscoveryIsTheClosedTruth":          true,
	"TestFilterGrammarIsClosed":              true,
	"TestPagingIsOneBasedAndBounded":         true,
	"TestPatchMatrixCells":                   true,
	"TestPatchIsAtomicOnOneInvalidOperation": true,
	"TestNamedRefusalsCarryTheirExactCodes":  true,
	"TestDecodeUserAcceptsStringifiedActive": true,
	// internal/audit
	"TestRedaction": true,
}

// packageSource concatenates every Go file in this package, so the fixture
// existence check reads what is actually compiled rather than a curated list.
func packageSource(t *testing.T) string { return readGoFiles(t, ".") }

// readGoFiles concatenates every Go file in one package directory.
func readGoFiles(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
	}
	return b.String()
}
