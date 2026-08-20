package scanning

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/scanning/corpus"
)

func mustLoad(t *testing.T) *Ruleset {
	t.Helper()
	rs, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return rs
}

func TestLoadSucceeds(t *testing.T) {
	rs := mustLoad(t)
	if rs.SnapshotVersion() == "" {
		t.Fatal("empty snapshot version")
	}
	if !strings.HasPrefix(rs.SnapshotVersion(), "gitleaks/v8.19.0+") {
		t.Fatalf("snapshot version %q missing pin prefix", rs.SnapshotVersion())
	}
}

func TestRuleCountUnderCeiling(t *testing.T) {
	if got := len(generatedRules); got > maxCompiledRules {
		t.Fatalf("compiled rule count %d exceeds ceiling %d", got, maxCompiledRules)
	}
}

// TestManifestEqualsAllowlist proves manifest ≡ allowlist (ADR §3): the
// generated manifest lists exactly the committed allowlist rule ids.
func TestManifestEqualsAllowlist(t *testing.T) {
	allow := readAllowlistFile(t)
	got := append([]string(nil), generatedManifest...)
	sort.Strings(allow)
	sort.Strings(got)
	if strings.Join(allow, ",") != strings.Join(got, ",") {
		t.Fatalf("manifest != allowlist\n  allowlist: %v\n  manifest:  %v", allow, got)
	}
}

func readAllowlistFile(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("rules/allowlist.txt")
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// TestLoadRejectsCorruptRuleset is the boot-refusal fixture (SS1): every kind of
// inconsistency in the compiled ruleset must fail Load, so a corrupted ruleset
// refuses to start rather than silently scanning with less than it claims.
func TestLoadRejectsCorruptRuleset(t *testing.T) {
	digest := "0000000000000000000000000000000000000000000000000000000000000000"
	good := genRule{id: "aws-access-token", regex: "AKIA[A-Z0-9]{16}", coverage: keywordCoverageComplete, digest: digest}

	cases := []struct {
		name     string
		rules    []genRule
		manifest []string
		snapshot string
	}{
		{"empty snapshot", []genRule{good}, []string{"aws-access-token"}, ""},
		{"uncompilable regex", []genRule{{id: "x", regex: "(", coverage: keywordCoverageComplete, digest: digest}}, []string{"x"}, "s"},
		{"empty digest", []genRule{{id: "x", regex: "a", coverage: keywordCoverageComplete, digest: ""}}, []string{"x"}, "s"},
		{"empty id", []genRule{{id: "", regex: "a", coverage: keywordCoverageComplete, digest: digest}}, nil, "s"},
		{"duplicate id", []genRule{good, good}, []string{"aws-access-token"}, "s"},
		{"manifest names uncompiled rule", []genRule{good}, []string{"ghost"}, "s"},
		{"compiled rule absent from manifest", []genRule{good}, nil, "s"},
		{"manifest lists the hik rule", []genRule{{id: hikRuleID, regex: "a", coverage: keywordCoverageComplete, digest: digest}}, []string{hikRuleID}, "s"},
		{"over ceiling", overCeiling(digest), nil, "s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := load(tc.rules, tc.manifest, tc.snapshot); err == nil {
				t.Fatalf("expected load to reject %s", tc.name)
			}
		})
	}
}

func overCeiling(digest string) []genRule {
	rules := make([]genRule, maxCompiledRules+1)
	for i := range rules {
		rules[i] = genRule{id: string(rune('a'+i%26)) + string(rune('0'+i/26)), regex: "a", coverage: keywordCoverageComplete, digest: digest}
	}
	return rules
}

// TestOffAllowlistRuleNotCompiled is part of SS1: a vendored rule that is not on
// the allowlist is proven not compiled in. github-refresh-token exists in the
// snapshot but is deliberately absent from the allowlist.
func TestOffAllowlistRuleNotCompiled(t *testing.T) {
	rs := mustLoad(t)
	for _, id := range rs.RuleIDs() {
		if id == "github-refresh-token" {
			t.Fatal("off-allowlist rule github-refresh-token was compiled in")
		}
	}
	if _, ok := rs.SemanticDigest("github-refresh-token"); ok {
		t.Fatal("off-allowlist rule has a digest")
	}
}

func TestSemanticDigest(t *testing.T) {
	rs := mustLoad(t)
	d, ok := rs.SemanticDigest("github-pat")
	if !ok || len(d) != 64 {
		t.Fatalf("github-pat digest = %q ok=%v; want 64 hex chars", d, ok)
	}
	if _, ok := rs.SemanticDigest("no-such-rule"); ok {
		t.Fatal("expected unknown rule digest lookup to fail")
	}
}

// TestScanEmptyKeywordRuleRunsRegex proves the seam contract that a rule with no
// keywords still runs its regex (prefilter is optimisation only).
func TestScanEmptyKeywordRuleRunsRegex(t *testing.T) {
	cr := &compiledRule{id: "kwless", re: regexp.MustCompile("SECRETVALUE"), keywords: nil, coverage: keywordCoverageIncomplete}
	if start, ok := cr.scanStart([]byte("nothing here"), []byte("nothing here")); !ok || start != 0 {
		t.Fatalf("keyword-less rule scanStart = (%d, %v); want (0, true)", start, ok)
	}
	rs := &Ruleset{rules: []*compiledRule{cr}}
	got, err := rs.Scan(context.Background(), []byte("a SECRETVALUE b"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "kwless" {
		t.Fatalf("Scan = %v; want one kwless finding", got)
	}
}

const plantedStripeCredential = "sk_live_0a1b2c0a1b2c"

func TestScanFindsStripeCredentialInMiddleOfSizeCap(t *testing.T) {
	content := bytes.Repeat([]byte(" "), 64*1024)
	copy(content[len(content)/2:], plantedStripeCredential)
	assertScanFindsRule(t, content, "stripe-access-token")
}

func TestScanFindsStripeCredentialAtOffsetZero(t *testing.T) {
	content := bytes.Repeat([]byte(" "), 64*1024)
	copy(content, plantedStripeCredential)
	assertScanFindsRule(t, content, "stripe-access-token")
}

func TestScanFindsStripeCredentialWithKeywordInFirst64Bytes(t *testing.T) {
	content := bytes.Repeat([]byte(" "), 64*1024)
	copy(content[32:], plantedStripeCredential)
	assertScanFindsRule(t, content, "stripe-access-token")
}

func TestScanFindsLaterStripeCredentialAfterFalseKeyword(t *testing.T) {
	content := bytes.Repeat([]byte(" "), 64*1024)
	copy(content[128:], "sk_test_junk")
	copy(content[48*1024:], plantedStripeCredential)
	assertScanFindsRule(t, content, "stripe-access-token")
}

func TestScanFindsHikCredentialInMiddleOfSizeCap(t *testing.T) {
	fixture, err := corpus.Hik()
	if err != nil {
		t.Fatalf("mint hik fixture: %v", err)
	}
	content := bytes.Repeat([]byte(" "), 64*1024)
	copy(content[len(content)/2:], fixture.TP[0])
	assertScanFindsRule(t, content, corpus.HikRuleID)
}

func assertScanFindsRule(t *testing.T, content []byte, ruleID string) {
	t.Helper()
	got, err := mustLoad(t).Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !containsRule(got, ruleID) {
		t.Fatalf("rule %q not found: %v", ruleID, got)
	}
}

func TestScanHonoursCancelledContext(t *testing.T) {
	rs := mustLoad(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rs.Scan(ctx, []byte("AKIAIOSFODNN7EXAMPLE")); err == nil {
		t.Fatal("Scan must return ctx error when cancelled")
	}
}

// TestScanAtSizeCap exercises Scan at the 64 KiB per-item budget (ADR §7).
func TestScanAtSizeCap(t *testing.T) {
	rs := mustLoad(t)
	const cap = 64 * 1024
	cred := "AKIAIOSFODNN7EXAMPLE"
	buf := bytes.Repeat([]byte("the quick brown fox "), cap/20)
	content := append(buf[:cap-len(cred)], []byte(cred)...)
	if len(content) != cap {
		t.Fatalf("content len %d; want %d", len(content), cap)
	}
	got, err := rs.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !containsRule(got, "aws-access-token") {
		t.Fatalf("credential at cap not found: %v", got)
	}
}

func containsRule(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
