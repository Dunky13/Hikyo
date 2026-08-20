package scanning

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestUnprovenKeywordsScanFullContent(t *testing.T) {
	const id = "aws-access-token"
	rs, err := load(
		[]genRule{{
			id:       id,
			regex:    `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`,
			keywords: []string{"akia", "asia", "abia", "acca"},
			coverage: keywordCoverageIncomplete,
			digest:   "test",
		}},
		[]string{id},
		"test",
	)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := rs.Scan(context.Background(), []byte("prefix A3TQ1234567890ABCDEF suffix"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != id {
		t.Fatalf("findings = %#v; want one %q finding", findings, id)
	}
}

func TestASCIIFoldPreservesUnicodePrefixOffsets(t *testing.T) {
	const id = "unicode-window"
	rs, err := load(
		[]genRule{{
			id:       id,
			regex:    `AKIA[A-Z0-9]{16}`,
			keywords: []string{"akia"},
			coverage: keywordCoverageComplete,
			digest:   "test",
		}},
		[]string{id},
		"test",
	)
	if err != nil {
		t.Fatal(err)
	}

	var expanding rune
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		lower := unicode.ToLower(r)
		if lower != r && utf8.RuneLen(lower) > utf8.RuneLen(r) {
			expanding = r
			break
		}
	}
	if expanding == 0 {
		t.Fatal("Unicode tables contain no uppercase rune with a longer UTF-8 lowercase form")
	}
	prefix := strings.Repeat(string([]rune{'\u0130', expanding, expanding, expanding}), 40)
	credential := "AKIA1234567890ABCDEF"
	content := []byte(prefix + credential)
	oldFold := bytes.ToLower(content)
	oldStart := bytes.Index(oldFold, []byte("akia")) - 64
	if len(oldFold) <= len(content) || oldStart <= len(prefix) {
		t.Fatalf("fixture U+%04X->U+%04X does not reproduce the old offset bug: folded=%d original=%d oldStart=%d credentialStart=%d",
			expanding, unicode.ToLower(expanding), len(oldFold), len(content), oldStart, len(prefix))
	}
	if got := len(asciiFold(content)); got != len(content) {
		t.Fatalf("ASCII fold changed byte length: got %d, want %d", got, len(content))
	}
	findings, err := rs.Scan(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != id {
		t.Fatalf("findings = %#v; want one %q finding", findings, id)
	}
}

func TestGeneratedKeywordCoverageStates(t *testing.T) {
	want := map[string]keywordCoverage{
		"aws-access-token":        keywordCoverageIncomplete,
		"github-app-token":        keywordCoverageComplete,
		"github-fine-grained-pat": keywordCoverageComplete,
		"github-oauth":            keywordCoverageComplete,
		"github-pat":              keywordCoverageComplete,
		"gitlab-pat":              keywordCoverageComplete,
		"hikyo-artifact":          keywordCoverageComplete,
		"private-key":             keywordCoverageComplete,
		"slack-bot-token":         keywordCoverageComplete,
		"slack-user-token":        keywordCoverageComplete,
		"stripe-access-token":     keywordCoverageFoldIncomplete,
	}
	if len(generatedRules) != len(want) {
		t.Fatalf("generated rule count = %d; want %d", len(generatedRules), len(want))
	}
	for _, rule := range generatedRules {
		if got := rule.coverage; got != want[rule.id] {
			t.Errorf("%s coverage = %s; want %s", rule.id, got, want[rule.id])
		}
		if rule.id == "stripe-access-token" && !slices.Equal(rule.specialFold, []string{"ſ", "K"}) {
			t.Errorf("stripe specialFold = %q; want [ſ K]", rule.specialFold)
		}
	}
}

func TestOrdinaryStripeContentUsesKeywordWindow(t *testing.T) {
	rs := mustLoad(t)
	var stripe *compiledRule
	for _, rule := range rs.rules {
		if rule.id == "stripe-access-token" {
			stripe = rule
			break
		}
	}
	if stripe == nil {
		t.Fatal("stripe-access-token rule not loaded")
	}
	if stripe.coverage != keywordCoverageFoldIncomplete {
		t.Fatalf("coverage = %s; want %s", stripe.coverage, keywordCoverageFoldIncomplete)
	}

	content := []byte(strings.Repeat("x", 128) + "sk_test_1234567890")
	start, ok := stripe.scanStart(content, asciiFold(content))
	if !ok || start == 0 {
		t.Fatalf("scanStart = (%d, %v); want a non-zero keyword window", start, ok)
	}
}

func TestStripeSpecialFoldCredentialsAreDetected(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	for name, credential := range map[string]string{
		"kelvin sign": "sK_test_1234567890",
		"long s":      "sk_teſt_1234567890",
	} {
		t.Run(name, func(t *testing.T) {
			content := []byte(strings.Repeat("ordinary prose without a scanner keyword. ", 8) + credential)
			findings, scanErr := rs.Scan(context.Background(), content)
			if scanErr != nil {
				t.Fatal(scanErr)
			}
			if !hasRuleID(findings, "stripe-access-token") {
				t.Fatalf("findings = %#v; want stripe-access-token", findings)
			}
		})
	}
}

func hasRuleID(findings []Finding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}
