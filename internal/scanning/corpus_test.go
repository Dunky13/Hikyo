package scanning

import (
	"context"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/scanning/corpus"
)

// ruleFamily maps a compiled rule id to its ADR §3 minimum-coverage family.
func ruleFamily(id string) string {
	switch {
	case id == "aws-access-token":
		return "aws"
	case id == "gitlab-pat":
		return "gitlab"
	case id == "stripe-access-token":
		return "stripe"
	case id == "private-key":
		return "pem"
	case id == hikRuleID:
		return "hik"
	case len(id) >= 6 && id[:6] == "github":
		return "github"
	case len(id) >= 5 && id[:5] == "slack":
		return "slack"
	}
	return ""
}

// TestMinimumCoverageFamilies is SS1: every ADR §3 family is represented by at
// least one compiled rule.
func TestMinimumCoverageFamilies(t *testing.T) {
	want := []string{"aws", "github", "gitlab", "slack", "stripe", "pem", "hik"}
	rs := mustLoad(t)
	have := map[string]bool{}
	for _, id := range rs.RuleIDs() {
		if fam := ruleFamily(id); fam != "" {
			have[fam] = true
		}
	}
	for _, fam := range want {
		if !have[fam] {
			t.Errorf("minimum-coverage family %q has no compiled rule", fam)
		}
	}
}

// TestCorpusCoversEveryRule is SS1: the fixture corpus must carry a TP and an FP
// for every compiled rule, and the scanner must agree — TP matches, FP does not.
func TestCorpusCoversEveryRule(t *testing.T) {
	rs := mustLoad(t)
	fixtures, err := corpus.All()
	if err != nil {
		t.Fatalf("corpus.All: %v", err)
	}

	byID := map[string]corpus.RuleFixtures{}
	for _, f := range fixtures {
		byID[f.RuleID] = f
	}

	ctx := context.Background()
	for _, id := range rs.RuleIDs() {
		f, ok := byID[id]
		if !ok {
			t.Errorf("rule %q has no corpus fixtures", id)
			continue
		}
		if len(f.TP) == 0 {
			t.Errorf("rule %q has no true-positive fixture", id)
		}
		if len(f.FP) == 0 {
			t.Errorf("rule %q has no false-positive fixture", id)
		}
		for _, tp := range f.TP {
			got, err := rs.Scan(ctx, []byte(tp))
			if err != nil {
				t.Fatalf("scan TP for %q: %v", id, err)
			}
			if !containsRule(got, id) {
				t.Errorf("rule %q did not match its true-positive fixture %q (got %v)", id, tp, got)
			}
		}
		for _, fp := range f.FP {
			got, err := rs.Scan(ctx, []byte(fp))
			if err != nil {
				t.Fatalf("scan FP for %q: %v", id, err)
			}
			if containsRule(got, id) {
				t.Errorf("rule %q matched its false-positive fixture %q", id, fp)
			}
		}
	}
}

// TestHikTwoStage proves the procedural CRC stage: a valid artifact matches, and
// truncated / checksum-corrupted / trailing near-misses do not (ADR §3, SS1).
func TestHikTwoStage(t *testing.T) {
	rs := mustLoad(t)
	hik, err := corpus.Hik()
	if err != nil {
		t.Fatalf("corpus.Hik: %v", err)
	}
	ctx := context.Background()

	got, err := rs.Scan(ctx, []byte(hik.TP[0]))
	if err != nil {
		t.Fatalf("scan hik TP: %v", err)
	}
	if !containsRule(got, hikRuleID) {
		t.Fatalf("valid hik artifact not matched: %v", got)
	}

	for _, fp := range hik.FP {
		got, err := rs.Scan(ctx, []byte(fp))
		if err != nil {
			t.Fatalf("scan hik FP: %v", err)
		}
		if containsRule(got, hikRuleID) {
			t.Errorf("checksum-invalid hik candidate %q was matched", fp)
		}
	}
}

func BenchmarkScan(b *testing.B) {
	rs, err := Load()
	if err != nil {
		b.Fatalf("Load: %v", err)
	}
	const cap = 64 * 1024
	buf := make([]byte, 0, cap)
	for len(buf) < cap-len("AKIAIOSFODNN7EXAMPLE") {
		buf = append(buf, "the quick brown fox "...)
	}
	buf = append(buf[:cap-len("AKIAIOSFODNN7EXAMPLE")], "AKIAIOSFODNN7EXAMPLE"...)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rs.Scan(ctx, buf); err != nil {
			b.Fatal(err)
		}
	}
}
