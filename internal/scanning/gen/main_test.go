package main

import (
	"errors"
	"slices"
	"testing"
)

func TestProveKeywordCoverageAllBranches(t *testing.T) {
	coverage, specialFold, err := proveKeywordCoverage(
		`(?:foo|bar)_[A-Z0-9]+`,
		[]string{"foo_", "bar_"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if coverage != coverageComplete {
		t.Fatalf("coverage = %q; want %q", coverage, coverageComplete)
	}
	if len(specialFold) != 0 {
		t.Fatalf("specialFold = %q; want none", specialFold)
	}
}

func TestProveKeywordCoverageAWSA3TBranchIncomplete(t *testing.T) {
	coverage, specialFold, err := proveKeywordCoverage(
		`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`,
		[]string{"akia", "asia", "abia", "acca"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if coverage != coverageIncomplete {
		t.Fatalf("coverage = %q; want %q", coverage, coverageIncomplete)
	}
	if len(specialFold) != 0 {
		t.Fatalf("specialFold = %q; want none", specialFold)
	}
}

func TestProveKeywordCoverageAccountsForRE2SpecialFolds(t *testing.T) {
	coverage, specialFold, err := proveKeywordCoverage(
		`(?i)\b((sk|rk)_(test|live|prod)_[0-9a-z]{10,99})`,
		[]string{"sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if coverage != coverageFoldIncomplete {
		t.Fatalf("coverage = %q; want %q", coverage, coverageFoldIncomplete)
	}
	want := []string{"ſ", "K"}
	if !slices.Equal(specialFold, want) {
		t.Fatalf("specialFold = %q; want %q", specialFold, want)
	}
}

func TestCompileAllowlistedRejectsDuplicateVendorRuleIDs(t *testing.T) {
	raw := []map[string]any{
		{"id": "duplicate", "regex": "first", "keywords": []any{"first"}},
		{"id": "duplicate", "regex": "second", "keywords": []any{"second"}},
	}
	_, err := compileAllowlisted([]string{"duplicate"}, raw)
	if !errors.Is(err, errDuplicateVendorRuleID) {
		t.Fatalf("error %v does not wrap errDuplicateVendorRuleID", err)
	}
}
