// Package corpus is the true-positive / false-positive fixture corpus for the
// secret scanner (ADR §3, SS1). It is a plain importable table so both the
// scanning tests and cmd/bench-scan consume the same fixtures — the corpus test
// walks the compiled ruleset and fails if any rule lacks a TP or FP fixture,
// and the benchmark scans the same items.
//
// Every credential here is planted, syntactically valid for its rule, and
// NON-LIVE — constructed from filler characters, never a real secret.
package corpus

import (
	"fmt"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// RuleFixtures holds the fixtures for one rule id. TP entries must match the
// rule; FP near-misses must not.
type RuleFixtures struct {
	RuleID string
	TP     []string
	FP     []string
}

// HikRuleID is the Hikyo-owned rule id, mirrored from the generated ruleset.
// The scanning corpus test cross-checks every fixture id against the compiled
// ruleset, so a drift here fails loudly.
const HikRuleID = "hikyo-artifact"

func repeat(alnum string, n int) string { return strings.Repeat(alnum, n) }

// Static returns the deterministic vendored-rule fixtures.
func Static() []RuleFixtures {
	return []RuleFixtures{
		{
			RuleID: "aws-access-token",
			TP:     []string{"AKIAIOSFODNN7EXAMPLE", "ASIAABCDEFGHIJKLMNOP"},
			FP:     []string{"AKIA0000", "not-an-aws-key", "AKIALOWERcaseletters"},
		},
		{
			RuleID: "github-pat",
			TP:     []string{"ghp_" + repeat("A0b1C2d3E4", 3) + repeat("Z", 6)},
			FP:     []string{"ghp_tooshort", "gph_notthisprefix1234"},
		},
		{
			RuleID: "github-oauth",
			TP:     []string{"gho_" + repeat("A0b1C2d3E4", 3) + repeat("Z", 6)},
			FP:     []string{"gho_short", "oauth_placeholder"},
		},
		{
			RuleID: "github-app-token",
			TP: []string{
				"ghs_" + repeat("A0b1C2d3E4", 3) + repeat("Z", 6),
				"ghu_" + repeat("A0b1C2d3E4", 3) + repeat("Z", 6),
			},
			FP: []string{"ghs_short", "ghx_" + repeat("A", 36)},
		},
		{
			RuleID: "github-fine-grained-pat",
			TP:     []string{"github_pat_" + repeat("A0b1C2d3E4", 8) + "ab"},
			FP:     []string{"github_pat_short", "github_pat_" + repeat("A", 40)},
		},
		{
			RuleID: "gitlab-pat",
			TP:     []string{"glpat-" + repeat("A0b1C2d3E4", 2)},
			FP:     []string{"glpat-short", "glpat-tooshort123"},
		},
		{
			RuleID: "slack-bot-token",
			TP:     []string{"xoxb-1234567890-0987654321-" + repeat("aB3", 6)},
			FP:     []string{"xoxb-short", "xoxb-onlyonefield-here"},
		},
		{
			RuleID: "slack-user-token",
			TP:     []string{"xoxp-1234567890-1234567890-1234567890-" + repeat("aB3xY", 6)},
			FP:     []string{"xoxp-short", "xoxp-1234567890-tooshort"},
		},
		{
			RuleID: "stripe-access-token",
			TP:     []string{"sk_live_" + repeat("0a1b2c", 3), "rk_test_" + repeat("9z8y7x", 3)},
			FP:     []string{"sk_live_x", "sk_placeholder_notreal"},
		},
		{
			RuleID: "private-key",
			TP: []string{
				"-----BEGIN RSA PRIVATE KEY-----\n" +
					repeat("MIIBOgIBAAJBAKp", 4) + "\n" +
					"-----END RSA PRIVATE KEY-----",
			},
			FP: []string{
				"-----BEGIN CERTIFICATE-----\n" + repeat("MIIBcert", 3) + "\n-----END CERTIFICATE-----",
				"a private key belongs in a secret, not config",
			},
		},
	}
}

// Hik mints the Hikyo-owned rule's fixtures at runtime: one valid artifact as a
// TP, and truncated / checksum-corrupted / trailing-character near-misses that
// the procedural CRC stage must reject (ADR §3, SS1).
func Hik() (RuleFixtures, error) {
	value, _, err := crypto.NewArtifact(crypto.ArtifactCLISession)
	if err != nil {
		return RuleFixtures{}, fmt.Errorf("corpus: mint hik artifact: %w", err)
	}
	if len(value) < 4 {
		return RuleFixtures{}, fmt.Errorf("corpus: minted hik artifact too short")
	}
	truncated := value[:len(value)-2]
	corrupted := flipLast(value)
	trailing := value + "0" // greedily absorbed, then fails the exact-length body decode
	return RuleFixtures{
		RuleID: HikRuleID,
		TP:     []string{value},
		FP:     []string{truncated, corrupted, trailing},
	}, nil
}

// flipLast changes the final checksum character to a different base62
// character, corrupting the checksum without changing the length or grammar.
func flipLast(value string) string {
	last := value[len(value)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return value[:len(value)-1] + string(repl)
}

// All returns the static fixtures plus the minted hik fixtures.
func All() ([]RuleFixtures, error) {
	hik, err := Hik()
	if err != nil {
		return nil, err
	}
	return append(Static(), hik), nil
}
