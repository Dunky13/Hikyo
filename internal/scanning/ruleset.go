// Package scanning is the secret-scanning ruleset (ADR docs/adr/secret-scanning.md).
//
// The compiled ruleset is a pinned, allowlisted, fixtured snapshot of the
// gitleaks rules plus one Hikyo-owned two-stage rule for the hik_ family. The
// runtime here imports no hash/HMAC primitive: per-rule semantic digests and
// the snapshot version are computed at generation and embedded as constants
// (see internal/scanning/gen). A Finding carries a rule id only — no match
// text, offset, length or excerpt exists on any exported type (ADR §4), so the
// scanner cannot mint a new disclosure path.
package scanning

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
)

// maxCompiledRules is the ruleset ceiling (ADR §7). Enforced at generation and
// re-asserted at Load.
const maxCompiledRules = 64

// genRule is the generated, embedded form of one compiled rule. The generator
// (internal/scanning/gen) is the single writer of the generatedRules table.
type genRule struct {
	id          string
	regex       string
	keywords    []string
	coverage    keywordCoverage
	specialFold []string
	digest      string
}

type keywordCoverage string

const (
	keywordCoverageComplete       keywordCoverage = "complete"
	keywordCoverageFoldIncomplete keywordCoverage = "foldIncomplete"
	keywordCoverageIncomplete     keywordCoverage = "incomplete"
)

// compiledRule is the runtime form: a compiled RE2 regex and a lowercased
// keyword prefilter. hik marks the Hikyo-owned rule, whose regex match is only
// a candidate — matchHik adds the procedural CRC stage.
type compiledRule struct {
	id          string
	re          *regexp.Regexp
	keywords    []string // ASCII-lowercased; prefilter only, never verdict-changing
	coverage    keywordCoverage
	specialFold [][]byte // non-ASCII UTF-8 sequences in the keyword's RE2 fold classes
	hik         bool
}

// scanStart returns the earliest safe offset at which to start scanning the
// (already-lowercased) content. A rule with no keywords scans from the start.
//
// Complete rules always use the keyword window. Fold-incomplete rules do too
// unless content contains a non-ASCII rune from a relevant RE2 simple-fold
// class; those rare items scan in full. Incomplete rules always scan in full.
// For windowed literal-prefix token grammars the keyword starts at the match
// start (with at most a word boundary before it), so retaining 64 lead bytes
// also preserves boundary context at the cut.
func (c *compiledRule) scanStart(content, lowerContent []byte) (int, bool) {
	switch c.coverage {
	case keywordCoverageIncomplete:
		return 0, true
	case keywordCoverageFoldIncomplete:
		for _, special := range c.specialFold {
			if bytes.Contains(content, special) {
				return 0, true
			}
		}
	}
	if len(c.keywords) == 0 {
		return 0, true
	}
	earliest := -1
	for _, kw := range c.keywords {
		if i := bytes.Index(lowerContent, []byte(kw)); i >= 0 && (earliest < 0 || i < earliest) {
			earliest = i
		}
	}
	if earliest < 0 {
		return 0, false
	}
	const contextLead = 64
	if earliest <= contextLead {
		return 0, true
	}
	return earliest - contextLead, true
}

// Finding is the redacted result: a rule id and nothing else. No match text,
// offset, length or excerpt may ever be added — the type is the enforcement
// point for the non-disclosure invariant (ADR §4, SS4).
type Finding struct {
	RuleID string
}

// Ruleset is the validated, boot-compiled ruleset.
type Ruleset struct {
	rules    []*compiledRule
	digests  map[string]string
	manifest []string
	snapshot string
}

// Load validates the embedded compiled ruleset and returns it. Any
// inconsistency is an error; server boot refuses to start on it (fail fast,
// ADR §7). Load is the only constructor callers use.
func Load() (*Ruleset, error) {
	return load(generatedRules, generatedManifest, snapshotVersion)
}

// load is the internal seam Load builds on, taking the ruleset data explicitly
// so a corrupted-ruleset fixture can prove the validation rejects it.
func load(rules []genRule, manifest []string, snapshot string) (*Ruleset, error) {
	if snapshot == "" {
		return nil, fmt.Errorf("scanning: empty snapshot version")
	}
	if len(rules) > maxCompiledRules {
		return nil, fmt.Errorf("scanning: compiled rule count %d exceeds ceiling %d", len(rules), maxCompiledRules)
	}

	compiled := make([]*compiledRule, 0, len(rules))
	digests := make(map[string]string, len(rules))
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r.id == "" {
			return nil, fmt.Errorf("scanning: rule with empty id")
		}
		if seen[r.id] {
			return nil, fmt.Errorf("scanning: duplicate rule id %q", r.id)
		}
		if r.digest == "" {
			return nil, fmt.Errorf("scanning: rule %q has empty semantic digest", r.id)
		}
		switch r.coverage {
		case keywordCoverageComplete, keywordCoverageIncomplete:
			if len(r.specialFold) != 0 {
				return nil, fmt.Errorf("scanning: rule %q has special folds with %s keyword coverage", r.id, r.coverage)
			}
		case keywordCoverageFoldIncomplete:
			if len(r.specialFold) == 0 {
				return nil, fmt.Errorf("scanning: rule %q has fold-incomplete keyword coverage without special folds", r.id)
			}
		default:
			return nil, fmt.Errorf("scanning: rule %q has invalid keyword coverage %q", r.id, r.coverage)
		}
		re, err := regexp.Compile(r.regex)
		if err != nil {
			return nil, fmt.Errorf("scanning: rule %q regex does not compile: %w", r.id, err)
		}
		compiled = append(compiled, &compiledRule{
			id:          r.id,
			re:          re,
			keywords:    lowerAll(r.keywords),
			coverage:    r.coverage,
			specialFold: bytesAll(r.specialFold),
			hik:         r.id == hikRuleID,
		})
		digests[r.id] = r.digest
		seen[r.id] = true
	}

	// manifest ≡ the vendored (non-hik) compiled rules.
	manifestSet := make(map[string]bool, len(manifest))
	for _, id := range manifest {
		if !seen[id] {
			return nil, fmt.Errorf("scanning: manifest lists %q which is not compiled", id)
		}
		if id == hikRuleID {
			return nil, fmt.Errorf("scanning: manifest must not list the hik rule %q", id)
		}
		manifestSet[id] = true
	}
	for id := range seen {
		if id == hikRuleID {
			continue
		}
		if !manifestSet[id] {
			return nil, fmt.Errorf("scanning: compiled rule %q is missing from the manifest", id)
		}
	}

	return &Ruleset{
		rules:    compiled,
		digests:  digests,
		manifest: append([]string(nil), manifest...),
		snapshot: snapshot,
	}, nil
}

// Scan reports which rules match content. It returns one Finding per matched
// rule (no offsets, so duplicate hits carry no information). Keywords prefilter
// only. ctx cancellation/deadline is honoured between rules — the scan shares
// the enclosing operation's clock (ADR §7).
func (r *Ruleset) Scan(ctx context.Context, content []byte) ([]Finding, error) {
	lower := asciiFold(content)
	var findings []Finding
	for _, cr := range r.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start, ok := cr.scanStart(content, lower)
		if !ok {
			continue
		}
		window := content[start:]
		if cr.hik {
			if matchHik(cr.re, window) {
				findings = append(findings, Finding{RuleID: cr.id})
			}
			continue
		}
		if cr.re.Match(window) {
			findings = append(findings, Finding{RuleID: cr.id})
		}
	}
	return findings, nil
}

// SnapshotVersion is the stable identifier binding the gitleaks pin and the
// allowlist digest (ADR §4).
func (r *Ruleset) SnapshotVersion() string { return r.snapshot }

// SemanticDigest returns the generation-time digest of a rule, used to key
// dismissals (ADR §4). The second result is false for an unknown rule id.
func (r *Ruleset) SemanticDigest(ruleID string) (string, bool) {
	d, ok := r.digests[ruleID]
	return d, ok
}

// RuleIDs returns the compiled rule ids in table order.
func (r *Ruleset) RuleIDs() []string {
	ids := make([]string, len(r.rules))
	for i, cr := range r.rules {
		ids[i] = cr.id
	}
	return ids
}

func lowerAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(asciiFold([]byte(s)))
	}
	return out
}

func bytesAll(in []string) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, len(in))
	for i, s := range in {
		out[i] = []byte(s)
	}
	return out
}

// asciiFold lowercases ASCII letters byte-wise. Every other byte is preserved,
// so keyword offsets remain valid offsets into the original UTF-8 content.
func asciiFold(in []byte) []byte {
	out := append([]byte(nil), in...)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		}
	}
	return out
}
