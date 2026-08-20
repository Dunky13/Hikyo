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
	id       string
	regex    string
	keywords []string
	digest   string
}

// compiledRule is the runtime form: a compiled RE2 regex and a lowercased
// keyword prefilter. hik marks the Hikyo-owned rule, whose regex match is only
// a candidate — matchHik adds the procedural CRC stage.
type compiledRule struct {
	id       string
	re       *regexp.Regexp
	keywords []string // lowercased; prefilter only, never verdict-changing
	hik      bool
}

// scanStart returns the earliest safe offset at which to start scanning the
// (already-lowercased) content. A rule with no keywords scans from the start.
//
// The existing prefilter already assumes every detectable match contains a
// keyword occurrence, matching upstream gitleaks' keyword semantics. For every
// allowlisted rule, that occurrence starts at the match start (the regexes are
// literal-prefix token grammars, with at most a word boundary before it).
// Therefore no match can begin more than 64 bytes before the earliest keyword;
// retaining that lead also preserves the context byte used by a word boundary
// at the cut. The suffix can neither miss a match nor mint a spurious boundary,
// so keywords remain an optimisation and do not change committed verdicts.
func (c *compiledRule) scanStart(lowerContent []byte) (int, bool) {
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
		re, err := regexp.Compile(r.regex)
		if err != nil {
			return nil, fmt.Errorf("scanning: rule %q regex does not compile: %w", r.id, err)
		}
		compiled = append(compiled, &compiledRule{
			id:       r.id,
			re:       re,
			keywords: lowerAll(r.keywords),
			hik:      r.id == hikRuleID,
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
	lower := bytes.ToLower(content)
	var findings []Finding
	for _, cr := range r.rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start, ok := cr.scanStart(lower)
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
		out[i] = string(bytes.ToLower([]byte(s)))
	}
	return out
}
