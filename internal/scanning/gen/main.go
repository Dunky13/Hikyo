// Command gen produces internal/scanning/rules_gen.go from the vendored
// gitleaks snapshot plus the committed allowlist. It runs via
// `go run ./internal/scanning/gen` and is drift-checked in CI like the other
// generated sources (regenerate, then `git diff --exit-code`).
//
// The import contract (ADR §3, fail-closed): the generator consumes exactly
// id, regex and keywords. description and tags are non-semantic annotations
// and are ignored. Any verdict-affecting field (entropy, allowlist(s), path,
// secretGroup) or any unrecognised key rejects the rule by name — unsupported
// semantics are never silently discarded. A regex that does not compile under
// RE2 (Go regexp) rejects the rule.
//
// The per-rule semantic digest and the snapshot version are computed here, at
// generation time, and emitted as string constants: the runtime scanning
// package imports no hash primitive (SS4).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
)

// Vendoring record (docs/handoff/74-secret-scanning.md phase 0). The snapshot
// is repository content; no network fetch at build or runtime.
const (
	gitleaksUpstream    = "github.com/gitleaks/gitleaks"
	gitleaksTag         = "v8.19.0"
	gitleaksCommit      = "44ad62e0b103f7907c4b3dd494aca64e4fefd94f"
	gitleaksSourcePath  = "config/gitleaks.toml"
	vendorTOMLSHA256    = "f0530f72a3962c6b824d7c03714a896b3e5e609d6a2f3bf11be97b6d715e1372"
	vendorLicenseSHA256 = "e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6"
)

// The Hikyo-owned rule (ADR §3). Two-stage by construction: this regex is the
// RE2 candidate-extraction stage over the hik_ grammar (prefix, version, the
// 2–4 char lowercase type list, base62 body+checksum — see
// internal/crypto/bearer.go). The procedural CRC stage lives in the runtime
// package and calls crypto.ParseArtifact; the CRC is never reimplemented and
// is not expressible in RE2. The capture group is the artifact type.
const (
	hikRuleID    = "hikyo-artifact"
	hikRuleRegex = `hik_1_([a-z]{2,4})_[0-9A-Za-z]{7,}`
)

var hikRuleKeywords = []string{"hik_"}

// maxCompiledRules mirrors the runtime cap; enforced here so generation fails
// closed before an oversized table is ever committed (ADR §7).
const maxCompiledRules = 64

// allowedFields are the keys a rule may carry. id/regex/keywords are consumed;
// description/tags are ignored as non-semantic.
var allowedFields = map[string]bool{
	"id": true, "description": true, "regex": true, "keywords": true, "tags": true,
}

// rejectFields name the verdict-affecting fields the contract refuses. Any
// other unrecognised key is also rejected, so the list is a clearer error, not
// the security boundary.
var rejectFields = map[string]bool{
	"entropy": true, "allowlist": true, "allowlists": true, "path": true, "secretGroup": true,
}

type genRule struct {
	id          string
	regex       string
	keywords    []string
	coverage    coverageState
	specialFold []string
	digest      string
}

type coverageState string

const (
	coverageComplete       coverageState = "complete"
	coverageFoldIncomplete coverageState = "foldIncomplete"
	coverageIncomplete     coverageState = "incomplete"
)

var errDuplicateVendorRuleID = errors.New("duplicate vendored rule id")

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "scanning/gen:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	tomlPath := filepath.Join(root, "internal", "scanning", "rules", "vendor", "gitleaks.toml")
	allowlistPath := filepath.Join(root, "internal", "scanning", "rules", "allowlist.txt")
	outPath := filepath.Join(root, "internal", "scanning", "rules_gen.go")

	allowlist, err := readAllowlist(allowlistPath)
	if err != nil {
		return err
	}
	rawRules, err := readVendorRules(tomlPath)
	if err != nil {
		return err
	}

	rules, err := compileAllowlisted(allowlist, rawRules)
	if err != nil {
		return err
	}

	// The hik_ rule is Hikyo-owned, not from the snapshot.
	hikCoverage, hikSpecialFold, err := proveKeywordCoverage(hikRuleRegex, hikRuleKeywords)
	if err != nil {
		return fmt.Errorf("prove %s keyword coverage: %w", hikRuleID, err)
	}
	rules = append(rules, genRule{
		id:          hikRuleID,
		regex:       hikRuleRegex,
		keywords:    hikRuleKeywords,
		coverage:    hikCoverage,
		specialFold: hikSpecialFold,
		digest:      semanticDigest(hikRuleID, hikRuleRegex, hikRuleKeywords),
	})

	if len(rules) > maxCompiledRules {
		return fmt.Errorf("compiled rule count %d exceeds ceiling %d", len(rules), maxCompiledRules)
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].id < rules[j].id })

	src, err := render(allowlist, rules)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, src, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("scanning/gen: wrote %d rules to %s\n", len(rules), outPath)
	return nil
}

// compileAllowlisted validates each allowlisted rule against the import
// contract and compiles its regex under RE2. Order follows the allowlist; the
// caller sorts the full set for deterministic output.
func compileAllowlisted(allowlist []string, rawRules []map[string]any) ([]genRule, error) {
	byID := make(map[string]map[string]any, len(rawRules))
	for _, r := range rawRules {
		id, _ := r["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("vendor rule with missing id")
		}
		if _, exists := byID[id]; exists {
			return nil, fmt.Errorf("%w %q", errDuplicateVendorRuleID, id)
		}
		byID[id] = r
	}

	out := make([]genRule, 0, len(allowlist))
	for _, id := range allowlist {
		raw, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("allowlisted rule %q not present in vendored snapshot", id)
		}
		gr, err := importRule(id, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, gr)
	}
	return out, nil
}

func importRule(id string, raw map[string]any) (genRule, error) {
	for k := range raw {
		if allowedFields[k] {
			continue
		}
		if rejectFields[k] {
			return genRule{}, fmt.Errorf("rule %q rejected: verdict-affecting field %q is outside the import contract", id, k)
		}
		return genRule{}, fmt.Errorf("rule %q rejected: unrecognised field %q is outside the import contract", id, k)
	}

	regex, ok := raw["regex"].(string)
	if !ok || regex == "" {
		return genRule{}, fmt.Errorf("rule %q rejected: missing regex", id)
	}
	if _, err := regexp.Compile(regex); err != nil {
		return genRule{}, fmt.Errorf("rule %q rejected: regex does not compile under RE2: %w", id, err)
	}

	keywords, err := stringSlice(raw["keywords"])
	if err != nil {
		return genRule{}, fmt.Errorf("rule %q: keywords: %w", id, err)
	}
	if err := requireASCIIKeywords(keywords); err != nil {
		return genRule{}, fmt.Errorf("rule %q: keywords: %w", id, err)
	}
	coverage, specialFold, err := proveKeywordCoverage(regex, keywords)
	if err != nil {
		return genRule{}, fmt.Errorf("rule %q: prove keyword coverage: %w", id, err)
	}

	return genRule{
		id:          id,
		regex:       regex,
		keywords:    keywords,
		coverage:    coverage,
		specialFold: specialFold,
		digest:      semanticDigest(id, regex, keywords),
	}, nil
}

func requireASCIIKeywords(keywords []string) error {
	for _, keyword := range keywords {
		for _, b := range []byte(keyword) {
			if b >= 0x80 {
				return fmt.Errorf("keyword %q is not ASCII", keyword)
			}
		}
	}
	return nil
}

type literalPosition struct {
	r    rune
	fold bool
}

type literalAtom struct {
	run []literalPosition
	gap bool
}

type literalPath []literalAtom

const (
	maxClassBranches = 16
	maxSyntaxPaths   = 4096
)

// proveKeywordCoverage classifies whether every regex branch contains a
// keyword in a mandatory literal run. Pure ASCII coverage is complete. A proof
// that only fails because RE2 simple case folding admits non-ASCII equivalents
// is fold-incomplete and carries those UTF-8 sequences for runtime fallback.
// Syntax too broad to enumerate cannot establish coverage and is incomplete.
func proveKeywordCoverage(expr string, keywords []string) (coverageState, []string, error) {
	if err := requireASCIIKeywords(keywords); err != nil {
		return coverageIncomplete, nil, err
	}
	if len(keywords) == 0 {
		return coverageIncomplete, nil, nil
	}
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return coverageIncomplete, nil, err
	}
	paths := requiredLiteralPaths(re)
	if _, ok := literalPathsGuaranteeKeywords(paths, keywords, false); ok {
		return coverageComplete, nil, nil
	}
	special, ok := literalPathsGuaranteeKeywords(paths, keywords, true)
	if !ok {
		return coverageIncomplete, nil, nil
	}
	runes := make([]rune, 0, len(special))
	for r := range special {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })
	out := make([]string, len(runes))
	for i, r := range runes {
		out[i] = string(r)
	}
	if len(out) == 0 {
		return coverageComplete, nil, nil
	}
	return coverageFoldIncomplete, out, nil
}

func literalPathsGuaranteeKeywords(paths []literalPath, keywords []string, allowSpecialFold bool) (map[rune]struct{}, bool) {
	allSpecial := make(map[rune]struct{})
	for _, path := range paths {
		covered := false
		for _, atom := range path {
			if atom.gap {
				continue
			}
			for _, keyword := range keywords {
				special, ok := literalRunGuaranteesKeyword(atom.run, keyword, allowSpecialFold)
				if ok {
					for r := range special {
						allSpecial[r] = struct{}{}
					}
					covered = true
					break
				}
			}
			if covered {
				break
			}
		}
		if !covered {
			return nil, false
		}
	}
	return allSpecial, true
}

func requiredLiteralPaths(re *syntax.Regexp) []literalPath {
	switch re.Op {
	case syntax.OpNoMatch:
		return nil
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return []literalPath{nil}
	case syntax.OpLiteral:
		run := make([]literalPosition, len(re.Rune))
		for i, r := range re.Rune {
			run[i] = literalPosition{r: r, fold: re.Flags&syntax.FoldCase != 0}
		}
		return []literalPath{{{run: run}}}
	case syntax.OpCharClass:
		if runes, ok := enumerateClass(re.Rune); ok {
			paths := make([]literalPath, 0, len(runes))
			for _, r := range runes {
				paths = append(paths, literalPath{{run: []literalPosition{{r: r}}}})
			}
			return paths
		}
		return gapPaths()
	case syntax.OpCapture:
		return requiredLiteralPaths(re.Sub[0])
	case syntax.OpAlternate:
		var out []literalPath
		for _, sub := range re.Sub {
			out = append(out, requiredLiteralPaths(sub)...)
		}
		return out
	case syntax.OpConcat:
		out := []literalPath{nil}
		for _, sub := range re.Sub {
			out = combineLiteralPaths(out, requiredLiteralPaths(sub))
		}
		return out
	case syntax.OpPlus:
		return appendGap(requiredLiteralPaths(re.Sub[0]))
	case syntax.OpRepeat:
		if re.Min == 0 {
			return gapPaths()
		}
		if re.Min == 1 && re.Max == 1 {
			return requiredLiteralPaths(re.Sub[0])
		}
		return appendGap(requiredLiteralPaths(re.Sub[0]))
	case syntax.OpQuest, syntax.OpStar:
		return gapPaths()
	default:
		return gapPaths()
	}
}

func enumerateClass(pairs []rune) ([]rune, bool) {
	var out []rune
	for i := 0; i+1 < len(pairs); i += 2 {
		lo, hi := pairs[i], pairs[i+1]
		if int64(hi-lo+1) > int64(maxClassBranches-len(out)) {
			return nil, false
		}
		for r := lo; r <= hi; r++ {
			out = append(out, r)
		}
	}
	return out, len(out) > 0
}

func combineLiteralPaths(left, right []literalPath) []literalPath {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	if len(left) > maxSyntaxPaths/len(right) {
		return gapPaths()
	}
	out := make([]literalPath, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			combined := append(literalPath(nil), a...)
			if len(combined) > 0 && len(b) > 0 &&
				!combined[len(combined)-1].gap && !b[0].gap {
				last := len(combined) - 1
				merged := append([]literalPosition(nil), combined[last].run...)
				merged = append(merged, b[0].run...)
				combined[last].run = merged
				combined = append(combined, b[1:]...)
			} else {
				combined = append(combined, b...)
			}
			out = append(out, combined)
		}
	}
	return out
}

func appendGap(paths []literalPath) []literalPath {
	if len(paths) == 0 {
		return nil
	}
	for i := range paths {
		paths[i] = append(paths[i], literalAtom{gap: true})
	}
	return paths
}

func gapPaths() []literalPath {
	return []literalPath{{{gap: true}}}
}

func literalRunGuaranteesKeyword(run []literalPosition, keyword string, allowSpecialFold bool) (map[rune]struct{}, bool) {
	want := []byte(keyword)
	for i, b := range want {
		if b >= 'A' && b <= 'Z' {
			want[i] = b + ('a' - 'A')
		}
	}
	if len(want) == 0 {
		return map[rune]struct{}{}, true
	}
	for start := 0; start+len(want) <= len(run); start++ {
		special := make(map[rune]struct{})
		matched := true
		for i, b := range want {
			positionSpecial, ok := positionGuaranteesKeyword(run[start+i], b, allowSpecialFold)
			if !ok {
				matched = false
				break
			}
			for r := range positionSpecial {
				special[r] = struct{}{}
			}
		}
		if matched {
			return special, true
		}
	}
	return nil, false
}

func positionGuaranteesKeyword(pos literalPosition, want byte, allowSpecialFold bool) (map[rune]struct{}, bool) {
	checkASCII := func(r rune) bool {
		if r > unicode.MaxASCII {
			return false
		}
		b := byte(r)
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		return b == want
	}
	if !pos.fold {
		return nil, checkASCII(pos.r)
	}

	special := make(map[rune]struct{})
	foundASCII := false
	for r := pos.r; ; r = unicode.SimpleFold(r) {
		if r <= unicode.MaxASCII {
			if !checkASCII(r) {
				return nil, false
			}
			foundASCII = true
		} else {
			if !allowSpecialFold {
				return nil, false
			}
			special[r] = struct{}{}
		}
		if unicode.SimpleFold(r) == pos.r {
			break
		}
	}
	return special, foundASCII
}

func stringSlice(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("not an array")
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("non-string element")
		}
		out = append(out, s)
	}
	return out, nil
}

// semanticDigest is sha256 over the canonical id ‖ regex ‖ sorted-keywords,
// NUL-separated so the fields cannot run together ambiguously. Same canonical
// form feeds the snapshot version. Changing a rule's detector changes this
// digest, which invalidates that rule's dismissals by construction (ADR §4).
func semanticDigest(id, regex string, keywords []string) string {
	kw := append([]string(nil), keywords...)
	sort.Strings(kw)
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(regex))
	h.Write([]byte{0})
	for _, k := range kw {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// snapshotVersion binds the gitleaks pin and the allowlist digest into a stable
// identifier recorded in acknowledgement tokens (ADR §4).
func snapshotVersion(rules []genRule) string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.id + ":" + r.digest
	}
	sort.Strings(ids)
	h := sha256.New()
	h.Write([]byte(gitleaksCommit))
	h.Write([]byte{0})
	for _, s := range ids {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("gitleaks/%s+%s", gitleaksTag, hex.EncodeToString(h.Sum(nil))[:12])
}

func readAllowlist(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen[line] {
			return nil, fmt.Errorf("allowlist: duplicate rule id %q", line)
		}
		seen[line] = true
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("allowlist is empty")
	}
	return out, nil
}

func readVendorRules(path string) ([]map[string]any, error) {
	var doc struct {
		Rules []map[string]any `toml:"rules"`
	}
	if _, err := toml.DecodeFile(path, &doc); err != nil {
		return nil, fmt.Errorf("decode vendor toml: %w", err)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("vendor toml has no rules")
	}
	return doc.Rules, nil
}

func render(allowlist []string, rules []genRule) ([]byte, error) {
	manifest := append([]string(nil), allowlist...)
	sort.Strings(manifest)

	var b bytes.Buffer
	fmt.Fprint(&b, "// Code generated by internal/scanning/gen. DO NOT EDIT.\n\n")
	fmt.Fprint(&b, "package scanning\n\n")

	fmt.Fprintf(&b, "// snapshotVersion binds the gitleaks pin and the allowlist digest.\n")
	fmt.Fprintf(&b, "const snapshotVersion = %q\n\n", snapshotVersion(rules))

	fmt.Fprint(&b, "// Vendoring record (ADR §3): provenance pinned executably.\n")
	fmt.Fprint(&b, "const (\n")
	fmt.Fprintf(&b, "\tgitleaksUpstream    = %q\n", gitleaksUpstream)
	fmt.Fprintf(&b, "\tgitleaksTag         = %q\n", gitleaksTag)
	fmt.Fprintf(&b, "\tgitleaksCommit      = %q\n", gitleaksCommit)
	fmt.Fprintf(&b, "\tgitleaksSourcePath  = %q\n", gitleaksSourcePath)
	fmt.Fprintf(&b, "\tvendorTOMLSHA256    = %q\n", vendorTOMLSHA256)
	fmt.Fprintf(&b, "\tvendorLicenseSHA256 = %q\n", vendorLicenseSHA256)
	fmt.Fprint(&b, ")\n\n")

	fmt.Fprintf(&b, "// hikRuleID and hikRuleRegex are the single source for the Hikyo-owned\n")
	fmt.Fprintf(&b, "// rule's RE2 candidate stage; hik.go compiles hikRuleRegex and adds the\n")
	fmt.Fprintf(&b, "// procedural CRC stage.\n")
	fmt.Fprintf(&b, "const hikRuleID = %q\n", hikRuleID)
	fmt.Fprintf(&b, "const hikRuleRegex = %q\n\n", hikRuleRegex)

	fmt.Fprint(&b, "// generatedRules is the compiled-rule table, sorted by id. Each carries a\n")
	fmt.Fprint(&b, "// generated keyword-coverage proof and semantic digest.\n")
	fmt.Fprint(&b, "var generatedRules = []genRule{\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "\t{id: %q, regex: %q, keywords: %s, coverage: %s, specialFold: %s, digest: %q},\n",
			r.id, r.regex, keywordsLiteral(r.keywords), coverageLiteral(r.coverage), keywordsLiteral(r.specialFold), r.digest)
	}
	fmt.Fprint(&b, "}\n\n")

	fmt.Fprint(&b, "// generatedManifest lists the vendored rule ids compiled in, sorted. A test\n")
	fmt.Fprint(&b, "// asserts it equals the committed allowlist exactly (the hik_ rule is not a\n")
	fmt.Fprint(&b, "// gitleaks rule and is tracked separately).\n")
	fmt.Fprintf(&b, "var generatedManifest = %s\n", stringSliceLiteral(manifest))

	src, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated source: %w\n%s", err, b.String())
	}
	return src, nil
}

func keywordsLiteral(kw []string) string {
	if len(kw) == 0 {
		return "nil"
	}
	return stringSliceLiteral(kw)
}

func coverageLiteral(coverage coverageState) string {
	switch coverage {
	case coverageComplete:
		return "keywordCoverageComplete"
	case coverageFoldIncomplete:
		return "keywordCoverageFoldIncomplete"
	case coverageIncomplete:
		return "keywordCoverageIncomplete"
	default:
		panic(fmt.Sprintf("unknown keyword coverage %q", coverage))
	}
}

func stringSliceLiteral(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return "[]string{" + strings.Join(parts, ", ") + "}"
}

// repoRoot walks up from the working directory to the module root (the
// directory holding go.mod), so the generator runs from anywhere.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from working directory")
		}
		dir = parent
	}
}
