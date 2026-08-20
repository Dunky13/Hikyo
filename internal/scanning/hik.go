package scanning

import (
	"regexp"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// matchHik is the procedural second stage of the hik_ rule. The RE2 stage
// (hikRuleRegex) extracts candidates over the hik_ grammar; this stage runs
// each candidate through crypto.ParseArtifact, which validates the grammar and
// the CRC-32 checksum locally. The CRC is not expressible in RE2 and is never
// reimplemented here — a checksum-invalid candidate (truncated, corrupted) is a
// non-match (ADR §3).
//
// The extracted capture group is the artifact type, passed to ParseArtifact.
// ParseArtifact does not itself require the type to be a currently-defined
// artifact type, so the strong signal is the checksum: a random 6-char base62
// suffix validates with probability 62^-6 (~1 in 5.7e10). A candidate followed
// immediately by further base62 characters is greedily absorbed by the regex
// and then fails the exact-length body decode — a miss, shared with any
// third-party scanner consuming the same exported grammar.
func matchHik(re *regexp.Regexp, content []byte) bool {
	for _, m := range re.FindAllSubmatch(content, -1) {
		candidate := string(m[0])
		artifactType := crypto.ArtifactType(string(m[1]))
		if crypto.ParseArtifact(candidate, artifactType) == nil {
			return true
		}
	}
	return false
}
