// Package delivery owns the canonical encodings the machine fetch path keys:
// the delivery manifest the change token covers, and the four-tuple the
// conditional cursor is bound to.
//
// It holds encoding and nothing else. The keying lives in internal/crypto
// (where `crypto/hmac` and `crypto/hkdf` are confined), the authorization lives
// at the chokepoint, and the projection this encodes is computed by the service.
// Splitting it out is what makes the seam the revision ADR needs testable: when
// real values and revisions land (#50/#51), Manifest's INPUT changes and
// nothing else does.
package delivery

import (
	"encoding/binary"
	"slices"
	"strings"
)

// ManifestVersion is the canonical encoding's version, carried INSIDE the
// signed bytes as well as on the token string. Inside matters: without it, two
// different encodings of the same content could produce the same token under a
// scheme change, which is the collision a version prefix on the outside cannot
// prevent.
const ManifestVersion = "v1"

// Presence is what the fetch surface reports about a key in one environment.
//
// It is NOT part of the manifest: the change token covers DELIVERED CONTENT
// only (revision ADR), so tightening `required_in` -- which changes what a
// future publish may commit, not what this snapshot delivers -- must not move
// the token and fire a rollout wave. `set` joined the enumeration with #51:
// a key the snapshot delivers is `set`, and one it does not carries whichever
// declared rule applies to it.
type Presence string

const (
	// PresenceRequired is declared required in this environment.
	PresenceRequired Presence = "required"
	// PresenceForbidden is declared forbidden in this environment.
	PresenceForbidden Presence = "forbidden"
	// PresenceOptional is neither.
	PresenceOptional Presence = "optional"
	// PresenceSet is a key the snapshot actually delivers.
	PresenceSet Presence = "set"
)

// Row is one delivery-manifest entry: an ordered `(key, classification,
// value-or-presence)` triple, per the schema ADR's amendment to the revision
// ADR.
//
// Classification is IN the manifest and that is the amendment's whole point: an
// adapter routing `secret` to a Kubernetes Secret and `config` to a ConfigMap
// would otherwise see an unchanged token across a reclassification and never
// fire the rollout that relocates the value.
type Row struct {
	Key            string
	Classification string
	// Value is the plaintext the snapshot delivers for this key. It is the
	// third element of the ADR's triple, and it is why the token moves when a
	// value moves -- which is the whole point of a change token.
	//
	// The manifest is computed server-side, from a snapshot the server already
	// holds in plaintext for the length of the operation, and the token that
	// comes out is KEYED: it is unforgeable and un-invertible without the
	// scoped key, so it flows into pod annotations and logs as ordinary
	// non-secret metadata while the values it covers never leave the server.
	Value string
}

// Manifest is the canonical encoding the change token is computed over.
//
// Rows are sorted by key, and every field is LENGTH-PREFIXED. Both are
// load-bearing: an unsorted encoding would make the token a function of the
// database's row order, and bare concatenation would let two different
// manifests encode identically — ("AB", "c") and ("A", "Bc") — which is a token
// collision, i.e. a missed rollout.
func Manifest(rows []Row) []byte {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b Row) int { return strings.Compare(a.Key, b.Key) })

	out := appendField(nil, ManifestVersion)
	out = binary.AppendUvarint(out, uint64(len(sorted)))
	for _, r := range sorted {
		out = appendField(out, r.Key)
		out = appendField(out, r.Classification)
		out = appendField(out, r.Value)
	}
	return out
}

// Cursor is the four-tuple a conditional fetch's cursor is bound to. The ADR is
// explicit that it is "never the environment's change token alone", and each
// component closes a distinct failure:
//
//	ChangeToken           the delivered content moved.
//	Projection            what this caller MAY SEE moved. Without it, a
//	                      workload granted `reveal` polls, the content has not
//	                      changed, the token matches, and it is told "current"
//	                      — so it runs indefinitely without the secrets it is
//	                      now entitled to, silently. And for a caller LACKING
//	                      `reveal`, a cursor derived from secret-bearing
//	                      content alone becomes a comparison oracle for whether
//	                      hidden values changed.
//	AuthorizationRevision the principal's authority moved at all — a grant
//	                      added, removed or narrowed.
//	PinGeneration         a pin was created, reassigned or released.
type Cursor struct {
	ChangeToken string
	// Projection is the caller's authorized delivery projection: the sorted
	// capability atoms it holds at the addressed environment. It is sorted by
	// the caller of EncodeCursor rather than trusted to arrive sorted.
	Projection []string
	// AuthorizationRevision is the principal's monotonic authority revision.
	AuthorizationRevision int64
	// PinGeneration is the (principal, environment) pin counter.
	PinGeneration int64
}

// CursorVersion is the tuple encoding's version, inside the signed bytes for
// the same reason ManifestVersion is.
const CursorVersion = "v1"

// EncodeCursor renders the four-tuple canonically. Every component is
// length-prefixed and the projection is sorted, so the encoding is injective:
// two different tuples cannot produce one cursor, which is what makes
// "recompute and compare" a sound test rather than a heuristic.
func EncodeCursor(c Cursor) []byte {
	projection := slices.Clone(c.Projection)
	slices.Sort(projection)
	projection = slices.Compact(projection)

	out := appendField(nil, CursorVersion)
	out = appendField(out, c.ChangeToken)
	out = binary.AppendUvarint(out, uint64(len(projection)))
	for _, p := range projection {
		out = appendField(out, p)
	}
	// Signed varints: a negative revision or generation is a defect rather than
	// a value, and encoding it unsigned would wrap it into a plausible-looking
	// large number instead of an obviously wrong one.
	out = binary.AppendVarint(out, c.AuthorizationRevision)
	out = binary.AppendVarint(out, c.PinGeneration)
	return out
}

// appendField writes one length-prefixed field. The same injectivity discipline
// the AAD and HKDF-info encodings use, for the same reason.
func appendField(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}
