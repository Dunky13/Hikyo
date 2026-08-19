// Package delivery owns the canonical encodings the machine fetch path keys:
// the delivery manifest the change token covers, and the five-tuple the
// conditional cursor is bound to.
//
// It holds encoding and nothing else. The keying lives in internal/crypto
// (where `crypto/hmac` and `crypto/hkdf` are confined), the authorization lives
// at the chokepoint, and the projection this encodes is computed by the service.
// Splitting it out is what makes the seam the revision-model ADR needs testable: when
// real values and revisions land (#50/#51), Manifest's INPUT changes and
// nothing else does.
package delivery

import (
	"encoding/binary"
	"slices"
	"strings"
	"time"
)

// SnapshotMaxAge is the server-asserted maximum age of an offline delivery
// snapshot (ops-spec § 6). Clients bind both timestamps into snapshot AAD and
// refuse the ciphertext after this interval.
const SnapshotMaxAge = 7 * 24 * time.Hour

// ManifestVersion is the canonical encoding's version, carried INSIDE the
// signed bytes as well as on the token string. Inside matters: without it, two
// different encodings of the same content could produce the same token under a
// scheme change, which is the collision a version prefix on the outside cannot
// prevent.
const ManifestVersion = "v1"

// Presence is what the fetch surface reports about a key in one environment.
//
// It is NOT part of the manifest: the change token covers DELIVERED CONTENT
// only (revision-model ADR), so tightening `required_in` -- which changes what a
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
// value-or-presence)` triple, per the schema-model ADR's amendment to the revision
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

// Cursor is the five-tuple a conditional fetch's cursor is bound to. The ADR is
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
//	ConfigOnly            the authorized delivery mode changed. Without it, a
//	                      config-only cursor could suppress a later full fetch.
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
	// ConfigOnly distinguishes the config projection from full delivery. The
	// change token remains over the full manifest; mode belongs only here.
	ConfigOnly bool
}

// CursorVersion is the tuple encoding's version, inside the signed bytes for
// the same reason ManifestVersion is.
const CursorVersion = "v1"

// EncodeCursor renders the five-tuple canonically. Every component is
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
	mode := "full"
	if c.ConfigOnly {
		mode = "config-only"
	}
	out = appendField(out, mode)
	return out
}

// appendField writes one length-prefixed field. The same injectivity discipline
// the AAD and HKDF-info encodings use, for the same reason.
func appendField(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// ---------------------------------------------------------------------------
// Import occurrence tokens (#68, import-paths ADR § Binding phase 1 to phase 2)
// ---------------------------------------------------------------------------

// OccurrenceVersion is the occurrence encoding's version, inside the signed
// bytes for the same reason ManifestVersion is.
const OccurrenceVersion = "v1"

// Occurrence is what a phase-1 presence read observed for one
// `(key, environment)`, and what phase 2 recomputes to decide whether anything
// moved. Each component closes a distinct movement the ADR names:
//
//	KeyID           the declaration this name resolves to. A key deleted and
//	                re-created under the same name is a different key.
//	EntryID         WHICH value occurrence is in effect, or "" for `absent`.
//	                Value row ids are minted per write and never reused, so an
//	                edit advances this and the token stops matching — which is
//	                precisely what a bucket label cannot do, since `set` → `set`
//	                with a changed value preserves the bucket.
//	Classification  a reclassification moved what the key IS.
//	Declaration     the declaration digest: a changed rule is a changed
//	                declaration, and consent was given against the old one.
//	Name            the key's NAME. For an undeclared key it is the only
//	                identity there is; for a declared one it rides along so the
//	                two encodings can never collide.
//	Declared        whether the project declares this key at all. An import
//	                proposes keys that do not exist yet, and phase 2 must be
//	                able to check those did not move either — so they get a
//	                token naming "undeclared and absent" rather than no token,
//	                which is the one row an edited manifest could otherwise
//	                forge freely.
//	IntendedClassification
//	IntendedType    for an undeclared key, exactly what the emitted bundle line
//	                will declare. Phase 2 accepts the expected undeclared ->
//	                declared transition only when both still match.
type Occurrence struct {
	Declared               bool
	Name                   string
	KeyID                  string
	EntryID                string
	Classification         string
	Declaration            string
	IntendedClassification string
	IntendedType           string
}

// EncodeOccurrence renders one occurrence canonically. Length-prefixed
// throughout, so the encoding is injective and "recompute and compare" is a
// sound test: a caller cannot construct bytes for a state they were not served.
//
// The declared/undeclared discriminator is a FIELD, not an absence: encoding
// the undeclared case as "the declared case with empty ids" would let a key
// whose declaration was somehow empty collide with one that has none.
func EncodeOccurrence(o Occurrence) []byte {
	kind := "undeclared"
	if o.Declared {
		kind = "declared"
	}
	out := appendField(nil, OccurrenceVersion)
	out = appendField(out, kind)
	out = appendField(out, o.Name)
	if !o.Declared {
		// Bind the one declaration transition this reviewed run authorizes.
		// These are not observations; they are the exact intended fields the
		// client will emit in its additive bundle.
		out = appendField(out, o.IntendedClassification)
		out = appendField(out, o.IntendedType)
		return out
	}
	out = appendField(out, o.KeyID)
	out = appendField(out, o.EntryID)
	out = appendField(out, o.Classification)
	return appendField(out, o.Declaration)
}
