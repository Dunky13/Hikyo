package operator

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// stampKeyVersion is the derivation version bound into the cursor tuple (§ 0.5),
// distinct from the stamp's own value prefix. A change here forces every cursor
// to mismatch once and every CR to re-sync — the intended upgrade path.
const stampKeyVersion = "v1"

// bindingInput is the local binding tuple the cursor is bound to (§ 0.5). Its
// digest is stored in status.cursorBinding; the cursor is presented only while a
// freshly computed digest still matches. Every component closes a distinct
// change that must invalidate the cursor even though the server's change token
// has not moved: a rotated credential (UID+resourceVersion), a moved scope, a
// changed projection, an edited mapping (source OR destination), a retargeted
// Secret, a different instance, a stamp-scheme bump.
type bindingInput struct {
	credentialUID             string
	credentialResourceVersion string
	org, project, environment string
	projection                string
	mapping                   []hikyov1.Mapping
	targetName                string
	instanceUID               string
}

// bindingDigest renders the tuple injectively (length-prefixed throughout, the
// mapping sorted by effective destination then source so a reordered-but-
// equivalent mapping yields the same digest) and returns its hex SHA-256. sha256
// is deliberately used, not the keyed stamp construction: this digest is
// local-only status metadata, never workload-visible, so there is nothing to
// key against — its only job is to detect local change, and it is compared only
// against a value this same code wrote.
func bindingDigest(in bindingInput) string {
	pairs := make([][2]string, 0, len(in.mapping))
	for _, m := range in.mapping {
		pairs = append(pairs, [2]string{string(m.Key), m.EffectiveSecretKey()})
	}
	slices.SortFunc(pairs, func(a, b [2]string) int {
		if c := strings.Compare(a[1], b[1]); c != 0 {
			return c
		}
		return strings.Compare(a[0], b[0])
	})

	var buf []byte
	buf = lp(buf, "hikyo/k8s-cursor-binding/"+stampKeyVersion)
	buf = lp(buf, in.credentialUID)
	buf = lp(buf, in.credentialResourceVersion)
	buf = lp(buf, in.org)
	buf = lp(buf, in.project)
	buf = lp(buf, in.environment)
	buf = lp(buf, in.projection)
	buf = lp(buf, in.targetName)
	buf = lp(buf, in.instanceUID)
	buf = lp(buf, stampKeyVersion)
	buf = binary.AppendUvarint(buf, uint64(len(pairs)))
	for _, p := range pairs {
		buf = lp(buf, p[0])
		buf = lp(buf, p[1])
	}

	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// lp appends one uvarint-length-prefixed field.
func lp(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}
