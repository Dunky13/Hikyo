package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Secret-scanning integration (#74, secret-scanning ADR §§2,4,5,7). This file
// is the service-layer seam every chokepoint calls: it turns a scanner match
// into the redacted Finding DTO the wire carries, mints and verifies the
// content-bound acknowledgement tokens, and emits the four scanning.* events
// inside the exact transaction shapes §7 fixes. The scanner (internal/scanning)
// returns a rule id and nothing else; the locator and the token are attached
// here, never by the scanner, so no match text can leak (ADR §4, SS4).
//
// sha256 for the token's content digest lives in service by design: the
// boundary test (SS4) confines HMAC/hash primitives away from scanning but
// leaves crypto/sha256 unrestricted precisely so an opaque, sealed token can
// bind the offending content without disclosing it. The unforgeable seal is the
// crypto envelope package's InstanceSealer — service never touches a keyed
// primitive itself.

const (
	// ackTTL bounds a Surface-2 acknowledgement (ADR §4: short-lived, ~15 min).
	// A Surface-1 keep-as-config token shares the bound.
	ackTTL = 15 * time.Minute
	// maxRequestFindings caps findings across one request (ADR §7): a request
	// exceeding it fails closed naming the cap, never a silent truncation.
	maxRequestFindings = 100

	// ackAADTable and ackAADFieldTag domain-separate the sealed ack token from
	// every other instance-field ciphertext. They are the owner_table/field_tag
	// of the InstanceFieldAAD; the token binds no row, so owner_row_id is empty.
	ackAADTable    = "scanning_ack"
	ackAADFieldTag = "v1"

	// ack kinds bind a token to one surface so a Surface-1 dismissal token can
	// never be replayed as a Surface-2 override and vice versa.
	ackKindValue = "s1"
	ackKindDecl  = "s2"

	// Surface-1 audit surfaces (ADR §5 finding_warned enum).
	surfaceValueWrite       = "value_write"
	surfaceDeclassification = "declassification"
	surfaceImportValue      = "import_value"

	// Surface-2 audit ingress (ADR §5 finding_blocked/overridden enum). edit is
	// the direct declaration ingress; plan and apply are the definitions Git-flow
	// chokepoints (#74 SS3, ADR §7 (b)/(c)). The wire ScanFinding.surface enum and
	// the audit ingress enum both carry all three.
	ingressEdit  = "edit"
	ingressPlan  = "plan"
	ingressApply = "apply"

	// surfaceCheck labels a finding surfaced by the read-only `definitions check`
	// dry-run (ADR §7). Check never persists and never mints a token, so this is a
	// wire surface only — it appears in no audit ingress enum.
	surfaceCheck = "check"
)

// errFindingCap is the fail-closed refusal when one request produces more than
// maxRequestFindings findings (ADR §7). It names the cap and never truncates.
var errFindingCap = fmt.Errorf("%w: scan produced more than %d findings; the request is refused rather than truncated",
	domain.ErrInvalid, maxRequestFindings)

// Finding is one redacted scan result surfaced to the writer, everywhere it
// travels (wire, CLI, import output). It carries a rule id, the surface/ingress
// it fired on, an immutable locator, and — where an acknowledgement is possible
// (Surface-1 stage keep-as-config, Surface-2 override) — an opaque token.
// Banned by construction: matched text, offsets, length, excerpts (ADR §4).
type Finding struct {
	RuleID          string
	Surface         string
	Locator         string
	Acknowledgement string
}

// --- acknowledgement token: sealed, content-bound, short-lived (ADR §4) ---

// ackBinding is the token's cleartext binding, sealed opaque under the instance
// key. It embeds no plaintext: contentSHA is a digest, not the field content.
type ackBinding struct {
	kind       string
	locator    string
	ruleDigest string
	contentSHA [32]byte
	snapshot   string
	mintNano   int64
}

func ackAAD() crypto.InstanceFieldAAD {
	return crypto.InstanceFieldAAD{OwnerTable: ackAADTable, FieldTag: ackAADFieldTag}
}

func appendAckField(dst, field []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(field)))
	return append(dst, field...)
}

func encodeAckBinding(b ackBinding) []byte {
	out := appendAckField(nil, []byte(b.kind))
	out = appendAckField(out, []byte(b.locator))
	out = appendAckField(out, []byte(b.ruleDigest))
	out = appendAckField(out, b.contentSHA[:])
	out = appendAckField(out, []byte(b.snapshot))
	out = binary.BigEndian.AppendUint64(out, uint64(b.mintNano))
	return out
}

var errBadAck = errors.New("service: acknowledgement token is unreadable")

func readAckField(b []byte) (field, rest []byte, err error) {
	n, adv := binary.Uvarint(b)
	if adv <= 0 || n > uint64(len(b)-adv) {
		return nil, nil, errBadAck
	}
	return b[adv : adv+int(n)], b[adv+int(n):], nil
}

func decodeAckBinding(msg []byte) (ackBinding, error) {
	var b ackBinding
	kind, rest, err := readAckField(msg)
	if err != nil {
		return b, err
	}
	loc, rest, err := readAckField(rest)
	if err != nil {
		return b, err
	}
	dig, rest, err := readAckField(rest)
	if err != nil {
		return b, err
	}
	cSHA, rest, err := readAckField(rest)
	if err != nil || len(cSHA) != len(b.contentSHA) {
		return b, errBadAck
	}
	snap, rest, err := readAckField(rest)
	if err != nil {
		return b, err
	}
	if len(rest) != 8 {
		return b, errBadAck
	}
	b.kind, b.locator, b.ruleDigest, b.snapshot = string(kind), string(loc), string(dig), string(snap)
	copy(b.contentSHA[:], cSHA)
	b.mintNano = int64(binary.BigEndian.Uint64(rest))
	return b, nil
}

// sealAck mints an opaque token for a binding. The seal is the crypto envelope
// package's instance sealer — unforgeable without the instance key, tamper-
// evident, and opaque. Base64url so it rides a JSON string and a CLI flag.
//
// fence:exempt — the token is minted and handed to the caller, NEVER written to
// any table, so no writer fence applies (there is no row to strand under a
// rotated DEK version). It is an ephemeral, content-bound, re-mintable artifact
// like a session token; a rotate-dek that eventually retires its version simply
// invalidates outstanding tokens, which is acceptable for an acknowledgement.
func sealAck(kr *crypto.Keyring, b ackBinding) (string, error) {
	ct, err := kr.ForInstance().SealField(ackAAD(), encodeAckBinding(b))
	if err != nil {
		return "", fmt.Errorf("service: seal acknowledgement: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// openAck reverses sealAck. A token that does not decode or does not open under
// the instance key (forged or tampered) is errBadAck — never a panic and never
// a partial read a caller could act on.
func openAck(kr *crypto.Keyring, token string) (ackBinding, error) {
	ct, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ackBinding{}, errBadAck
	}
	msg, err := kr.ForInstance().OpenField(ackAAD(), ct)
	if err != nil {
		return ackBinding{}, errBadAck
	}
	return decodeAckBinding(msg)
}

func contentDigest(content []byte) [32]byte { return sha256.Sum256(content) }

// ackRef is the opaque reference to a token recorded in a finding_overridden
// event (ADR §5): sha256(token), never the live token itself — the token is a
// stateless capability valid for its TTL, and putting it in an audit-read-able
// row would hand every reader a live override authority.
func ackRef(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ackSet tracks the tokens a resubmission presented, consuming each as it
// matches a current finding so surplus tokens can be rejected by name (ADR §4).
type ackSet struct {
	tokens []string
	used   []bool
}

func newAckSet(tokens []string) *ackSet {
	return &ackSet{tokens: tokens, used: make([]bool, len(tokens))}
}

// match finds one unconsumed token that binds exactly this finding under this
// kind at the current snapshot, within the TTL. It returns the matched token
// and consumes it. A token that decodes to the right locator+rule+snapshot but
// a stale content digest is left UNCONSUMED and surfaced as a stale rejection by
// the caller's surplus sweep.
func (a *ackSet) match(kr *crypto.Keyring, kind, locator, ruleDigest, snapshot string, cSHA [32]byte, now time.Time) (string, bool) {
	for i, tok := range a.tokens {
		if a.used[i] {
			continue
		}
		b, err := openAck(kr, tok)
		if err != nil {
			continue
		}
		if b.kind != kind || b.locator != locator || b.ruleDigest != ruleDigest {
			continue
		}
		if b.snapshot != snapshot {
			continue // version skew: rejected by the surplus sweep
		}
		if b.contentSHA != cSHA {
			continue // stale: content changed since minting
		}
		if now.Sub(time.Unix(0, b.mintNano)) > ackTTL {
			continue // expired
		}
		a.used[i] = true
		return tok, true
	}
	return "", false
}

// unconsumed reports the count of tokens no finding claimed — surplus, stale,
// version-skewed, or expired. The caller rejects them by name (ADR §4: a
// standing pre-authorization is structurally impossible).
func (a *ackSet) unconsumed() int {
	n := 0
	for _, u := range a.used {
		if !u {
			n++
		}
	}
	return n
}

// classifyRejections names every unconsumed token against the findings that
// exist now (ADR §4 / SS3: rejection BY NAME, with a structural reason). The
// precedence is deterministic so the message is stable: a token that does not
// decode is unreadable; one whose bound locator+rule matches no current finding
// is surplus; otherwise the mismatch that kept it from matching its finding is
// the reason — version-skew before stale before expired.
func (a *ackSet) classifyRejections(kr *crypto.Keyring, findings []declFinding, snapshot string, now time.Time) []scanRejection {
	var out []scanRejection
	for i, tok := range a.tokens {
		if a.used[i] {
			continue
		}
		rej := scanRejection{Index: i}
		b, err := openAck(kr, tok)
		if err != nil || b.kind != ackKindDecl {
			rej.Reason = rejectUnreadable
			out = append(out, rej)
			continue
		}
		rej.Locator = b.locator
		var match *declFinding
		for j := range findings {
			if findings[j].locator == b.locator && findings[j].ruleDigest == b.ruleDigest {
				match = &findings[j]
				break
			}
		}
		switch {
		case match == nil:
			// No current finding shares this token's locator+rule.
			rej.Reason = rejectSurplus
		case b.snapshot != snapshot:
			rej.Reason, rej.RuleID = rejectVersionSkew, match.ruleID
		case b.contentSHA != match.cSHA:
			rej.Reason, rej.RuleID = rejectStale, match.ruleID
		case now.Sub(time.Unix(0, b.mintNano)) > ackTTL:
			rej.Reason, rej.RuleID = rejectExpired, match.ruleID
		default:
			// Binds an exact current finding yet stayed unconsumed: a second token
			// aimed at the one finding a prior token already claimed — surplus.
			rej.Reason, rej.RuleID = rejectSurplus, match.ruleID
		}
		out = append(out, rej)
	}
	return out
}

// --- Surface 1: warn, non-blocking (ADR §2 Surface 1, §4, §7) ---

// scanConfigValue is the Surface-1 chokepoint helper, run inside the value
// write's transaction after authorization. A non-config classification is a
// no-op (Surface 3: a secret value is never scanned, so the scanner cannot leak
// what it never reads). It scans the canonical stored bytes, and for each rule
// match:
//
//   - if dismissable and a prior dismissal already covers (key, ruleDigest,
//     fingerprint), the finding is suppressed entirely (no warn, no event);
//   - else if dismissable and the resubmission presents a valid keep-as-config
//     token for it, a dismissal row is written and finding_dismissed emitted;
//   - else finding_warned is emitted and the finding rides the response (with a
//     fresh keep-as-config token when dismissable).
//
// dismissable is true only on the stage path — the sole Surface-1 ingress whose
// operation authorizes the dismissal store ops (ADR §7 warn transaction). The
// declare/copy/clone/import/declassification ingresses are warn-only: they
// surface findings and emit finding_warned, but carry no acknowledgement.
//
// total accumulates findings across a multi-item request; exceeding
// maxRequestFindings fails the whole transaction closed (ADR §7).
func scanConfigValue(ctx context.Context, r store.Repos, p authz.Proof, kr *crypto.Keyring, rs *scanning.Ruleset,
	scope domain.Scope, keyID, classification string, canonical []byte, surface string,
	principal domain.PrincipalID, acks *ackSet, dismissable bool, total *int) ([]Finding, error) {
	if rs == nil {
		// A booted server always wires the ruleset (Boot refuses to start on a
		// Load error, ADR §7); a nil ruleset is a pre-#74 test with scanning off.
		return nil, nil
	}
	if classification != string(schema.Config) {
		return nil, nil // Surface 3
	}
	matches, err := rs.Scan(ctx, canonical)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}
	var out []Finding
	cSHA := contentDigest(canonical)
	var fingerprint []byte
	if dismissable {
		fingerprint = kr.ScanningFingerprint(string(scope.Org), string(scope.Project), string(scope.Env), keyID, canonical)
	}
	for _, m := range matches {
		digest, ok := rs.SemanticDigest(m.RuleID)
		if !ok {
			return nil, fmt.Errorf("service: rule %q has no semantic digest", m.RuleID)
		}
		if dismissable {
			exists, err := r.ScanningDismissals().Exists(ctx, p, keyID, digest, fingerprint)
			if err != nil {
				return nil, err
			}
			if exists {
				continue // sticky dismissal already covers this value
			}
			if acks != nil {
				if _, matched := acks.match(kr, ackKindValue, keyID, digest, rs.SnapshotVersion(), cSHA, time.Now()); matched {
					if err := recordDismissal(ctx, r, p, kr, keyID, digest, fingerprint, m.RuleID, principal); err != nil {
						return nil, err
					}
					continue // dismissed, not warned
				}
			}
		}
		*total++
		if *total > maxRequestFindings {
			return nil, errFindingCap
		}
		if err := emitFindingWarned(ctx, r, p, principal, keyID, m.RuleID, surface); err != nil {
			return nil, err
		}
		f := Finding{RuleID: m.RuleID, Surface: surface, Locator: keyID}
		if dismissable {
			tok, err := sealAck(kr, ackBinding{
				kind: ackKindValue, locator: keyID, ruleDigest: digest,
				contentSHA: cSHA, snapshot: rs.SnapshotVersion(), mintNano: time.Now().UnixNano(),
			})
			if err != nil {
				return nil, err
			}
			f.Acknowledgement = tok
		}
		out = append(out, f)
	}
	return out, nil
}

func recordDismissal(ctx context.Context, r store.Repos, p authz.Proof, kr *crypto.Keyring,
	keyID, ruleDigest string, fingerprint []byte, ruleID string, principal domain.PrincipalID) error {
	id, err := newID("dsm")
	if err != nil {
		return err
	}
	if err := r.ScanningDismissals().Insert(ctx, p, store.NewDismissal{
		ID: id, KeyID: keyID, RuleDigest: ruleDigest, Fingerprint: fingerprint,
		CreatedBy: string(principal), CreatedAt: time.Now(),
	}); err != nil {
		return err
	}
	ev, err := domainEvent(ctx, audit.EventScanningFindingDismissed, principal,
		audit.Object{Type: "key", ID: keyID}, audit.Payload{
			"rule_id":      ruleID,
			"dismissal_id": id,
		})
	if err != nil {
		return err
	}
	return r.Audit().InsertTenant(ctx, p, ev)
}

func emitFindingWarned(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID,
	keyID, ruleID, surface string) error {
	ev, err := domainEvent(ctx, audit.EventScanningFindingWarned, principal,
		audit.Object{Type: "key", ID: keyID}, audit.Payload{
			"rule_id": ruleID,
			"surface": surface,
		})
	if err != nil {
		return err
	}
	return r.Audit().InsertTenant(ctx, p, ev)
}

// --- Surface 2: block, at every declaration ingress (ADR §2 Surface 2, §4) ---

// scanLeaf is one author-controlled string leaf of a declaration ingress, with
// its immutable schema-location-class locator (never instance-derived) and its
// canonical content bytes.
type scanLeaf struct {
	Locator string
	Content []byte
}

// Surface-2 locator classes (ADR §4: immutable schema-location-class, never
// instance-derived). Two enum members offending the same rule share a locator
// and are distinguished only by their content digest, so the locator carries no
// index. These strings are the single source of truth the field-coverage matrix
// test (SS3) checks every author-controlled string leaf against.
const (
	locKeyName            = "key.name"
	locKeyDescription     = "key.description"
	locKeyDeprecationNote = "key.deprecation_note"
	locKeyFolderPath      = "key.folder_path"
	locDeclPattern        = "key.declaration.pattern"
	locDeclEnumMember     = "key.declaration.enum_member"
	locDeclScheme         = "key.declaration.scheme"
	locDeclJSONSchema     = "key.declaration.json_schema"
	locGroupName          = "key_group.name"
	locEnvironmentName    = "environment.name"
	locEnvironmentNote    = "environment.note"
	locFolderPath         = "folder.path"
)

func nonEmptyLeaf(locator, content string) []scanLeaf {
	if content == "" {
		return nil
	}
	return []scanLeaf{{Locator: locator, Content: []byte(content)}}
}

// declarationLeaves extracts every author-controlled string leaf of a key
// declaration: the pattern, each enum member, each URL scheme, and the JSON
// Schema document. Type keywords, numeric bounds and booleans are server-
// interpreted, not author free-text, so they are the closed exclusion list.
// AnyOf alternatives all map to the same locator class (no index) — content
// digests distinguish findings.
func declarationLeaves(d schema.Declaration) []scanLeaf {
	var out []scanLeaf
	add := func(rules []schema.Rule) {
		for _, r := range rules {
			out = append(out, nonEmptyLeaf(locDeclPattern, r.Pattern)...)
			for _, m := range r.Members {
				out = append(out, nonEmptyLeaf(locDeclEnumMember, m)...)
			}
			for _, s := range r.Schemes {
				out = append(out, nonEmptyLeaf(locDeclScheme, s)...)
			}
			if len(r.JSONSchema) > 0 {
				out = append(out, scanLeaf{Locator: locDeclJSONSchema, Content: r.JSONSchema})
			}
		}
	}
	if d.Rule != nil {
		add([]schema.Rule{*d.Rule})
	}
	add(d.AnyOf)
	return out
}

// keySpecLeaves is every author-controlled string leaf of a key creation.
func keySpecLeaves(spec KeySpec) []scanLeaf {
	var out []scanLeaf
	out = append(out, nonEmptyLeaf(locKeyName, spec.Name)...)
	out = append(out, nonEmptyLeaf(locKeyDescription, spec.Description)...)
	out = append(out, nonEmptyLeaf(locKeyDeprecationNote, spec.DeprecationNote)...)
	out = append(out, nonEmptyLeaf(locKeyFolderPath, spec.FolderPath)...)
	out = append(out, declarationLeaves(spec.Declaration)...)
	return out
}

// keyMetadataLeaves is the author-controlled leaves of a metadata PATCH: only
// the members actually being written (a nil pointer leaves the field alone, so
// there is nothing new to scan).
func keyMetadataLeaves(m KeyMetadataUpdate) []scanLeaf {
	var out []scanLeaf
	if m.FolderPath != nil {
		out = append(out, nonEmptyLeaf(locKeyFolderPath, *m.FolderPath)...)
	}
	if m.Description != nil {
		out = append(out, nonEmptyLeaf(locKeyDescription, *m.Description)...)
	}
	if m.DeprecationNote != nil {
		out = append(out, nonEmptyLeaf(locKeyDeprecationNote, *m.DeprecationNote)...)
	}
	return out
}

// bundleLeaves extracts every author-controlled string leaf of an incoming
// definitions bundle (#74 SS3, ADR §7 (b)/(c)) — the same leaf set Surface 2
// enumerates for direct edits, mapped onto the same locator classes. The whole
// bundle is walked (not the diff): a plan artifact is stored declaration text and
// must not be born carrying a credential in any entry, even one copied verbatim
// from current state.
//
// Closed exclusion list, mirroring the direct-edit discipline (fixed schema
// keywords + server-generated ids are NOT scanned):
//   - Bundle.FormatVersion / Key.Deprecated: not strings.
//   - Key.ID / KeyGroup.ID / Environment.ID: server-generated identifiers.
//   - Key.Classification: closed secret|config enum.
//   - Key.Group and Presence.Environments (required_in/forbidden_in): NAME
//     references, not composed content. definitions.Resolve (validateKeyReferences,
//     run before persistPlan) refuses a reference to an entity the bundle does not
//     declare, so a credential there either matches a declared group/environment
//     NAME — itself scanned here via locGroupName/locEnvironmentName — or fails
//     resolution before the plan persists. Scanning the reference in addition would
//     double-report the one leaf that already blocks.
//   - The declaration's type keywords / numeric bounds: schema.declarationLeaves'
//     own closed exclusion (reused verbatim).
func bundleLeaves(b definitions.Bundle) []scanLeaf {
	var out []scanLeaf
	for _, e := range b.Environments {
		out = append(out, nonEmptyLeaf(locEnvironmentName, e.Name)...)
	}
	for _, g := range b.KeyGroups {
		out = append(out, nonEmptyLeaf(locGroupName, g.Name)...)
	}
	for _, k := range b.Keys {
		out = append(out, nonEmptyLeaf(locKeyName, k.Name)...)
		out = append(out, nonEmptyLeaf(locKeyDescription, k.Description)...)
		out = append(out, nonEmptyLeaf(locKeyDeprecationNote, k.DeprecationNote)...)
		out = append(out, nonEmptyLeaf(locKeyFolderPath, k.FolderPath)...)
		out = append(out, declarationLeaves(k.Declaration)...)
	}
	return out
}

// scanBundleForCheck is the read-only `definitions check` scan (ADR §7): it
// surfaces a finding per credential-shaped leaf without persisting anything and
// without minting a token — Check is a non-blocking diagnostic, so an override
// capability there would be a refusal ceremony that never happened. Findings ride
// the CheckResult; no scanning.* event is emitted.
func scanBundleForCheck(ctx context.Context, rs *scanning.Ruleset, b definitions.Bundle) ([]Finding, error) {
	if rs == nil {
		return nil, nil // scanning off (pre-#74 test); a booted server always wires it
	}
	var out []Finding
	total := 0
	for _, leaf := range bundleLeaves(b) {
		matches, err := rs.Scan(ctx, leaf.Content)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			total++
			if total > maxRequestFindings {
				return nil, errFindingCap
			}
			out = append(out, Finding{RuleID: m.RuleID, Surface: surfaceCheck, Locator: leaf.Locator})
		}
	}
	return out, nil
}

// declScanResult is what scanDeclaration reports. blocked findings refuse the
// write (finding_blocked committed alone); overridden findings ride the write's
// own transaction (finding_overridden). rejections name every presented token
// that no current finding claimed — surplus, stale, version-skewed, expired, or
// unreadable — each identified by name (ADR §4 / SS3).
type declScanResult struct {
	blocked    []Finding
	overridden []overrideAck
	rejections []scanRejection
}

type overrideAck struct {
	ruleID  string
	locator string
	ackRef  string
	ingress string
}

// declFinding is one current scan finding, retained so an unconsumed
// acknowledgement token can be classified against the findings that exist NOW.
type declFinding struct {
	locator    string
	ruleID     string
	ruleDigest string
	cSHA       [32]byte
}

// Rejection reason classes (ADR §4 / SS3: a resubmitted token that no current
// finding claims is refused BY NAME, with a structural reason). Precedence when
// more than one could apply is deterministic, tested: unreadable → surplus →
// version-skew → stale → expired.
const (
	rejectUnreadable  = "unreadable"   // does not decode, or bound to another surface
	rejectSurplus     = "surplus"      // no current finding shares its locator+rule
	rejectVersionSkew = "version-skew" // ruleset snapshot changed since minting
	rejectStale       = "stale"        // field content changed since minting
	rejectExpired     = "expired"      // older than the acknowledgement TTL
)

// scanRejection names one presented acknowledgement token that no current
// finding claimed. It carries the token's submission index (always available),
// its bound locator and rule id when the token decodes, and a structural reason
// class — never any matched text or the token's content digest.
type scanRejection struct {
	Index   int    // 0-based position in the submitted acknowledgements
	Locator string // bound locator, or "" when the token does not decode
	RuleID  string // rule id of the finding it targeted, when one exists
	Reason  string // one of the reject* classes above
}

// reasonDetail is the caller-safe explanation for a rejection class.
func reasonDetail(reason string) string {
	switch reason {
	case rejectStale:
		return "the field content changed since the token was minted"
	case rejectVersionSkew:
		return "the ruleset version changed since the token was minted"
	case rejectSurplus:
		return "no current finding corresponds to this token"
	case rejectExpired:
		return "the acknowledgement token has expired"
	default:
		return "the token is unreadable or was minted for a different surface"
	}
}

// Describe renders one rejection for the refusal body and CLI, naming the token
// (by submission index and, when it decodes, its bound locator/rule) and the
// structural reason. It embeds no matched text.
func (r scanRejection) Describe() string {
	who := fmt.Sprintf("token #%d", r.Index+1)
	if r.Locator != "" {
		who += " (" + r.Locator
		if r.RuleID != "" {
			who += "/" + r.RuleID
		}
		who += ")"
	}
	return fmt.Sprintf("%s: %s — %s", who, r.Reason, reasonDetail(r.Reason))
}

// declFieldObject is the audit object for a Surface-2 event: the immutable
// declaration-field locator class (ADR §5), never an instance-derived id.
func declFieldObject(locator string) audit.Object {
	return audit.Object{Type: "declaration_field", ID: locator}
}

func (d declScanResult) refuses() bool { return len(d.blocked) > 0 || len(d.rejections) > 0 }

// scanDeclaration scans every leaf, matches presented override tokens against
// the current findings, and classifies each finding as overridden (valid token)
// or blocked (none). It mints no events and performs no writes — the caller
// shapes the outcome into the §7 transaction (refuse: block events alone;
// accept: override events with the write). Exceeding maxRequestFindings fails
// closed (ADR §7).
// ingress is the audit ingress class (edit / plan / apply) this scan runs at; it
// stamps each blocked finding's Surface and each override's ingress so the events
// carry the door that fired (ADR §5).
func scanDeclaration(ctx context.Context, kr *crypto.Keyring, rs *scanning.Ruleset,
	leaves []scanLeaf, acks *ackSet, now time.Time, ingress string) (declScanResult, error) {
	if rs == nil {
		// Scanning off (pre-#74 test); a booted server always wires the ruleset.
		return declScanResult{}, nil
	}
	var res declScanResult
	var findings []declFinding
	total := 0
	for _, leaf := range leaves {
		matches, err := rs.Scan(ctx, leaf.Content)
		if err != nil {
			return declScanResult{}, err
		}
		if len(matches) == 0 {
			continue
		}
		cSHA := contentDigest(leaf.Content)
		for _, m := range matches {
			digest, ok := rs.SemanticDigest(m.RuleID)
			if !ok {
				return declScanResult{}, fmt.Errorf("service: rule %q has no semantic digest", m.RuleID)
			}
			total++
			if total > maxRequestFindings {
				return declScanResult{}, errFindingCap
			}
			// Retained so a leftover token can be named against a current finding.
			findings = append(findings, declFinding{locator: leaf.Locator, ruleID: m.RuleID, ruleDigest: digest, cSHA: cSHA})
			if acks != nil {
				if tok, matched := acks.match(kr, ackKindDecl, leaf.Locator, digest, rs.SnapshotVersion(), cSHA, now); matched {
					res.overridden = append(res.overridden, overrideAck{ruleID: m.RuleID, locator: leaf.Locator, ackRef: ackRef(tok), ingress: ingress})
					continue
				}
			}
			tok, err := sealAck(kr, ackBinding{
				kind: ackKindDecl, locator: leaf.Locator, ruleDigest: digest,
				contentSHA: cSHA, snapshot: rs.SnapshotVersion(), mintNano: now.UnixNano(),
			})
			if err != nil {
				return declScanResult{}, err
			}
			res.blocked = append(res.blocked, Finding{
				RuleID: m.RuleID, Surface: ingress, Locator: leaf.Locator, Acknowledgement: tok,
			})
		}
	}
	if acks != nil {
		res.rejections = acks.classifyRejections(kr, findings, rs.SnapshotVersion(), now)
	}
	return res, nil
}

// scanRefusalErr is the Surface-2 block returned to the transport: a
// bad_request-class refusal carrying the typed findings array. Each blocked
// finding names its immutable locator, rule id, and a fresh content-bound
// acknowledgement token; rejections name surplus/stale tokens.
type scanRefusalErr struct {
	blocked    []Finding
	rejections []scanRejection
}

func (e *scanRefusalErr) Error() string {
	return fmt.Sprintf("secret-scanning refused the declaration: %d finding(s), %d rejected token(s)",
		len(e.blocked), len(e.rejections))
}

// Is lets callers and the transport treat a scan refusal as an invalid-input
// refusal (bad_request class) without matching on the concrete type.
func (e *scanRefusalErr) Is(target error) bool { return target == domain.ErrInvalid }

// Findings is the typed detail the transport renders into the Error body's
// findings array.
func (e *scanRefusalErr) Findings() []Finding { return e.blocked }

// Rejections names the tokens the resubmission presented that no current
// finding claimed — each rendered as a caller-safe string carrying its
// submission index, bound locator/rule, and a structural reason class (ADR §4 /
// SS3). Strings (not the unexported struct) so the contract crosses the package
// boundary and embeds no matched text.
func (e *scanRefusalErr) Rejections() []string {
	out := make([]string, len(e.rejections))
	for i, r := range e.rejections {
		out[i] = r.Describe()
	}
	return out
}

// SafeDetail is the caller-safe refusal body. It names each blocked field's
// locator+rule and each rejected token BY NAME (index, bound locator/rule,
// reason class) — never any matched text. Both halves are rendered so a refusal
// carrying ONLY rejected tokens (every finding overridden, but a surplus/stale
// token presented) is not an empty message.
func (e *scanRefusalErr) SafeDetail() string {
	var parts []string
	if len(e.blocked) > 0 {
		locators := make([]string, 0, len(e.blocked))
		for _, f := range e.blocked {
			locators = append(locators, f.Locator+" ("+f.RuleID+")")
		}
		parts = append(parts, fmt.Sprintf("a declaration field carries a credential-shaped string: %s", strings.Join(locators, ", ")))
	}
	if len(e.rejections) > 0 {
		named := make([]string, 0, len(e.rejections))
		for _, r := range e.rejections {
			named = append(named, r.Describe())
		}
		parts = append(parts, "rejected acknowledgement token(s): "+strings.Join(named, "; "))
	}
	return strings.Join(parts, "; ")
}

// blockedEvent builds one finding_blocked event. The object is the finding's
// immutable locator class, never instance-derived (ADR §5). It is captured via
// az.CaptureAudit (below), the one write path that survives the rollback the
// refusal forces — so the block events land while nothing else persists.
func blockedEvent(ctx context.Context, principal domain.PrincipalID, f Finding) (audit.Event, error) {
	return domainEvent(ctx, audit.EventScanningFindingBlocked, principal, declFieldObject(f.Locator), audit.Payload{
		"rule_id": f.RuleID,
		// A blocked finding's Surface IS its ingress class (edit / plan / apply),
		// stamped by scanDeclaration — one source of truth for door identity.
		"ingress": f.Surface,
	})
}

// emitFindingOverridden writes one finding_overridden event, committed in the
// declaration write's own transaction (ADR §5,§7).
func emitFindingOverridden(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID,
	o overrideAck) error {
	ev, err := domainEvent(ctx, audit.EventScanningFindingOverridden, principal, declFieldObject(o.locator), audit.Payload{
		"rule_id":             o.ruleID,
		"ingress":             o.ingress,
		"acknowledgement_ref": o.ackRef,
	})
	if err != nil {
		return err
	}
	return r.Audit().InsertTenant(ctx, p, ev)
}

// applyDeclarationScan runs a Surface-2 scan inside a declaration ingress and
// shapes the §7 transaction. It runs post-authorize and BEFORE any declaration
// state persists.
//
//   - On refusal it CAPTURES the finding_blocked events via az.CaptureAudit —
//     the one write path that survives a rollback — and returns a *scanRefusalErr.
//     The caller returns that error from its tx closure, so the whole attempt
//     rolls back (nothing else persists) while the captured block events flush in
//     their own transaction before the refusal reaches the caller (ADR §5,§7).
//   - On acceptance it emits the finding_overridden events with r.Audit inside
//     the write's own transaction and returns nil; the caller proceeds with the
//     write, and the events commit with it.
//
// scope is the event chain the block events carry (org→project for the
// project-scoped ingresses; the org being created for org create) — passed
// explicitly because CaptureAudit binds no chain from the proof.
func applyDeclarationScan(ctx context.Context, r store.Repos, p authz.Proof, az *authz.TxAuthorizer,
	kr *crypto.Keyring, rs *scanning.Ruleset, principal domain.PrincipalID, scope domain.Scope,
	leaves []scanLeaf, acks *ackSet, ingress string) error {
	res, err := scanDeclaration(ctx, kr, rs, leaves, acks, time.Now(), ingress)
	if err != nil {
		return err
	}
	if res.refuses() {
		for _, f := range res.blocked {
			ev, err := blockedEvent(ctx, principal, f)
			if err != nil {
				return err
			}
			az.CaptureAudit(audit.TrailTenant, scope, ev)
		}
		return &scanRefusalErr{blocked: res.blocked, rejections: res.rejections}
	}
	for _, o := range res.overridden {
		if err := emitFindingOverridden(ctx, r, p, principal, o); err != nil {
			return err
		}
	}
	return nil
}

// scanSurface2Preflight reaches the Surface-2 verdict in a READ-only transaction
// BEFORE the caller resolves a project sealer. sealerFor / prepareSchemaPublish
// MINT the project DEK on first use — a wrapped-key row committed in the
// keyring adapter's OWN transaction, outside the caller's write transaction — so
// a scan that runs only inside that later write transaction leaves the minted
// row behind when it blocks, violating ADR §7 (a Surface-2 refusal persists
// NOTHING but the finding_blocked events). This helper closes the gap for the
// two ingresses that can first-mint the DEK (environment create, and key create
// on a project whose DEK no value or key has yet minted): the mint is skipped
// entirely when the scan blocks, because the caller returns before reaching the
// sealer.
//
// It authorizes (op, scope) inside the read transaction — the same authorize
// sealerFor performs before it mints — so the scan stays after-authorize and
// opens no unauthorized-scan oracle. On refusal it CAPTURES the finding_blocked
// events via az.CaptureAudit; settleDenials flushes them in their own
// transaction after the read rolls back (the read wrote nothing else), so the
// block events land while nothing else persists, and it returns *scanRefusalErr.
// On acceptance it returns the overridden acks for the caller to emit with
// r.Audit INSIDE the write transaction, so finding_overridden commits with the
// write (ADR §5,§7).
//
// The scanned leaves are request-derived (the entity name / key spec), identical
// to what the write transaction would carry, so the pre-flight verdict cannot
// diverge from an in-transaction scan of the same bytes. Ingresses that operate
// on an existing key (rename, declaration update, reclassify) never first-mint —
// the key's create already minted the DEK — and so keep the in-transaction
// applyDeclarationScan; nothing they can block mints a new row.
func scanSurface2Preflight(ctx context.Context, db *store.DB, kr *crypto.Keyring, rs *scanning.Ruleset,
	actor Actor, op authz.Operation, scope domain.Scope, leaves []scanLeaf, acks []string, ingress string) ([]overrideAck, error) {
	if rs == nil {
		// Scanning off (pre-#74 test); a booted server always wires the ruleset.
		return nil, nil
	}
	var overrides []overrideAck
	err := tx.Read(ctx, db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		if _, err := az.Authorize(ctx, caller, op, scope); err != nil {
			return err
		}
		res, err := scanDeclaration(ctx, kr, rs, leaves, newAckSet(acks), time.Now(), ingress)
		if err != nil {
			return err
		}
		if res.refuses() {
			for _, f := range res.blocked {
				ev, err := blockedEvent(ctx, caller.Principal, f)
				if err != nil {
					return err
				}
				az.CaptureAudit(audit.TrailTenant, scope, ev)
			}
			return &scanRefusalErr{blocked: res.blocked, rejections: res.rejections}
		}
		overrides = res.overridden
		return nil
	})
	if err != nil {
		return nil, err
	}
	return overrides, nil
}

// emitOverrides writes the finding_overridden events an accepted Surface-2
// pre-flight produced, inside the caller's write transaction (ADR §5,§7).
func emitOverrides(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID, overrides []overrideAck) error {
	for _, o := range overrides {
		if err := emitFindingOverridden(ctx, r, p, principal, o); err != nil {
			return err
		}
	}
	return nil
}
