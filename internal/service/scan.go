package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
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

	// Surface-2 audit ingress (ADR §5 finding_blocked/overridden enum). plan and
	// apply belong to #70; only edit exists at this ingress today.
	ingressEdit = "edit"
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
	locOrgName            = "org.name"
	locOrgMetadata        = "org.metadata"
	locProjectName        = "project.name"
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

// declScanResult is what scanDeclaration reports. blocked findings refuse the
// write (finding_blocked committed alone); overridden findings ride the write's
// own transaction (finding_overridden). rejections name every presented token
// that no current finding claimed — surplus, stale, version-skewed, or expired.
type declScanResult struct {
	blocked    []Finding
	overridden []overrideAck
	rejections []string
}

type overrideAck struct {
	ruleID  string
	locator string
	ackRef  string
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
func scanDeclaration(ctx context.Context, kr *crypto.Keyring, rs *scanning.Ruleset,
	leaves []scanLeaf, acks *ackSet, now time.Time) (declScanResult, error) {
	if rs == nil {
		// Scanning off (pre-#74 test); a booted server always wires the ruleset.
		return declScanResult{}, nil
	}
	var res declScanResult
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
			if acks != nil {
				if tok, matched := acks.match(kr, ackKindDecl, leaf.Locator, digest, rs.SnapshotVersion(), cSHA, now); matched {
					res.overridden = append(res.overridden, overrideAck{ruleID: m.RuleID, locator: leaf.Locator, ackRef: ackRef(tok)})
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
				RuleID: m.RuleID, Surface: ingressEdit, Locator: leaf.Locator, Acknowledgement: tok,
			})
		}
	}
	if acks != nil {
		if n := acks.unconsumed(); n > 0 {
			res.rejections = append(res.rejections,
				fmt.Sprintf("%d acknowledgement token(s) matched no current finding (surplus, stale, or version-skewed) and were rejected", n))
		}
	}
	return res, nil
}

// scanRefusalErr is the Surface-2 block returned to the transport: a
// bad_request-class refusal carrying the typed findings array. Each blocked
// finding names its immutable locator, rule id, and a fresh content-bound
// acknowledgement token; rejections name surplus/stale tokens.
type scanRefusalErr struct {
	blocked    []Finding
	rejections []string
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
// finding claimed.
func (e *scanRefusalErr) Rejections() []string { return e.rejections }

func (e *scanRefusalErr) SafeDetail() string {
	locators := make([]string, 0, len(e.blocked))
	for _, f := range e.blocked {
		locators = append(locators, f.Locator+" ("+f.RuleID+")")
	}
	return fmt.Sprintf("a declaration field carries a credential-shaped string: %v", locators)
}

// blockedEvent builds one finding_blocked event. The object is the finding's
// immutable locator class, never instance-derived (ADR §5). It is captured via
// az.CaptureAudit (below), the one write path that survives the rollback the
// refusal forces — so the block events land while nothing else persists.
func blockedEvent(ctx context.Context, principal domain.PrincipalID, f Finding) (audit.Event, error) {
	return domainEvent(ctx, audit.EventScanningFindingBlocked, principal, declFieldObject(f.Locator), audit.Payload{
		"rule_id": f.RuleID,
		"ingress": ingressEdit,
	})
}

// emitFindingOverridden writes one finding_overridden event, committed in the
// declaration write's own transaction (ADR §5,§7).
func emitFindingOverridden(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID,
	o overrideAck) error {
	ev, err := domainEvent(ctx, audit.EventScanningFindingOverridden, principal, declFieldObject(o.locator), audit.Payload{
		"rule_id":             o.ruleID,
		"ingress":             ingressEdit,
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
	leaves []scanLeaf, acks *ackSet) error {
	res, err := scanDeclaration(ctx, kr, rs, leaves, acks, time.Now())
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
