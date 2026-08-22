// Package scimproto is the SCIM 2.0 wire protocol Hikyo implements: the closed
// resource set, the closed filter grammar, the closed PATCH operation x path
// matrix, the RFC 7644 error shapes, and the discovery documents.
//
// It is deliberately free of storage and authorization. Everything here is a
// pure function of bytes, which is what lets the closed matrix and the closed
// error mapping have one fixture per cell rather than one end-to-end test per
// guess (#73 §8).
//
// Nothing generic is implemented. The ADR's posture is "each advertised absent
// in ServiceProviderConfig, each refused with the RFC 7644 error shape, never
// half-implemented", so an unimplemented feature is a named refusal here and an
// honest `false` in the discovery document — never a silent partial answer.
package scimproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// Schema URIs, the only ones this server speaks.
const (
	SchemaUser          = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError         = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaSPConfig      = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType  = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchemaRes     = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	SchemaEnterpriseExt = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

// MediaType is the SCIM content type. Responses use it; requests are accepted
// with it or with plain JSON, because real IdPs send both.
const MediaType = "application/scim+json"

// scimType values, the closed 400-class discriminator set (§8).
const (
	TypeInvalidFilter = "invalidFilter"
	TypeInvalidPath   = "invalidPath"
	TypeInvalidValue  = "invalidValue"
	TypeInvalidSyntax = "invalidSyntax"
	TypeMutability    = "mutability"
	TypeUniqueness    = "uniqueness"
	TypeNoTarget      = "noTarget"
	TypeTooMany       = "tooMany"
)

// Error is an RFC 7644 error body plus the status it must be rendered with.
type Error struct {
	Status int
	// SCIMType is the 400-class discriminator. It is EMPTY for anything that is
	// not a 400-class refusal — notably the 501s, where the ADR says so by name:
	// scimType is a 400-class discriminator and putting one on a 501 would
	// invent a code the RFC does not define.
	SCIMType string
	Detail   string
}

func (e *Error) Error() string {
	if e.SCIMType == "" {
		return fmt.Sprintf("scim: %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("scim: %d %s: %s", e.Status, e.SCIMType, e.Detail)
}

// Unwrap makes an RFC error answer the domain sentinel a caller outside the
// wire would test for. The two vocabularies have to coexist: a refusal is a
// SCIM error on the wire and an invalid request everywhere else, and without
// this a service returning one would be unclassifiable off the wire.
func (e *Error) Unwrap() error {
	switch {
	case e.Status >= 500:
		return nil
	case e.Status == http.StatusNotFound:
		return domain.ErrNotFound
	case e.Status == http.StatusConflict:
		return domain.ErrConflict
	case e.Status == http.StatusUnauthorized:
		return domain.ErrUnauthenticated
	default:
		return domain.ErrInvalid
	}
}

// Body renders the error as the RFC 7644 wire object.
func (e *Error) Body() map[string]any {
	out := map[string]any{
		"schemas": []string{SchemaError},
		"status":  strconv.Itoa(e.Status),
		"detail":  e.Detail,
	}
	if e.SCIMType != "" {
		out["scimType"] = e.SCIMType
	}
	return out
}

func bad(scimType, format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, SCIMType: scimType, Detail: fmt.Sprintf(format, args...)}
}

// NotImplemented is the refusal for the four endpoint classes this server does
// not implement — Bulk, /Me, sorting and .search. HTTP 501, and NO scimType.
func NotImplemented(what string) *Error {
	return &Error{
		Status: http.StatusNotImplemented,
		Detail: what + " is not implemented by this SCIM service provider; " +
			"ServiceProviderConfig advertises it as unsupported.",
	}
}

// NotFound is the RFC's 404 for a resource id this binding did not mint.
func NotFound() *Error {
	return &Error{Status: http.StatusNotFound, Detail: "Resource not found."}
}

// Conflict maps a uniqueness violation.
func Conflict(detail string) *Error {
	return &Error{Status: http.StatusConflict, SCIMType: TypeUniqueness, Detail: detail}
}

// Unauthorized is the credential-versus-binding-path mismatch and every other
// authentication failure — NEVER a SCIM 400 (§8).
func Unauthorized() *Error {
	return &Error{Status: http.StatusUnauthorized, Detail: "Authentication failed."}
}

// ---------------------------------------------------------------------------
// Resource decoding
// ---------------------------------------------------------------------------

// bodyBound is the largest request body this surface accepts, an entry in the
// ops-spec bound registry. SCIM traffic is low-frequency administrative
// traffic with bounded pages and no fan-out, so the envelope is small on
// purpose.
//
// The same number is enforced EARLIER, in api's contract-validation decoder,
// because validation materializes the body before this package sees it. This
// check is the protocol's own statement of the bound, not the only one.
const bodyBound = 256 << 10 // 256 KiB (ops-catalogue SCIM § "Wire request body cap", fixed)

// filterBound is the largest filter this server parses. It matches the
// per-string bound: a filter is one IdP-supplied string like any other.
const filterBound = stringBound

// stringBound is the largest single IdP-supplied string this surface stores.
const stringBound = 1024

// User is the subset of RFC 7643's User this server implements. Every other
// member is accepted and round-tripped as opaque display metadata — never
// matched, never a linking key, never verified authority (§5.2).
type User struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName,omitempty"`
	// Active is decoded from the generic object rather than by the struct tag:
	// Entra sends `"True"`, which fails to unmarshal into a *bool BEFORE
	// NormalizeActive could apply the tolerance the ADR mandates.
	Active *bool          `json:"-"`
	Groups []GroupRef     `json:"groups,omitempty"`
	Meta   *Meta          `json:"meta,omitempty"`
	Extra  map[string]any `json:"-"`
}

// GroupRef is the response-only `groups` member on a User (RFC 7643 makes it
// read-only; membership is authored exclusively through Group operations).
type GroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// Group is the subset of RFC 7643's Group this server implements.
type Group struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id,omitempty"`
	ExternalID  string         `json:"externalId,omitempty"`
	DisplayName string         `json:"displayName,omitempty"`
	Members     []Member       `json:"members"`
	Meta        *Meta          `json:"meta,omitempty"`
	Extra       map[string]any `json:"-"`
}

// Member is one member reference. `Type` carries the IdP's own claim about
// what the reference points at; a group-typed one is refused by name.
type Member struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// Meta is the RFC common attribute block.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"`
}

// ErrBodyTooLarge is the named bound refusal (§9's admission entry).
var ErrBodyTooLarge = &Error{
	Status: http.StatusRequestEntityTooLarge,
	Detail: "The request body exceeds this service provider's bound.",
}

// DecodeUser parses a User resource under the parse-don't-cast discipline:
// IdP-supplied strings are attacker-influencable free text at a trust
// boundary, so they are bounded and UTF-8-checked here and nowhere later.
//
// The `password` attribute is refused BY NAME (§5.2) rather than dropped:
// silently ignoring it would let an administrator believe provisioning had set
// a credential, and the credential-establishment contract is the only path to
// one.
func DecodeUser(raw []byte) (User, *Error) {
	var generic map[string]any
	if e := decodeObject(raw, &generic); e != nil {
		return User{}, e
	}
	// SCIM attribute names are case-INSENSITIVE (RFC 7643 §2.1), so the
	// refusal has to be too: `"Password"` accepted while `"password"` refused
	// would be a refusal in name only.
	for k := range generic {
		if strings.EqualFold(k, "password") {
			return User{}, bad(TypeInvalidValue,
				"The password attribute is not supported: provisioning never establishes credentials.")
		}
	}
	var u User
	if err := json.Unmarshal(raw, &u); err != nil {
		return User{}, bad(TypeInvalidSyntax, "The request body is not a valid User resource.")
	}
	if v, present := generic["active"]; present {
		active, e := NormalizeActive(v)
		if e != nil {
			return User{}, e
		}
		u.Active = &active
	}
	if e := boundStrings("", generic, 0); e != nil {
		return User{}, e
	}
	u.Extra = generic
	return u, nil
}

// DecodeGroup parses a Group resource.
func DecodeGroup(raw []byte) (Group, *Error) {
	var generic map[string]any
	if e := decodeObject(raw, &generic); e != nil {
		return Group{}, e
	}
	var g Group
	if err := json.Unmarshal(raw, &g); err != nil {
		return Group{}, bad(TypeInvalidSyntax, "The request body is not a valid Group resource.")
	}
	if e := boundStrings("", generic, 0); e != nil {
		return Group{}, e
	}
	g.Extra = generic
	return g, nil
}

// CheckMembers applies §6's two named member refusals: a group-typed member
// (nested groups: v1 is flat, and Okta and Entra provision direct user
// members) and an empty reference. Both are `invalidValue`, 400.
func CheckMembers(members []Member) *Error {
	for _, m := range members {
		if strings.EqualFold(m.Type, "Group") {
			return bad(TypeInvalidValue, "Nested group members are not supported: this service provider is flat.")
		}
		if m.Value == "" {
			return bad(TypeInvalidValue, "A member reference carries no value.")
		}
		if e := boundString("members.value", m.Value); e != nil {
			return e
		}
	}
	return nil
}

func decodeObject(raw []byte, into *map[string]any) *Error {
	if len(raw) > bodyBound {
		return ErrBodyTooLarge
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return bad(TypeInvalidSyntax, "The request body is not a JSON object.")
	}
	return rejectDuplicateKeys(*into, 0)
}

// rejectDuplicateKeys refuses an object carrying two keys that differ only in
// case. SCIM attribute names are case-INSENSITIVE (RFC 7643 §2.1), so
// `{"userName":"a","UserName":"b"}` names one attribute twice — and the two
// readers disagree about which value wins: the generic map keeps both, while
// `encoding/json` folds them into the struct and takes the last. A body whose
// meaning depends on which decoder looks at it is not a body this server
// should accept, and it is a plausible smuggling shape (`"Password"` beside a
// benign `"password"`).
//
// Recursive, because an extension object can carry the duplicate just as well
// as the top level can.
func rejectDuplicateKeys(v any, depth int) *Error {
	if depth > 12 {
		// boundStrings owns the nesting refusal; this walk simply stops.
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		seen := make(map[string]string, len(t))
		for k, child := range t {
			folded := asciiLower(k)
			if first, dup := seen[folded]; dup {
				return bad(TypeInvalidSyntax,
					"The resource names one attribute twice, as %q and %q; SCIM attribute names are case-insensitive.",
					first, k)
			}
			seen[folded] = k
			if e := rejectDuplicateKeys(child, depth+1); e != nil {
				return e
			}
		}
	case []any:
		for _, child := range t {
			if e := rejectDuplicateKeys(child, depth+1); e != nil {
				return e
			}
		}
	}
	return nil
}

// boundStrings walks the WHOLE decoded resource. Bounding a hand-picked set of
// core fields left every extension value, and every member `display`, `type`
// and `$ref`, free to consume the entire body bound — which is the same
// resource-exhaustion surface one layer in.
func boundStrings(path string, v any, depth int) *Error {
	if depth > 12 {
		return bad(TypeInvalidValue, "The resource nests more deeply than this service provider accepts.")
	}
	switch t := v.(type) {
	case string:
		return boundString(orDefault(path, "attribute"), t)
	case map[string]any:
		for k, child := range t {
			if e := boundString("attribute name", k); e != nil {
				return e
			}
			if e := boundStrings(join(path, k), child, depth+1); e != nil {
				return e
			}
		}
	case []any:
		for _, child := range t {
			if e := boundStrings(path, child, depth+1); e != nil {
				return e
			}
		}
	}
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func boundString(name, v string) *Error {
	if len(v) > stringBound {
		return bad(TypeInvalidValue, "The %s attribute exceeds this service provider's length bound.", name)
	}
	if !utf8.ValidString(v) {
		return bad(TypeInvalidValue, "The %s attribute is not valid UTF-8.", name)
	}
	return nil
}

// NormalizeActive reads the `active` attribute, tolerating Entra's stringified
// booleans ("True"/"False") — a NAMED tolerance, not a general string-to-bool
// coercion: anything else is `invalidValue`.
func NormalizeActive(v any) (bool, *Error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, bad(TypeInvalidValue, "The active attribute must be a boolean.")
}

// ExtensionDecl is one schema extension a binding DECLARES. §5.1 admits
// `externalId` or "a declared enterprise/custom extension path" as a subject
// source, and declaration at binding creation is what closes the set: an
// extension is describable in discovery precisely because a binding named it.
type ExtensionDecl struct {
	// URN is the extension schema.
	URN string
	// Attribute is the one attribute the binding names at that URN. It is
	// empty for the built-in enterprise extension, whose attribute set is
	// fixed and fully described.
	Attribute string
}

// EnterpriseExtension is declared by every binding: it is built in, its
// attributes are the RFC's, and a connector may send them whether or not this
// binding's subject source lives there.
func EnterpriseExtension() ExtensionDecl { return ExtensionDecl{URN: SchemaEnterpriseExt} }

// Declares reports whether a URN is in a declared set.
func Declares(declared []ExtensionDecl, urn string) bool {
	for _, d := range declared {
		if strings.EqualFold(d.URN, urn) {
			return true
		}
	}
	return false
}

// SchemasFor returns the schema URIs a rendered User must declare: the core one
// plus every DECLARED extension present among its round-tripped attributes.
//
// The declared set and the discovery documents are built from the SAME list, so
// a resource can never claim conformance to a schema `/Schemas` does not
// describe — and an UNDECLARED extension never reaches here at all, because
// ingest refuses it by name.
func SchemasFor(attributes map[string]any, declared []ExtensionDecl) []string {
	out := []string{SchemaUser}
	for _, ext := range declared {
		if _, present := attributes[ext.URN]; present {
			out = append(out, ext.URN)
		}
	}
	sort.Strings(out[1:])
	return out
}

// UndeclaredExtension returns the first `urn:`-keyed top-level attribute that
// no declared extension covers, or "". A resource carrying one is refused: this
// server's discovery is "the closed truth of what it implements" (§8), and
// storing an attribute under a schema it never described would make that claim
// false the moment the resource were read back.
func UndeclaredExtension(attributes map[string]any, declared []ExtensionDecl) string {
	names := make([]string, 0, len(attributes))
	for k := range attributes {
		names = append(names, k)
	}
	sort.Strings(names) // a deterministic refusal names the same schema every time
	for _, k := range names {
		if strings.HasPrefix(strings.ToLower(k), "urn:") && !Declares(declared, k) {
			return k
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// The closed filter grammar
// ---------------------------------------------------------------------------

// FilterShape is the closed set of filters this server answers, and doubles as
// the audit payload's `filter_shape` enum.
type FilterShape string

const (
	FilterNone          FilterShape = "none"
	FilterUserNameEq    FilterShape = "userName_eq"
	FilterExternalIDEq  FilterShape = "externalId_eq"
	FilterDisplayNameEq FilterShape = "displayName_eq"
)

// Filter is a parsed filter: the shape and the single compared value.
type Filter struct {
	Shape FilterShape
	Value string
}

// Resource discriminates which attribute set a filter may name.
type Resource string

const (
	ResourceUser  Resource = "user"
	ResourceGroup Resource = "group"
)

// ParseFilter accepts exactly the four probes Okta and Entra issue —
// `userName eq "..."` and `externalId eq "..."` on Users, `displayName eq
// "..."` and `externalId eq "..."` on Groups — and refuses everything else
// with `invalidFilter`. Both discover a group by `displayName eq` before
// creating or updating it, which is why that one is not optional.
//
// It is a hand-written recognizer rather than a general SCIM filter parser on
// purpose: a general parser would accept expressions the storage layer cannot
// answer, and every one of those is a filter silently returning the wrong set.
func ParseFilter(raw string, res Resource) (Filter, *Error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Filter{Shape: FilterNone}, nil
	}
	// The bound lives HERE rather than in the contract: a schema `maxLength`
	// would refuse an over-long filter BEFORE the credential authenticates,
	// which is a pre-authentication answer about the request. Post-auth it is
	// an ordinary named refusal.
	if len(raw) > filterBound {
		return Filter{}, bad(TypeInvalidFilter,
			"The filter exceeds this service provider's bound of %d bytes.", filterBound)
	}
	attr, value, ok := splitEq(raw)
	if !ok {
		return Filter{}, bad(TypeInvalidFilter,
			"Only `attribute eq \"value\"` filters are supported by this service provider.")
	}
	switch {
	case res == ResourceUser && strings.EqualFold(attr, "userName"):
		return Filter{Shape: FilterUserNameEq, Value: value}, nil
	case res == ResourceGroup && strings.EqualFold(attr, "displayName"):
		return Filter{Shape: FilterDisplayNameEq, Value: value}, nil
	case strings.EqualFold(attr, "externalId"):
		return Filter{Shape: FilterExternalIDEq, Value: value}, nil
	}
	return Filter{}, bad(TypeInvalidFilter,
		"The attribute %q is not filterable on this resource.", attr)
}

// splitEq recognizes `attr eq "value"` with no compound operators.
//
// The scan is QUOTE-AWARE, and that is the whole point of maskQuoted below:
// RFC 7644 values are JSON string literals, so a group called
// `Sales and Marketing` or `R&D (EU)` contains the very tokens a compound
// filter would — and a naive substring scan refuses Okta's and Entra's group
// discovery probe for any group whose name happens to say "and". Logical
// operators and parentheses are refused only OUTSIDE quotes.
func splitEq(raw string) (attr, value string, ok bool) {
	mask, terminated := maskQuoted(raw)
	if !terminated {
		return "", "", false // an unterminated string literal is malformed
	}
	// asciiLower, not strings.ToLower: Unicode case folding can CHANGE BYTE
	// LENGTH (Kelvin sign to k, for one), and the index found in the folded
	// string is used to slice the ORIGINAL. A length-changing fold turns that
	// into an out-of-range slice on crafted input. Filter keywords are ASCII,
	// so an ASCII fold is both sufficient and length-preserving.
	lower := asciiLower(mask)
	if strings.ContainsAny(mask, "()") {
		return "", "", false
	}
	for _, forbidden := range []string{" and ", " or ", " not "} {
		if strings.Contains(lower, forbidden) {
			return "", "", false
		}
	}
	if strings.HasPrefix(lower, "not ") {
		return "", "", false
	}
	// Indices come from the MASK and slice the ORIGINAL: the mask preserves
	// length and only blanks the inside of string literals, so the two are
	// index-identical by construction.
	idx := strings.Index(lower, " eq ")
	if idx < 0 {
		return "", "", false
	}
	attr = strings.TrimSpace(raw[:idx])
	rest := strings.TrimSpace(raw[idx+len(" eq "):])
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", "", false
	}
	var decoded string
	if err := json.Unmarshal([]byte(rest), &decoded); err != nil {
		return "", "", false
	}
	if attr == "" || strings.ContainsAny(attr, " \t") {
		return "", "", false
	}
	return attr, decoded, true
}

// asciiLower folds A-Z only, byte for byte. Every token this scanner looks for
// — `eq`, `and`, `or`, `not` — is ASCII, and preserving length is what makes
// mask indices safe to apply to the original.
func asciiLower(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// maskQuoted blanks the CONTENTS of every JSON string literal, preserving
// length and the surrounding quotes, so a token scan sees only what is outside
// the values. It reports whether every literal was terminated.
func maskQuoted(raw string) (string, bool) {
	out := []byte(raw)
	inQuote, escaped := false, false
	for i := range out {
		c := out[i]
		switch {
		case !inQuote:
			if c == '"' {
				inQuote = true
			}
		case escaped:
			escaped, out[i] = false, ' '
		case c == '\\':
			escaped, out[i] = true, ' '
		case c == '"':
			inQuote = false
		default:
			out[i] = ' '
		}
	}
	return string(out), !inQuote
}

// ---------------------------------------------------------------------------
// Paging
// ---------------------------------------------------------------------------

// Page is a 1-based RFC 7644 page request.
type Page struct {
	StartIndex int
	Count      int
}

// ParsePage reads `startIndex` and `count`, clamping to the server's bound.
// RFC 7644 §3.4.2.4 makes `count` a request, so a larger one is answered with
// the bound rather than refused; an out-of-range page returns an empty
// `Resources` with a truthful `totalResults`, which the caller handles.
func ParsePage(startIndex, count string, bound int) (Page, *Error) {
	p := Page{StartIndex: 1, Count: bound}
	if startIndex != "" {
		v, err := strconv.Atoi(startIndex)
		if err != nil {
			return Page{}, bad(TypeInvalidValue, "startIndex must be an integer.")
		}
		// RFC 7644: a value less than 1 is interpreted as 1.
		if v < 1 {
			v = 1
		}
		p.StartIndex = v
	}
	if count != "" {
		v, err := strconv.Atoi(count)
		if err != nil {
			return Page{}, bad(TypeInvalidValue, "count must be an integer.")
		}
		if v < 0 {
			v = 0
		}
		if v > bound {
			v = bound
		}
		p.Count = v
	}
	return p, nil
}

// ListResponse renders the RFC-shaped list envelope.
func ListResponse(total int, page Page, resources []any) map[string]any {
	if resources == nil {
		resources = []any{}
	}
	return map[string]any{
		"schemas":      []string{SchemaListResponse},
		"totalResults": total,
		"startIndex":   page.StartIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}

// Slice applies a page to an ordered result set. An out-of-range page yields
// an empty slice, and the caller still reports the truthful total.
func Slice[T any](all []T, page Page) []T {
	if page.StartIndex > len(all) || page.Count == 0 {
		return nil
	}
	start := page.StartIndex - 1
	end := start + page.Count
	if end > len(all) {
		end = len(all)
	}
	return all[start:end]
}

// ---------------------------------------------------------------------------
// The closed PATCH operation x path matrix
// ---------------------------------------------------------------------------

// PatchOp is one decoded PATCH operation.
type PatchOp struct {
	Op string `json:"op"`
	// Path is the RFC's attribute path. It is named `Path` on the wire because
	// RFC 7644 names it that; nothing derived from it ever reaches an audit
	// payload field of that name, which the registry forbids.
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// PatchRequest is a decoded PatchOp message.
type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

// PathKind is the closed set of path shapes the matrix has columns for.
type PathKind int

const (
	// PathNone is the pathless value object: `{"op":"add","value":{...}}`,
	// which merges the object's attributes.
	PathNone PathKind = iota
	// PathPlain is an ordinary attribute path (`userName`, `displayName`,
	// `externalId`).
	PathPlain
	// PathActive is `active` — a Users-only column.
	PathActive
	// PathMembers is `members` — a Groups-only column.
	PathMembers
	// PathMemberValue is `members[value eq "..."]` — a Groups-only column, and
	// the only filtered path the matrix admits.
	PathMemberValue
)

// ParsedPatch is one validated operation: the matrix cell it landed in, plus
// whatever the cell needs.
type ParsedPatch struct {
	Op    string
	Kind  PathKind
	Attr  string
	Value json.RawMessage
	// MemberValue is the id named by `members[value eq "..."]`.
	MemberValue string
}

// matrixCell is one accepted cell of §8's operation x path table.
type matrixCell struct {
	op   string
	kind PathKind
}

// accepted is the matrix, verbatim from the ADR. Anything not in it refuses
// with `invalidPath`, which is the whole point of writing it as a table: a
// reader can check it against the ADR line by line, and there is no code path
// that could accept a cell the table omits.
//
//	| op \ path | (none)     | plain | active | members         | members[value eq] |
//	| add       | merge      | yes   | yes    | add refs        | -                 |
//	| replace   | merge      | yes   | yes    | replace set     | -                 |
//	| remove    | -          | yes   | -      | clear set       | remove ref        |
var accepted = map[matrixCell]bool{
	{"add", PathNone}: true, {"add", PathPlain}: true, {"add", PathActive}: true, {"add", PathMembers}: true,
	{"replace", PathNone}: true, {"replace", PathPlain}: true, {"replace", PathActive}: true, {"replace", PathMembers}: true,
	{"remove", PathPlain}: true, {"remove", PathMembers}: true, {"remove", PathMemberValue}: true,
}

// requiredAttributes may not be removed: `remove` on a plain path is accepted
// only for non-required attributes (§8's "non-required only").
var requiredAttributes = []string{"userName", "displayName", "id"}

// isRequiredAttribute compares case-INSENSITIVELY: SCIM attribute names are,
// so `remove UserName` must be refused exactly as `remove userName` is.
func isRequiredAttribute(attr string) bool {
	for _, r := range requiredAttributes {
		if strings.EqualFold(attr, r) {
			return true
		}
	}
	return false
}

// ParsePatch decodes and validates a whole PATCH request against the matrix.
//
// It validates EVERYTHING before returning, because a PATCH is atomic: any
// invalid operation fails the whole request with nothing committed. Validating
// as you apply would leave the first half of a request applied when the second
// half is refused.
func ParsePatch(raw []byte, res Resource) ([]ParsedPatch, *Error) {
	if len(raw) > bodyBound {
		return nil, ErrBodyTooLarge
	}
	var req PatchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, bad(TypeInvalidSyntax, "The request body is not a valid PatchOp message.")
	}
	if len(req.Operations) == 0 {
		return nil, bad(TypeInvalidValue, "A PatchOp message must carry at least one operation.")
	}
	if !slices.Contains(req.Schemas, SchemaPatchOp) {
		return nil, bad(TypeInvalidValue,
			"A PATCH request must declare the %q schema.", SchemaPatchOp)
	}
	out := make([]ParsedPatch, 0, len(req.Operations))
	for _, op := range req.Operations {
		parsed, e := parseOne(op, res)
		if e != nil {
			return nil, e
		}
		out = append(out, parsed)
	}
	return out, nil
}

func parseOne(op PatchOp, res Resource) (ParsedPatch, *Error) {
	verb := strings.ToLower(strings.TrimSpace(op.Op))
	switch verb {
	case "add", "replace", "remove":
	default:
		return ParsedPatch{}, bad(TypeInvalidSyntax, "Unknown PATCH operation %q.", op.Op)
	}
	kind, attr, memberValue, e := classifyPath(op.Path, res)
	if e != nil {
		return ParsedPatch{}, e
	}
	if !accepted[matrixCell{verb, kind}] {
		return ParsedPatch{}, bad(TypeInvalidPath,
			"The operation %q is not supported on the path %q by this service provider.", verb, op.Path)
	}
	if verb == "remove" && kind == PathPlain && isRequiredAttribute(attr) {
		return ParsedPatch{}, bad(TypeInvalidPath, "The attribute %q is required and cannot be removed.", attr)
	}
	if verb != "remove" && len(op.Value) == 0 {
		return ParsedPatch{}, bad(TypeInvalidValue, "The operation %q requires a value.", verb)
	}
	// The value's SHAPE is part of the cell, not a later concern. Checking only
	// presence lets `active: null`, a scalar where an object belongs and a
	// non-array `members` through the matrix and into the fold, where they
	// become a silent no-op instead of the mandated `invalidValue`.
	if verb != "remove" {
		if e := checkValueShape(res, kind, op.Value); e != nil {
			return ParsedPatch{}, e
		}
	}
	return ParsedPatch{Op: verb, Kind: kind, Attr: attr, Value: op.Value, MemberValue: memberValue}, nil
}

// checkValueShape validates the value against the column it landed in.
func checkValueShape(res Resource, kind PathKind, raw json.RawMessage) *Error {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return bad(TypeInvalidValue, "The operation value is not valid JSON.")
	}
	switch kind {
	case PathNone:
		values, ok := decoded.(map[string]any)
		if !ok {
			return bad(TypeInvalidValue, "A pathless operation's value must be an object.")
		}
		if res == ResourceGroup {
			for attribute := range values {
				if !isGroupPatchAttribute(attribute) {
					return bad(TypeInvalidPath,
						"The pathless Group operation contains unsupported attribute %q.", attribute)
				}
			}
		}
	case PathActive:
		if _, e := NormalizeActive(decoded); e != nil {
			return e
		}
	case PathMembers:
		if _, ok := decoded.([]any); !ok {
			return bad(TypeInvalidValue, "The members value must be an array of references.")
		}
	case PathPlain:
		if decoded == nil {
			return bad(TypeInvalidValue, "A null value is not an assignment; use remove.")
		}
	}
	return nil
}

// classifyPath maps a raw path onto a matrix column. The matrix is PER
// RESOURCE: `active` cells apply to Users only and `members` cells to Groups
// only, so a cross-resource path (`members` on a User, `active` on a Group)
// refuses with `invalidPath` rather than being quietly ignored.
func classifyPath(raw string, res Resource) (PathKind, string, string, *Error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return PathNone, "", "", nil
	}
	if member, ok := parseMemberFilter(p); ok {
		if res != ResourceGroup {
			return 0, "", "", bad(TypeInvalidPath, "The path %q is not valid on this resource.", raw)
		}
		if member == unsupportedMemberFilter {
			// A members filter this server does not implement —
			// `members[display eq "…"]`, say. §8's closed mapping puts an
			// unaccepted PATCH cell at `invalidPath`, not `invalidValue`:
			// nothing is wrong with the VALUE, the path is simply not one of
			// the matrix's columns.
			return 0, "", "", bad(TypeInvalidPath,
				"The filtered path %q is not supported; only `members[value eq \"…\"]` is.", raw)
		}
		if member == "" {
			// RECOGNISED, and resolving to nothing. That is `noTarget`, which
			// is a different statement from "this path is not one I implement".
			return 0, "", "", bad(TypeNoTarget, "The members filter names no member.")
		}
		return PathMemberValue, "members", member, nil
	}
	if strings.ContainsAny(p, "[]") {
		// A filtered path this server does not implement. Refusing by name is
		// the ADR's posture; guessing at it is how a PATCH silently edits the
		// wrong element.
		return 0, "", "", bad(TypeInvalidPath, "The filtered path %q is not supported.", raw)
	}
	switch {
	case strings.EqualFold(p, "active"):
		if res != ResourceUser {
			return 0, "", "", bad(TypeInvalidPath, "The path %q is not valid on this resource.", raw)
		}
		return PathActive, "active", "", nil
	case strings.EqualFold(p, "members"):
		if res != ResourceGroup {
			return 0, "", "", bad(TypeInvalidPath, "The path %q is not valid on this resource.", raw)
		}
		return PathMembers, "members", "", nil
	}
	if strings.Contains(p, ".") || strings.Contains(p, ":") {
		// Sub-attribute and schema-qualified paths are outside the closed
		// matrix; the discovery document says so and this refuses by name.
		return 0, "", "", bad(TypeInvalidPath, "The path %q is not supported by this service provider.", raw)
	}
	if !isAttrName(p) {
		return 0, "", "", bad(TypeInvalidPath, "The path %q is not a valid attribute name.", raw)
	}
	if res == ResourceGroup && !isGroupPatchAttribute(p) {
		return 0, "", "", bad(TypeInvalidPath, "The path %q is not valid on this resource.", raw)
	}
	return PathPlain, p, "", nil
}

func isGroupPatchAttribute(attribute string) bool {
	return strings.EqualFold(attribute, "displayName") ||
		strings.EqualFold(attribute, "externalId") ||
		strings.EqualFold(attribute, "members")
}

// isAttrName is RFC 7643 §2.1's ATTRNAME: an ALPHA followed by letters, digits
// ocr hyphens. Without it any string free of `.`/`:`/`[`/`]` — `"foo bar"`,
// `"()"`, `""` — walked straight into an accepted matrix cell.
func isAttrName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}

// parseMemberFilter recognizes `members[value eq "..."]`, the one filtered
// path in the matrix.
func parseMemberFilter(p string) (string, bool) {
	const prefix = "members["
	if !strings.HasPrefix(strings.ToLower(p), prefix) || !strings.HasSuffix(p, "]") {
		return "", false
	}
	inner := p[len(prefix) : len(p)-1]
	attr, value, ok := splitEq(inner)
	if !ok || !strings.EqualFold(attr, "value") {
		return unsupportedMemberFilter, true // a members filter, not one we implement
	}
	return value, true
}

// unsupportedMemberFilter distinguishes "a members filter I do not implement"
// from "the one I do implement, naming nothing". They are different refusals:
// `invalidPath` and `noTarget`.
const unsupportedMemberFilter = "\x00unsupported"

// ErrNoTarget is the RFC's `noTarget`: a PATCH path that resolved to nothing.
func ErrNoTarget(detail string) *Error { return bad(TypeNoTarget, "%s", detail) }

// ErrMutability is the write-once refusal (§5.1's subject change, and any
// other immutable attribute).
func ErrMutability(detail string) *Error { return bad(TypeMutability, "%s", detail) }

// ErrInvalidValue is the type / missing-required refusal.
func ErrInvalidValue(detail string) *Error { return bad(TypeInvalidValue, "%s", detail) }

// ErrInvalidSyntax is the RFC's `invalidSyntax`: a body that is not a valid
// resource at all. It is the shape the transport hands back when the request
// could not even be bound — the same refusal DecodeUser makes, rendered from
// one place so the two cannot disagree.
func ErrInvalidSyntax(detail string) *Error { return bad(TypeInvalidSyntax, "%s", detail) }

// AsError unwraps an *Error from an error chain, so a transport can render the
// protocol shape without type-switching on every call site.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// Discovery
//
// These three documents are "the closed truth of what this server implements"
// (§8). Every absence advertised here is ALSO refused by name at its endpoint;
// the pair is what makes "never half-implemented" checkable rather than
// aspirational.
// ---------------------------------------------------------------------------

// ServiceProviderConfig advertises the implemented subset. Every `supported`
// below is false for a reason stated at the refusal site: no Bulk, no filter
// beyond the four `eq` probes, no sorting, no ETag, and no change-password —
// provisioning never establishes credentials.
func ServiceProviderConfig(maxResults int) map[string]any {
	return map[string]any{
		"schemas":          []string{SchemaSPConfig},
		"documentationUri": "https://github.com/Hikyo-Org/Hikyo",
		"patch":            map[string]any{"supported": true},
		"bulk": map[string]any{
			"supported": false, "maxOperations": 0, "maxPayloadSize": 0,
		},
		// `supported: true` with maxResults is honest: a filter IS answered,
		// but only the four probes ParseFilter admits. The rest is
		// `invalidFilter`, which is the RFC's own answer for an unsupported
		// filter rather than a claim never to filter at all.
		"filter":         map[string]any{"supported": true, "maxResults": maxResults},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []any{map[string]any{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "A Hikyo provisioning credential, presented as a bearer token.",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig"},
	}
}

// ResourceTypes is the closed resource set: User and Group, and nothing else.
// The User type declares its supported schema EXTENSION, because a binding
// whose subject source is an extension path is describing an attribute a
// connector can only learn about from here.
func ResourceTypes(declared []ExtensionDecl) map[string]any {
	types := []any{
		map[string]any{
			"schemas": []string{SchemaResourceType},
			"id":      "User", "name": "User", "endpoint": "/Users",
			"description": "SCIM core User", "schema": SchemaUser,
			// Derived from the SAME declared list `SchemasFor` renders from and
			// ingest enforces, so a resource can never declare a schema this
			// document omits and no attribute can be stored under one.
			"schemaExtensions": schemaExtensionEntries(declared),
			"meta":             map[string]any{"resourceType": "ResourceType"},
		},
		map[string]any{
			"schemas": []string{SchemaResourceType},
			"id":      "Group", "name": "Group", "endpoint": "/Groups",
			"description": "SCIM core Group", "schema": SchemaGroup,
			"schemaExtensions": []any{},
			"meta":             map[string]any{"resourceType": "ResourceType"},
		},
	}
	return ListResponse(len(types), Page{StartIndex: 1, Count: len(types)}, types)
}

// schemaExtensionEntries renders a declared set as RFC 7643 schemaExtension
// entries. None is required: an identity provider that sends only core
// attributes provisions perfectly well.
func schemaExtensionEntries(declared []ExtensionDecl) []any {
	out := make([]any, 0, len(declared))
	for _, ext := range declared {
		out = append(out, map[string]any{"schema": ext.URN, "required": false})
	}
	return out
}

// attr builds one RFC 7643 attribute definition. The discovery document is
// "the closed truth of what this server implements" (§8), and an attribute list
// is the only place a connector can read that truth before it pushes.
func attr(name, typ, mutability, uniqueness string, required, caseExact, multi bool) map[string]any {
	return map[string]any{
		"name": name, "type": typ, "multiValued": multi,
		"required": required, "caseExact": caseExact,
		"mutability": mutability, "returned": "default", "uniqueness": uniqueness,
	}
}

// Schemas lists the schema URIs this server speaks, WITH their attribute
// definitions. The definitions are not decoration: `userName` is advertised
// `caseExact: false` (which is why it is refused as a subject source),
// `externalId` byte-exact, and the subject-source attribute immutable — every
// one of those is a refusal this server actually makes.
func Schemas(declared []ExtensionDecl) map[string]any {
	user := map[string]any{
		"schemas": []string{SchemaSchemaRes},
		"id":      SchemaUser, "name": "User",
		"description": "SCIM core User. Every attribute this server INTERPRETS is listed " +
			"below; any other attribute an identity provider sends is stored and returned " +
			"verbatim as display metadata, and is never identity material.",
		"attributes": []any{
			// `id` is an RFC common attribute rather than a core-schema one, but
			// it is listed because it is the handle every subsequent request uses
			// and a connector reading this document must know it is server-assigned
			// and immutable, not something it may choose.
			attr("id", "string", "readOnly", "global", false, true, false),
			attr("userName", "string", "readWrite", "server", true, false, false),
			attr("externalId", "string", "readWrite", "none", false, true, false),
			attr("active", "boolean", "readWrite", "none", false, false, false),
			map[string]any{
				"name": "groups", "type": "complex", "multiValued": true,
				"required": false, "mutability": "readOnly", "returned": "default",
				"description": "Membership is authored exclusively through Group operations.",
				"subAttributes": []any{
					attr("value", "string", "readOnly", "none", false, true, false),
					attr("type", "string", "readOnly", "none", false, false, false),
				},
			},
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
	group := map[string]any{
		"schemas": []string{SchemaSchemaRes},
		"id":      SchemaGroup, "name": "Group",
		"description": "SCIM core Group. Every attribute this server INTERPRETS is listed " +
			"below; any other attribute an identity provider sends is stored and returned " +
			"verbatim as display metadata.",
		"attributes": []any{
			attr("id", "string", "readOnly", "global", false, true, false),
			// displayName is deliberately NOT unique: RFC 7643 does not make it
			// so, and this server answers a `displayName eq` probe with every
			// match rather than an arbitrary one.
			attr("displayName", "string", "readWrite", "none", true, false, false),
			attr("externalId", "string", "readWrite", "none", false, true, false),
			map[string]any{
				"name": "members", "type": "complex", "multiValued": true,
				"required": false, "mutability": "readWrite", "returned": "default",
				"description": "User members only; nested groups are refused by name.",
				"subAttributes": []any{
					attr("value", "string", "immutable", "none", true, true, false),
					attr("type", "string", "immutable", "none", false, false, false),
				},
			},
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
	enterprise := map[string]any{
		"schemas": []string{SchemaSchemaRes},
		"id":      SchemaEnterpriseExt, "name": "EnterpriseUser",
		"description": "Enterprise User extension. Any attribute here may be a binding's declared subject source, in which case it is write-once per resource.",
		"attributes": []any{
			attr("employeeNumber", "string", "readWrite", "none", false, true, false),
			attr("costCenter", "string", "readWrite", "none", false, true, false),
			attr("organization", "string", "readWrite", "none", false, true, false),
			attr("division", "string", "readWrite", "none", false, true, false),
			attr("department", "string", "readWrite", "none", false, true, false),
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
	out := []any{user, group}
	for _, ext := range declared {
		if strings.EqualFold(ext.URN, SchemaEnterpriseExt) {
			out = append(out, enterprise)
			continue
		}
		// A CUSTOM extension is described by exactly what this server accepts
		// under it: the one attribute the binding declared as its subject
		// source, immutable per resource (§5.1's write-once). Enumerating more
		// would be describing attributes nothing implements.
		out = append(out, map[string]any{
			"schemas": []string{SchemaSchemaRes},
			"id":      ext.URN, "name": "DeclaredExtension",
			"description": "A custom extension declared by this binding. Only the attribute " +
				"below is accepted under it, and it is the binding's write-once subject source.",
			"attributes": []any{
				attr(ext.Attribute, "string", "immutable", "server", false, true, false),
			},
			"meta": map[string]any{"resourceType": "Schema"},
		})
	}
	return ListResponse(len(out), Page{StartIndex: 1, Count: len(out)}, out)
}
