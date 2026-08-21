// Package api is the HTTP contract.
//
// `openapi.yaml` beside this file is the single source of truth for every
// consumer — the Go server types, the TypeScript client, the oasdiff freeze
// gate — and it is embedded here so a running server validates traffic
// against exactly the bytes CI diffed, never against a copy that drifted.
//
// The document is hand-written and reviewed like code: the api-cli-surface
// ADR's version promise covers behaviour (authorization formula, side
// effects, idempotency, error semantics), and no schema differ can police
// that. What CI *can* police is that the document and the Go registries agree
// — see the cross-check tests beside this file.
package api

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// SpecYAML is the contract as authored. Exported so tooling (the oasdiff
// gate's fixtures, the TypeScript generator's freshness check) reads one copy.
//
//go:embed openapi.yaml
var SpecYAML []byte

// Revision is this server's API revision, advertised at `/api/v1/meta`. A
// client compares an operation's `x-hikyo-min-revision` against it and refuses
// unsupported verbs naming the server version — a bare version string is not
// the mechanism, the per-operation registry is.
//
// Revision 2 introduces the definitions Git-flow operations. Every pre-existing
// operation remains revision 1; clients gate only the new verbs on revision 2.
const Revision = 2

// PathPrefix is the URL version prefix. A future break gets `/api/v2`; v1
// explicitly does not plan one.
const PathPrefix = "/api/v1"

// scimMediaType is RFC 7644's content type. It is spelled here rather than
// imported from internal/scimproto because api may not depend on internal.
const scimMediaType = "application/scim+json"

// Extension keys. Each is cross-checked against a Go registry in CI, so the
// document cannot describe an authorization posture the code does not have.
const (
	extClass       = "x-hikyo-class"
	extOperation   = "x-hikyo-operation"
	extFormula     = "x-hikyo-formula"
	extArtifacts   = "x-hikyo-artifacts"
	extMinRevision = "x-hikyo-min-revision"
	// ExtOpenEnum marks an enum declared OPEN: it may gain values additively
	// and every generated consumer must tolerate unknown ones. Open enums
	// deliberately carry no `enum` keyword, so runtime validation tolerates
	// growth rather than rejecting a newer server's response.
	ExtOpenEnum = "x-extensible-enum"
)

var (
	loadOnce   sync.Once
	doc        *openapi3.T
	router     routers.Router
	operations map[string]Operation
	loadErr    error
)

// scimJSONDecoder teaches the request validator to read `application/scim+json`
// (RFC 7644 §3.1). kin-openapi ships decoders for `application/json` and a few
// others and refuses anything else outright, so without this every SCIM request
// is rejected as an unsupported content type before its schema is even
// consulted — a 400 that looks like the identity provider's fault and is not.
//
// The bytes ARE JSON; only the media type differs, so the decoder is the JSON
// one. It is registered once, beside the document load, because the validator
// is a package-level singleton and a decoder registered later would apply to
// some requests and not others.
func scimJSONDecoder(body io.Reader, _ http.Header, _ *openapi3.SchemaRef, _ openapi3filter.EncodingFn) (any, error) {
	// The protocol's own 1 MiB bound applies LATER, in the handler. Contract
	// validation runs first and materializes the whole body, so without a bound
	// here a pre-auth request could exhaust memory before anything checked its
	// size. Read one byte past the bound: a short read proves it fits.
	limited := io.LimitReader(body, SCIMBodyBound+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > SCIMBodyBound {
		return nil, errors.New("api: the SCIM request body exceeds the bound")
	}
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	// A single Decode stops at the end of the first JSON value, so
	// `{"a":1}{"b":2}` would validate as `{"a":1}` and the handler would parse
	// something the contract never saw. Require the reader to be spent.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("api: trailing content after the SCIM request body")
	}
	return decoded, nil
}

// SCIMBodyBound is the largest SCIM request body this server accepts
// (ops-catalogue SCIM § "Wire request body cap": 256 KiB, fixed). It is
// declared here, at the FIRST place that materializes one, and re-stated by the
// protocol package's own check so the two cannot drift apart silently.
const SCIMBodyBound = 256 << 10

func load() {
	openapi3filter.RegisterBodyDecoder(scimMediaType, scimJSONDecoder)
	// The bound profile is checked HERE, not only in tests: kin-openapi's
	// generic validation happily accepts a prohibited dialect or a legacy
	// `nullable`, so without this the runtime would enforce a document the
	// freeze policy would refuse. The two must agree about what the contract
	// even is.
	if loadErr = CheckProfile(SpecYAML); loadErr != nil {
		loadErr = fmt.Errorf("api: openapi.yaml violates the bound 3.1 profile: %w", loadErr)
		return
	}
	loader := &openapi3.Loader{IsExternalRefsAllowed: false}
	doc, loadErr = loader.LoadFromData(SpecYAML)
	if loadErr != nil {
		loadErr = fmt.Errorf("api: load openapi.yaml: %w", loadErr)
		return
	}
	if loadErr = doc.Validate(loader.Context); loadErr != nil {
		loadErr = fmt.Errorf("api: openapi.yaml is not a valid document: %w", loadErr)
		return
	}
	operations, loadErr = collectOperations(doc)
	if loadErr != nil {
		return
	}
	router, loadErr = gorillamux.NewRouter(doc)
	if loadErr != nil {
		loadErr = fmt.Errorf("api: build router: %w", loadErr)
	}
}

// Doc returns the parsed contract. It fails loudly rather than serving
// unvalidated traffic: an unparseable embedded document is a build defect.
func Doc() (*openapi3.T, error) {
	loadOnce.Do(load)
	return doc, loadErr
}

// Operation is one row of the contract registry, derived from the document
// rather than restated in Go — one source, no drift.
type Operation struct {
	ID          string
	Method      string
	Path        string
	Class       string
	AuthzOp     string
	Formula     []string
	Artifacts   []string
	MinRevision int
	// Secured reports whether the operation inherits the document's session
	// security requirement. An operation that clears it with `security: []`
	// is a pre-authentication path and must be classified as one.
	Secured bool
}

const (
	ArtifactNone               = "none"
	ArtifactHumanSession       = "human-session"
	ArtifactMachineCredential  = "machine-credential"
	ArtifactSCIMCredential     = "scim-credential"
	ArtifactInstanceCredential = "instance-credential"
	ArtifactLocal              = "local"
)

// AdmitsArtifact reports whether the operation's OpenAPI declaration admits
// the authenticated artifact class. The declaration is a closed allowlist.
func (o Operation) AdmitsArtifact(class string) bool {
	for _, declared := range o.Artifacts {
		if declared == class {
			return true
		}
	}
	return false
}

func cloneOperation(op Operation) Operation {
	op.Formula = append([]string(nil), op.Formula...)
	op.Artifacts = append([]string(nil), op.Artifacts...)
	return op
}

// AuthorizationOperationAdmitsArtifact reports whether any contract operation
// mapped to the named authorization operation admits class. The HTTP path uses
// its exact operation row; this derived view preserves the same contract at
// in-process chokepoint calls where no request operation exists.
func AuthorizationOperationAdmitsArtifact(id, class string) (admitted, described bool) {
	loadOnce.Do(load)
	if loadErr != nil {
		return false, false
	}
	for _, op := range operations {
		if op.AuthzOp != id {
			continue
		}
		described = true
		if op.AdmitsArtifact(class) {
			admitted = true
		}
	}
	return admitted, described
}

type operationContextKey struct{}

// OperationFromContext returns the contract row attached at HTTP admission.
// Absence means an in-process caller rather than an unclassified HTTP route.
func OperationFromContext(ctx context.Context) (Operation, bool) {
	op, ok := ctx.Value(operationContextKey{}).(Operation)
	if !ok || op.ID == "" {
		return Operation{}, false
	}
	return cloneOperation(op), true
}

func withOperation(ctx context.Context, op Operation) context.Context {
	if op.ID == "" {
		return ctx
	}
	return context.WithValue(ctx, operationContextKey{}, cloneOperation(op))
}

// Operations returns every operation in the contract, keyed by operationId.
func Operations() (map[string]Operation, error) {
	_, err := Doc()
	if err != nil {
		return nil, err
	}
	out := make(map[string]Operation, len(operations))
	for id, op := range operations {
		out[id] = cloneOperation(op)
	}
	return out, nil
}

func collectOperations(d *openapi3.T) (map[string]Operation, error) {
	global := len(d.Security) > 0
	out := map[string]Operation{}
	for path, item := range d.Paths.Map() {
		for method, op := range item.Operations() {
			var err error
			row := Operation{
				ID:      op.OperationID,
				Method:  method,
				Path:    path,
				Secured: global,
			}
			if op.Security != nil {
				row.Secured = len(*op.Security) > 0
			}
			if row.Class, err = extString(op.Extensions, extClass); err != nil {
				return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
			}
			if row.AuthzOp, err = optionalString(op.Extensions, extOperation); err != nil {
				return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
			}
			if row.Formula, err = optionalStrings(op.Extensions, extFormula); err != nil {
				return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
			}
			if row.Artifacts, err = extStrings(op.Extensions, extArtifacts); err != nil {
				return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
			}
			if len(row.Artifacts) == 0 {
				return nil, fmt.Errorf("api: %s %s: extension %s must declare at least one artifact class", method, path, extArtifacts)
			}
			if row.MinRevision, err = extInt(op.Extensions, extMinRevision); err != nil {
				return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
			}
			if row.ID == "" {
				return nil, fmt.Errorf("api: %s %s has no operationId", method, path)
			}
			if _, dup := out[row.ID]; dup {
				return nil, fmt.Errorf("api: duplicate operationId %q", row.ID)
			}
			out[row.ID] = row
		}
	}
	return out, nil
}

// ErrNoRoute reports a request that the contract does not describe. It is a
// distinct error because the response differs from a malformed request: an
// undescribed path is a 404, a described path with a bad body is a 400.
var ErrNoRoute = errors.New("api: no route in the contract matches this request")

// ValidationError wraps a contract violation with the request member that
// caused it. The member name is safe to return to the caller: request-shape
// validation happens before any tenant resolution, so it reveals nothing
// about what exists or who may reach it.
type ValidationError struct {
	Member string
	Err    error
}

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

type resolvedRequest struct {
	request *http.Request
	route   *routers.Route
	params  map[string]string
	op      Operation
}

func resolveRequest(r *http.Request) (*resolvedRequest, error) {
	loadOnce.Do(load)
	if loadErr != nil {
		return nil, loadErr
	}
	route, params, err := router.FindRoute(r)
	if err != nil {
		return nil, ErrNoRoute
	}
	if route == nil || route.Operation == nil {
		return nil, fmt.Errorf("api: matched route %q has no OpenAPI operation", r.URL.Path)
	}
	op, ok := operations[route.Operation.OperationID]
	if !ok {
		return nil, fmt.Errorf("api: matched operation %q is absent from the contract registry", route.Operation.OperationID)
	}
	return &resolvedRequest{request: r, route: route, params: params, op: cloneOperation(op)}, nil
}

// MatchedRequest is one request's single resolution through the contract:
// the route the OpenAPI router matched, its path parameters, and a cloned
// immutable operation row. The mutable kin-openapi values stay attempt-local
// and never enter a request context.
type MatchedRequest struct {
	request *http.Request
	route   *routers.Route
	params  map[string]string
	op      Operation
}

// ValidatedRequest carries the original request and the cloned operation row
// proven by its validation. Its fields are private, so another package cannot
// construct an alternate row or attach one to a different request.
type ValidatedRequest struct {
	request *http.Request
	op      Operation
}

// MatchRequest resolves a request through the embedded contract exactly once.
// A request the contract does not describe is ErrNoRoute — the caller's 404,
// distinct from a described route carrying a bad request.
func MatchRequest(r *http.Request) (*MatchedRequest, error) {
	resolved, err := resolveRequest(r)
	if err != nil {
		return nil, err
	}
	return &MatchedRequest{
		request: resolved.request,
		route:   resolved.route,
		params:  resolved.params,
		op:      resolved.op,
	}, nil
}

// Operation returns a copy of the immutable contract row this request matched.
// Consumers may hold and read it; editing the copy changes nothing.
func (m *MatchedRequest) Operation() Operation { return cloneOperation(m.op) }

// Validate checks the matched request against the contract and reports the
// offending member on failure. The request is validated AS MATCHED: a caller
// that replaces r.Body on the same *http.Request between MatchRequest and
// Validate (the SCIM wire body bound does) is honoured; one that swaps in a
// different request must match again.
//
// Authentication is deliberately NOT evaluated here: the security scheme is
// satisfied by resolving a session row inside the request's own transaction
// at the authorization chokepoint, never by a middleware that decides
// "authenticated" before one exists. The filter is told to accept every
// security requirement so it validates shape only. Only successful validation
// returns a value capable of attaching the matched operation to context.
func (m *MatchedRequest) Validate() (*ValidatedRequest, error) {
	input := &openapi3filter.RequestValidationInput{
		Request:    m.request,
		PathParams: m.params,
		Route:      m.route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			// The SCIM WIRE routes' bodies are validated by the protocol layer,
			// after the provisioning credential authenticates — not here.
			//
			// Contract validation runs before any credential is resolved, so a
			// body check here answers an unauthenticated caller with a Hikyo 400
			// describing what is wrong with their request. The wire's contract
			// is that nothing about a request is answered before the caller has
			// proved they may ask; the uniform 401 is the whole answer.
			//
			// Nothing is lost: the SCIM body schema is deliberately open
			// (`additionalProperties: true`, no required members), so this
			// check only ever rejected "not a JSON object" — which
			// `scimproto.DecodeUser`/`DecodeGroup`/`ParsePatch` reject
			// themselves, post-auth, as an RFC 7644 `invalidSyntax`.
			ExcludeRequestBody: IsSCIMWireOperation(m.op.ID),
		},
	}
	if err := openapi3filter.ValidateRequest(m.request.Context(), input); err != nil {
		return nil, &ValidationError{Member: offendingMember(err), Err: err}
	}
	return &ValidatedRequest{request: m.request, op: cloneOperation(m.op)}, nil
}

// Operation returns a copy of the operation row proven by validation.
func (v *ValidatedRequest) Operation() Operation {
	if v == nil {
		return Operation{}
	}
	return cloneOperation(v.op)
}

// Request returns the request that passed validation with its immutable
// operation row attached. It deliberately accepts no request or context: a
// caller cannot validate route A and attach that result to request B.
func (v *ValidatedRequest) Request() *http.Request {
	if v == nil || v.request == nil {
		return nil
	}
	return v.request.WithContext(withOperation(v.request.Context(), v.op))
}

// ValidateRequest matches and validates once, returning the immutable row that
// passed validation. Admission uses the two-step form because SCIM body policy
// must run between matching and shape validation.
func ValidateRequest(r *http.Request) (*ValidatedRequest, error) {
	match, err := MatchRequest(r)
	if err != nil {
		return nil, err
	}
	return match.Validate()
}

// IsSCIMWireOperation reports whether a contract operation is one of the
// identity provider's own protocol endpoints, as opposed to the SCIM
// ADMINISTRATION surface (which is ordinary domain surface under a human
// session and is validated pre-auth like everything else).
//
// The two families are told apart by their operation-id shape, which is a
// convention this function makes load-bearing: wire operations are
// `scim<Verb>`, administration operations are `<verb>Scim<Noun>`. The contract
// cross-check test pins that both families are non-empty, so a renamed
// operation cannot silently move a route from one side to the other.
func IsSCIMWireOperation(operationID string) bool {
	return strings.HasPrefix(operationID, "scim")
}

// ValidateResponse checks a recorded response against the contract. This is
// the CI wire-response duty: contract tests assert what actually went over
// the socket, not what a handler intended.
func ValidateResponse(r *http.Request, status int, header http.Header, body []byte) error {
	resolved, err := resolveRequest(r)
	if err != nil {
		return err
	}
	return openapi3filter.ValidateResponse(r.Context(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    r,
			PathParams: resolved.params,
			Route:      resolved.route,
			Options: &openapi3filter.Options{
				AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			},
		},
		Status: status,
		Header: header,
		Body:   readCloser(body),
		Options: &openapi3filter.Options{
			AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
			IncludeResponseStatus: true,
		},
	})
}

// OperationFor reports the full contract row for the request. Artifact
// admission consumes this row at runtime, so the same embedded OpenAPI bytes
// drive both request validation and bearer-class eligibility.
func OperationFor(r *http.Request) (Operation, bool) {
	resolved, err := resolveRequest(r)
	if err != nil {
		return Operation{}, false
	}
	return cloneOperation(resolved.op), true
}

// jsonPointerInReason recovers the offending member from a schema error.
//
// Under the 3.1 profile kin-openapi validates through a 2020-12 engine and
// reports the location inside SchemaError.Reason (`at "/username"`) rather
// than in the structured JSONPointer, which comes back empty. Reading it out
// of the message is a version-coupled shortcut, so
// TestRequestValidationReportsTheOffendingMember pins it: a kin-openapi
// upgrade that changes the phrasing fails the build instead of quietly
// degrading every `bad_request` detail to "body".
var jsonPointerInReason = regexp.MustCompile(`at "(/[^"]*)"`)

func offendingMember(err error) string {
	var reqErr *openapi3filter.RequestError
	if !errors.As(err, &reqErr) {
		return "request"
	}
	if reqErr.Parameter != nil {
		return reqErr.Parameter.Name
	}
	var schemaErr *openapi3.SchemaError
	if errors.As(reqErr.Err, &schemaErr) {
		if path := schemaErr.JSONPointer(); len(path) > 0 {
			return path[len(path)-1]
		}
	}
	if m := jsonPointerInReason.FindStringSubmatch(err.Error()); m != nil {
		if segments := strings.Split(strings.TrimPrefix(m[1], "/"), "/"); segments[0] != "" {
			return segments[len(segments)-1]
		}
	}
	return "body"
}

func extString(ext map[string]any, key string) (string, error) {
	v, err := optionalString(ext, key)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("missing required extension %s", key)
	}
	return v, nil
}

func optionalString(ext map[string]any, key string) (string, error) {
	raw, ok := ext[key]
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("extension %s is not a string", key)
	}
	return s, nil
}

func extStrings(ext map[string]any, key string) ([]string, error) {
	out, err := optionalStrings(ext, key)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("missing required extension %s", key)
	}
	return out, nil
}

func optionalStrings(ext map[string]any, key string) ([]string, error) {
	raw, ok := ext[key]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("extension %s is not a list", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("extension %s holds a non-string entry", key)
		}
		out = append(out, s)
	}
	return out, nil
}

func extInt(ext map[string]any, key string) (int, error) {
	raw, ok := ext[key]
	if !ok {
		return 0, fmt.Errorf("missing required extension %s", key)
	}
	switch v := raw.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("extension %s is not an integer", key)
		}
		return int(v), nil
	case uint64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("extension %s is not an integer (%T)", key, raw)
	}
}
