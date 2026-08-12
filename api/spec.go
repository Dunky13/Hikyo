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
	_ "embed"
	"errors"
	"fmt"
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
// Pre-freeze the revision is 1 and stays there: it advances only when an
// operation is added after the freeze, which is the only moment a client can
// legitimately outrun a server.
const Revision = 1

// PathPrefix is the URL version prefix. A future break gets `/api/v2`; v1
// explicitly does not plan one.
const PathPrefix = "/api/v1"

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
	loadOnce sync.Once
	doc      *openapi3.T
	router   routers.Router
	loadErr  error
)

func load() {
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

// Operations returns every operation in the contract, keyed by operationId.
func Operations() (map[string]Operation, error) {
	d, err := Doc()
	if err != nil {
		return nil, err
	}
	global := len(d.Security) > 0
	out := map[string]Operation{}
	for path, item := range d.Paths.Map() {
		for method, op := range item.Operations() {
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

// ValidateRequest checks a request against the contract and reports the
// offending member on failure.
//
// Authentication is deliberately NOT evaluated here: the security scheme is
// satisfied by resolving a session row inside the request's own transaction
// at the authorization chokepoint, never by a middleware that decides
// "authenticated" before one exists. The filter is told to accept every
// security requirement so it validates shape only.
func ValidateRequest(r *http.Request) error {
	loadOnce.Do(load)
	if loadErr != nil {
		return loadErr
	}
	route, params, err := router.FindRoute(r)
	if err != nil {
		return ErrNoRoute
	}
	input := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: params,
		Route:      route,
		Options: &openapi3filter.Options{
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		},
	}
	if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
		return &ValidationError{Member: offendingMember(err), Err: err}
	}
	return nil
}

// ValidateResponse checks a recorded response against the contract. This is
// the CI wire-response duty: contract tests assert what actually went over
// the socket, not what a handler intended.
func ValidateResponse(r *http.Request, status int, header http.Header, body []byte) error {
	loadOnce.Do(load)
	if loadErr != nil {
		return loadErr
	}
	route, params, err := router.FindRoute(r)
	if err != nil {
		return ErrNoRoute
	}
	return openapi3filter.ValidateResponse(r.Context(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    r,
			PathParams: params,
			Route:      route,
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

// OperationIDFor reports which contract operation a request resolves to, so
// the transport layer can look up its artifact eligibility and minimum
// revision without a second routing table.
func OperationIDFor(r *http.Request) (string, bool) {
	loadOnce.Do(load)
	if loadErr != nil {
		return "", false
	}
	route, _, err := router.FindRoute(r)
	if err != nil || route.Operation == nil {
		return "", false
	}
	return route.Operation.OperationID, true
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
