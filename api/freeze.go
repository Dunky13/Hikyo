package api

import (
	"errors"
	"fmt"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oasdiff/oasdiff/checker"
	"github.com/oasdiff/oasdiff/diff"
	oasload "github.com/oasdiff/oasdiff/load"
)

// The freeze gate (api-cli-surface ADR § Version promise).
//
// "The freeze is a CI invariant, not a doc sentence": once the freeze tag
// exists, the pipeline diffs api/openapi.yaml against the immutable freeze
// commit with a full structural diff, FAIL-CLOSED OVER AN ALLOWLIST of
// permitted addition change-types. Any change id not on the allowlist — a
// change oasdiff classes below "breaking", or one a future oasdiff version
// introduces — is a red build.
//
// Trusting oasdiff's own breaking/non-breaking taxonomy was considered and
// rejected: it classes some forbidden changes as warning or info, notably
// removals after a deprecation window this promise does not offer. Severity
// is oasdiff's opinion; the allowlist is Hikyo's policy.
//
// State of this gate today: NO FREEZE TAG EXISTS, so there is no immutable
// base to diff against and the gate cannot bind the live contract yet. It is
// therefore FIXTURE-PROVEN NOW AND FREEZE-ARMED LATER — the fixtures below
// exercise every rule against synthetic base/revised pairs, so the machinery
// is known to work on the day the tag is cut rather than being written that
// day.

// PermittedChanges is the fail-closed allowlist: the oasdiff change ids that
// count as permitted additions under the version promise.
//
// The promise is: new endpoints, new OPTIONAL request fields, new response
// fields, and growth of enums declared open. Everything else — including
// anything oasdiff invents in a future release — is refused until reviewed
// and added here deliberately.
var PermittedChanges = map[string]bool{
	// New surface.
	"endpoint-added":                    true,
	"api-operation-id-added":            true,
	"api-tag-added":                     true,
	"response-media-type-added":         true,
	"response-success-status-added":     true,
	"response-non-success-status-added": true,

	// New optional inputs. A new REQUIRED request property is deliberately
	// absent: it breaks every existing client on the day it ships.
	"new-optional-request-parameter":        true,
	"new-optional-request-property":         true,
	"new-optional-request-header-parameter": true,
	"request-property-became-optional":      true,
	"request-parameter-became-optional":     true,

	// New outputs. Clients must ignore unknown fields — stated in the spec —
	// so a response gaining a member is additive by construction.
	//
	// `response-property-became-optional` is deliberately ABSENT: a field
	// every existing client was entitled to require, becoming one the server
	// may omit, breaks each of them. oasdiff does not grade it as breaking;
	// this promise does.
	"response-property-added":          true,
	"response-optional-property-added": true,
	"response-required-property-added": true,

	// Enum growth is deliberately NOT allowlisted, and the reason is worth
	// stating because the naive reading is the opposite. An OPEN enum carries
	// no `enum` keyword at all — growth is an edit to `x-extensible-enum`,
	// which oasdiff does not report as an enum change — so permitting
	// `*-enum-value-added` would buy nothing for open enums and would licence
	// growth of the CLOSED ones, which never grow. oasdiff cannot tell the
	// two apart; leaving the ids off the list is what makes the distinction
	// hold.

	// Documentation-only movement. It changes no wire behaviour, and refusing
	// it would make improving a description a breaking change.
	"api-deprecated":                        true,
	"endpoint-deprecated":                   true,
	"api-description-changed":               true,
	"api-summary-changed":                   true,
	"description-changed":                   true,
	"request-property-description-changed":  true,
	"response-property-description-changed": true,
}

// Violation is one refused change.
type Violation struct {
	ID        string
	Operation string
	Path      string
	Text      string
	Level     string
}

func (v Violation) String() string {
	where := v.Path
	if v.Operation != "" {
		where = v.Operation + " " + v.Path
	}
	if where == "" {
		where = "(document)"
	}
	return fmt.Sprintf("[%s] %s: %s (oasdiff level %s)", v.ID, where, v.Text, v.Level)
}

// CheckFreeze diffs revised against base and returns every change that is not
// a permitted addition, plus any violation of the bound 3.1 profile.
//
// Both halves matter and neither subsumes the other: oasdiff sees structural
// change but has no opinion about `nullable` or `jsonSchemaDialect`, and
// CheckProfile sees the profile but has no memory of what the document said
// yesterday.
func CheckFreeze(base, revised []byte) ([]Violation, error) {
	if err := CheckProfile(revised); err != nil {
		return []Violation{{
			ID: "hikyo-profile", Text: err.Error(), Level: "ERR",
		}}, nil
	}

	baseSpec, err := specInfo(base, "freeze-base")
	if err != nil {
		return nil, fmt.Errorf("freeze gate: loading the base document: %w", err)
	}
	revisedSpec, err := specInfo(revised, "openapi.yaml")
	if err != nil {
		return nil, fmt.Errorf("freeze gate: loading the revised document: %w", err)
	}

	// GetWithOperationsSourcesMap, not Get: several checks dereference the
	// sources map, so passing nil panics rather than degrading. A gate that
	// crashes is a gate that gets skipped.
	report, sources, err := diff.GetWithOperationsSourcesMap(diff.NewConfig(), baseSpec, revisedSpec)
	if err != nil {
		return nil, fmt.Errorf("freeze gate: diffing: %w", err)
	}

	// Every check, down to INFO. The default run reports breaking changes
	// only, which is precisely the fail-open behaviour the ADR rejects.
	config := checker.NewConfig(checker.GetAllChecks())
	changes := checker.CheckBackwardCompatibilityUntilLevel(config, report, sources, checker.INFO)

	var violations []Violation
	for _, change := range changes {
		id := change.GetId()
		if PermittedChanges[id] {
			continue
		}
		violations = append(violations, Violation{
			ID:        id,
			Operation: change.GetOperation(),
			Path:      change.GetPath(),
			Text:      change.GetUncolorizedText(checker.NewDefaultLocalizer()),
			Level:     change.GetLevel().String(),
		})
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].ID != violations[j].ID {
			return violations[i].ID < violations[j].ID
		}
		return violations[i].Path < violations[j].Path
	})
	return violations, nil
}

// ErrFrozen reports that the gate refused a change.
var ErrFrozen = errors.New("api: change refused by the freeze gate")

// specInfo parses a document into the shape oasdiff wants, with references
// resolved (it expects them resolved and does not resolve them itself).
func specInfo(raw []byte, name string) (*oasload.SpecInfo, error) {
	loader := &openapi3.Loader{IsExternalRefsAllowed: false}
	doc, err := loader.LoadFromData(raw)
	if err != nil {
		return nil, err
	}
	return &oasload.SpecInfo{Spec: doc, Url: name}, nil
}
