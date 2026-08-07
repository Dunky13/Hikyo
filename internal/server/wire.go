package server

import (
	"encoding/json"

	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/admission"
	"github.com/Dunky13/wenv/internal/service"
)

// retryAfterSeconds is what an overloaded instance advertises, in whole
// seconds, on every pre-auth path alike.
var retryAfterSeconds = int(admission.RetryAfter.Seconds())

// wireOrg converts a service organisation to its wire shape.
//
// `metadata` round-trips absent / null / value distinctly, which is the 3.1
// nullability profile the amendment banner binds: a nil RawMessage is absent,
// a literal `null` decodes to a nil map behind a non-nil pointer, and a value
// is a value. Collapsing the first two would make "the operator cleared the
// metadata" indistinguishable from "the operator did not mention it".
func wireOrg(o service.Org) apigen.Org {
	out := apigen.Org{
		Id:        o.ID,
		Name:      o.Name,
		Active:    o.Active,
		CreatedAt: o.CreatedAt,
	}
	if len(o.Metadata) == 0 {
		return out
	}
	var decoded map[string]any
	if err := json.Unmarshal(o.Metadata, &decoded); err != nil {
		// Stored metadata that will not decode is a storage defect, not a
		// caller error. Emitting the member as absent would hide it; the
		// store validates JSON in both directions, so reaching here means
		// something upstream is broken and the response validator in the
		// contract tests is where that surfaces.
		return out
	}
	out.Metadata = &decoded
	return out
}

// marshalMetadata converts the request's optional metadata member back to the
// raw JSON the store holds. Absent and null both become nil — "no metadata"
// has one representation at rest.
func marshalMetadata(m *map[string]any) (json.RawMessage, error) {
	if m == nil || *m == nil {
		return json.RawMessage(`{}`), nil
	}
	return json.Marshal(*m)
}
