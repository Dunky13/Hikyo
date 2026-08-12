// Package badstore is a negative fixture for the proof-signature analyzer:
// a repository surface that omits proofs and smuggles tenant-typed
// identifiers, both directly and through a struct field.
package badstore

import (
	"context"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
)

type Filter struct {
	Org domain.OrgID // transitive smuggle
}

type WidgetRepo interface {
	// Missing proof parameter entirely.
	Get(ctx context.Context, id string) (string, error)
	// Proof present but a tenant-typed parameter beside it.
	List(ctx context.Context, p authz.Proof, org domain.OrgID) ([]string, error)
	// Tenant type hidden in a struct field.
	Search(ctx context.Context, p authz.Proof, f Filter) ([]string, error)
}

type Repos interface {
	Widgets() WidgetRepo
}

type ReadRepos interface {
	Widgets() WidgetRepo
}
