// Package service is the domain layer. Handlers cannot reach the datastore
// directly: internal/store is importable only by this package (and its own
// subpackages) — enforced by the import-boundary test.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// System answers operational questions for the HTTP layer.
type System struct {
	DB *store.DB
}

// Ready reports whether a request would actually work: the datastore is
// reachable. Migrations are current by construction at serve time — the
// server refuses to start otherwise (fail-closed serving).
func (s *System) Ready(ctx context.Context) error {
	return s.DB.Ping(ctx)
}

// Orgs is the demonstration aggregate's service.
type Orgs struct {
	DB *store.DB
}

// Create publishes a new org through the transactional boundary.
func (s *Orgs) Create(ctx context.Context, name string, active bool, metadata json.RawMessage) (store.Org, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return store.Org{}, fmt.Errorf("service: generate org id: %w", err)
	}
	org := store.Org{
		ID:        "org_" + id.String(),
		Name:      name,
		Active:    active,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos) error {
		return r.Orgs().Create(ctx, org)
	})
	if err != nil {
		return store.Org{}, err
	}
	return org, nil
}

func (s *Orgs) Get(ctx context.Context, id string) (store.Org, error) {
	return s.DB.Read().Orgs().Get(ctx, id)
}

func (s *Orgs) List(ctx context.Context) ([]store.Org, error) {
	return s.DB.Read().Orgs().List(ctx)
}

func (s *Orgs) Count(ctx context.Context) (int64, error) {
	return s.DB.Read().Orgs().Count(ctx)
}
