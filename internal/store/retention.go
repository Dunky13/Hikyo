package store

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
)

// GCEligibleSnapshot is one payload candidate with the effective bounded
// policy that made it eligible. It contains lineage identifiers, never value
// material.
type GCEligibleSnapshot struct {
	ID            string
	OrgID         string
	ProjectID     string
	EnvironmentID string
	Revision      int64
	// Eligible rows always carry a bounded policy, so Unlimited is false.
	Policy RetentionPolicy
}

// RetentionConsequence is transaction-time truth about a released pin's
// snapshot. A later sweep may move collection_eligible to already_collected.
type RetentionConsequence string

const (
	RetentionRetained           RetentionConsequence = "retained"
	RetentionCollectionEligible RetentionConsequence = "collection_eligible"
	RetentionAlreadyCollected   RetentionConsequence = "already_collected"
)

// RetentionReader exposes persisted scheduler health.
type RetentionReader interface {
	LastPruneSuccess(ctx context.Context, p authz.Proof) (time.Time, bool, error)
}

// RetentionRepo owns scheduler GC plus the snapshot lock that makes the
// pin-release decision transaction-time truth.
type RetentionRepo interface {
	RetentionReader
	LockSnapshot(ctx context.Context, p authz.Proof, snapshotID string) error
	Eligible(ctx context.Context, p authz.Proof, now time.Time, limit int) ([]GCEligibleSnapshot, error)
	MarkCollected(ctx context.Context, p authz.Proof, snapshotID, policy string, now time.Time) (bool, error)
	DeleteCollectedEntries(ctx context.Context, p authz.Proof, snapshotID string) (int64, error)
	SetLastPruneSuccess(ctx context.Context, p authz.Proof, at time.Time) error
}
