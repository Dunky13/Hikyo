// Package badgrant is the negative fixture for the grant-lock analyzer (#54
// B14): it stands in for the resolution surface and contains a grant writer that
// does NOT take the principal-row lock, which must be reported, plus a locked
// writer and a read that must not.
package badgrant

import (
	"context"

	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// LockedWriter is the correct shape: it takes the principal-row lock before the
// grant insert, so it must NOT be flagged.
func LockedWriter(ctx context.Context, q *sqlitegen.Queries, lock string, p sqlitegen.InsertGrantParams) error {
	if _, err := q.LockPrincipalRow(ctx, lock); err != nil {
		return err
	}
	return q.InsertGrant(ctx, p)
}

// LocklessWriter is the violation: a grant-table write with no principal-row
// lock, which the credential-reset org-bounded test relies on.
func LocklessWriter(ctx context.Context, q *sqlitegen.Queries, p sqlitegen.InsertGrantParams) error {
	return q.InsertGrant(ctx, p)
}

// GrantReadIsFine proves the analyzer does not flag a grant read.
func GrantReadIsFine(ctx context.Context, q *sqlitegen.Queries, id string) ([]sqlitegen.ListGrantsForPrincipalRow, error) {
	return q.ListGrantsForPrincipal(ctx, id)
}
