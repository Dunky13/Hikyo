// Package badauthn is the negative fixture for the sole-denial-writer
// analyzer: it stands in for the resolution surface and contains a SECOND
// proof-free writer, which must be reported.
package badauthn

import (
	"context"

	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// WriteDenial is the one licensed write path.
func WriteDenial(ctx context.Context, q *sqlitegen.Queries, p sqlitegen.InsertInstanceAuditEventParams) error {
	return q.InsertInstanceAuditEvent(ctx, p)
}

// SecondWriter is the violation: a mutating generated query reached from the
// resolution surface outside the denial writer.
func SecondWriter(ctx context.Context, q *sqlitegen.Queries, p sqlitegen.InsertTenantAuditEventParams) error {
	return q.InsertTenantAuditEvent(ctx, p)
}

// ReadsAreFine proves the analyzer does not flag reads.
func ReadsAreFine(ctx context.Context, q *sqlitegen.Queries, id string) (string, error) {
	return q.GetPrincipalKind(ctx, id)
}
