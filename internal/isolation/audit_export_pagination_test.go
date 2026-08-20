package isolation

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// TestAuditExportDoesNotTruncateAboveThePageCap is the regression for the audit
// page-size clamp: an export whose requested pageSize exceeds
// store.AuditMaxPageSize must still emit EVERY row. The store caps a page at
// AuditMaxPageSize, so the export loop's end-of-data test (len(rows) < pageSize)
// would mistake a full clamped first page for EOF and silently stop unless the
// service clamps pageSize to the same cap first. The fix lives in the pure-Go
// export loop, so sqlite exercises it fully; the SQL is identical on postgres.
func TestAuditExportDoesNotTruncateAboveThePageCap(t *testing.T) {
	db := seededDB(t, openSQLite)

	// Seed one more than the page cap, so a correct export must read a SECOND
	// page. org-scope events for org_a, which alice holds audit-read over.
	const fillers = store.AuditMaxPageSize + 1
	var b strings.Builder
	b.WriteString("INSERT INTO audit_tenant_events (id, type, schema_version, occurred_at, occurred_asserted, recorded_at, actor_class, scope_class, org_id, outcome, origin, payload) VALUES ")
	for i := 0; i < fillers; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "('aud_fill_%d', 'grant.created', 1, '2026-01-01T00:00:00.000000Z', 0, '2026-01-01T00:00:00.000000Z', 'system', 'org', 'org_a', 'success', 'system', '{\"filler\":true}')", i)
	}
	execRaw(t, db, b.String())

	var out bytes.Buffer
	// pageSize well above the cap: without the service-side clamp the first
	// clamped page (AuditMaxPageSize rows) reads as EOF and drops the rest.
	if err := (&service.Audits{DB: db}).Export(t.Context(), alice, domain.Scope{Org: orgA},
		store.AuditFilter{}, store.AuditMaxPageSize+500, &out); err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := strings.Count(out.String(), `"filler":true`); got != fillers {
		t.Fatalf("export emitted %d filler events, want all %d — the page cap truncated the export", got, fillers)
	}
}
