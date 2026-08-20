package isolation

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestPendingPerProjectCapSQLite(t *testing.T)   { runPendingPerProjectCap(t, seededDB(t, openSQLite)) }
func TestPendingPerProjectCapPostgres(t *testing.T) { runPendingPerProjectCap(t, seededDB(t, openPostgres)) }

// runPendingPerProjectCap: the ops-spec § 8 loud cap on pending versions per
// project. Once the project holds MaxPendingPerProject pending rows, staging a
// NEW cell is refused by name. Re-staging an existing cell stays allowed
// (delete-then-insert never grows the count), which the cap counts by excluding
// the cell being staged. Runs on both engines.
func runPendingPerProjectCap(t *testing.T, db *store.DB) {
	const ts = "'2026-01-01T00:00:00.000000Z'"

	// Fill (project A1) to the cap with filler pending rows, each owned by its
	// own principal so the (env, key, owner) uniqueness holds. `unset` rows carry
	// no ciphertext, so the seed needs no sealing.
	var principals, pending strings.Builder
	principals.WriteString("INSERT INTO principals (id, kind, created_at) VALUES ")
	pending.WriteString("INSERT INTO pending_changes (id, org_id, project_id, environment_id, key_id, owner_id, operation, ciphertext, staged_from_revision, staged_from_entry, created_at) VALUES ")
	for i := 0; i < service.MaxPendingPerProject; i++ {
		if i > 0 {
			principals.WriteString(",")
			pending.WriteString(",")
		}
		fmt.Fprintf(&principals, "('usr_pfill_%d', 'human', %s)", i, ts)
		fmt.Fprintf(&pending, "('pcv_fill_%d', 'org_a', 'prj_a1', 'env_a1', 'key_a1', 'usr_pfill_%d', 'unset', NULL, 0, '', %s)", i, i, ts)
	}
	execRaw(t, db, principals.String())
	execRaw(t, db, pending.String())

	// A genuinely new cell (alice has never staged here) is refused by name.
	if _, err := valueSvc(t, db).Set(t.Context(), service.LocalPrincipal(alice),
		scopeEnv(orgA, prjA1, envA1), "SHARED_KEY", "over-the-cap", nil); !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("staging past the per-project pending cap must be refused with ErrLimitExceeded: %v", err)
	}
}
