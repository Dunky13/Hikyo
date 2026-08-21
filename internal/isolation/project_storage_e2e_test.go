package isolation

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestProjectStorageHighWaterSQLite(t *testing.T) {
	runProjectStorageHighWater(t, seededDB(t, openSQLite))
}
func TestProjectStorageHighWaterPostgres(t *testing.T) {
	runProjectStorageHighWater(t, seededDB(t, openPostgres))
}

// runProjectStorageHighWater is the ops-spec § 8 / § 141 per-project storage
// high-water: once a project's stored payload (value cells plus published
// snapshot entries) reaches the high-water, a NEW publish is refused by name.
// No test can seed 4 GiB, so the exact refuse value (4 GiB) is pinned by the
// conformance bound registry; this proves the accounting SUMS BOTH tables and
// the refusal fires at the boundary, on both engines, through the real publish.
func runProjectStorageHighWater(t *testing.T, db *store.DB) {
	kr := probeKeyring(t, db)
	values := valueSvc(t, db)
	actor := service.LocalPrincipal(custodian)
	scope := scopeEnv(orgA, prjA1, envA1)

	// A first publish under the production high-water establishes real stored
	// bytes: the value cell and its snapshot entry, both sealed.
	staged, err := values.Set(t.Context(), actor, scope, "SHARED_KEY", "first", nil)
	if err != nil {
		t.Fatalf("stage first value: %v", err)
	}
	base := &service.Revisions{DB: db, Keyring: kr}
	if _, err := base.Publish(t.Context(), actor, scope, []string{staged.VersionID}); err != nil {
		t.Fatalf("first publish must succeed on an empty project: %v", err)
	}

	// The project's stored payload across BOTH tables — the exact quantity the
	// refusal sums. LENGTH is the byte count of a BLOB / bytea on both engines.
	stored := queryInt(t, db,
		"SELECT (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM value_entries WHERE org_id = 'org_a' AND project_id = 'prj_a1')"+
			" + (SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM snapshot_entries WHERE org_id = 'org_a' AND project_id = 'prj_a1')")
	if stored <= 0 {
		t.Fatalf("first publish stored no payload bytes (value_entries + snapshot_entries) = %d", stored)
	}

	// Stage a second change. With the high-water set to exactly the bytes now
	// stored, the project is AT the water, so the new publish is refused by name.
	second, err := values.Set(t.Context(), actor, scope, "SHARED_KEY", "second", nil)
	if err != nil {
		t.Fatalf("stage second value: %v", err)
	}
	atWater := &service.Revisions{DB: db, Keyring: kr, ProjectStorageHighWater: int64(stored)}
	_, err = atWater.Publish(t.Context(), actor, scope, []string{second.VersionID})
	if !errors.Is(err, domain.ErrLimitExceeded) {
		t.Fatalf("publish into a project at the storage high-water must be refused with ErrLimitExceeded: %v", err)
	}
	// The refusal must NAME what holds the space (ops-spec § 141): the retention
	// window and the pinned revisions, so the operator knows how to reclaim it.
	for _, want := range []string{"storage high-water", "retention", "pinned revisions"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must name %q so the operator can reclaim space: %q", want, err)
		}
	}

	// One byte of headroom lets the same staged change through: the boundary is
	// `>=`, so below the water publishes normally.
	belowWater := &service.Revisions{DB: db, Keyring: kr, ProjectStorageHighWater: int64(stored) + 1}
	if _, err := belowWater.Publish(t.Context(), actor, scope, []string{second.VersionID}); err != nil {
		t.Fatalf("publish below the high-water must succeed: %v", err)
	}
}
