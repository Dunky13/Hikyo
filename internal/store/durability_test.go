package store

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeSettingRow answers one SHOW query with a canned value.
type fakeSettingRow struct {
	value string
	err   error
}

func (r fakeSettingRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.value
	return nil
}

type fakeSettings map[string]string

func (f fakeSettings) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	name := strings.TrimPrefix(sql, "SHOW ")
	v, ok := f[name]
	if !ok {
		return fakeSettingRow{err: pgx.ErrNoRows}
	}
	return fakeSettingRow{value: v}
}

// The fsync leg cannot restart a live CI server, so both legs are unit
// tested through the querier seam; the synchronous_commit leg is
// additionally exercised for real against the CI database (isolation
// package, ALTER DATABASE ... SET synchronous_commit).
func TestVerifyPGDurability(t *testing.T) {
	ctx := context.Background()
	if err := verifyPGDurability(ctx, fakeSettings{"fsync": "on", "synchronous_commit": "on"}); err != nil {
		t.Fatalf("durable settings refused: %v", err)
	}
	for name, f := range map[string]fakeSettings{
		"fsync off":              {"fsync": "off", "synchronous_commit": "on"},
		"synchronous_commit off": {"fsync": "on", "synchronous_commit": "off"},
		"local is not on":        {"fsync": "on", "synchronous_commit": "local"},
	} {
		err := verifyPGDurability(ctx, f)
		if err == nil {
			t.Errorf("%s: boot not refused", name)
			continue
		}
		if !strings.Contains(err.Error(), "refusing to boot") {
			t.Errorf("%s: refusal does not name itself: %v", name, err)
		}
	}
}

func TestAuditExportCoordinationRejectsUnknownEngine(t *testing.T) {
	db := &DB{engine: Engine("future")}
	if _, err := db.AuditExportSnapshotTime(t.Context()); err == nil || !strings.Contains(err.Error(), "unknown engine") {
		t.Fatalf("snapshot time unknown-engine refusal = %v", err)
	}
	if err := db.AwaitAuditExportWriters(t.Context()); err == nil || !strings.Contains(err.Error(), "unknown engine") {
		t.Fatalf("writer barrier unknown-engine refusal = %v", err)
	}
}
