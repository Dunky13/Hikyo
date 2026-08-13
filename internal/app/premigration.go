package app

// The automatic pre-migration export (#76, ops spec § 11: "daily
// backup-export + automatic pre-migration export when public recipients are
// configured, LOUD SKIP otherwise").
//
// Migrations are roll-forward only and no down-migration exists anywhere in
// this system, so the sentence "downgrade = restore from backup" is the whole
// of the downgrade story. That makes the export immediately before a schema
// change the single artifact standing between a bad migration and a rebuilt
// instance — and makes its ABSENCE something an operator must be told about
// while they can still act on it, not discovered afterwards.
//
// The skip is non-fatal by the ops spec's own wording: an unconfigured backup
// must not block a migration. Loud therefore has to mean durable, which is
// why the skip lands in the instance audit trail beside a warning log, and
// not only in a log line nobody scrolls back to.
//
// Ordering is the delicate part, and it is forced:
//
//	 1. take (or decline to take) the export, against the OLD schema — an
//	    export taken after the migration is not a pre-migration export;
//	 2. migrate;
//	 3. record what happened in (1), which is only now writable, because the
//	    audit tables are reached through a schema-checked store and step 1
//	    runs before this binary's schema exists.
//
// Nothing is exported when the datastore has no schema yet: a first run has
// no prior state, so there is neither anything to back up nor anywhere to
// write the record.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Dunky13/hikyo/internal/config"
	"github.com/Dunky13/hikyo/internal/crypto/backup"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
)

// preMigrationRecord is what step 1 decided, carried to step 3.
type preMigrationRecord struct {
	// exported is set when an artifact was published.
	exported *service.ExportResult
	// skipReason is set when there was prior state and no recipient policy.
	skipReason string
}

// pending reports whether step 3 has anything to write.
func (r preMigrationRecord) pending() bool { return r.exported != nil || r.skipReason != "" }

const noRecipientsReason = "no backup recipients configured (HIKYO_BACKUP_RECIPIENTS / HIKYO_BACKUP_DIR)"

// preMigrationExport is step 1. It never fails the caller for want of a
// backup: the ops spec makes the skip loud, not blocking. An export that was
// ATTEMPTED and failed is different — that is a configured policy not being
// honoured, and it is returned as an error.
func preMigrationExport(ctx context.Context, cfg *config.Config, log *slog.Logger) (preMigrationRecord, error) {
	options := backup.Options{Recipients: cfg.BackupRecipients}
	db, err := store.Open(ctx, storeConfig(cfg))
	if err != nil {
		// No datastore to open is a first run for sqlite and a real failure
		// for postgres; either way the migration attempt that follows will
		// say so far better than a backup preflight can. Logged so a skipped
		// export is never entirely silent.
		log.Warn("pre-migration export preflight could not open the datastore; leaving it to the migration to report", "err", err)
		return preMigrationRecord{}, nil
	}
	defer db.Close()
	if _, err := store.SchemaVersion(ctx, db); err != nil {
		if errors.Is(err, store.ErrNoSchema) {
			// A datastore with no prior state. Nothing to export and nowhere
			// to record it.
			return preMigrationRecord{}, nil
		}
		// Any OTHER failure is a store that exists but cannot be read — not a
		// fresh instance, and not a state to silently skip the one artifact a
		// bad migration can be recovered from.
		return preMigrationRecord{}, fmt.Errorf("pre-migration export preflight: %w", err)
	}

	if !options.Configured() || cfg.BackupDir == "" {
		log.Warn("PRE-MIGRATION EXPORT SKIPPED: this migration has no backup to fall back to. "+
			"Migrations are roll-forward only; the documented downgrade path is restoring a backup, and there will be none.",
			"reason", noRecipientsReason)
		return preMigrationRecord{skipReason: noRecipientsReason}, nil
	}

	result, err := (&service.Backup{DB: db, Options: options}).Export(ctx, cfg.BackupDir)
	if err != nil {
		return preMigrationRecord{}, err
	}
	log.Info("pre-migration export published", "path", result.Path, "bytes", result.Bytes)
	return preMigrationRecord{exported: &result}, nil
}

// recordPreMigration is step 3: the durable half, written after the migration
// has made the audit tables current.
func recordPreMigration(ctx context.Context, cfg *config.Config, log *slog.Logger, rec preMigrationRecord) {
	if !rec.pending() {
		return
	}
	db, err := store.Open(ctx, storeConfig(cfg))
	if err != nil {
		log.Error("pre-migration export happened but its record could not be written", "err", err)
		return
	}
	defer db.Close()
	svc := &service.Backup{DB: db, Options: backup.Options{Recipients: cfg.BackupRecipients}}
	if rec.exported != nil {
		err = svc.RecordExport(ctx, service.TriggerPreMigration, *rec.exported)
	} else {
		err = svc.RecordSkip(ctx, service.TriggerPreMigration, rec.skipReason)
	}
	if err != nil {
		// The migration has already run and the artifact (or its absence) is
		// already a fact. Failing the boot here would trade a missing audit
		// row for an instance that will not start; say it loudly instead.
		log.Error("pre-migration export record could not be written", "err", err)
	}
}
