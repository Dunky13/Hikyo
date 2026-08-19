package service

// Backup export (#76, encryption-model ADR § Backups and exports, ops spec § 11).
//
// Two properties are worth stating before the code, because both are easy to
// lose in a refactor and neither is recoverable afterwards:
//
//  1. Export NEVER touches the root key. Every sensitive field in the
//     snapshot is already envelope ciphertext and the wrapped key hierarchy
//     travels inside it, so the artifact is readable only by someone holding
//     BOTH the backup identity and the root key — two custody stores, two
//     failure domains, exactly as the threat model requires. A backup path
//     that loaded the keyring would quietly collapse that into one.
//
//  2. The artifact is published ATOMICALLY. It is written under a `.partial`
//     name, closed (age's Close is what writes the final chunk that
//     distinguishes a complete archive from a prefix), fsynced, and only then
//     renamed. A partially written backup must never be mistakable for a
//     complete one — the failure mode where an operator discovers at restore
//     time that last night's file stops half-way.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto/backup"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// ExportTrigger says why an export ran, and rides the audit event: an
// operator asking for one and a migration taking one automatically are
// different facts about the same artifact.
type ExportTrigger string

const (
	// TriggerManual is `hikyo backup export`.
	TriggerManual ExportTrigger = "manual"
	// TriggerPreMigration is the automatic export the ops spec requires
	// immediately before a schema change.
	TriggerPreMigration ExportTrigger = "pre-migration"
)

// Backup is the export service. Options carries the recipient policy; a
// zero-recipient policy is refused by the container package rather than
// re-checked here, so there is exactly one place that decides it.
type Backup struct {
	DB      *store.DB
	Options backup.Options
	Now     func() time.Time
}

func (s *Backup) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ExportResult describes a published artifact.
type ExportResult struct {
	Path     string
	Bytes    int64
	Manifest store.Manifest
}

// Export writes one age-encrypted archive into dir and returns where it
// landed. It does NOT write the audit event: an export can run against a
// datastore whose schema is about to change, and the record of it belongs
// after the migration that follows. RecordExport is the other half.
func (s *Backup) Export(ctx context.Context, dir string) (ExportResult, error) {
	if dir == "" {
		return ExportResult{}, errors.New("backup export needs a destination directory")
	}
	// Recipient policy first: refusing before a temp file exists keeps a
	// zero-recipient refusal from leaving debris behind.
	if err := s.Options.Validate(); err != nil {
		return ExportResult{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ExportResult{}, fmt.Errorf("backup destination %s: %w", dir, err)
	}
	work, err := os.MkdirTemp(dir, ".export-")
	if err != nil {
		return ExportResult{}, fmt.Errorf("backup staging directory: %w", err)
	}
	defer os.RemoveAll(work)

	// The staging file is unique per export (CreateTemp), never a fixed
	// `<final>.partial`: two exports in the same second — an operator export
	// racing an automatic pre-migration one — must not write the same inode
	// and publish each other's half-written bytes.
	f, err := os.CreateTemp(dir, ".hikyo-export-*.partial")
	if err != nil {
		return ExportResult{}, fmt.Errorf("backup staging file: %w", err)
	}
	partial := f.Name()
	// One unwind for every failure below: close (idempotent after an explicit
	// Close) and remove the staged file. publish removes it on success.
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
		os.Remove(partial)
	}()
	if err := f.Chmod(0o600); err != nil {
		return ExportResult{}, fmt.Errorf("backup staging file mode: %w", err)
	}
	result, err := s.writeArchive(ctx, f, work)
	if err != nil {
		return ExportResult{}, err
	}
	// fsync before publication: a link that beats the data to disk publishes
	// a name with nothing behind it.
	if err := f.Sync(); err != nil {
		return ExportResult{}, fmt.Errorf("backup artifact fsync: %w", err)
	}
	closed = true
	if err := f.Close(); err != nil {
		return ExportResult{}, fmt.Errorf("backup artifact close: %w", err)
	}
	info, err := os.Stat(partial)
	if err != nil {
		return ExportResult{}, fmt.Errorf("backup artifact stat: %w", err)
	}
	final, err := s.publish(dir, partial)
	if err != nil {
		return ExportResult{}, err
	}
	result.Path, result.Bytes = final, info.Size()
	return result, nil
}

// publish gives the staged artifact its final name without ever replacing an
// existing one: link(2) fails on an existing target where rename(2) would
// silently overwrite last night's backup. Same-second collisions get a
// numeric suffix; more than a handful in one second is not an export cadence,
// it is a bug, and it fails loudly.
func (s *Backup) publish(dir, partial string) (string, error) {
	base := fmt.Sprintf("hikyo-%s-%s", s.DB.Engine(), s.now().UTC().Format("20060102T150405Z"))
	for n := range 10 {
		name := base + ".age"
		if n > 0 {
			name = fmt.Sprintf("%s-%d.age", base, n+1)
		}
		final := filepath.Join(dir, name)
		err := os.Link(partial, final)
		if err == nil {
			// The staged name is removed by Export's deferred cleanup; the
			// link above is what made the artifact durable.
			return final, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("publish backup artifact: %w", err)
		}
	}
	return "", fmt.Errorf("publish backup artifact: 10 exports named %s already exist", base)
}

// writeArchive is the container-around-archive composition, kept separate so
// every failure above unwinds the partial file exactly once.
func (s *Backup) writeArchive(ctx context.Context, f *os.File, work string) (ExportResult, error) {
	w, err := backup.Encrypt(f, s.Options)
	if err != nil {
		return ExportResult{}, err
	}
	manifest, err := store.Export(ctx, s.DB, w, work)
	if err != nil {
		w.Close()
		return ExportResult{}, err
	}
	// age's Close writes the final chunk. Without it the file decrypts as a
	// truncated archive — which the restore path refuses, correctly, so a
	// missed Close would surface as "every backup is corrupt".
	if err := w.Close(); err != nil {
		return ExportResult{}, fmt.Errorf("seal backup container: %w", err)
	}
	return ExportResult{Manifest: manifest}, nil
}

// RecordExport writes the export's audit event. It is separate from Export
// because the pre-migration export runs against the OLD schema and its record
// belongs in the new one.
func (s *Backup) RecordExport(ctx context.Context, trigger ExportTrigger, r ExportResult) error {
	mode, count := s.recipientPolicy()
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		e, err := domainEvent(ctx, audit.EventBackupExported, "",
			audit.Object{Type: "backup", ID: filepath.Base(r.Path)}, audit.Payload{
				"trigger":         string(trigger),
				"recipient_mode":  mode,
				"recipient_count": int64(count),
				"engine":          string(r.Manifest.Engine),
				"schema_version":  r.Manifest.SchemaVersion,
				"artifact_bytes":  r.Bytes,
				"destination":     r.Path,
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}

// RecordSkip is the LOUD half of "automatic pre-migration export when public
// recipients are configured, loud skip otherwise". The skip is non-fatal by
// the ops spec's own wording — a migration must not be blocked by an
// unconfigured backup — so the loudness has to come from somewhere that
// survives the morning after, which is the durable trail, not a log line
// nobody scrolls back to.
func (s *Backup) RecordSkip(ctx context.Context, trigger ExportTrigger, reason string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		e, err := newAuditEvent(ctx, audit.EventBackupExportSkipped, "",
			audit.Object{Type: "backup", ID: string(trigger)}, audit.OutcomeFailure, "",
			audit.Payload{"trigger": string(trigger), "reason": reason})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}

// recipientPolicy reports the mode and the count WITHOUT naming a recipient:
// public recipients are not secret, but writing them into every export event
// would put the operator's escrow topology in the trail.
func (s *Backup) recipientPolicy() (string, int) {
	if s.Options.Passphrase != "" {
		return "passphrase", 1
	}
	return "recipients", len(s.Options.Recipients)
}
