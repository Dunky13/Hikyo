package compose

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// Offline per-key audit records (compose-integration ADR § "Audit during
// offline serve", amendment 3; audit-model ADR "Offline records").
//
// The obligation the threat model puts on the server — a durable record BEFORE
// disclosure — moves client-side here: one durable, immutable, per-key local
// record fsynced BEFORE plaintext is released. The CALLER owns that ordering;
// Append only guarantees the batch file is fsynced (file + directory) before it
// returns, so a caller that calls Append and only then releases plaintext meets
// the amendment.
//
// This package deliberately offers PRIMITIVES, not a composite "serve then
// reconcile" verb. The ADR fixes the ORDER (records durable before plaintext;
// reconcile before the next fetch), but the ORCHESTRATION of that order — fetch,
// serve, reconcile, block-until-reconciled — is the CLI's, wired over
// Append/Pending/MarkFlushed. A composite API here would bury the ordering the
// CLI must own and cannot see the fetch transaction. (ops-spec § 6: reconcile
// is an ordering rule the CLI enforces, not a window this package manages.)
//
// Records are batched one-file-per-flush-unit; reconciliation is idempotent
// server-side via RecordID, so a crash between "server accepted" and
// MarkFlushed only re-sends — never double-counts.

const offlineDir = "offline-records"

// validClassifications are the only OfflineRecord.Classification values (schema
// ADR: a key is `config` or `secret`).
var validClassifications = map[string]bool{"config": true, "secret": true}

// OfflineRecord is one disclosed key during an offline serve. Every field is
// required: an unattributable record is worse than useless at reconciliation.
// RecordID is the idempotency key; it MUST be set by the caller before the
// plaintext op (so a retry re-sends the same id).
type OfflineRecord struct {
	RecordID       string `json:"record_id"`
	KeyID          string `json:"key_id"`
	KeyName        string `json:"key_name"`
	Classification string `json:"classification"`
	OccurredAt     string `json:"occurred_at"` // client-asserted RFC3339
	CredentialID   string `json:"credential_id"`
	Generation     string `json:"generation"`
	ServedFrom     string `json:"served_from"`
}

// validate rejects any record missing a required field or carrying a malformed
// time, classification, or generation stamp.
func (r OfflineRecord) validate() error {
	for name, v := range map[string]string{
		"record_id": r.RecordID, "key_id": r.KeyID, "key_name": r.KeyName,
		"credential_id": r.CredentialID, "served_from": r.ServedFrom,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("compose: offline record %s is empty", name)
		}
	}
	if !validClassifications[r.Classification] {
		return fmt.Errorf("compose: offline record classification %q is not one of config, secret", r.Classification)
	}
	if _, err := time.Parse(time.RFC3339, r.OccurredAt); err != nil {
		return fmt.Errorf("compose: offline record occurred_at %q is not RFC3339: %w", r.OccurredAt, err)
	}
	if err := crypto.ParseStamp(r.Generation); err != nil {
		return fmt.Errorf("compose: offline record generation: %w", err)
	}
	return nil
}

// NewRecordID returns a random 128-bit hex id — no dependency, sufficient
// collision resistance for an idempotency key.
func NewRecordID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("compose: record id randomness: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Append writes records as ONE new batch file, 0600, fsynced (file + dir)
// before returning. Every record is validated first — a single invalid record
// fails the whole batch, so no partial, unauditable disclosure record is
// written. Callers MUST call Append and confirm success BEFORE releasing any
// plaintext to the workload.
func Append(stateDir string, records []OfflineRecord) error {
	if len(records) == 0 {
		return nil
	}
	for i, r := range records {
		if err := r.validate(); err != nil {
			return fmt.Errorf("compose: offline record %d invalid: %w", i, err)
		}
	}
	dir := filepath.Join(stateDir, offlineDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("compose: create offline-records dir: %w", err)
	}
	// Explicit 0700, not umask-dependent (client local-state protection model).
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("compose: chmod offline-records dir: %w", err)
	}

	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("compose: marshal offline records: %w", err)
	}
	suffix, err := NewRecordID()
	if err != nil {
		return err
	}
	// <unix-nanos>-<random>.json: nanos orders locally (not trusted for audit
	// ordering — the server keys off recorded_at), random avoids collisions.
	name := fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), suffix)
	if err := writeFileFsync(filepath.Join(dir, name), data, 0o600); err != nil {
		return fmt.Errorf("compose: write offline record: %w", err)
	}
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("compose: fsync offline-records dir: %w", err)
	}
	return nil
}

// Pending returns all buffered records (flattened) and OPAQUE handles for the
// batch files holding them, sorted by handle so the local nanos ordering is
// stable. A handle is the batch file's bare basename; it is only meaningful to
// MarkFlushed, which resolves it strictly under stateDir/offline-records/.
func Pending(stateDir string) (records []OfflineRecord, handles []string, err error) {
	dir := filepath.Join(stateDir, offlineDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("compose: list offline records: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, nil, fmt.Errorf("compose: read offline record %s: %w", n, err)
		}
		var batch []OfflineRecord
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&batch); err != nil {
			return nil, nil, fmt.Errorf("compose: parse offline record %s: %w", n, err)
		}
		records = append(records, batch...)
		handles = append(handles, n)
	}
	return records, handles, nil
}

// MarkFlushed deletes the batch files named by the given OPAQUE handles after
// the server accepted their records. A handle MUST be a bare basename produced
// by Pending; anything with a path separator, "..", or that resolves outside
// stateDir/offline-records/ is refused, so this can never be steered into
// deleting an arbitrary path. Reconciliation is idempotent, so a crash before
// deletion only re-sends.
func MarkFlushed(stateDir string, handles []string) error {
	dir := filepath.Join(stateDir, offlineDir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("compose: open offline-records dir: %w", err)
	}
	defer root.Close()
	for _, h := range handles {
		if h == "" || h != filepath.Base(h) || strings.ContainsAny(h, `/\`) || h == ".." {
			return fmt.Errorf("compose: refusing to flush non-opaque handle %q", h)
		}
		if err := root.Remove(h); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("compose: remove flushed record %s: %w", h, err)
		}
	}
	return nil
}
