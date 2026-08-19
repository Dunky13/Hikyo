package compose

import (
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
)

// Offline per-key audit records (compose-integration ADR § "Audit during
// offline serve", amendment 3; audit-model ADR "Offline records").
//
// The obligation the threat model puts on the server — a durable record BEFORE
// disclosure — moves client-side here: one durable, immutable, per-key local
// record fsynced BEFORE plaintext is released. The CALLER owns that ordering;
// Append only guarantees the file is fsynced (file + directory) before it
// returns, so a caller that calls Append and only then releases plaintext meets
// the amendment.
//
// Records are batched one-file-per-flush-unit; reconciliation is idempotent
// server-side via RecordID, so a crash between "server accepted" and
// MarkFlushed only re-sends — never double-counts.

const offlineDir = "offline-records"

// OfflineRecord is one disclosed key during an offline serve. RecordID is the
// idempotency key; it MUST be set by the caller before the plaintext op (so a
// retry re-sends the same id) — Append refuses an empty one rather than mint a
// fresh id that would defeat idempotency.
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
// before returning. Callers MUST call Append and confirm success BEFORE
// releasing any plaintext to the workload.
func Append(stateDir string, records []OfflineRecord) error {
	if len(records) == 0 {
		return nil
	}
	for i, r := range records {
		if strings.TrimSpace(r.RecordID) == "" {
			return fmt.Errorf("compose: offline record %d has no record_id (set it before the plaintext op for idempotency)", i)
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
	path := filepath.Join(dir, name)
	if err := writeFileFsync(path, data, 0o600); err != nil {
		return fmt.Errorf("compose: write offline record: %w", err)
	}
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("compose: fsync offline-records dir: %w", err)
	}
	return nil
}

// Pending returns all buffered records (flattened) and the files holding them,
// sorted by filename so the local nanos ordering is stable.
func Pending(stateDir string) ([]OfflineRecord, []string, error) {
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

	var records []OfflineRecord
	var files []string
	for _, n := range names {
		path := filepath.Join(dir, n)
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("compose: read offline record %s: %w", n, err)
		}
		var batch []OfflineRecord
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&batch); err != nil {
			return nil, nil, fmt.Errorf("compose: parse offline record %s: %w", n, err)
		}
		records = append(records, batch...)
		files = append(files, path)
	}
	return records, files, nil
}

// MarkFlushed deletes the given files after the server accepted their records.
// Reconciliation is idempotent, so a crash before deletion only re-sends.
func MarkFlushed(files []string) error {
	for _, f := range files {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("compose: remove flushed record %s: %w", f, err)
		}
	}
	return nil
}
