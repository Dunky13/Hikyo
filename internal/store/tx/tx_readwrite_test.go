package tx

// A read transaction must never take sqlite's write intent: the read pool
// opens plain deferred transactions (WAL readers do not block the writer),
// while the write pool's DSN carries _txlock=immediate. This test holds a
// read transaction open across a full write transaction — if the read pool
// wrongly opened BEGIN IMMEDIATE, the writer would burn its busy_timeout and
// retry budget against the reader's lock and fail loudly here.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

func TestReadTransactionDoesNotBlockWriter(t *testing.T) {
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "rw.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	readOpen := make(chan struct{})
	release := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- Read(t.Context(), db, func(ctx context.Context, _ store.ReadRepos, _ *authz.TxAuthorizer) error {
			close(readOpen)
			<-release
			return nil
		})
	}()
	<-readOpen

	start := time.Now()
	writeErr := Write(t.Context(), db, func(ctx context.Context, _ store.Repos, _ *authz.TxAuthorizer) error {
		return nil
	})
	elapsed := time.Since(start)
	close(release)
	if err := <-readDone; err != nil {
		t.Fatalf("read transaction: %v", err)
	}
	if writeErr != nil {
		t.Fatalf("writer failed while a read transaction was open: %v", writeErr)
	}
	// The writer must not have waited out busy_timeout against the reader.
	if elapsed > 2*time.Second {
		t.Fatalf("writer took %v with a read transaction open — the read pool is taking write intent", elapsed)
	}
}
