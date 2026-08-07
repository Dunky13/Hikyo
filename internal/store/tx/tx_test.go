package tx

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Dunky13/wenv/internal/store"
)

func TestRetryablePostgres(t *testing.T) {
	cases := []struct {
		code string
		want bool
	}{
		{"40001", true},
		{"40P01", true},
		{"23505", false}, // unique_violation is not transient
	}
	for _, c := range cases {
		err := error(&pgconn.PgError{Code: c.code})
		if got := retryable(store.EnginePostgres, err); got != c.want {
			t.Errorf("code %s: retryable = %v, want %v", c.code, got, c.want)
		}
	}
	if retryable(store.EnginePostgres, errors.New("plain")) {
		t.Error("plain error must not be retryable")
	}
}

func TestRetryableSQLiteRejectsPlainErrors(t *testing.T) {
	// SQLITE_BUSY paths are exercised end-to-end by the conformance
	// harness's concurrent-writes scenario; here only the negative.
	if retryable(store.EngineSQLite, errors.New("plain")) {
		t.Error("plain error must not be retryable")
	}
}
