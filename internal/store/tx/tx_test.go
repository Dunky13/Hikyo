package tx

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Dunky13/hikyo/internal/store"
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
	if retryable(store.EngineSQLite, errors.New("plain")) {
		t.Error("plain error must not be retryable")
	}
}

func TestRetryLoopExhaustsBoundedAttempts(t *testing.T) {
	calls := 0
	err := retryLoop(t.Context(), store.EnginePostgres, func(context.Context) error {
		calls++
		return &pgconn.PgError{Code: "40001"}
	})
	if err == nil {
		t.Fatal("exhaustion must surface as an error")
	}
	if calls != attempts {
		t.Fatalf("attempts = %d, want %d (initial try + %d retries)", calls, attempts, len(backoff))
	}
	if !strings.Contains(err.Error(), "retries exhausted") {
		t.Fatalf("exhaustion must be loud, got: %v", err)
	}
}

func TestRetryLoopStopsOnNonRetryable(t *testing.T) {
	calls := 0
	sentinel := errors.New("constraint violation")
	err := retryLoop(t.Context(), store.EnginePostgres, func(context.Context) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("non-retryable error must surface unchanged, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("non-retryable error must not be retried: %d calls", calls)
	}
}

func TestRetryLoopSucceedsAfterTransientFailures(t *testing.T) {
	calls := 0
	err := retryLoop(t.Context(), store.EnginePostgres, func(context.Context) error {
		calls++
		if calls < 3 {
			return &pgconn.PgError{Code: "40P01"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestRetryLoopRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	err := retryLoop(ctx, store.EnginePostgres, func(context.Context) error {
		calls++
		cancel() // cancel between attempt and backoff wait
		return &pgconn.PgError{Code: "40001"}
	})
	if err == nil {
		t.Fatal("cancelled context must abort the retry loop")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retry after cancellation)", calls)
	}
}
