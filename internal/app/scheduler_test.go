package app

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerRunsAtStartupAndOnTicker(t *testing.T) {
	var runs atomic.Int64
	reached := make(chan struct{}, 1)
	s := &Scheduler{
		Interval: 10 * time.Millisecond,
		Deadline: time.Second,
		Log:      testLogger(),
		Jobs: []ScheduledJob{{
			Name: "payload_gc",
			Run: func(context.Context) error {
				if runs.Add(1) >= 2 {
					select {
					case reached <- struct{}{}:
					default:
					}
				}
				return nil
			},
			LastSuccess: func(context.Context) (time.Time, bool, error) {
				return time.Now().UTC(), true, nil
			},
		}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	select {
	case <-reached:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("scheduler did not run at startup and on its ticker")
	}
	<-done
}

func TestSchedulerDeadlineAndStaleSuccessAreLoudOpsLogs(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := &Scheduler{
		Deadline: 10 * time.Millisecond,
		Log:      log,
		Now:      func() time.Time { return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC) },
		Jobs: []ScheduledJob{{
			Name: "payload_gc",
			Run: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
			LastSuccess: func(context.Context) (time.Time, bool, error) {
				return time.Date(2026, 8, 14, 11, 59, 0, 0, time.UTC), true, nil
			},
		}},
	}
	s.runOnce(t.Context(), "startup")
	text := logged.String()
	for _, want := range []string{"scheduler job failed", "payload_gc", "last_prune_success is stale"} {
		if !strings.Contains(text, want) {
			t.Fatalf("ops log %q does not contain %q", text, want)
		}
	}
}

func TestSchedulerExposesLastPruneSuccessOnOpsLog(t *testing.T) {
	var logged bytes.Buffer
	at := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	s := &Scheduler{
		Log: slog.New(slog.NewTextHandler(&logged, nil)),
		Now: func() time.Time { return at.Add(time.Hour) },
	}
	s.checkHealth(t.Context(), ScheduledJob{
		Name: "payload_gc",
		LastSuccess: func(context.Context) (time.Time, bool, error) {
			return at, true, nil
		},
	})
	text := logged.String()
	for _, want := range []string{"scheduler job health", "payload_gc", "last_prune_success=2026-08-15T11:00:00.000Z"} {
		if !strings.Contains(text, want) {
			t.Fatalf("ops log %q does not contain %q", text, want)
		}
	}
}
