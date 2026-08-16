package importer

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if handled, code := RunInternalSubprocess(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func TestSubprocessDeadlineIsFreshPerInvocationAndClampedToRun(t *testing.T) {
	now := time.Now()
	runDeadline := now.Add(5 * time.Minute)
	ctx, cancel := context.WithDeadline(t.Context(), runDeadline)
	defer cancel()
	spec := newSubprocessSpec(ctx, "/bin/true", nil, 1)
	if got := time.Unix(0, spec.RunDeadlineUnixNano); !got.Equal(runDeadline) {
		t.Fatalf("stored deadline = %s, want whole-run deadline %s", got, runDeadline)
	}
	if got := subprocessDeadline(spec, now); !got.Equal(now.Add(RequestDeadline)) {
		t.Fatalf("first request deadline = %s", got)
	}
	later := now.Add(time.Minute)
	if got := subprocessDeadline(spec, later); !got.Equal(later.Add(RequestDeadline)) {
		t.Fatalf("later request did not receive a fresh request window: %s", got)
	}
	nearRunEnd := runDeadline.Add(-10 * time.Second)
	if got := subprocessDeadline(spec, nearRunEnd); !got.Equal(runDeadline) {
		t.Fatalf("request deadline = %s, want run clamp %s", got, runDeadline)
	}
}
