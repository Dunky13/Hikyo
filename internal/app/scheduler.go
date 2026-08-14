package app

import (
	"context"
	"log/slog"
	"time"
)

const (
	defaultSchedulerInterval = time.Hour
	defaultJobDeadline       = 10 * time.Minute
	pruneStaleAfter          = 24 * time.Hour
)

// ScheduledJob is one bounded background operation. LastSuccess reads the
// job's persisted health marker; nil means the job has no staleness contract.
type ScheduledJob struct {
	Name        string
	Run         func(context.Context) error
	LastSuccess func(context.Context) (time.Time, bool, error)
}

// Scheduler runs every registered job once on startup and then hourly. Jobs
// share no transaction or deadline, so one failure cannot roll back another or
// silently disable future ticks.
type Scheduler struct {
	Jobs     []ScheduledJob
	Interval time.Duration
	Deadline time.Duration
	Log      *slog.Logger
	Now      func() time.Time
}

func (s *Scheduler) interval() time.Duration {
	if s.Interval <= 0 {
		return defaultSchedulerInterval
	}
	return s.Interval
}

func (s *Scheduler) deadline() time.Duration {
	if s.Deadline <= 0 {
		return defaultJobDeadline
	}
	return s.Deadline
}

func (s *Scheduler) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func (s *Scheduler) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Run blocks until cancellation. The first pass is the startup catch-up run.
func (s *Scheduler) Run(ctx context.Context) {
	s.runOnce(ctx, "startup")
	ticker := time.NewTicker(s.interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx, "hourly")
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context, trigger string) {
	for _, job := range s.Jobs {
		if ctx.Err() != nil {
			return
		}
		jobCtx, cancel := context.WithTimeout(ctx, s.deadline())
		err := job.Run(jobCtx)
		cancel()
		if err != nil {
			s.logger().Error("scheduler job failed", "job", job.Name, "trigger", trigger, "err", err)
		}
		s.checkHealth(ctx, job)
	}
}

func (s *Scheduler) checkHealth(ctx context.Context, job ScheduledJob) {
	if job.LastSuccess == nil {
		return
	}
	at, ok, err := job.LastSuccess(ctx)
	if err != nil {
		s.logger().Error("scheduler job health check failed", "job", job.Name, "err", err)
		return
	}
	if !ok {
		s.logger().Warn("last_prune_success has never been recorded", "job", job.Name)
		return
	}
	age := s.now().Sub(at)
	// This log is the operator narrative beside the same persisted timestamp
	// exposed by doctor, the instance health API, and /metrics.
	s.logger().Info("scheduler job health", "job", job.Name, "last_prune_success", at, "age", age)
	if age > pruneStaleAfter {
		s.logger().Warn("last_prune_success is stale", "job", job.Name, "last_prune_success", at, "age", age)
	}
}
