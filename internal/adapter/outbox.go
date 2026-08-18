package adapter

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"
)

const (
	RetryFloor = 30 * time.Second
	RetryCap   = time.Hour
	LeaseTime  = 2 * time.Minute
)

type JobKind string

const (
	Converge JobKind = "converge"
	Scrub    JobKind = "scrub"
	Activate JobKind = "activate"
)

type Job struct {
	ID                 string
	OrgID              string
	ProjectID          string
	EnvironmentID      string
	TargetID           string
	Kind               JobKind
	RouteMoveID        string
	AuthorityPrincipal string
	Generation         int64
	Attempt            int
	LeaseOwner         string
	CreatedAt          time.Time
}

type JobStore interface {
	ClaimDue(context.Context, string, time.Time, time.Time) (Job, bool, error)
	Journal(Job) Journal
	Retry(context.Context, Job, time.Time, []Change, []string, error) error
	Succeed(context.Context, Job, int64, []string, time.Time) error
	Fail(context.Context, Job, time.Time, error) error
}

type LoadedSync struct {
	Module   Module
	Request  SyncRequest
	Revision int64
	Release  func()
}

type LoadedActivation struct {
	Module  Module
	Request ConnectionRequest
	Release func()
}

type ActivationLoader interface {
	LoadActivation(context.Context, Job, Journal) (LoadedActivation, error)
}

type ActivationStore interface {
	Activate(context.Context, Job, Connection, time.Time) error
}

// Loader assembles plaintext only after the job has a durable lease and its
// recorded authority will be rechecked by Journal.Gate before each read/push.
// Release must zero/forget plaintext and credential buffers.
type Loader interface {
	Load(context.Context, Job, Journal) (LoadedSync, error)
}

type Worker struct {
	Store  JobStore
	Loader Loader
	ID     string
	Poll   time.Duration
	Now    func() time.Time
	Log    *slog.Logger
	Jitter func(time.Duration) time.Duration
	Wait   func(context.Context, time.Duration) error
}

func (w *Worker) wait(ctx context.Context, delay time.Duration) error {
	if w.Wait != nil {
		return w.Wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func RetryDelay(attempt int, jitter func(time.Duration) time.Duration) time.Duration {
	delay := RetryFloor
	for i := 1; i < attempt && delay < RetryCap; i++ {
		delay *= 2
		if delay > RetryCap {
			delay = RetryCap
		}
	}
	if jitter == nil {
		return delay/2 + time.Duration(rand.Int64N(int64(delay/2)))
	}
	return jitter(delay)
}

func retryDue(now time.Time, attempt int, jitter func(time.Duration) time.Duration, err error) time.Time {
	if at, ok := ProviderRetryAt(err); ok && at.After(now) {
		return at
	}
	return now.Add(RetryDelay(attempt, jitter))
}

func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	if w.Store == nil || w.Loader == nil || w.ID == "" {
		return false, errors.New("adapter: worker requires store, loader, and id")
	}
	now := w.now()
	leaseDeadline := now.Add(LeaseTime)
	leaseSafeDeadline := leaseDeadline.Add(-5 * time.Second)
	job, ok, err := w.Store.ClaimDue(ctx, w.ID, now, leaseDeadline)
	if err != nil || !ok {
		return ok, err
	}
	journal := w.Store.Journal(job)
	if err := journal.Gate(ctx, Effect{Surface: Secret, EffectiveName: "*", Disposition: Update}); err != nil {
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrSuperseded) {
			return true, w.Store.Fail(ctx, job, w.now(), err)
		}
		due := retryDue(w.now(), job.Attempt, w.Jitter, err)
		return true, w.Store.Retry(ctx, job, due, nil, nil, err)
	}
	if job.Kind == Activate {
		loader, ok := w.Loader.(ActivationLoader)
		if !ok {
			return true, w.Store.Fail(ctx, job, w.now(), errors.New("adapter: activation loader is not configured"))
		}
		activationStore, ok := w.Store.(ActivationStore)
		if !ok {
			return true, w.Store.Fail(ctx, job, w.now(), errors.New("adapter: activation store is not configured"))
		}
		for {
			loaded, loadErr := loader.LoadActivation(ctx, job, journal)
			err = loadErr
			if err == nil {
				var connection Connection
				connection, err = loaded.Module.TestConnection(ctx, loaded.Request)
				if loaded.Release != nil {
					loaded.Release()
				}
				if err == nil {
					err = activationStore.Activate(ctx, job, connection, w.now())
					if err == nil {
						return true, nil
					}
				}
			}
			retryAt, rateLimited := ProviderRetryAt(err)
			if !rateLimited || !retryAt.After(w.now()) || retryAt.After(leaseSafeDeadline) {
				break
			}
			if waitErr := w.wait(ctx, retryAt.Sub(w.now())); waitErr != nil {
				err = waitErr
				break
			}
		}
		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrSuperseded) {
			return true, w.Store.Fail(ctx, job, w.now(), err)
		}
		if errors.Is(err, ErrProviderAuth) || errors.Is(err, ErrConflict) {
			return true, w.Store.Fail(ctx, job, w.now(), err)
		}
		due := retryDue(w.now(), job.Attempt, w.Jitter, err)
		return true, w.Store.Retry(ctx, job, due, nil, nil, err)
	}
	completed := []Change{}
	var result SyncResult
	var revision int64
	for {
		loaded, loadErr := w.Loader.Load(ctx, job, journal)
		if loadErr != nil {
			err = loadErr
			if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrSuperseded) || errors.Is(err, ErrProviderAuth) {
				return true, w.Store.Fail(ctx, job, w.now(), err)
			}
			due := retryDue(w.now(), job.Attempt, w.Jitter, err)
			return true, w.Store.Retry(ctx, job, due, nil, nil, err)
		}
		revision = loaded.Revision
		loaded.Request.Teardown = job.Kind == Scrub
		loaded.Request.Completed = append([]Change(nil), completed...)
		result, err = loaded.Module.Sync(ctx, loaded.Request, journal)
		if loaded.Release != nil {
			loaded.Release()
		}
		if err == nil {
			return true, w.Store.Succeed(ctx, job, revision, result.Warnings, w.now())
		}
		retryAt, rateLimited := ProviderRetryAt(err)
		if !rateLimited || !retryAt.After(w.now()) || retryAt.After(leaseSafeDeadline) {
			break
		}
		for _, change := range result.Changes {
			found := false
			for _, prior := range completed {
				if prior.Surface == change.Surface && prior.EffectiveName == change.EffectiveName {
					found = true
					break
				}
			}
			if !found {
				completed = append(completed, change)
			}
		}
		if waitErr := w.wait(ctx, retryAt.Sub(w.now())); waitErr != nil {
			err = waitErr
			break
		}
	}
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrSuperseded) {
		return true, w.Store.Fail(ctx, job, w.now(), err)
	}
	if errors.Is(err, ErrProviderAuth) {
		return true, w.Store.Fail(ctx, job, w.now(), err)
	}
	due := retryDue(w.now(), job.Attempt, w.Jitter, err)
	if !job.CreatedAt.IsZero() && w.now().Sub(job.CreatedAt) > time.Hour {
		log := w.Log
		if log == nil {
			log = slog.Default()
		}
		log.Error("adapter target has failed for more than one hour", "target_id", job.TargetID, "job_id", job.ID)
	}
	failures := append(append([]Change{}, result.Failed...), result.Conflicts...)
	return true, w.Store.Retry(ctx, job, due, failures, result.Warnings, err)
}

func (w *Worker) Run(ctx context.Context) {
	poll := w.Poll
	if poll <= 0 || poll >= RetryFloor {
		poll = time.Second
	}
	log := w.Log
	if log == nil {
		log = slog.Default()
	}
	for {
		worked, err := w.RunOnce(ctx)
		if err != nil {
			log.Error("adapter outbox worker failed", "err", err)
		}
		if worked {
			continue
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
