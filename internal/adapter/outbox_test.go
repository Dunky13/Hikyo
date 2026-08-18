package adapter

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryCurveIsBoundedAndJittered(t *testing.T) {
	half := func(d time.Duration) time.Duration { return d / 2 }
	tests := []struct {
		attempt int
		want    time.Duration
	}{{1, 15 * time.Second}, {2, 30 * time.Second}, {7, 16 * time.Minute}, {99, 30 * time.Minute}}
	for _, tt := range tests {
		if got := RetryDelay(tt.attempt, half); got != tt.want {
			t.Errorf("attempt %d delay = %s, want %s", tt.attempt, got, tt.want)
		}
	}
}

func TestWorkerProviderAuthIsTerminalButTransportRemainsRetryable(t *testing.T) {
	tests := []struct {
		name      string
		kind      JobKind
		loadErr   error
		moduleErr error
		wantFail  bool
	}{
		{name: "converge revoked before load", kind: Converge, loadErr: ErrProviderAuth, wantFail: true},
		{name: "scrub revoked before load", kind: Scrub, loadErr: ErrProviderAuth, wantFail: true},
		{name: "converge provider rejects credential", kind: Converge, moduleErr: ErrProviderAuth, wantFail: true},
		{name: "scrub provider rejects credential", kind: Scrub, moduleErr: ErrProviderAuth, wantFail: true},
		{name: "converge transport retries", kind: Converge, moduleErr: errors.New("connection reset")},
		{name: "scrub transport retries", kind: Scrub, moduleErr: errors.New("connection reset")},
		{name: "converge indeterminate 5xx retries", kind: Converge, moduleErr: ErrIndeterminate},
		{name: "scrub indeterminate 5xx retries", kind: Scrub, moduleErr: ErrIndeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &workerJobStore{job: Job{ID: "job_1", OrgID: "org_1", ProjectID: "project_1", EnvironmentID: "env_1", TargetID: "target_1", Kind: tt.kind, AuthorityPrincipal: "user_1", Generation: 1, Attempt: 1}}
			worker := Worker{
				Store: store, Loader: workerLoader{loadErr: tt.loadErr, module: workerModule{syncErr: tt.moduleErr}}, ID: "worker_1",
				Now: func() time.Time { return time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC) }, Jitter: func(time.Duration) time.Duration { return time.Second },
			}
			worked, err := worker.RunOnce(t.Context())
			if err != nil || !worked {
				t.Fatalf("RunOnce() = %v, %v", worked, err)
			}
			if store.failed != tt.wantFail || store.retried == tt.wantFail {
				t.Fatalf("terminal=%v retry=%v, want terminal=%v", store.failed, store.retried, tt.wantFail)
			}
		})
	}
}

func TestWorkerActivationRequiresAttentionOnlyForCredentialOrCollision(t *testing.T) {
	tests := []struct {
		name          string
		connectionErr error
		activationErr error
		wantFail      bool
	}{
		{name: "pending credential rejected", connectionErr: ErrProviderAuth, wantFail: true},
		{name: "pending namespace collision", activationErr: ErrConflict, wantFail: true},
		{name: "pending route transport retries", connectionErr: errors.New("connection reset")},
		{name: "pending route indeterminate retries", connectionErr: ErrIndeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &workerJobStore{job: Job{ID: "job_activate", OrgID: "org_1", ProjectID: "project_1", EnvironmentID: "env_1", TargetID: "target_1", Kind: Activate, RouteMoveID: "move_1", AuthorityPrincipal: "user_1", Generation: 2, Attempt: 1}, activationErr: tt.activationErr}
			worker := Worker{
				Store: store, Loader: workerActivationLoader{module: workerModule{connectionErr: tt.connectionErr}}, ID: "worker_1",
				Now: func() time.Time { return time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC) }, Jitter: func(time.Duration) time.Duration { return time.Second },
			}
			worked, err := worker.RunOnce(t.Context())
			if err != nil || !worked {
				t.Fatalf("RunOnce() = %v, %v", worked, err)
			}
			if store.failed != tt.wantFail || store.retried == tt.wantFail {
				t.Fatalf("terminal=%v retry=%v, want terminal=%v", store.failed, store.retried, tt.wantFail)
			}
		})
	}
}

type workerJobStore struct {
	job                        Job
	journal                    Journal
	failed, retried, succeeded bool
	activationErr              error
	retryFailures              []Change
	retryDue                   time.Time
	warnings                   []string
}

type cursorModule struct {
	now       time.Time
	calls     int
	completed []Change
}

func (*cursorModule) ValidateConfig(Config) error { return nil }
func (*cursorModule) TestConnection(context.Context, ConnectionRequest) (Connection, error) {
	return Connection{}, nil
}
func (*cursorModule) Plan(context.Context, PlanRequest) (Plan, error) { return Plan{}, nil }
func (m *cursorModule) Sync(_ context.Context, request SyncRequest, _ Journal) (SyncResult, error) {
	m.calls++
	if m.calls == 1 {
		return SyncResult{Changes: []Change{{Surface: Secret, EffectiveName: "DONE", Disposition: Update}}}, retryAtTestError{at: m.now.Add(time.Second)}
	}
	m.completed = append([]Change(nil), request.Completed...)
	return SyncResult{Warnings: []string{"provider delivery cap is near"}}, nil
}

type cursorLoader struct {
	module   Module
	loads    int
	releases int
}

func (l *cursorLoader) Load(context.Context, Job, Journal) (LoadedSync, error) {
	l.loads++
	return LoadedSync{Module: l.module, Release: func() { l.releases++ }}, nil
}

func TestWorkerRateWaitReleasesPlaintextAndResumesAfterCompletedName(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	module := &cursorModule{now: now}
	loader := &cursorLoader{module: module}
	store := &workerJobStore{job: Job{ID: "job_cursor", Kind: Converge, Attempt: 1}}
	waits := 0
	worker := Worker{
		Store: store, Loader: loader, ID: "worker_1", Now: func() time.Time { return now },
		Wait: func(_ context.Context, delay time.Duration) error {
			waits++
			if loader.releases != 1 || delay != time.Second {
				t.Fatalf("wait started with releases=%d delay=%s", loader.releases, delay)
			}
			return nil
		},
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %v, %v", worked, err)
	}
	if waits != 1 || loader.loads != 2 || loader.releases != 2 || !store.succeeded || store.retried {
		t.Fatalf("waits=%d loads=%d releases=%d succeeded=%v retried=%v", waits, loader.loads, loader.releases, store.succeeded, store.retried)
	}
	if len(module.completed) != 1 || module.completed[0].EffectiveName != "DONE" {
		t.Fatalf("resume cursor = %+v", module.completed)
	}
	if len(store.warnings) != 1 || store.warnings[0] != "provider delivery cap is near" {
		t.Fatalf("persisted warnings = %v", store.warnings)
	}
}

func (s *workerJobStore) ClaimDue(context.Context, string, time.Time, time.Time) (Job, bool, error) {
	return s.job, true, nil
}
func (s *workerJobStore) Journal(Job) Journal {
	if s.journal != nil {
		return s.journal
	}
	return workerJournal{}
}
func (s *workerJobStore) Retry(_ context.Context, _ Job, due time.Time, failed []Change, warnings []string, _ error) error {
	s.retried = true
	s.retryDue = due
	s.retryFailures = append([]Change{}, failed...)
	s.warnings = append([]string(nil), warnings...)
	return nil
}

type retryAtTestError struct{ at time.Time }

func (e retryAtTestError) Error() string      { return "rate limited" }
func (e retryAtTestError) RetryAt() time.Time { return e.at }

func TestWorkerHonorsProviderRetryDeadline(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	want := now.Add(3 * time.Minute)
	store := &workerJobStore{job: Job{ID: "job_rate", Kind: Converge, Attempt: 1}}
	worker := Worker{
		Store: store, Loader: workerLoader{module: workerModule{syncErr: retryAtTestError{at: want}}}, ID: "worker_1",
		Now: func() time.Time { return now }, Jitter: func(time.Duration) time.Duration { return time.Second },
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %v, %v", worked, err)
	}
	if !store.retried || !store.retryDue.Equal(want) {
		t.Fatalf("retry due = %s, retried=%v; want %s", store.retryDue, store.retried, want)
	}
}

type slowLeaseJournal struct {
	now      *time.Time
	leaseEnd time.Time
	calls    int
}

func (j *slowLeaseJournal) Gate(context.Context, Effect) error {
	j.calls++
	if j.calls == 1 {
		*j.now = j.now.Add(LeaseTime - 10*time.Second)
		return nil
	}
	if !j.now.Before(j.leaseEnd) {
		return ErrSuperseded
	}
	return nil
}
func (*slowLeaseJournal) Reserve(context.Context, Effect) (LedgerState, error) { return Reserved, nil }
func (*slowLeaseJournal) Prepare(context.Context, Effect, LedgerState) error   { return nil }
func (*slowLeaseJournal) Finish(context.Context, Effect, Completion) error     { return nil }
func (*slowLeaseJournal) Refuse(context.Context, Effect) error                 { return nil }
func (*slowLeaseJournal) ReleaseReservation(context.Context, Effect) error     { return nil }

type leaseCheckingLoader struct {
	module Module
	loads  int
}

func (l *leaseCheckingLoader) Load(ctx context.Context, _ Job, journal Journal) (LoadedSync, error) {
	l.loads++
	if err := journal.Gate(ctx, Effect{Surface: Secret, EffectiveName: "*", Disposition: Update}); err != nil {
		return LoadedSync{}, err
	}
	return LoadedSync{Module: l.module}, nil
}
func (l *leaseCheckingLoader) LoadActivation(ctx context.Context, _ Job, journal Journal) (LoadedActivation, error) {
	l.loads++
	if err := journal.Gate(ctx, Effect{Surface: Secret, EffectiveName: "*", Disposition: Update}); err != nil {
		return LoadedActivation{}, err
	}
	return LoadedActivation{Module: l.module, Request: ConnectionRequest{Gate: func(context.Context) error { return nil }}}, nil
}

func TestWorkerSlowInitialGateCannotWaitPastOriginalDurableLease(t *testing.T) {
	for _, kind := range []JobKind{Converge, Activate} {
		t.Run(string(kind), func(t *testing.T) {
			claimedAt := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
			now := claimedAt
			retryAt := claimedAt.Add(LeaseTime + 5*time.Second)
			journal := &slowLeaseJournal{now: &now, leaseEnd: claimedAt.Add(LeaseTime)}
			module := workerModule{syncErr: retryAtTestError{at: retryAt}, connectionErr: retryAtTestError{at: retryAt}}
			loader := &leaseCheckingLoader{module: module}
			store := &workerJobStore{job: Job{ID: "job_slow_gate", Kind: kind, RouteMoveID: "move_slow_gate", Attempt: 1}, journal: journal}
			waits := 0
			worker := Worker{
				Store: store, Loader: loader, ID: "worker_slow_gate", Now: func() time.Time { return now },
				Wait: func(_ context.Context, delay time.Duration) error {
					waits++
					now = now.Add(delay)
					return nil
				},
			}
			if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
				t.Fatalf("RunOnce() = %v, %v", worked, err)
			}
			if waits != 0 || loader.loads != 1 || !store.retried || store.failed {
				t.Fatalf("waits=%d loads=%d retried=%v failed=%v, want direct nonterminal retry", waits, loader.loads, store.retried, store.failed)
			}
			if !store.retryDue.Equal(retryAt) {
				t.Fatalf("retry due=%s, want provider deadline %s", store.retryDue, retryAt)
			}
		})
	}
}
func (s *workerJobStore) Succeed(_ context.Context, _ Job, _ int64, warnings []string, _ time.Time) error {
	s.succeeded = true
	s.warnings = append([]string(nil), warnings...)
	return nil
}
func (s *workerJobStore) Fail(context.Context, Job, time.Time, error) error {
	s.failed = true
	return nil
}
func (s *workerJobStore) Activate(context.Context, Job, Connection, time.Time) error {
	return s.activationErr
}

type workerLoader struct {
	loadErr error
	module  Module
}

func (l workerLoader) Load(context.Context, Job, Journal) (LoadedSync, error) {
	return LoadedSync{Module: l.module}, l.loadErr
}

type workerModule struct {
	syncErr, connectionErr error
	result                 SyncResult
}

func (workerModule) ValidateConfig(Config) error { return nil }
func (m workerModule) TestConnection(context.Context, ConnectionRequest) (Connection, error) {
	return Connection{Version: "1.21.0", DestinationID: 42}, m.connectionErr
}

type workerActivationLoader struct{ module Module }

func (l workerActivationLoader) Load(context.Context, Job, Journal) (LoadedSync, error) {
	return LoadedSync{}, errors.New("unexpected ordinary load")
}
func (l workerActivationLoader) LoadActivation(context.Context, Job, Journal) (LoadedActivation, error) {
	return LoadedActivation{Module: l.module, Request: ConnectionRequest{Gate: func(context.Context) error { return nil }}}, nil
}
func (workerModule) Plan(context.Context, PlanRequest) (Plan, error) { return Plan{}, nil }
func (m workerModule) Sync(context.Context, SyncRequest, Journal) (SyncResult, error) {
	return m.result, m.syncErr
}

func TestWorkerRetryFailureNamesIncludeFailedAndConflicts(t *testing.T) {
	failed := Change{Surface: Secret, EffectiveName: "BROKEN"}
	conflict := Change{Surface: Variable, EffectiveName: "CLAIMED"}
	store := &workerJobStore{job: Job{ID: "job_1", Kind: Converge, Attempt: 1}}
	worker := Worker{
		Store: store, Loader: workerLoader{module: workerModule{syncErr: errors.New("retry"), result: SyncResult{Failed: []Change{failed}, Conflicts: []Change{conflict}, Warnings: []string{"provider cap is near"}}}}, ID: "worker_1",
		Now: func() time.Time { return time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC) }, Jitter: func(time.Duration) time.Duration { return time.Second },
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %v, %v", worked, err)
	}
	if len(store.retryFailures) != 2 || store.retryFailures[0] != failed || store.retryFailures[1] != conflict {
		t.Fatalf("retry failures = %+v, want failed then conflict", store.retryFailures)
	}
	if len(store.warnings) != 1 || store.warnings[0] != "provider cap is near" {
		t.Fatalf("retry warnings = %v", store.warnings)
	}
}

func TestWorkerDefiniteProviderAbsenceSchedulesFreshConvergeAttempt(t *testing.T) {
	change := Change{Surface: Variable, EffectiveName: "LOG_LEVEL", Disposition: Update}
	store := &workerJobStore{job: Job{ID: "job_1", Kind: Converge, Attempt: 1}}
	worker := Worker{
		Store: store, Loader: workerLoader{module: workerModule{syncErr: errors.New("provider PUT returned 404"), result: SyncResult{Failed: []Change{change}}}}, ID: "worker_1",
		Now: func() time.Time { return time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC) }, Jitter: func(time.Duration) time.Duration { return time.Second },
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %v, %v", worked, err)
	}
	if !store.retried || store.failed || len(store.retryFailures) != 1 || store.retryFailures[0] != change {
		t.Fatalf("retried=%v failed=%v failures=%+v", store.retried, store.failed, store.retryFailures)
	}
}

type workerJournal struct{}

func (workerJournal) Gate(context.Context, Effect) error { return nil }
func (workerJournal) Reserve(context.Context, Effect) (LedgerState, error) {
	return Reserved, nil
}
func (workerJournal) Prepare(context.Context, Effect, LedgerState) error { return nil }
func (workerJournal) Finish(context.Context, Effect, Completion) error   { return nil }
func (workerJournal) Refuse(context.Context, Effect) error               { return nil }
func (workerJournal) ReleaseReservation(context.Context, Effect) error   { return nil }
