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
	job             Job
	failed, retried bool
	activationErr   error
	retryFailures   []Change
}

func (s *workerJobStore) ClaimDue(context.Context, string, time.Time, time.Time) (Job, bool, error) {
	return s.job, true, nil
}
func (*workerJobStore) Journal(Job) Journal { return workerJournal{} }
func (s *workerJobStore) Retry(_ context.Context, _ Job, _ time.Time, failed []Change, _ error) error {
	s.retried = true
	s.retryFailures = append([]Change{}, failed...)
	return nil
}
func (*workerJobStore) Succeed(context.Context, Job, int64, time.Time) error { return nil }
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
		Store: store, Loader: workerLoader{module: workerModule{syncErr: errors.New("retry"), result: SyncResult{Failed: []Change{failed}, Conflicts: []Change{conflict}}}}, ID: "worker_1",
		Now: func() time.Time { return time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC) }, Jitter: func(time.Duration) time.Duration { return time.Second },
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %v, %v", worked, err)
	}
	if len(store.retryFailures) != 2 || store.retryFailures[0] != failed || store.retryFailures[1] != conflict {
		t.Fatalf("retry failures = %+v, want failed then conflict", store.retryFailures)
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
