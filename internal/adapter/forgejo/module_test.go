package forgejo

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
)

func TestSyncClaimPruneAndTeardown(t *testing.T) {
	api := &fakeAPI{id: 42, version: "1.21.11", secrets: map[string]bool{}}
	journal := newFakeJournal()
	module := Module{API: api}
	target := testTarget()

	_, err := module.Sync(t.Context(), adapter.SyncRequest{
		Target: target,
		Manifest: []adapter.ManifestEntry{
			{KeyID: "key_secret", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "secret-value"},
			{KeyID: "key_config", CanonicalName: "LOG_LEVEL", Classification: adapter.ConfigClassification, Value: "debug"},
		},
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	wantWrites := []string{"put-secret:PROD_MANAGED_BY_WENV", "create-variable:PROD_MANAGED_BY_WENV", "put-secret:PROD_TOKEN", "create-variable:PROD_LOG_LEVEL"}
	if !slices.Equal(api.writes, wantWrites) {
		t.Fatalf("writes = %v, want sentinel-first %v", api.writes, wantWrites)
	}
	for _, key := range []string{"secret:PROD_MANAGED_BY_WENV", "variable:PROD_MANAGED_BY_WENV", "variable:PROD_LOG_LEVEL", "secret:PROD_TOKEN"} {
		if journal.states[key] != adapter.Owned {
			t.Errorf("%s state = %q, want owned", key, journal.states[key])
		}
	}

	api.writes = nil
	ledger := journal.ledger()
	_, err = module.Sync(t.Context(), adapter.SyncRequest{Target: target, Ledger: ledger, Teardown: true}, journal)
	if err != nil {
		t.Fatal(err)
	}
	wantDeletes := []string{"delete-secret:PROD_TOKEN", "delete-variable:PROD_LOG_LEVEL", "delete-secret:PROD_MANAGED_BY_WENV", "delete-variable:PROD_MANAGED_BY_WENV"}
	if !slices.Equal(api.writes, wantDeletes) {
		t.Fatalf("teardown writes = %v, want sentinels-last %v", api.writes, wantDeletes)
	}
	if len(journal.states) != 4 {
		t.Fatalf("teardown custody history = %v, want four released rows", journal.states)
	}
	for name, state := range journal.states {
		if state != adapter.Released {
			t.Fatalf("teardown ledger %s = %q, want released", name, state)
		}
	}
}

func TestReservedCrashReplayDoesNotCaptureASecretCreatedInTheGap(t *testing.T) {
	api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{"TOKEN": true}}
	journal := newFakeJournal()
	journal.states["secret:TOKEN"] = adapter.Reserved
	module := Module{API: api}

	result, err := module.Sync(t.Context(), adapter.SyncRequest{
		Target:   testTargetNoPrefix(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "ours"}},
		Ledger:   journal.ledger(),
	}, journal)
	if !errors.Is(err, adapter.ErrConflict) {
		t.Fatalf("Sync() error = %v, want exists-unowned", err)
	}
	if len(result.Conflicts) != 1 || slices.Contains(api.writes, "put-secret:TOKEN") {
		t.Fatalf("result=%+v writes=%v; reserved replay captured provider name", result, api.writes)
	}
	if _, exists := journal.states["secret:TOKEN"]; exists {
		t.Fatal("refused reservation was not released")
	}
}

func TestSyncReleasesUndesiredCrashReservationWithoutConflictOrProviderDelete(t *testing.T) {
	for _, tt := range []struct {
		name     string
		teardown bool
	}{
		{name: "converge"},
		{name: "scrub", teardown: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}}
			journal := newFakeJournal()
			journal.states["secret:STALE"] = adapter.Reserved

			result, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{
				Target:   testTargetNoPrefix(),
				Ledger:   journal.ledger(),
				Teardown: tt.teardown,
			}, journal)
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := journal.states["secret:STALE"]; exists {
				t.Fatal("stale pre-dispatch reservation remained claimed")
			}
			if journal.releases["secret:STALE"] != 1 || journal.refusals != 0 {
				t.Fatalf("release calls=%v refusals=%d, want one local release and no conflict refusal", journal.releases, journal.refusals)
			}
			if slices.Contains(api.writes, "delete-secret:STALE") || len(result.Conflicts) != 0 {
				t.Fatalf("writes=%v conflicts=%v; local reservation release reached provider/conflict path", api.writes, result.Conflicts)
			}
		})
	}
}

func TestDispatchWindowVariableReplayUsesUpdateNotCreate(t *testing.T) {
	api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}}
	journal := newFakeJournal()
	journal.states["variable:LOG_LEVEL"] = adapter.Dispatched
	module := Module{API: api}

	_, err := module.Sync(t.Context(), adapter.SyncRequest{
		Target:   testTargetNoPrefix(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "LOG_LEVEL", Classification: adapter.ConfigClassification, Value: "debug"}},
		Ledger:   journal.ledger(),
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(api.writes, "update-variable:LOG_LEVEL") || slices.Contains(api.writes, "create-variable:LOG_LEVEL") {
		t.Fatalf("dispatch replay writes = %v, want LOG_LEVEL update and never create", api.writes)
	}
	if journal.states["variable:LOG_LEVEL"] != adapter.Owned {
		t.Fatal("dispatch replay did not confirm ownership")
	}
}

func TestOwnedVariableDeletedAtProviderRetriesCreateUnderFreshEffect(t *testing.T) {
	api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{"update-variable:LOG_LEVEL": &ResponseError{Status: 404}}}
	journal := newFakeJournal()
	journal.states["secret:MANAGED_BY_WENV"] = adapter.Owned
	journal.states["variable:MANAGED_BY_WENV"] = adapter.Owned
	journal.states["variable:LOG_LEVEL"] = adapter.Owned

	request := adapter.SyncRequest{
		Target:   testTargetNoPrefix(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "LOG_LEVEL", Classification: adapter.ConfigClassification, Value: "debug"}},
		Ledger:   journal.ledger(),
	}
	_, err := (&Module{API: api}).Sync(t.Context(), request, journal)
	if !IsNotFound(err) {
		t.Fatalf("first Sync() error = %v, want definite 404 retry", err)
	}
	want := []string{"put-secret:MANAGED_BY_WENV", "update-variable:MANAGED_BY_WENV", "update-variable:LOG_LEVEL"}
	if !slices.Equal(api.writes, want) {
		t.Fatalf("first-attempt writes=%v, want exactly one request for repaired effect %v", api.writes, want)
	}
	if _, claimed := journal.states["variable:LOG_LEVEL"]; claimed {
		t.Fatalf("absence-proven variable remained claimed as %q", journal.states["variable:LOG_LEVEL"])
	}
	completion := journal.completions["variable:LOG_LEVEL"]
	if journal.prepares["variable:LOG_LEVEL"] != 1 || len(completion) != 1 || completion[0].Outcome != "failure" || completion[0].State != "" {
		t.Fatalf("first effect prepare=%d completion=%+v", journal.prepares["variable:LOG_LEVEL"], completion)
	}

	request.Ledger = journal.ledger()
	if _, err := (&Module{API: api}).Sync(t.Context(), request, journal); err != nil {
		t.Fatal(err)
	}
	want = append(want, "put-secret:MANAGED_BY_WENV", "update-variable:MANAGED_BY_WENV", "create-variable:LOG_LEVEL")
	if !slices.Equal(api.writes, want) {
		t.Fatalf("replay writes=%v, want fresh create attempt %v", api.writes, want)
	}
	completion = journal.completions["variable:LOG_LEVEL"]
	if journal.prepares["variable:LOG_LEVEL"] != 2 || len(completion) != 2 || completion[1].Outcome != "success" || completion[1].State != adapter.Owned {
		t.Fatalf("replay effects prepare=%d completion=%+v", journal.prepares["variable:LOG_LEVEL"], completion)
	}
}

func TestPostPrepareGateFailureFinishesWithoutProviderRequest(t *testing.T) {
	gateErr := errors.New("authority changed")
	for _, tt := range []struct {
		name  string
		state adapter.LedgerState
	}{
		{name: "reserved", state: adapter.Reserved},
		{name: "owned", state: adapter.Owned},
		{name: "dispatched", state: adapter.Dispatched},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{}}
			journal := newFakeJournal()
			journal.states["secret:MANAGED_BY_WENV"] = tt.state
			journal.gateErrAt, journal.gateErr = 5, gateErr
			_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{Target: testTargetNoPrefix(), Ledger: journal.ledger()}, journal)
			if !errors.Is(err, gateErr) {
				t.Fatalf("Sync() error = %v, want gate error", err)
			}
			if len(api.writes) != 0 {
				t.Fatalf("provider writes after failed post-Prepare gate = %v", api.writes)
			}
			completion := journal.completions["secret:MANAGED_BY_WENV"]
			if len(completion) != 1 || completion[0].Outcome != "failure" || completion[0].State != tt.state || journal.states["secret:MANAGED_BY_WENV"] != tt.state {
				t.Fatalf("completion=%+v state=%q, want preserved %q", completion, journal.states["secret:MANAGED_BY_WENV"], tt.state)
			}
		})
	}
}

func TestPrunePostPrepareGateFailureFinishesAndReleasesFence(t *testing.T) {
	gateErr := errors.New("generation superseded")
	api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{}}
	journal := newFakeJournal()
	journal.states["variable:OLD"] = adapter.Owned
	journal.gateErrAt, journal.gateErr = 5, gateErr
	_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{Target: testTargetNoPrefix(), Teardown: true, Ledger: journal.ledger()}, journal)
	if !errors.Is(err, gateErr) {
		t.Fatalf("Sync() error = %v, want gate error", err)
	}
	if len(api.writes) != 0 {
		t.Fatalf("provider deletes after failed post-Prepare gate = %v", api.writes)
	}
	completion := journal.completions["variable:OLD"]
	if len(completion) != 1 || completion[0].Outcome != "failure" || completion[0].State != adapter.Owned {
		t.Fatalf("completion = %+v", completion)
	}
}

func TestPostPrepareGateFailurePropagatesFinishErrorFirst(t *testing.T) {
	gateErr := errors.New("authority changed")
	finishErr := errors.New("durable OUTCOME failed")
	api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{}}
	journal := newFakeJournal()
	journal.states["secret:MANAGED_BY_WENV"] = adapter.Reserved
	journal.gateErrAt, journal.gateErr = 5, gateErr
	journal.finishErrFor, journal.finishErr = "secret:MANAGED_BY_WENV", finishErr
	_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{Target: testTargetNoPrefix(), Ledger: journal.ledger()}, journal)
	if !errors.Is(err, finishErr) || errors.Is(err, gateErr) {
		t.Fatalf("Sync() error = %v, want Finish error before Gate error", err)
	}
}

func TestFinishErrorsOverrideVariableConflictAndPruneProviderErrors(t *testing.T) {
	finishErr := errors.New("durable OUTCOME failed")
	t.Run("variable conflict", func(t *testing.T) {
		api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{}, conflict: map[string]bool{"MODE": true}}
		journal := newFakeJournal()
		journal.states["secret:MANAGED_BY_WENV"] = adapter.Owned
		journal.states["variable:MANAGED_BY_WENV"] = adapter.Owned
		journal.finishErrFor = "variable:MODE"
		journal.finishErr = finishErr
		_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{Target: testTargetNoPrefix(), Manifest: []adapter.ManifestEntry{{CanonicalName: "MODE", Classification: adapter.ConfigClassification, Value: "x"}}, Ledger: journal.ledger()}, journal)
		if !errors.Is(err, finishErr) {
			t.Fatalf("Sync() error = %v, want Finish error", err)
		}
	})
	t.Run("prune provider error", func(t *testing.T) {
		providerErr := errors.New("connection reset")
		api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{"delete-variable:OLD": providerErr}}
		journal := newFakeJournal()
		journal.states["variable:OLD"] = adapter.Owned
		journal.finishErrFor = "variable:OLD"
		journal.finishErr = finishErr
		_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{Target: testTargetNoPrefix(), Teardown: true, Ledger: journal.ledger()}, journal)
		if !errors.Is(err, finishErr) {
			t.Fatalf("Sync() error = %v, want Finish error over provider error", err)
		}
	})
}

func TestProviderOutcomeMatrixPreservesOnlyClaimsThatMayHaveLanded(t *testing.T) {
	tests := []struct {
		name      string
		prior     adapter.LedgerState
		provider  error
		wantState adapter.LedgerState
		want      error
	}{
		{name: "reserved definite 4xx releases", prior: adapter.Reserved, provider: &ResponseError{Status: 400}, wantState: "", want: &ResponseError{}},
		{name: "reserved 5xx retains dispatched", prior: adapter.Reserved, provider: &ResponseError{Status: 503}, wantState: adapter.Dispatched, want: adapter.ErrIndeterminate},
		{name: "reserved network retains dispatched", prior: adapter.Reserved, provider: errors.New("connection reset"), wantState: adapter.Dispatched, want: adapter.ErrIndeterminate},
		{name: "owned definite 4xx retains owned", prior: adapter.Owned, provider: &ResponseError{Status: 403}, wantState: adapter.Owned, want: &ResponseError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, failures: map[string]error{"put-secret:TOKEN": tt.provider}}
			journal := newFakeJournal()
			journal.states["secret:MANAGED_BY_WENV"] = adapter.Owned
			journal.states["variable:MANAGED_BY_WENV"] = adapter.Owned
			journal.states["secret:TOKEN"] = tt.prior
			_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{
				Target:   testTargetNoPrefix(),
				Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "value"}},
				Ledger:   journal.ledger(),
			}, journal)
			var response *ResponseError
			if _, responseWanted := tt.want.(*ResponseError); responseWanted {
				if !errors.As(err, &response) {
					t.Fatalf("Sync() error = %v, want ResponseError", err)
				}
			} else if !errors.Is(err, tt.want) {
				t.Fatalf("Sync() error = %v, want %v", err, tt.want)
			}
			if got := journal.states["secret:TOKEN"]; got != tt.wantState {
				t.Fatalf("terminal state = %q, want %q", got, tt.wantState)
			}
		})
	}
}

func TestSyncFreshGateImmediatelyPrecedesEverySensitiveProviderRequest(t *testing.T) {
	var trace []string
	api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, trace: &trace}
	journal := newFakeJournal()
	journal.trace = &trace
	_, err := (&Module{API: api}).Sync(t.Context(), adapter.SyncRequest{
		Target: testTargetNoPrefix(),
		Manifest: []adapter.ManifestEntry{
			{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "value"},
		},
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	gates := 0
	requests := 0
	for i, step := range trace {
		if step == "gate" {
			gates++
			continue
		}
		if step == "resolve" || step == "version" || step == "list-secrets" || strings.HasPrefix(step, "put-") || strings.HasPrefix(step, "create-") || strings.HasPrefix(step, "update-") || strings.HasPrefix(step, "delete-") {
			requests++
			if i == 0 || trace[i-1] != "gate" {
				t.Fatalf("provider request %q at %d has no immediately preceding gate: trace=%v", step, i, trace)
			}
		}
	}
	if requests == 0 || gates < requests {
		t.Fatalf("gates=%d requests=%d trace=%v", gates, requests, trace)
	}
}

func TestPlanAndTestConnectionGateEveryProviderRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*Module, func(context.Context) error) error
	}{
		{name: "plan", run: func(module *Module, gate func(context.Context) error) error {
			_, err := module.Plan(t.Context(), adapter.PlanRequest{Target: testTargetNoPrefix(), Gate: gate})
			return err
		}},
		{name: "test connection", run: func(module *Module, gate func(context.Context) error) error {
			_, err := module.TestConnection(t.Context(), adapter.ConnectionRequest{Destination: testTargetNoPrefix().Destination, Gate: gate})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var trace []string
			api := &fakeAPI{id: 42, version: "1.21.0", secrets: map[string]bool{}, trace: &trace}
			gate := func(context.Context) error { trace = append(trace, "gate"); return nil }
			if err := tc.run(&Module{API: api}, gate); err != nil {
				t.Fatal(err)
			}
			for i, step := range trace {
				if step != "resolve" && step != "version" && step != "list-secrets" {
					continue
				}
				if i == 0 || trace[i-1] != "gate" {
					t.Fatalf("request %q lacks fresh gate: %v", step, trace)
				}
			}
			if got := strings.Count(strings.Join(trace, ","), "gate"); got != 2 {
				t.Fatalf("gates=%d trace=%v", got, trace)
			}
		})
	}
}

func testTarget() adapter.Target {
	t := testTargetNoPrefix()
	t.NamePrefix = "PROD_"
	return t
}

func testTargetNoPrefix() adapter.Target {
	return adapter.Target{ID: "target_1", Environment: "env_1", Generation: 7,
		Destination: adapter.Destination{Kind: adapter.Repository, Owner: "acme", Name: "app", NumericID: 42}}
}

type fakeAPI struct {
	id       int64
	version  string
	secrets  map[string]bool
	writes   []string
	conflict map[string]bool
	failures map[string]error
	trace    *[]string
}

func (f *fakeAPI) Version(context.Context) (string, error) {
	if f.trace != nil {
		*f.trace = append(*f.trace, "version")
	}
	return f.version, nil
}
func (f *fakeAPI) ResolveDestination(context.Context, adapter.Destination) (int64, error) {
	if f.trace != nil {
		*f.trace = append(*f.trace, "resolve")
	}
	return f.id, nil
}
func (f *fakeAPI) ListSecretNames(context.Context, adapter.Destination) ([]string, error) {
	if f.trace != nil {
		*f.trace = append(*f.trace, "list-secrets")
	}
	var out []string
	for name := range f.secrets {
		out = append(out, name)
	}
	slices.Sort(out)
	return out, nil
}
func (f *fakeAPI) PutSecret(_ context.Context, _ adapter.Destination, name, _ string) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "put-secret")
	}
	f.writes = append(f.writes, "put-secret:"+name)
	if err := f.failures["put-secret:"+name]; err != nil {
		return err
	}
	f.secrets[name] = true
	return nil
}
func (f *fakeAPI) DeleteSecret(_ context.Context, _ adapter.Destination, name string) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "delete-secret")
	}
	f.writes = append(f.writes, "delete-secret:"+name)
	if err := f.failures["delete-secret:"+name]; err != nil {
		return err
	}
	delete(f.secrets, name)
	return nil
}
func (f *fakeAPI) CreateVariable(_ context.Context, _ adapter.Destination, name, _ string) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "create-variable")
	}
	f.writes = append(f.writes, "create-variable:"+name)
	if f.conflict[name] {
		return &ResponseError{Status: 409}
	}
	return nil
}
func (f *fakeAPI) UpdateVariable(_ context.Context, _ adapter.Destination, name, _ string) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "update-variable")
	}
	f.writes = append(f.writes, "update-variable:"+name)
	if err := f.failures["update-variable:"+name]; err != nil {
		return err
	}
	return nil
}
func (f *fakeAPI) DeleteVariable(_ context.Context, _ adapter.Destination, name string) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "delete-variable")
	}
	f.writes = append(f.writes, "delete-variable:"+name)
	if err := f.failures["delete-variable:"+name]; err != nil {
		return err
	}
	return nil
}

type fakeJournal struct {
	states       map[string]adapter.LedgerState
	prepares     map[string]int
	completions  map[string][]adapter.Completion
	trace        *[]string
	gateCalls    int
	gateErrAt    int
	gateErr      error
	finishErrFor string
	finishErr    error
	releases     map[string]int
	refusals     int
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{states: map[string]adapter.LedgerState{}, prepares: map[string]int{}, completions: map[string][]adapter.Completion{}, releases: map[string]int{}}
}
func effectKey(e adapter.Effect) string { return string(e.Surface) + ":" + e.EffectiveName }
func (j *fakeJournal) Gate(context.Context, adapter.Effect) error {
	j.gateCalls++
	if j.trace != nil {
		*j.trace = append(*j.trace, "gate")
	}
	if j.gateCalls == j.gateErrAt {
		return j.gateErr
	}
	return nil
}
func (j *fakeJournal) Reserve(_ context.Context, e adapter.Effect) (adapter.LedgerState, error) {
	key := effectKey(e)
	if state, ok := j.states[key]; ok {
		return state, nil
	}
	j.states[key] = adapter.Reserved
	return adapter.Reserved, nil
}
func (j *fakeJournal) Prepare(_ context.Context, e adapter.Effect, _ adapter.LedgerState) error {
	if j.trace != nil {
		*j.trace = append(*j.trace, "prepare")
	}
	j.states[effectKey(e)] = adapter.Dispatched
	j.prepares[effectKey(e)]++
	return nil
}
func (j *fakeJournal) Finish(_ context.Context, e adapter.Effect, completion adapter.Completion) error {
	if effectKey(e) == j.finishErrFor {
		return j.finishErr
	}
	j.completions[effectKey(e)] = append(j.completions[effectKey(e)], completion)
	if completion.State == "" {
		delete(j.states, effectKey(e))
	} else {
		j.states[effectKey(e)] = completion.State
	}
	return nil
}
func (j *fakeJournal) Refuse(_ context.Context, e adapter.Effect) error {
	j.refusals++
	delete(j.states, effectKey(e))
	return nil
}
func (j *fakeJournal) ReleaseReservation(_ context.Context, e adapter.Effect) error {
	key := effectKey(e)
	if j.states[key] != adapter.Reserved {
		return adapter.ErrSuperseded
	}
	j.releases[key]++
	delete(j.states, key)
	return nil
}
func (j *fakeJournal) ledger() []adapter.LedgerEntry {
	out := make([]adapter.LedgerEntry, 0, len(j.states))
	for key, state := range j.states {
		parts := strings.SplitN(key, ":", 2)
		out = append(out, adapter.LedgerEntry{Surface: adapter.Surface(parts[0]), EffectiveName: parts[1], State: state})
	}
	return out
}
