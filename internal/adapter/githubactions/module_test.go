package githubactions

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
)

func TestModulePlansSecretsByNameAndVariablesWithoutReading(t *testing.T) {
	api := &fakeAPI{id: 42, secretNames: []string{"TAKEN"}}
	plan, err := (&Module{API: api, Seal: fakeSeal}).Plan(t.Context(), adapter.PlanRequest{
		Target: testTarget(), Gate: allow,
		Manifest: []adapter.ManifestEntry{
			{CanonicalName: "TAKEN", Classification: adapter.SecretClassification},
			{CanonicalName: "MODE", Classification: adapter.ConfigClassification},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []adapter.Change{
		{Surface: adapter.Secret, EffectiveName: adapter.SentinelName, Disposition: adapter.Create},
		{Surface: adapter.Secret, EffectiveName: "TAKEN", Disposition: adapter.Conflict},
		{Surface: adapter.Variable, EffectiveName: adapter.SentinelName, Disposition: adapter.Unknown},
		{Surface: adapter.Variable, EffectiveName: "MODE", Disposition: adapter.Unknown},
	}
	if !slices.Equal(plan.Changes, want) {
		t.Fatalf("Plan() = %+v, want %+v", plan.Changes, want)
	}
}

func TestPlanClassifiesDurableOwnedMissingVariableAsCreate(t *testing.T) {
	plan, err := (&Module{API: &fakeAPI{id: 42}}).Plan(t.Context(), adapter.PlanRequest{
		Target: testTarget(), Gate: allow,
		Manifest: []adapter.ManifestEntry{{CanonicalName: "MODE", Classification: adapter.ConfigClassification}},
		Ledger:   []adapter.LedgerEntry{{Surface: adapter.Variable, EffectiveName: "MODE", State: adapter.Owned, Missing: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plan.Changes, adapter.Change{Surface: adapter.Variable, EffectiveName: "MODE", Disposition: adapter.Create}) {
		t.Fatalf("Plan() = %+v, want durable owned-missing create", plan.Changes)
	}
}

func TestSyncSealsSecretsAndSurfacesFirstDispatch204Capture(t *testing.T) {
	api := &fakeAPI{id: 42, secretStatus: map[string]int{adapter.SentinelName: http.StatusCreated, "TOKEN": http.StatusNoContent}}
	journal := newFakeJournal()
	result, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
		Target:   testTarget(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "plain"}},
	}, journal)
	if !errors.Is(err, adapter.ErrConflict) {
		t.Fatalf("Sync() error = %v, want possible-capture conflict", err)
	}
	if slices.Contains(api.secretValues, "plain") || !slices.Contains(api.secretValues, "sealed:plain") {
		t.Fatalf("provider secret bodies = %v", api.secretValues)
	}
	if len(result.Conflicts) != 1 || result.Conflicts[0].EffectiveName != "TOKEN" || journal.states["secret:TOKEN"] != "" {
		t.Fatalf("result=%+v states=%v", result, journal.states)
	}
	completion := journal.completions["secret:TOKEN"]
	if completion.ProviderStatus != http.StatusNoContent || completion.Finding != "possible_capture" {
		t.Fatalf("capture completion = %+v", completion)
	}
}

func TestDispatchedSecret204ConfirmsOwnership(t *testing.T) {
	api := &fakeAPI{id: 42, secretStatus: map[string]int{adapter.SentinelName: http.StatusCreated, "TOKEN": http.StatusNoContent}}
	journal := newFakeJournal()
	journal.states["secret:TOKEN"] = adapter.Dispatched
	_, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
		Target: testTarget(), Ledger: journal.ledger(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "plain"}},
	}, journal)
	if err != nil || journal.states["secret:TOKEN"] != adapter.Owned {
		t.Fatalf("Sync() = %v; state=%q", err, journal.states["secret:TOKEN"])
	}
}

func TestVariableCreateUsesOnlyExact409AsConflict(t *testing.T) {
	for _, tt := range []struct {
		name         string
		status       int
		wantConflict bool
	}{
		{name: "409", status: http.StatusConflict, wantConflict: true},
		{name: "422 ambiguous", status: http.StatusUnprocessableEntity},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{id: 42, variableCreateStatus: map[string]int{"MODE": tt.status}}
			journal := newFakeJournal()
			result, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
				Target:   testTarget(),
				Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "MODE", Classification: adapter.ConfigClassification, Value: "debug"}},
			}, journal)
			if errors.Is(err, adapter.ErrConflict) != tt.wantConflict || len(result.Conflicts) != btoi(tt.wantConflict) {
				t.Fatalf("Sync() error=%v conflicts=%+v", err, result.Conflicts)
			}
			if slices.Contains(api.writes, "update-variable:MODE") {
				t.Fatal("unowned variable was blindly patched")
			}
		})
	}
}

func TestOwnedVariableMissingRecreatesViaPostInSameSync(t *testing.T) {
	api := &fakeAPI{id: 42, variableUpdateStatus: map[string]int{"MODE": http.StatusNotFound}}
	journal := newFakeJournal()
	journal.states["secret:"+adapter.SentinelName] = adapter.Owned
	journal.states["variable:"+adapter.SentinelName] = adapter.Owned
	journal.states["variable:MODE"] = adapter.Owned
	_, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
		Target: testTarget(), Ledger: journal.ledger(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "MODE", Classification: adapter.ConfigClassification, Value: "debug"}},
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	wantSuffix := []string{"update-variable:MODE", "create-variable:MODE"}
	if len(api.writes) < 2 || !slices.Equal(api.writes[len(api.writes)-2:], wantSuffix) || journal.states["variable:MODE"] != adapter.Owned {
		t.Fatalf("writes=%v state=%q", api.writes, journal.states["variable:MODE"])
	}
}

func TestOwnedMissingVariableSurvivesCrashBoundaryAndRetriesCreateOnly(t *testing.T) {
	api := &fakeAPI{
		id:                   42,
		variableUpdateStatus: map[string]int{"MODE": http.StatusNotFound},
	}
	journal := newFakeJournal()
	journal.prepareFailures["variable:MODE"] = []error{nil, errors.New("simulated crash before owned-missing POST")}
	journal.states["secret:"+adapter.SentinelName] = adapter.Owned
	journal.states["variable:"+adapter.SentinelName] = adapter.Owned
	journal.states["variable:MODE"] = adapter.Owned
	request := adapter.SyncRequest{
		Target:   testTarget(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "MODE", Classification: adapter.ConfigClassification, Value: "debug"}},
	}
	request.Ledger = journal.ledger()
	if _, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), request, journal); err == nil {
		t.Fatal("first Sync() succeeded, want provider interruption")
	}
	if journal.states["variable:MODE"] != adapter.Owned || !journal.missing["variable:MODE"] {
		t.Fatalf("after interruption state=%q missing=%v, want owned-missing custody", journal.states["variable:MODE"], journal.missing["variable:MODE"])
	}

	before := len(api.writes)
	request.Ledger = journal.ledger()
	if _, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), request, journal); err != nil {
		t.Fatal(err)
	}
	retryWrites := api.writes[before:]
	if slices.Contains(retryWrites, "update-variable:MODE") || !slices.Contains(retryWrites, "create-variable:MODE") {
		t.Fatalf("owned-missing retry writes=%v, want POST without PATCH", retryWrites)
	}
	if journal.states["variable:MODE"] != adapter.Owned || journal.missing["variable:MODE"] {
		t.Fatalf("after retry state=%q missing=%v", journal.states["variable:MODE"], journal.missing["variable:MODE"])
	}
}

func TestStalePublicKeyRefetchesAndResealsOnce(t *testing.T) {
	api := &fakeAPI{id: 42, putFailures: map[string][]error{"TOKEN": {&ResponseError{Status: http.StatusUnprocessableEntity}}}}
	journal := newFakeJournal()
	_, err := (&Module{API: api, Seal: func(value []byte, key PublicKey) (string, error) {
		return key.ID + ":" + string(value), nil
	}}).Sync(t.Context(), adapter.SyncRequest{
		Target:   testTarget(),
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "plain"}},
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	if api.publicKeyCalls != 2 || !slices.Contains(api.secretValues, "key-2:plain") {
		t.Fatalf("public-key calls=%d secret bodies=%v", api.publicKeyCalls, api.secretValues)
	}
}

func TestSelectedOrganizationWritesUseFullSetReplacementImmediately(t *testing.T) {
	api := &fakeAPI{id: 9}
	target := testTarget()
	target.Destination = adapter.Destination{Kind: adapter.Organization, Owner: "acme", NumericID: 9, Visibility: "selected", SelectedRepositoryIDs: []int64{11, 22}}
	_, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
		Target: target,
		Manifest: []adapter.ManifestEntry{
			{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "plain"},
			{KeyID: "key_2", CanonicalName: "MODE", Classification: adapter.ConfigClassification, Value: "debug"},
		},
	}, newFakeJournal())
	if err != nil {
		t.Fatal(err)
	}
	for i, write := range api.writes {
		if (strings.HasPrefix(write, "put-secret:") || strings.HasPrefix(write, "create-variable:")) && (i+1 >= len(api.writes) || !strings.HasPrefix(api.writes[i+1], "replace-selected:")) {
			t.Fatalf("selected replacement did not immediately follow %q: %v", write, api.writes)
		}
	}
}

func TestSelectedReplacementFailureRetainsDispatchedCustody(t *testing.T) {
	api := &fakeAPI{id: 9, replaceSelectedErr: errors.New("replacement transport failed")}
	target := testTarget()
	target.Destination = adapter.Destination{Kind: adapter.Organization, Owner: "acme", NumericID: 9, Visibility: "selected", SelectedRepositoryIDs: []int64{11}}
	journal := newFakeJournal()
	_, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
		Target:   target,
		Manifest: []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "plain"}},
	}, journal)
	if err == nil {
		t.Fatal("Sync() succeeded, want replacement failure")
	}
	if journal.states["secret:"+adapter.SentinelName] != adapter.Dispatched {
		t.Fatalf("primary write custody=%q, want dispatched", journal.states["secret:"+adapter.SentinelName])
	}
}

func TestSyncResumeCursorDoesNotReplayCompletedName(t *testing.T) {
	api := &fakeAPI{id: 42}
	journal := newFakeJournal()
	journal.states["secret:DONE"] = adapter.Owned
	_, err := (&Module{API: api, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{
		Target: testTarget(), Ledger: journal.ledger(),
		Manifest:  []adapter.ManifestEntry{{KeyID: "key_1", CanonicalName: "DONE", Classification: adapter.SecretClassification, Value: "plain"}},
		Completed: []adapter.Change{{Surface: adapter.Secret, EffectiveName: "DONE", Disposition: adapter.Update}},
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(api.writes, "put-secret:DONE") {
		t.Fatalf("completed name replayed: %v", api.writes)
	}
}

func TestGitHubNamingAndValueLimitsRefuseByName(t *testing.T) {
	for _, row := range []adapter.ManifestEntry{
		{CanonicalName: "GITHUB_TOKEN", Classification: adapter.SecretClassification, Value: "x"},
		{CanonicalName: "lower", Classification: adapter.ConfigClassification, Value: "x"},
		{CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: strings.Repeat("x", 48*1024+1)},
		{CanonicalName: "TOKEN", Classification: adapter.SecretClassification, Value: "a\x00b"},
	} {
		_, err := (&Module{API: &fakeAPI{id: 42}, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{Target: testTarget(), Manifest: []adapter.ManifestEntry{row}}, newFakeJournal())
		if err == nil || !strings.Contains(err.Error(), row.CanonicalName) {
			t.Fatalf("Sync(%q) = %v, want named refusal", row.CanonicalName, err)
		}
	}
}

func TestPlanWarnsForExactSecretAndLowerBoundVariableLimits(t *testing.T) {
	secretNames := make([]string, 100)
	for i := range secretNames {
		secretNames[i] = fmt.Sprintf("SECRET_%03d", i)
	}
	variableLedger := make([]adapter.LedgerEntry, 500)
	for i := range variableLedger {
		variableLedger[i] = adapter.LedgerEntry{Surface: adapter.Variable, EffectiveName: fmt.Sprintf("VARIABLE_%03d", i), State: adapter.Owned}
	}
	for _, tt := range []struct {
		name        string
		target      adapter.Target
		secretNames []string
		ledger      []adapter.LedgerEntry
		want        string
	}{
		{name: "environment secret cap", target: adapter.Target{ID: "target_env", Generation: 1, Destination: adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod", RepositoryID: 41, NumericID: 42}}, secretNames: secretNames, want: "secret count 101 exceeds environment cap 100"},
		{name: "organization workflow truncation", target: adapter.Target{ID: "target_org", Generation: 1, Destination: adapter.Destination{Kind: adapter.Organization, Owner: "team", NumericID: 42, Visibility: "all"}}, secretNames: secretNames, want: "first 100 secrets alphabetically"},
		{name: "repository variable lower bound", target: testTarget(), ledger: variableLedger, want: "variable count lower bound 501 exceeds repository cap 500"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{id: 42, repositoryID: 41, secretNames: tt.secretNames}
			plan, err := (&Module{API: api, Seal: fakeSeal}).Plan(t.Context(), adapter.PlanRequest{Target: tt.target, Ledger: tt.ledger, Gate: allow})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(plan.Warnings, func(warning string) bool { return strings.Contains(warning, tt.want) }) {
				t.Fatalf("Plan() warnings = %v, want %q", plan.Warnings, tt.want)
			}
		})
	}
}

func TestSyncWarnsForWorkflowVariableByteLowerBound(t *testing.T) {
	manifest := make([]adapter.ManifestEntry, 6)
	completed := make([]adapter.Change, 6)
	for i := range manifest {
		name := fmt.Sprintf("VARIABLE_%d", i)
		manifest[i] = adapter.ManifestEntry{KeyID: fmt.Sprintf("key_%d", i), CanonicalName: name, Classification: adapter.ConfigClassification, Value: strings.Repeat("x", 44*1024)}
		completed[i] = adapter.Change{Surface: adapter.Variable, EffectiveName: name, Disposition: adapter.Update}
	}
	result, err := (&Module{API: &fakeAPI{id: 42}, Seal: fakeSeal}).Sync(t.Context(), adapter.SyncRequest{Target: testTarget(), Manifest: manifest, Completed: completed}, newFakeJournal())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(result.Warnings, func(warning string) bool { return strings.Contains(warning, "256 KB delivery cap") }) {
		t.Fatalf("Sync() warnings = %v, want byte lower-bound warning", result.Warnings)
	}
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}

func allow(context.Context) error                        { return nil }
func fakeSeal(value []byte, _ PublicKey) (string, error) { return "sealed:" + string(value), nil }

func testTarget() adapter.Target {
	return adapter.Target{ID: "target_1", Generation: 1, Destination: adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo", NumericID: 42}}
}

func TestConnectionAutoCreatesMissingEnvironmentThenPinsBothIdentities(t *testing.T) {
	api := &fakeAPI{id: 73, repositoryID: 42, resolveErrors: []error{&ResponseError{Status: http.StatusNotFound}, nil}}
	module := &Module{API: api, Seal: fakeSeal}
	destination := adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod"}
	connection, err := module.TestConnection(t.Context(), adapter.ConnectionRequest{
		Destination: destination, Access: adapter.Access{Credential: "github_pat_fine"}, Gate: allow,
		AllowEnvironmentCreate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if api.createEnvironmentCalls != 1 || connection.DestinationID != 73 || connection.RepositoryID != 42 {
		t.Fatalf("auto-create calls=%d connection=%+v", api.createEnvironmentCalls, connection)
	}
}

func TestConnectionSurfacesCredentialExpirationMetadata(t *testing.T) {
	want := time.Date(2026, 9, 30, 12, 34, 56, 0, time.UTC)
	api := &fakeAPI{id: 42, credentialExpiresAt: want}
	connection, err := (&Module{API: api}).TestConnection(t.Context(), adapter.ConnectionRequest{
		Destination: adapter.Destination{Kind: adapter.Repository, Owner: "team", Name: "repo"},
		Access:      adapter.Access{Credential: "github_pat_fine"}, Gate: allow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !connection.CredentialExpiresAt.Equal(want) {
		t.Fatalf("CredentialExpiresAt = %s, want %s", connection.CredentialExpiresAt, want)
	}
}

func TestConnectionIdentityMismatchNamesReconfigurationNotPermissions(t *testing.T) {
	api := &fakeAPI{resolveErrors: []error{fmt.Errorf("%w: configured repository 42, resolved 43", adapter.ErrDestinationID)}}
	_, err := (&Module{API: api}).TestConnection(t.Context(), adapter.ConnectionRequest{
		Destination: adapter.Destination{
			Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod",
			RepositoryID: 42, NumericID: 73,
		},
		Access: adapter.Access{Credential: "github_pat_fine"}, Gate: allow,
	})
	if err == nil || !errors.Is(err, adapter.ErrDestinationID) || !strings.Contains(err.Error(), "re-configure") {
		t.Fatalf("TestConnection() = %v, want named identity reconfiguration refusal", err)
	}
	if strings.Contains(err.Error(), "permission") {
		t.Fatalf("identity mismatch mislabeled as permission failure: %v", err)
	}
}

func TestConnectionNamesEnvironmentAdministrationRemedies(t *testing.T) {
	api := &fakeAPI{resolveErrors: []error{&ResponseError{Status: http.StatusNotFound}}, createEnvironmentErr: &ResponseError{Status: http.StatusForbidden}}
	module := &Module{API: api}
	_, err := module.TestConnection(t.Context(), adapter.ConnectionRequest{
		Destination: adapter.Destination{Kind: adapter.Environment, Owner: "team", Name: "repo", Environment: "prod"},
		Access:      adapter.Access{Credential: "github_pat_fine"}, Gate: allow, AllowEnvironmentCreate: true,
	})
	if err == nil || !strings.Contains(err.Error(), "pre-create") || !strings.Contains(err.Error(), "widen") {
		t.Fatalf("TestConnection() = %v, want both Administration remedies", err)
	}
}

type fakeAPI struct {
	id                     int64
	repositoryID           int64
	resolveErrors          []error
	createEnvironmentErr   error
	createEnvironmentCalls int
	secretNames            []string
	secretStatus           map[string]int
	variableCreateStatus   map[string]int
	variableUpdateStatus   map[string]int
	replaceSelectedErr     error
	credentialExpiresAt    time.Time
	putFailures            map[string][]error
	publicKeyCalls         int
	writes                 []string
	secretValues           []string
}

func (f *fakeAPI) CredentialExpiresAt() time.Time { return f.credentialExpiresAt }

func (f *fakeAPI) ResolveDestination(_ context.Context, destination adapter.Destination) (DestinationIdentity, error) {
	if len(f.resolveErrors) != 0 {
		err := f.resolveErrors[0]
		f.resolveErrors = f.resolveErrors[1:]
		if err != nil {
			return DestinationIdentity{}, err
		}
	}
	repositoryID := f.repositoryID
	if destination.Kind == adapter.Environment && repositoryID == 0 {
		repositoryID = destination.RepositoryID
	}
	return DestinationIdentity{ID: f.id, RepositoryID: repositoryID}, nil
}
func (f *fakeAPI) CreateEnvironment(context.Context, adapter.Destination) error {
	f.createEnvironmentCalls++
	return f.createEnvironmentErr
}
func (f *fakeAPI) VerifySelectedRepositories(context.Context, adapter.Destination) error { return nil }
func (f *fakeAPI) ReplaceSelectedRepositories(_ context.Context, _ adapter.Destination, surface adapter.Surface, name string) error {
	f.writes = append(f.writes, "replace-selected:"+string(surface)+":"+name)
	return f.replaceSelectedErr
}
func (f *fakeAPI) ListSecretNames(context.Context, adapter.Destination) ([]string, error) {
	return append([]string(nil), f.secretNames...), nil
}
func (f *fakeAPI) PublicKey(context.Context, adapter.Destination) (PublicKey, error) {
	f.publicKeyCalls++
	return PublicKey{ID: "key-" + string(rune('0'+f.publicKeyCalls))}, nil
}
func (f *fakeAPI) PutSecret(_ context.Context, _ adapter.Destination, name, encrypted, _ string) (WriteResult, error) {
	f.writes = append(f.writes, "put-secret:"+name)
	f.secretValues = append(f.secretValues, encrypted)
	if failures := f.putFailures[name]; len(failures) != 0 {
		err := failures[0]
		f.putFailures[name] = failures[1:]
		return WriteResult{}, err
	}
	status := f.secretStatus[name]
	if status == 0 {
		status = http.StatusCreated
	}
	return WriteResult{Status: status}, nil
}
func (f *fakeAPI) DeleteSecret(context.Context, adapter.Destination, string) error { return nil }
func (f *fakeAPI) CreateVariable(_ context.Context, _ adapter.Destination, name, _ string) (WriteResult, error) {
	f.writes = append(f.writes, "create-variable:"+name)
	status := f.variableCreateStatus[name]
	if status == 0 {
		status = http.StatusCreated
	}
	if status != http.StatusCreated {
		return WriteResult{Status: status}, &ResponseError{Status: status}
	}
	return WriteResult{Status: status}, nil
}
func (f *fakeAPI) UpdateVariable(_ context.Context, _ adapter.Destination, name, _ string) (WriteResult, error) {
	f.writes = append(f.writes, "update-variable:"+name)
	status := f.variableUpdateStatus[name]
	if status == 0 {
		status = http.StatusNoContent
	}
	if status != http.StatusNoContent {
		return WriteResult{Status: status}, &ResponseError{Status: status}
	}
	return WriteResult{Status: status}, nil
}
func (f *fakeAPI) DeleteVariable(context.Context, adapter.Destination, string) error { return nil }

type fakeJournal struct {
	states          map[string]adapter.LedgerState
	missing         map[string]bool
	completions     map[string]adapter.Completion
	prepareFailures map[string][]error
}

func newFakeJournal() *fakeJournal {
	return &fakeJournal{states: map[string]adapter.LedgerState{}, missing: map[string]bool{}, completions: map[string]adapter.Completion{}, prepareFailures: map[string][]error{}}
}
func effectKey(effect adapter.Effect) string {
	return string(effect.Surface) + ":" + effect.EffectiveName
}
func (j *fakeJournal) ledger() []adapter.LedgerEntry {
	rows := make([]adapter.LedgerEntry, 0, len(j.states))
	for key, state := range j.states {
		parts := strings.SplitN(key, ":", 2)
		if state != "" {
			rows = append(rows, adapter.LedgerEntry{Surface: adapter.Surface(parts[0]), EffectiveName: parts[1], State: state, Missing: j.missing[key]})
		}
	}
	return rows
}
func (*fakeJournal) Gate(context.Context, adapter.Effect) error { return nil }
func (j *fakeJournal) Reserve(_ context.Context, effect adapter.Effect) (adapter.LedgerState, error) {
	key := effectKey(effect)
	if state := j.states[key]; state != "" {
		return state, nil
	}
	j.states[key] = adapter.Reserved
	return adapter.Reserved, nil
}
func (j *fakeJournal) Prepare(_ context.Context, effect adapter.Effect, _ adapter.LedgerState) error {
	key := effectKey(effect)
	if failures := j.prepareFailures[key]; len(failures) != 0 {
		err := failures[0]
		j.prepareFailures[key] = failures[1:]
		return err
	}
	return nil
}
func (j *fakeJournal) Finish(_ context.Context, effect adapter.Effect, completion adapter.Completion) error {
	j.states[effectKey(effect)] = completion.State
	j.missing[effectKey(effect)] = completion.Missing
	j.completions[effectKey(effect)] = completion
	return nil
}
func (j *fakeJournal) Refuse(_ context.Context, effect adapter.Effect) error {
	delete(j.states, effectKey(effect))
	return nil
}
func (j *fakeJournal) ReleaseReservation(_ context.Context, effect adapter.Effect) error {
	delete(j.states, effectKey(effect))
	return nil
}
