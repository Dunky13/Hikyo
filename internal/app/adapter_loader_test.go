package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestAdapterModuleFactorySelectsPrivateEgressByExactOrigin(t *testing.T) {
	want := netip.MustParsePrefix("10.42.0.0/16")
	seen := []netip.Prefix(nil)
	factory := &adapterModuleFactory{
		egressPolicy: map[string][]netip.Prefix{"https://git.internal.example": {want}},
		providers: map[adapter.Provider]providerConstructor{
			adapter.ForgejoProvider: func(_ adapter.Config, _ string, allowed []netip.Prefix) (adapter.Module, func(), error) {
				seen = append([]netip.Prefix(nil), allowed...)
				return stubProviderModule{}, nil, nil
			},
		},
	}
	lease, err := factory.Build(adapter.ForgejoProvider, adapter.Config{Origin: "https://git.internal.example"}, "token")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if len(seen) != 1 || seen[0] != want {
		t.Fatalf("exact origin policy = %v", seen)
	}
}

func TestAdapterLoaderGatesBeforeLoadAndEveryPlaintextOpen(t *testing.T) {
	credential := []byte("provider-token")
	firstValue := []byte("first-value")
	secondOpened := false
	loadCalled := false
	releases := 0
	journal := &orderedLoaderJournal{failAt: 4}
	loader := &adapterLoader{
		moduleFactory: func(adapter.Provider, adapter.Config, string) (*adapter.ModuleLease, error) {
			return adapter.NewModuleLease(stubProviderModule{}, func() { releases++ })
		},
		loadExecution: func(context.Context, adapter.Job) (store.AdapterExecution, error) {
			loadCalled = true
			if journal.calls != 1 {
				t.Fatalf("LoadExecution ran after %d gates, want exactly the manifest gate", journal.calls)
			}
			return store.AdapterExecution{
				Provider: "forgejo", Origin: "https://git.example", CredentialOwnerID: "adapter_1", CredentialCiphertext: []byte("sealed-credential"),
				Target: adapter.Target{ID: "target_1", Environment: "env_1", Destination: adapter.Destination{Kind: adapter.Repository, Owner: "acme", Name: "app", NumericID: 42}},
				Entries: []store.AdapterSnapshotEntry{
					{ID: "entry_1", SnapshotID: "snapshot_1", KeyID: "key_1", KeyName: "FIRST", Classification: string(adapter.SecretClassification), Ciphertext: []byte("sealed-first")},
					{ID: "entry_2", SnapshotID: "snapshot_1", KeyID: "key_2", KeyName: "SECOND", Classification: string(adapter.SecretClassification), Ciphertext: []byte("sealed-second")},
				},
			}, nil
		},
		openField: func(aad crypto.ProjectFieldAAD, _ []byte) ([]byte, error) {
			switch aad.OwnerTable {
			case "adapters":
				if journal.calls != 2 {
					t.Fatalf("credential opened after %d gates, want 2", journal.calls)
				}
				return credential, nil
			case "snapshot_entries":
				if aad.OwnerRowID == "entry_2" {
					secondOpened = true
				}
				if journal.calls != 3 {
					t.Fatalf("snapshot opened after %d gates, want 3", journal.calls)
				}
				return firstValue, nil
			default:
				return nil, errors.New("unexpected AAD")
			}
		},
	}
	_, err := loader.Load(t.Context(), adapter.Job{OrgID: "org_1", ProjectID: "project_1", EnvironmentID: "env_1"}, journal)
	if !errors.Is(err, adapter.ErrUnauthorized) {
		t.Fatalf("Load() = %v, want gate refusal", err)
	}
	if !loadCalled || journal.calls != 4 || secondOpened || releases != 1 {
		t.Fatalf("load=%v gates=%d second_opened=%v releases=%d", loadCalled, journal.calls, secondOpened, releases)
	}
	for _, buffer := range [][]byte{credential, firstValue} {
		for _, value := range buffer {
			if value != 0 {
				t.Fatalf("authorized plaintext was not zeroed after later gate loss: %v", buffer)
			}
		}
	}
}

func TestAdapterActivationLoaderRefusesBeforePendingCredentialOpen(t *testing.T) {
	loadCalled := false
	openCalled := false
	journal := &orderedLoaderJournal{failAt: 2}
	loader := &adapterLoader{
		moduleFactory: newAdapterModuleFactory(nil).Build,
		loadActivation: func(context.Context, adapter.Job) (store.AdapterActivation, error) {
			loadCalled = true
			if journal.calls != 1 {
				t.Fatalf("LoadActivation ran after %d gates, want route-material gate", journal.calls)
			}
			return store.AdapterActivation{
				Provider: "forgejo", Origin: "https://git.next.example", CredentialOwnerID: "adapter_1", CredentialCiphertext: []byte("sealed-pending-credential"),
				Target: adapter.Target{ID: "target_1", Environment: "env_1", Destination: adapter.Destination{Kind: adapter.Repository, Owner: "acme", Name: "app"}},
			}, nil
		},
		openField: func(crypto.ProjectFieldAAD, []byte) ([]byte, error) {
			openCalled = true
			return []byte("provider-token"), nil
		},
	}
	_, err := loader.LoadActivation(t.Context(), adapter.Job{OrgID: "org_1", ProjectID: "project_1", EnvironmentID: "env_1"}, journal)
	if !errors.Is(err, adapter.ErrUnauthorized) {
		t.Fatalf("LoadActivation() = %v, want gate refusal", err)
	}
	if !loadCalled || openCalled || journal.calls != 2 {
		t.Fatalf("load=%v open=%v gates=%d", loadCalled, openCalled, journal.calls)
	}
}

func TestAdapterLoaderRejectsUnknownProviderBeforeCredentialOpen(t *testing.T) {
	openCalled := false
	factoryCalled := false
	loader := &adapterLoader{
		loadExecution: func(context.Context, adapter.Job) (store.AdapterExecution, error) {
			return store.AdapterExecution{Provider: "gitlab", CredentialCiphertext: []byte("sealed")}, nil
		},
		openField: func(crypto.ProjectFieldAAD, []byte) ([]byte, error) {
			openCalled = true
			return []byte("credential"), nil
		},
		moduleFactory: func(adapter.Provider, adapter.Config, string) (*adapter.ModuleLease, error) {
			factoryCalled = true
			return adapter.NewModuleLease(stubProviderModule{}, nil)
		},
	}
	_, err := loader.Load(t.Context(), adapter.Job{}, &orderedLoaderJournal{})
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("Load() = %v, want unknown provider refusal", err)
	}
	if openCalled || factoryCalled {
		t.Fatalf("unknown provider opened credential=%v called factory=%v", openCalled, factoryCalled)
	}
}

type orderedLoaderJournal struct {
	calls  int
	failAt int
}

func (j *orderedLoaderJournal) Gate(context.Context, adapter.Effect) error {
	j.calls++
	if j.calls == j.failAt {
		return adapter.ErrUnauthorized
	}
	return nil
}
func (*orderedLoaderJournal) Reserve(context.Context, adapter.Effect) (adapter.LedgerState, error) {
	return adapter.Reserved, nil
}
func (*orderedLoaderJournal) Prepare(context.Context, adapter.Effect, adapter.LedgerState) error {
	return nil
}
func (*orderedLoaderJournal) Finish(context.Context, adapter.Effect, adapter.Completion) error {
	return nil
}
func (*orderedLoaderJournal) Refuse(context.Context, adapter.Effect) error { return nil }
func (*orderedLoaderJournal) ReleaseReservation(context.Context, adapter.Effect) error {
	return nil
}
