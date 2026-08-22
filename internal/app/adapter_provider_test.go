package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/adapter/forgejo"
	"github.com/Hikyo-Org/hikyo/internal/adapter/githubactions"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestAdapterModuleFactoryRegistryIsTotal(t *testing.T) {
	registry := deploymentProviderRegistry()
	if len(registry) != len(adapter.SupportedProviders()) {
		t.Fatalf("registry entries = %d, supported providers = %d", len(registry), len(adapter.SupportedProviders()))
	}
	for _, provider := range adapter.SupportedProviders() {
		if registry[provider] == nil {
			t.Fatalf("provider %q has no construction entry", provider)
		}
	}
}

func TestAdapterModuleFactoryDispatchesCompiledInProviders(t *testing.T) {
	factory := newAdapterModuleFactory(nil)
	forgejoLease, err := factory.Build(adapter.ForgejoProvider, adapter.Config{Origin: "https://forgejo.example"}, "scoped-token")
	if err != nil {
		t.Fatal(err)
	}
	defer forgejoLease.Release()
	if _, ok := forgejoLease.Module.(*forgejo.Module); !ok {
		t.Fatalf("forgejo module = %T", forgejoLease.Module)
	}

	githubLease, err := factory.Build(adapter.GitHubActionsProvider, adapter.Config{Origin: "https://api.github.com"}, "github_pat_fine")
	if err != nil {
		t.Fatal(err)
	}
	defer githubLease.Release()
	if _, ok := githubLease.Module.(*githubactions.Module); !ok {
		t.Fatalf("github module = %T", githubLease.Module)
	}
}

func TestAdapterModuleFactoryReleasesPartialConstructionOnce(t *testing.T) {
	wantErr := errors.New("partial construction")
	releases := 0
	factory := &adapterModuleFactory{
		providers: map[adapter.Provider]providerConstructor{
			adapter.ForgejoProvider: func(adapter.Config, string, []netip.Prefix) (adapter.Module, func(), error) {
				return nil, func() { releases++ }, wantErr
			},
		},
	}
	if _, err := factory.Build(adapter.ForgejoProvider, adapter.Config{Origin: "https://forgejo.example"}, "scoped-token"); !errors.Is(err, wantErr) {
		t.Fatalf("Build() = %v, want %v", err, wantErr)
	}
	if releases != 1 {
		t.Fatalf("partial construction releases = %d, want 1", releases)
	}
}

func TestAdapterModuleLeaseReleasesSuccessOnce(t *testing.T) {
	releases := 0
	factory := &adapterModuleFactory{
		providers: map[adapter.Provider]providerConstructor{
			adapter.ForgejoProvider: func(adapter.Config, string, []netip.Prefix) (adapter.Module, func(), error) {
				return stubProviderModule{}, func() { releases++ }, nil
			},
		},
	}
	lease, err := factory.Build(adapter.ForgejoProvider, adapter.Config{Origin: "https://forgejo.example"}, "scoped-token")
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	lease.Release()
	if releases != 1 {
		t.Fatalf("successful construction releases = %d, want 1", releases)
	}
}

func TestDeploymentModuleRefusesClassicGitHubPAT(t *testing.T) {
	_, err := newAdapterModuleFactory(nil).Build(adapter.GitHubActionsProvider, adapter.Config{Origin: "https://api.github.com"}, "ghp_classic")
	if err == nil || !strings.Contains(err.Error(), "classic") {
		t.Fatalf("deploymentModule() = %v, want named classic PAT refusal", err)
	}
}

func TestDeploymentModuleNeverInfersProviderFromCredential(t *testing.T) {
	_, err := newAdapterModuleFactory(nil).Build(adapter.Provider(""), adapter.Config{Origin: "https://api.github.com"}, "github_pat_fine")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("deploymentModule() = %v, want missing persisted provider refusal", err)
	}
}

func TestWorkerAndServiceWiringUseEquivalentModulesFromOneFactory(t *testing.T) {
	wiring := newAdapterModuleWiring(map[string][]netip.Prefix{"https://forgejo.example": {netip.MustParsePrefix("10.42.0.0/16")}})
	loader := &adapterLoader{
		moduleFactory: wiring.worker,
		loadActivation: func(context.Context, adapter.Job) (store.AdapterActivation, error) {
			return store.AdapterActivation{Provider: string(adapter.ForgejoProvider), Origin: "https://forgejo.example", CredentialCiphertext: []byte("sealed")}, nil
		},
		openField: func(crypto.ProjectFieldAAD, []byte) ([]byte, error) {
			return []byte("scoped-token"), nil
		},
	}
	loaded, err := loader.LoadActivation(t.Context(), adapter.Job{}, &orderedLoaderJournal{})
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Release()
	serviceLease, err := wiring.service(adapter.ForgejoProvider, adapter.Config{Origin: "https://forgejo.example"}, "scoped-token")
	if err != nil {
		t.Fatal(err)
	}
	defer serviceLease.Release()
	if reflect.TypeOf(loaded.Module) != reflect.TypeOf(serviceLease.Module) {
		t.Fatalf("worker module = %T, service module = %T", loaded.Module, serviceLease.Module)
	}
}

type stubProviderModule struct{}

func (stubProviderModule) ValidateConfig(adapter.Config) error { return nil }
func (stubProviderModule) TestConnection(context.Context, adapter.ConnectionRequest) (adapter.Connection, error) {
	return adapter.Connection{}, nil
}
func (stubProviderModule) Plan(context.Context, adapter.PlanRequest) (adapter.Plan, error) {
	return adapter.Plan{}, nil
}
func (stubProviderModule) Sync(context.Context, adapter.SyncRequest, adapter.Journal) (adapter.SyncResult, error) {
	return adapter.SyncResult{}, nil
}
