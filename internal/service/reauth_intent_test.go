package service

import (
	"errors"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

func TestDisclosureReauthIntentRefusesMultipleEnvironments(t *testing.T) {
	t.Parallel()

	_, err := NewDisclosureReauthIntent(PurposeReveal, []string{"env_dev", "env_prod"}, []string{"key_a"})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("NewDisclosureReauthIntent error = %v, want domain.ErrInvalid", err)
	}
}

func TestZeroReauthIntentDoesNotExposeEmptyDerivedValues(t *testing.T) {
	t.Parallel()

	if purpose, err := (ReauthIntent{}).Purpose(); err == nil || purpose != "" {
		t.Fatalf("zero intent purpose = %q, %v; want an error", purpose, err)
	}
	if operation, err := (ReauthIntent{}).Operation(); err == nil || operation != "" {
		t.Fatalf("zero intent operation = %q, %v; want an error", operation, err)
	}
	if adapter, err := (ReauthIntent{}).isAdapter(); err == nil || adapter {
		t.Fatalf("zero intent adapter classification = %t, %v; want an error", adapter, err)
	}
	if unbound, err := (ReauthIntent{}).isUnbound(); err == nil || unbound {
		t.Fatalf("zero intent unbound classification = %t, %v; want an error", unbound, err)
	}
}

func TestReauthIntentDerivesCanonicalBinding(t *testing.T) {
	t.Parallel()

	type makeIntent func(t *testing.T) ReauthIntent
	tests := []struct {
		name                 string
		make                 makeIntent
		targetEnvironment    string
		wantPurpose          ReauthPurpose
		wantOperation        authz.Operation
		wantEnvironment      string
		wantKeySet           string
		wantEnvironmentSet   string
		wantChallengeBinding string
	}{
		{
			name: "unbound human reauthentication",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewUnboundReauthIntent("env_prod")
				return mustReauthIntent(t, intent, err)
			},
			wantEnvironment: "env_prod",
		},
		{
			name: "reveal",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewRevealReauthIntent("env_prod", []string{"key_b", "key_a"})
				return mustReauthIntent(t, intent, err)
			},
			wantPurpose:          PurposeReveal,
			wantOperation:        authz.OpValueReveal,
			wantEnvironment:      "env_prod",
			wantKeySet:           "key_a\nkey_b",
			wantChallengeBinding: `{"operation":"reveal","environment_id":"env_prod","key_ids":["key_a","key_b"]}`,
		},
		{
			name: "copy",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewCopyReauthIntent("env_prod", []string{"key_b", "key_a"})
				return mustReauthIntent(t, intent, err)
			},
			wantPurpose:          PurposeCopy,
			wantOperation:        authz.OpValueCopySource,
			wantEnvironment:      "env_prod",
			wantKeySet:           "key_a\nkey_b",
			wantChallengeBinding: `{"operation":"copy","environment_id":"env_prod","key_ids":["key_a","key_b"]}`,
		},
		{
			name: "publish",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewPublishReauthIntent("env_prod", []string{"key_b", "key_a"})
				return mustReauthIntent(t, intent, err)
			},
			wantPurpose:          PurposePublish,
			wantOperation:        authz.OpValueCopyDestination,
			wantEnvironment:      "env_prod",
			wantKeySet:           "key_a\nkey_b",
			wantChallengeBinding: `{"operation":"publish","environment_id":"env_prod","key_ids":["key_a","key_b"]}`,
		},
		{
			name: "mint",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewMintReauthIntent("env_prod", []string{"key_b", "key_a"})
				return mustReauthIntent(t, intent, err)
			},
			wantPurpose:          PurposeMint,
			wantOperation:        authz.OpCredentialMint,
			wantEnvironment:      "env_prod",
			wantKeySet:           "key_a\nkey_b",
			wantChallengeBinding: `{"operation":"mint","environment_id":"env_prod","key_ids":["key_a","key_b"]}`,
		},
		{
			name: "adapter configure",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewAdapterConfigureReauthIntent([]string{"env_prod", "env_dev", "env_prod"})
				return mustReauthIntent(t, intent, err)
			},
			targetEnvironment:    "env_prod",
			wantPurpose:          PurposeAdapter,
			wantOperation:        authz.OpAdapterConfigure,
			wantEnvironment:      "env_prod",
			wantEnvironmentSet:   "env_dev\nenv_prod",
			wantChallengeBinding: `{"purpose":"adapter","operation":"adapter.configure","environment_id":"env_prod","environment_ids":["env_dev","env_prod"]}`,
		},
		{
			name: "adapter credential set",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewAdapterCredentialSetReauthIntent([]string{"env_prod", "env_dev"})
				return mustReauthIntent(t, intent, err)
			},
			targetEnvironment:    "env_prod",
			wantPurpose:          PurposeAdapter,
			wantOperation:        authz.OpAdapterCredentialSet,
			wantEnvironment:      "env_prod",
			wantEnvironmentSet:   "env_dev\nenv_prod",
			wantChallengeBinding: `{"purpose":"adapter","operation":"adapter.credential-set","environment_id":"env_prod","environment_ids":["env_dev","env_prod"]}`,
		},
		{
			name: "adapter adopt",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewAdapterAdoptReauthIntent([]string{"env_prod", "env_dev"})
				return mustReauthIntent(t, intent, err)
			},
			targetEnvironment:    "env_prod",
			wantPurpose:          PurposeAdapter,
			wantOperation:        authz.OpAdapterAdopt,
			wantEnvironment:      "env_prod",
			wantEnvironmentSet:   "env_dev\nenv_prod",
			wantChallengeBinding: `{"purpose":"adapter","operation":"adapter.adopt","environment_id":"env_prod","environment_ids":["env_dev","env_prod"]}`,
		},
		{
			name: "adapter sync",
			make: func(t *testing.T) ReauthIntent {
				intent, err := NewAdapterSyncReauthIntent([]string{"env_prod", "env_dev"})
				return mustReauthIntent(t, intent, err)
			},
			targetEnvironment:    "env_prod",
			wantPurpose:          PurposeAdapter,
			wantOperation:        authz.OpAdapterSync,
			wantEnvironment:      "env_prod",
			wantEnvironmentSet:   "env_dev\nenv_prod",
			wantChallengeBinding: `{"purpose":"adapter","operation":"adapter.sync","environment_id":"env_prod","environment_ids":["env_dev","env_prod"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			intent := tt.make(t)
			binding, err := intent.bindingFor(tt.targetEnvironment)
			if err != nil {
				t.Fatal(err)
			}
			if binding.purpose != tt.wantPurpose || binding.operation != tt.wantOperation ||
				binding.environmentID != tt.wantEnvironment || binding.keySet != tt.wantKeySet ||
				binding.environmentSet != tt.wantEnvironmentSet {
				t.Fatalf("binding = %#v, want purpose=%q operation=%q environment=%q key-set=%q environment-set=%q",
					binding, tt.wantPurpose, tt.wantOperation, tt.wantEnvironment, tt.wantKeySet, tt.wantEnvironmentSet)
			}
			if got := binding.challengeBinding; got != tt.wantChallengeBinding {
				t.Fatalf("challenge binding = %q, want byte-exact %q", got, tt.wantChallengeBinding)
			}
		})
	}
}

func mustReauthIntent(t *testing.T, intent ReauthIntent, err error) ReauthIntent {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return intent
}
