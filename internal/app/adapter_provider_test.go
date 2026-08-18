package app

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/adapter/forgejo"
	"github.com/Hikyo-Org/hikyo/internal/adapter/githubactions"
)

func TestDeploymentModuleDispatchesCompiledInProviders(t *testing.T) {
	forgejoModule, forgetForgejo, err := deploymentModule("forgejo", "https://forgejo.example", "scoped-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer forgetForgejo()
	if _, ok := forgejoModule.(*forgejo.Module); !ok {
		t.Fatalf("forgejo module = %T", forgejoModule)
	}

	githubModule, forgetGitHub, err := deploymentModule("github-actions", "https://api.github.com", "github_pat_fine", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer forgetGitHub()
	if _, ok := githubModule.(*githubactions.Module); !ok {
		t.Fatalf("github module = %T", githubModule)
	}
}

func TestDeploymentModuleRefusesClassicGitHubPAT(t *testing.T) {
	_, _, err := deploymentModule("github-actions", "https://api.github.com", "ghp_classic", nil)
	if err == nil || !strings.Contains(err.Error(), "classic") {
		t.Fatalf("deploymentModule() = %v, want named classic PAT refusal", err)
	}
}

func TestDeploymentModuleNeverInfersProviderFromCredential(t *testing.T) {
	_, _, err := deploymentModule("", "https://api.github.com", "github_pat_fine", nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("deploymentModule() = %v, want missing persisted provider refusal", err)
	}
}
