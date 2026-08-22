package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

func TestResolveAccessScopePreservesCanonicalRoutes(t *testing.T) {
	for _, tc := range []struct {
		name          string
		resolved      Resolved
		instanceScope bool
		wantPath      string
		wantLabel     string
	}{
		{
			name:          "instance",
			resolved:      Resolved{},
			instanceScope: true,
			wantPath:      api.PathPrefix + "/instance/grants",
			wantLabel:     "instance",
		},
		{
			name:      "org",
			resolved:  resolvedTenantDimensions("org/one", "", ""),
			wantPath:  api.PathPrefix + "/orgs/org%2Fone/grants",
			wantLabel: "org/one",
		},
		{
			name:      "project",
			resolved:  resolvedTenantDimensions("org_one", "project/one", ""),
			wantPath:  api.PathPrefix + "/orgs/org_one/projects/project%2Fone/grants",
			wantLabel: "org_one/project/one",
		},
		{
			name:      "environment",
			resolved:  resolvedTenantDimensions("org_one", "project_one", "env/one"),
			wantPath:  api.PathPrefix + "/orgs/org_one/projects/project_one/environments/env%2Fone/grants",
			wantLabel: "org_one/project_one/env/one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := resolveAccessScope(tc.resolved, commonFlags{}, tc.instanceScope, "access grant list")
			if err != nil {
				t.Fatal(err)
			}
			if scope.path != tc.wantPath || scope.label != tc.wantLabel {
				t.Fatalf("scope = {%q, %q}, want {%q, %q}", scope.path, scope.label, tc.wantPath, tc.wantLabel)
			}
		})
	}
}

func TestResolveAccessScopeRefusesSparseHierarchy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolved Resolved
		want     string
	}{
		{
			name:     "project without org",
			resolved: resolvedTenantDimensions("", "project_one", ""),
			want:     "project",
		},
		{
			name:     "environment without project",
			resolved: resolvedTenantDimensions("org_one", "", "env_one"),
			want:     "environment",
		},
		{
			name:     "environment and project without org",
			resolved: resolvedTenantDimensions("", "project_one", "env_one"),
			want:     "project",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveAccessScope(tc.resolved, commonFlags{}, false, "access grant list")
			if err == nil {
				t.Fatal("sparse scope was accepted")
			}
			var cliErr *Error
			if !errors.As(err, &cliErr) || cliErr.Code != ExitUsage {
				t.Fatalf("error = %v, want ExitUsage", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

func resolvedTenantDimensions(org, project, environment string) Resolved {
	return Resolved{Values: map[Dimension]string{
		DimOrg: org, DimProject: project, DimEnv: environment,
	}}
}

func TestGrantResultRowRendersEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		outcome api.GrantOutcome
		want    string
	}{
		{outcome: api.GrantOutcomeCreated(), want: "created"},
		{outcome: api.GrantOutcomeOriginAdded(), want: "origin added"},
		{outcome: api.GrantOutcomeUnchanged(), want: "unchanged"},
	} {
		t.Run(tc.outcome.String(), func(t *testing.T) {
			row, err := grantResultRow(apigen.GrantResult{
				GrantId: "grt_1", Capability: "read", Outcome: tc.outcome,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(row, "|"); got != "read|grt_1|"+tc.want {
				t.Fatalf("row = %q", got)
			}
		})
	}
}
