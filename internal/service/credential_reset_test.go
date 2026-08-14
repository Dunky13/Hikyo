package service

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// classifyResetTarget is the org-bounded reachability test at the heart of the
// credential-reset rules (ADR - Recovery). These pin the three outcomes plus the
// fail-closed grantless case.
func TestClassifyResetTarget(t *testing.T) {
	g := func(cap domain.Capability, org domain.OrgID, prj domain.ProjectID) domain.Grant {
		return domain.Grant{Capability: cap, Scope: domain.Scope{Org: org, Project: prj}}
	}
	cases := []struct {
		name        string
		grants      []domain.Grant
		wantOrg     string
		wantInst    bool
		wantOrgHits int
	}{
		{
			name:        "org-bounded to one org",
			grants:      []domain.Grant{g("read", "org_a", "prj_a1"), g("edit", "org_a", "")},
			wantOrg:     "org_a",
			wantOrgHits: 1,
		},
		{
			name:        "instance-scoped grant is an instance capability",
			grants:      []domain.Grant{g("read", "org_a", ""), g("instance-config", "", "")},
			wantInst:    true,
			wantOrgHits: 0,
		},
		{
			name:        "grants spanning two orgs are multi-org",
			grants:      []domain.Grant{g("read", "org_a", ""), g("read", "org_b", "")},
			wantOrgHits: 2,
		},
		{
			name:        "a grantless target is fail-closed to the instance path",
			grants:      nil,
			wantOrgHits: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			org, inst, count := classifyResetTarget(c.grants)
			if inst != c.wantInst {
				t.Fatalf("instanceCap = %v, want %v", inst, c.wantInst)
			}
			if count != c.wantOrgHits {
				t.Fatalf("orgCount = %d, want %d", count, c.wantOrgHits)
			}
			if !inst && count == 1 && org != c.wantOrg {
				t.Fatalf("org = %q, want %q", org, c.wantOrg)
			}
		})
	}
}
