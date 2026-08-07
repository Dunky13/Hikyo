package authz

// Boundary tests for the proof lifecycle (tenant-isolation ADR, invariant
// 5): nil, foreign-transaction, ended-transaction, and operation-mismatched
// proofs are each rejected fail-closed at Verify. These live in-package
// deliberately — constructing a proof outside authorize() is exactly what
// the forgery guard bans everywhere else.

import (
	"testing"

	"github.com/Dunky13/wenv/internal/domain"
)

const demoOp = Operation("environment.read")

func mintTenant(t *testing.T, tok *TxToken) Proof {
	t.Helper()
	return &proof{
		kind: kindTenant,
		op:   demoOp,
		chain: domain.Scope{
			Org: "org_a", Project: "prj_a", Env: "env_a",
		},
		tok: tok,
	}
}

func TestVerifyRejectsNilProof(t *testing.T) {
	if _, err := Verify(nil, StoreEnvironmentsGet, NewTxToken()); err == nil {
		t.Fatal("nil proof accepted")
	}
	var typedNil *proof
	if _, err := Verify(typedNil, StoreEnvironmentsGet, NewTxToken()); err == nil {
		t.Fatal("typed-nil proof accepted")
	}
}

func TestVerifyRejectsForeignTransaction(t *testing.T) {
	p := mintTenant(t, NewTxToken())
	other := NewTxToken()
	if _, err := Verify(p, StoreEnvironmentsGet, other); err == nil {
		t.Fatal("foreign-transaction proof accepted")
	}
	if _, err := Verify(p, StoreEnvironmentsGet, nil); err == nil {
		t.Fatal("nil-token boundary accepted a proof")
	}
}

func TestVerifyRejectsEndedTransaction(t *testing.T) {
	tok := NewTxToken()
	p := mintTenant(t, tok)
	tok.Invalidate()
	if _, err := Verify(p, StoreEnvironmentsGet, tok); err == nil {
		t.Fatal("proof outlived its transaction")
	}
}

// A proof minted in one transaction attempt must die in the retry attempt:
// the transaction package invalidates the attempt's token on rollback and
// mints a fresh token for the next attempt, so the copied Go value carries a
// reference to a dead transaction (tenant-isolation ADR: "not reusable
// across retries").
func TestVerifyRejectsProofAcrossRetryAttempts(t *testing.T) {
	first := NewTxToken()
	p := mintTenant(t, first)
	first.Invalidate() // rollback of attempt 1
	second := NewTxToken()
	if _, err := Verify(p, StoreEnvironmentsGet, second); err == nil {
		t.Fatal("attempt-1 proof accepted in attempt 2")
	}
}

func TestVerifyRejectsOperationMismatch(t *testing.T) {
	tok := NewTxToken()
	p := mintTenant(t, tok) // minted for environment.read
	if _, err := Verify(p, StoreEnvironmentsUpdateNote, tok); err == nil {
		t.Fatal("read-formula proof accepted on the mutation path")
	}
}

func TestVerifyAcceptsAndReturnsResolvedChain(t *testing.T) {
	tok := NewTxToken()
	p := mintTenant(t, tok)
	chain, err := Verify(p, StoreEnvironmentsGet, tok)
	if err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	want := domain.Scope{Org: "org_a", Project: "prj_a", Env: "env_a"}
	if chain != want {
		t.Fatalf("chain = %+v, want %+v", chain, want)
	}
}

func TestSystemProofBoundToSiteOperationSet(t *testing.T) {
	tok := NewTxToken()
	p, err := SystemAuthority(SiteMigration, tok)
	if err != nil {
		t.Fatalf("registered site refused: %v", err)
	}
	// Every site's operation set is empty today, so a system proof must be
	// rejected for every store operation — the fail-closed default.
	for op := range (RegistryFacts{}).StoreOps() {
		if _, err := Verify(p, op, tok); err == nil {
			t.Fatalf("system proof from %q accepted for %q outside its site set", SiteMigration, op)
		}
	}
}

func TestSystemAuthorityRefusesUnregisteredSite(t *testing.T) {
	if _, err := SystemAuthority(SystemSite("cron"), NewTxToken()); err == nil {
		t.Fatal("unregistered mint site accepted")
	}
	if _, err := SystemAuthority(SiteBoot, nil); err == nil {
		t.Fatal("system authority minted without a transaction")
	}
}

func TestEvaluateInheritanceAndDenyByDefault(t *testing.T) {
	chain := domain.Scope{Org: "o1", Project: "p1", Env: "e1"}
	readEnv := Formula{{Cap: domain.CapRead, At: domain.LevelEnv}}
	cases := []struct {
		name   string
		grants []domain.Grant
		want   bool
	}{
		{"no grants", nil, false},
		{"exact env grant", []domain.Grant{{Capability: domain.CapRead, Scope: chain}}, true},
		{"project grant inherits down", []domain.Grant{{Capability: domain.CapRead, Scope: domain.Scope{Org: "o1", Project: "p1"}}}, true},
		{"org grant inherits down", []domain.Grant{{Capability: domain.CapRead, Scope: domain.Scope{Org: "o1"}}}, true},
		{"instance grant inherits down", []domain.Grant{{Capability: domain.CapRead, Scope: domain.Scope{}}}, true},
		{"foreign org grant", []domain.Grant{{Capability: domain.CapRead, Scope: domain.Scope{Org: "o2"}}}, false},
		{"sibling project grant", []domain.Grant{{Capability: domain.CapRead, Scope: domain.Scope{Org: "o1", Project: "p2"}}}, false},
		{"sibling env grant", []domain.Grant{{Capability: domain.CapRead, Scope: domain.Scope{Org: "o1", Project: "p1", Env: "e2"}}}, false},
		{"wrong capability", []domain.Grant{{Capability: domain.CapEdit, Scope: chain}}, false},
	}
	for _, tc := range cases {
		if got := evaluate(readEnv, chain, tc.grants); got != tc.want {
			t.Errorf("%s: evaluate = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestEvaluateGrantDeeperThanAtomNeverCovers(t *testing.T) {
	// manage-projects at org level; a grant scoped to a single env inside
	// the org must not satisfy an org-level atom.
	chain := domain.Scope{Org: "o1"}
	f := Formula{{Cap: domain.CapManageProjects, At: domain.LevelOrg}}
	grants := []domain.Grant{{
		Capability: domain.CapManageProjects,
		Scope:      domain.Scope{Org: "o1", Project: "p1", Env: "e1"},
	}}
	if evaluate(f, chain, grants) {
		t.Fatal("env-scoped grant satisfied an org-level atom")
	}
}

func TestEvaluateInstanceAtomRequiresInstanceGrant(t *testing.T) {
	f := Formula{{Cap: domain.CapInstanceConfig, At: domain.LevelNone}}
	orgAdmin := []domain.Grant{{Capability: domain.CapInstanceConfig, Scope: domain.Scope{Org: "o1"}}}
	if evaluate(f, domain.Scope{}, orgAdmin) {
		t.Fatal("org-scoped grant satisfied an instance atom — route selection became authorization")
	}
	instance := []domain.Grant{{Capability: domain.CapInstanceConfig, Scope: domain.Scope{}}}
	if !evaluate(f, domain.Scope{}, instance) {
		t.Fatal("instance grant refused for an instance atom")
	}
}

func TestEvaluateConjunction(t *testing.T) {
	chain := domain.Scope{Org: "o1", Project: "p1", Env: "e1"}
	f := Formula{
		{Cap: domain.CapRead, At: domain.LevelEnv},
		{Cap: domain.CapEdit, At: domain.LevelEnv},
	}
	readOnly := []domain.Grant{{Capability: domain.CapRead, Scope: chain}}
	if evaluate(f, chain, readOnly) {
		t.Fatal("half-satisfied conjunction accepted")
	}
	both := append(readOnly, domain.Grant{Capability: domain.CapEdit, Scope: chain})
	if !evaluate(f, chain, both) {
		t.Fatal("fully-satisfied conjunction refused")
	}
}
