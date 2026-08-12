package isolation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// mvp-boundary A2: the per-formula matrix, DRIVEN BY THE AUTHORIZATION
// REGISTRY. The registry is the fixture generator — for every registered
// operation the planner derives
//
//   - one GRANT fixture: a principal holding exactly the formula's atoms at
//     the addressed scope, which must be authorized; and
//   - one DENY fixture PER ATOM: a principal holding the formula minus that
//     atom, which must be refused with the class's uniform sentinel.
//
// Deriving rather than hand-listing is what makes the criterion "a formula
// without a fixture fails CI" hold for tickets that have not been written yet:
// #50/#58's publish, pin, adapter and values-export formulas get their matrix
// rows the moment they are registered, with no fixture author in the loop.
//
// What CAN fail to be planned — and therefore what fails CI — is a formula the
// planner cannot seed: an atom outside the closed capability set, an atom at a
// level the addressing table has no scope for, an empty formula, or a class
// whose refusal contract is undeclared. TestMatrixPlannerRejectsUnfixtured is
// the negative test: it feeds the planner a synthetic registry containing one
// such formula and asserts the planner reports it, rather than asserting only
// that today's real registry happens to plan.

// matrixScopes is the addressing table: for each depth, the fixture chain a
// planned operation is exercised against. A new tenant depth with no entry is
// unplannable, which is the intended CI failure.
var matrixScopes = map[domain.Level]domain.Scope{
	domain.LevelNone:    {},
	domain.LevelOrg:     {Org: orgA},
	domain.LevelProject: {Org: orgA, Project: prjA1},
	domain.LevelEnv:     {Org: orgA, Project: prjA1, Env: envA1},
}

// matrixCase is one generated row: which principal, addressing what, and
// whether the chokepoint must mint a proof.
type matrixCase struct {
	name string
	// grants is the exact grant set the case's principal is seeded with.
	grants []domain.Grant
	scope  domain.Scope
	allow  bool
	// omitted names the atom removed for a deny case, for the failure message.
	omitted string
}

// matrixPlan is the generated fixture set for one operation.
type matrixPlan struct {
	op    authz.Operation
	cases []matrixCase
}

// planMatrix derives the whole matrix from registry facts. It returns the
// plans and the unplannable operations, each with the reason — the "a formula
// without a fixture fails CI" half, expressed as a pure function so the
// negative test can drive it with a synthetic registry.
func planMatrix(
	classes map[authz.Operation]authz.Class,
	levels map[authz.Operation]domain.Level,
	formulas map[authz.Operation]authz.Formula,
) ([]matrixPlan, []string) {
	var plans []matrixPlan
	var problems []string

	ops := make([]authz.Operation, 0, len(classes))
	for op := range classes {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i] < ops[j] })

	for _, op := range ops {
		class := classes[op]
		if class != authz.ClassTenant && class != authz.ClassInstance {
			// Only the two proof-minting classes reach Authorize; the
			// unauthenticated and system classes have their own probe
			// contracts (invariant 1's network unreachability, the
			// pre-auth admission contract) and no formula to exercise.
			continue
		}
		formula := formulas[op]
		if len(formula) == 0 {
			problems = append(problems, fmt.Sprintf("%s: registered with an empty formula — nothing to fixture", op))
			continue
		}
		level := levels[op]
		if class == authz.ClassInstance {
			level = domain.LevelNone
		}
		scope, ok := matrixScopes[level]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: addresses depth %d, which the matrix addressing table cannot reach", op, level))
			continue
		}

		full := make([]domain.Grant, 0, len(formula))
		bad := false
		for _, atom := range formula {
			if !domain.IsCapability(atom.Cap) {
				problems = append(problems, fmt.Sprintf("%s: atom %q is not in the closed capability set — no fixture can seed it", op, atom.Cap))
				bad = true
				continue
			}
			atomScope, ok := matrixScopes[atom.At]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: atom %q sits at depth %d, which the matrix addressing table cannot reach", op, atom.Cap, atom.At))
				bad = true
				continue
			}
			full = append(full, domain.Grant{Capability: atom.Cap, Scope: atomScope})
		}
		if bad {
			continue
		}

		plan := matrixPlan{op: op}
		plan.cases = append(plan.cases, matrixCase{
			name: "grant", grants: full, scope: scope, allow: true,
		})
		// One deny case per atom: hold everything the formula demands EXCEPT
		// this one. A conjunction that quietly loses a conjunct passes the
		// grant case and fails exactly here.
		for i, atom := range formula {
			without := make([]domain.Grant, 0, len(full))
			without = append(without, full[:i]...)
			without = append(without, full[i+1:]...)
			plan.cases = append(plan.cases, matrixCase{
				name:    "deny_without_" + string(atom.Cap),
				grants:  without,
				scope:   scope,
				omitted: string(atom.Cap),
			})
		}
		plans = append(plans, plan)
	}
	return plans, problems
}

func TestFormulaMatrixSQLite(t *testing.T)   { runFormulaMatrix(t, seededDB(t, openSQLite)) }
func TestFormulaMatrixPostgres(t *testing.T) { runFormulaMatrix(t, seededDB(t, openPostgres)) }

// runFormulaMatrix executes the generated matrix against a real datastore
// through the real chokepoint. It is E2E in the sense that matters for A2: the
// chain resolution, the grant table and the uniform sentinel are all live —
// only the transport above Authorize is absent, and the transport carries no
// formula (that is the whole point of the chokepoint).
func runFormulaMatrix(t *testing.T, db *store.DB) {
	plans, problems := planMatrix(facts.Operations(), facts.TenantOperations(), facts.Formulas())
	for _, p := range problems {
		t.Errorf("registry drove no fixture: %s", p)
	}
	if len(plans) == 0 {
		t.Fatal("the matrix planned nothing — the generator would be vacuously green")
	}
	classes := facts.Operations()

	for _, plan := range plans {
		t.Run(string(plan.op), func(t *testing.T) {
			for _, c := range plan.cases {
				t.Run(c.name, func(t *testing.T) {
					principal := seedMatrixPrincipal(t, db, string(plan.op)+"/"+c.name, c.grants)
					err := authorizeAs(t, db, principal, plan.op, c.scope)
					switch {
					case c.allow && err != nil:
						t.Fatalf("%s: holding exactly the formula must authorize, got %v", plan.op, err)
					case c.allow:
						return
					}
					// Deny contract by class: a tenant operation answers the
					// uniform nonexistent response, an instance operation the
					// grant-refusal sentinel.
					want := domain.ErrUnauthorized
					if classes[plan.op] == authz.ClassTenant {
						want = domain.ErrNotFound
					}
					if !errors.Is(err, want) {
						t.Fatalf("%s without %q: got %v, want %v", plan.op, c.omitted, err, want)
					}
				})
			}
		})
	}
}

// seedMatrixPrincipal creates a throwaway principal holding exactly the given
// grants, with the origin every grant row must carry. The id is derived from
// the case name so a failure names the case that produced it.
func seedMatrixPrincipal(t *testing.T, db *store.DB, caseName string, grants []domain.Grant) domain.PrincipalID {
	t.Helper()
	id := "usr_mx_" + strings.NewReplacer("/", "_", ".", "_", "-", "_").Replace(caseName)
	execRaw(t, db, fmt.Sprintf(
		`INSERT INTO principals (id, kind, created_at) VALUES ('%s', 'human', %s)`, id, ts))
	for i, g := range grants {
		gid := fmt.Sprintf("%s_g%d", id, i)
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
				`VALUES ('%s', '%s', '%s', %s, %s, %s, %s)`,
			gid, id, g.Capability,
			sqlText(string(g.Scope.Org)), sqlText(string(g.Scope.Project)), sqlText(string(g.Scope.Env)), ts))
		execRaw(t, db, fmt.Sprintf(
			`INSERT INTO grant_origins (id, grant_id, kind, subject, created_at) `+
				`VALUES ('gor_%s', '%s', 'manual', '%s', %s)`, gid, gid, id, ts))
	}
	return domain.PrincipalID(id)
}

func sqlText(v string) string {
	if v == "" {
		return "NULL"
	}
	return "'" + v + "'"
}

// authorizeAs runs the chokepoint for one (principal, operation, scope) inside
// a real transaction and reports what it answered. The proof is discarded: the
// matrix asserts the AUTHORIZATION decision, and the store binding is invariant
// 8's subject, not this one's.
func authorizeAs(t *testing.T, db *store.DB, p domain.PrincipalID, op authz.Operation, scope domain.Scope) error {
	t.Helper()
	return tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		_, err := az.Authorize(ctx, authz.Identity{Principal: p}, op, scope)
		return err
	})
}

// TestMatrixPlannerRejectsUnfixtured is the NEGATIVE test A2 demands: it proves
// the completeness machinery actually fires, rather than proving that today's
// fixtures happen to pass. It drives the planner with a synthetic registry
// carrying three formulas the planner cannot fixture, and asserts each is
// reported. Without this, the generator could silently skip an operation and
// the suite would still be green.
func TestMatrixPlannerRejectsUnfixtured(t *testing.T) {
	const (
		emptyFormula = authz.Operation("synthetic.empty-formula")
		unknownAtom  = authz.Operation("synthetic.unknown-atom")
		unknownDepth = authz.Operation("synthetic.unknown-depth")
		fine         = authz.Operation("synthetic.plannable")
	)
	classes := map[authz.Operation]authz.Class{
		emptyFormula: authz.ClassTenant,
		unknownAtom:  authz.ClassTenant,
		unknownDepth: authz.ClassTenant,
		fine:         authz.ClassTenant,
	}
	levels := map[authz.Operation]domain.Level{
		emptyFormula: domain.LevelOrg,
		unknownAtom:  domain.LevelOrg,
		unknownDepth: domain.Level(99),
		fine:         domain.LevelOrg,
	}
	formulas := map[authz.Operation]authz.Formula{
		emptyFormula: {},
		unknownAtom:  {{Cap: domain.Capability("invented-by-a-later-ticket"), At: domain.LevelOrg}},
		unknownDepth: {{Cap: domain.CapRead, At: domain.LevelOrg}},
		fine:         {{Cap: domain.CapRead, At: domain.LevelOrg}},
	}

	plans, problems := planMatrix(classes, levels, formulas)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{string(emptyFormula), string(unknownAtom), string(unknownDepth)} {
		if !strings.Contains(joined, want) {
			t.Errorf("planner did not refuse %q — an unfixtured formula would ride into CI green.\ngot:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, string(fine)) {
		t.Errorf("planner refused the plannable formula: %s", joined)
	}
	if len(plans) != 1 || plans[0].op != fine {
		t.Errorf("planner produced %d plans, want exactly the plannable one", len(plans))
	}
	// The plannable formula must yield the grant case AND one deny case per
	// atom; a planner that produced only the positive would make every
	// conjunction untested.
	if len(plans) == 1 && len(plans[0].cases) != 2 {
		t.Errorf("plannable formula produced %d cases, want 1 grant + 1 deny per atom", len(plans[0].cases))
	}
}

// TestMatrixCoversEveryProofMintingOperation pins the other half of A2: every
// tenant- and instance-class operation in the live registry is in the plan.
// The planner skipping one silently is exactly the failure the criterion names.
func TestMatrixCoversEveryProofMintingOperation(t *testing.T) {
	plans, problems := planMatrix(facts.Operations(), facts.TenantOperations(), facts.Formulas())
	for _, p := range problems {
		t.Errorf("unplannable operation: %s", p)
	}
	planned := map[authz.Operation]bool{}
	for _, p := range plans {
		planned[p.op] = true
	}
	for op, class := range facts.Operations() {
		if class != authz.ClassTenant && class != authz.ClassInstance {
			continue
		}
		if !planned[op] {
			t.Errorf("operation %q has no generated fixture", op)
		}
	}
}

// TestRevocationIsImmediate is A2's "revocation immediate (no cache)" arm at
// the chokepoint: a principal authorized a moment ago is refused on the very
// next call once the grant row is gone, with no invalidation step anywhere —
// because there is nothing to invalidate.
func TestRevocationIsImmediateSQLite(t *testing.T) {
	runRevocationIsImmediate(t, seededDB(t, openSQLite))
}
func TestRevocationIsImmediatePostgres(t *testing.T) {
	runRevocationIsImmediate(t, seededDB(t, openPostgres))
}

func runRevocationIsImmediate(t *testing.T, db *store.DB) {
	scope := domain.Scope{Org: orgA, Project: prjA1, Env: envA1}
	if err := authorizeAs(t, db, alice, authz.OpEnvRead, scope); err != nil {
		t.Fatalf("precondition: alice reads env_a1: %v", err)
	}
	grants := &service.Grants{DB: db}
	if err := grants.Revoke(t.Context(), service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: alice, Capability: domain.CapRead, Scope: orgAScope,
	}); err != nil {
		t.Fatalf("revoke alice's org-scope read: %v", err)
	}
	if err := authorizeAs(t, db, alice, authz.OpEnvRead, scope); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after revocation the read must answer the uniform nonexistent response, got %v", err)
	}
}
