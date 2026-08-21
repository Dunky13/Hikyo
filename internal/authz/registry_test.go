package authz

// Constructor-negative fixtures for the validating registry constructor. Every
// registry invariant that is checkable inside this package aborts newRegistry
// (and therefore package initialization, via mustNewRegistry) rather than
// surfacing later as a runtime authorization anomaly. The cross-contract half —
// that a named store op corresponds to a real store method, and that every
// operation is audited or reviewed-exempt — stays in internal/isolation, where
// the store method set and the exemption fixture live.

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// baseSpec is a well-formed tenant read row. Each negative test mutates it into
// exactly one violation; TestConstructorAcceptsBaseSpec proves the unmutated
// fixture is accepted, so a rejection can only come from the mutation.
func baseSpec() opSpec {
	return opSpec{
		class:    ClassTenant,
		level:    domain.LevelEnv,
		formula:  Formula{{Cap: domain.CapRead, At: domain.LevelEnv}},
		storeOps: map[StoreOp]bool{StoreEnvironmentsGet: true},
		events:   []audit.EventType{audit.EventOrgRead},
	}
}

func rejects(t *testing.T, name string, spec opSpec) {
	t.Helper()
	if _, err := newRegistry(map[Operation]opSpec{Operation("x.op"): spec}); err == nil {
		t.Fatalf("%s: newRegistry accepted a malformed spec", name)
	}
}

// TestConstructorAcceptsBaseSpec keeps the negative fixtures honest: if the
// unmutated baseSpec were itself rejected, every rejects() case would pass
// vacuously.
func TestConstructorAcceptsBaseSpec(t *testing.T) {
	if _, err := newRegistry(map[Operation]opSpec{Operation("x.op"): baseSpec()}); err != nil {
		t.Fatalf("baseSpec rejected: %v", err)
	}
}

func TestConstructorRejectsBothAuditDispositions(t *testing.T) {
	s := baseSpec() // already carries events
	s.auditedNone = true
	rejects(t, "events+audited-none", s)
}

func TestConstructorRejectsAuditedNoneOnNonTenant(t *testing.T) {
	s := baseSpec()
	s.class = ClassInstance
	s.level = domain.LevelNone
	s.events = nil
	s.auditedNone = true
	rejects(t, "audited-none non-tenant", s)
}

func TestConstructorRejectsAuditedNoneWithNonReadFormula(t *testing.T) {
	s := baseSpec()
	s.formula = Formula{{Cap: domain.CapEdit, At: domain.LevelEnv}}
	s.storeOps = map[StoreOp]bool{StoreEnvironmentsGet: true}
	s.events = nil
	s.auditedNone = true
	rejects(t, "audited-none non-read formula", s)
}

func TestConstructorRejectsAuditedNoneThatMutates(t *testing.T) {
	s := baseSpec()
	s.storeOps = map[StoreOp]bool{StoreEnvironmentsGet: true, StoreEnvironmentsUpdateNote: true}
	s.events = nil
	s.auditedNone = true
	rejects(t, "audited-none mutating", s)
}

func TestConstructorRejectsEmptyFormula(t *testing.T) {
	s := baseSpec()
	s.formula = nil
	rejects(t, "empty formula", s)
}

func TestConstructorRejectsAtomWithoutCapability(t *testing.T) {
	s := baseSpec()
	s.formula = Formula{{Cap: "", At: domain.LevelEnv}}
	rejects(t, "empty atom capability", s)
}

func TestConstructorRejectsTenantAtomDeeperThanLevel(t *testing.T) {
	s := baseSpec()
	s.level = domain.LevelOrg
	s.formula = Formula{{Cap: domain.CapRead, At: domain.LevelEnv}}
	rejects(t, "atom deeper than tenant level", s)
}

func TestConstructorRejectsTenantWithNonTenantLevel(t *testing.T) {
	s := baseSpec()
	s.level = domain.LevelNone
	s.formula = Formula{{Cap: domain.CapRead, At: domain.LevelNone}}
	rejects(t, "tenant op at instance level", s)
}

func TestConstructorRejectsStubClass(t *testing.T) {
	s := baseSpec()
	s.class = ClassStub
	rejects(t, "stub class", s)
}

func TestConstructorRejectsMalformedStoreOp(t *testing.T) {
	s := baseSpec()
	s.storeOps = map[StoreOp]bool{StoreOp("environmentsGet"): true}
	rejects(t, "store op without package", s)
}

func TestConstructorRejectsUnknownStoreOp(t *testing.T) {
	s := baseSpec()
	// Well-formed `package.Method` shape but absent from the catalogue.
	s.storeOps = map[StoreOp]bool{StoreOp("orgs.Nonexistent"): true}
	rejects(t, "unknown store op", s)
}

func TestConstructorRejectsFalseStoreOpEntry(t *testing.T) {
	s := baseSpec()
	s.storeOps = map[StoreOp]bool{StoreEnvironmentsGet: false}
	rejects(t, "false store-op entry", s)
}

func TestConstructorRejectsNoAuditDisposition(t *testing.T) {
	s := baseSpec()
	s.events = nil // no events, no audited-none, no reviewed exemption
	rejects(t, "no audit disposition", s)
}

func TestConstructorRejectsReviewExemptWithEvents(t *testing.T) {
	s := baseSpec() // carries events
	s.reviewExempt = true
	rejects(t, "reviewed exemption + events", s)
}

func TestConstructorRejectsReviewExemptWithAuditedNone(t *testing.T) {
	s := baseSpec()
	s.events = nil
	s.auditedNone = true
	s.reviewExempt = true
	rejects(t, "reviewed exemption + audited-none", s)
}

func TestConstructorRejectsUnreviewedAuditExemption(t *testing.T) {
	s := baseSpec()
	s.events = nil
	s.reviewExempt = true
	rejects(t, "unreviewed audit exemption", s)
}

func TestConstructorRejectsUnknownCapability(t *testing.T) {
	s := baseSpec()
	s.formula = Formula{{Cap: domain.Capability("not-a-capability"), At: domain.LevelEnv}}
	rejects(t, "unknown capability", s)
}

func TestConstructorRejectsAtomDeeperThanCapability(t *testing.T) {
	s := baseSpec()
	// manage-projects is grantable no deeper than org; an env atom is illegal
	// even though the tenant op addresses env.
	s.formula = Formula{{Cap: domain.CapManageProjects, At: domain.LevelEnv}}
	rejects(t, "atom deeper than capability", s)
}

func TestConstructorRejectsInstanceWithTenantLevel(t *testing.T) {
	s := baseSpec()
	s.class = ClassInstance
	s.level = domain.LevelOrg
	rejects(t, "instance op at tenant level", s)
}

func TestConstructorRejectsInstanceWithTenantFormulaAtom(t *testing.T) {
	s := baseSpec()
	s.class = ClassInstance
	s.level = domain.LevelNone
	rejects(t, "instance op with tenant formula atom", s)
}

func TestConstructorRejectsUnauthenticatedClass(t *testing.T) {
	s := baseSpec()
	s.class = ClassUnauthenticated
	rejects(t, "unauthenticated class", s)
}

func TestConstructorRejectsSystemClass(t *testing.T) {
	s := baseSpec()
	s.class = ClassSystem
	rejects(t, "system class", s)
}

func TestConstructorRejectsEmptyEvent(t *testing.T) {
	s := baseSpec()
	s.events = []audit.EventType{""}
	rejects(t, "empty event type", s)
}

func TestConstructorRejectsUnregisteredEvent(t *testing.T) {
	s := baseSpec()
	s.events = []audit.EventType{audit.EventType("not.a.registered.event")}
	rejects(t, "unregistered event type", s)
}

func TestConstructorRejectsDuplicateEvent(t *testing.T) {
	s := baseSpec()
	s.events = []audit.EventType{audit.EventOrgRead, audit.EventOrgRead}
	rejects(t, "duplicate event type", s)
}

// TestConstructorDeepClonesSpec proves immutability: mutating every nested
// mutable field of the source spec after construction cannot reach into the
// installed registry row.
func TestConstructorDeepClonesSpec(t *testing.T) {
	spec := baseSpec()
	r, err := newRegistry(map[Operation]opSpec{Operation("x.op"): spec})
	if err != nil {
		t.Fatalf("baseSpec rejected: %v", err)
	}
	got := r.ops[Operation("x.op")]

	spec.storeOps[StoreEnvironmentsGet] = false
	spec.storeOps[StoreEnvironmentsUpdateNote] = true
	spec.formula[0].Cap = domain.CapEdit
	spec.events[0] = audit.EventOrgDeleted

	if !got.storeOps[StoreEnvironmentsGet] || got.storeOps[StoreEnvironmentsUpdateNote] {
		t.Error("registry storeOps map shares backing with the source spec")
	}
	if got.formula[0].Cap != domain.CapRead {
		t.Error("registry formula slice shares backing with the source spec")
	}
	if got.events[0] != audit.EventOrgRead {
		t.Error("registry events slice shares backing with the source spec")
	}
}

func TestRegistryLookupDoesNotExposeMutableState(t *testing.T) {
	r, err := newRegistry(map[Operation]opSpec{Operation("x.op"): baseSpec()})
	if err != nil {
		t.Fatalf("baseSpec rejected: %v", err)
	}
	first, ok := r.authorizationSpec(Operation("x.op"))
	if !ok {
		t.Fatal("registered operation missing")
	}
	first.formula[0].Cap = domain.CapEdit

	second, ok := r.authorizationSpec(Operation("x.op"))
	if !ok {
		t.Fatal("registered operation missing after lookup mutation")
	}
	if second.formula[0].Cap != domain.CapRead {
		t.Fatal("registry lookup exposed mutable formula backing")
	}
}

func TestConstructorRejectsEmptyOperationKey(t *testing.T) {
	if _, err := newRegistry(map[Operation]opSpec{Operation(""): baseSpec()}); err == nil {
		t.Fatal("newRegistry accepted an empty operation key")
	}
}

// TestConstructorAcceptsRealTable is the green anchor: the production policy
// table must satisfy every constructor invariant. mustNewRegistry already
// asserts this at package init, but a focused test names the seam under review.
func TestConstructorAcceptsRealTable(t *testing.T) {
	r, err := newRegistry(operationTable)
	if err != nil {
		t.Fatalf("real operation table rejected: %v", err)
	}
	if len(r.ops) != len(operationTable) {
		t.Fatalf("registry holds %d ops, table has %d", len(r.ops), len(operationTable))
	}
	if len(registry.ops) != len(operationTable) {
		t.Fatalf("package registry holds %d ops, table has %d", len(registry.ops), len(operationTable))
	}
}
