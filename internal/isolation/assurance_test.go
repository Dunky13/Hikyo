package isolation

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// The assurance-enforcement guard.
//
// The human-auth ADR makes `reveal`, `reveal-history`, `manage-members`,
// `credential-reset` and every instance capability MFA-mandatory, evaluated
// as SESSION assurance at the same chokepoint as authorize(). This slice
// records assurance but does not enforce it, deliberately: no factor exists
// to satisfy the rule, and enforcing it would leave a freshly bootstrapped
// administrator unable to perform the operations that administer the
// instance, with no in-product path to enrol out of it (#47 scope decision,
// taken with the human).
//
// A deferral with a comment behind it decays. This is the check that makes it
// expire on its own: the moment a factor beyond a password becomes mintable,
// the deferral's premise is false and the build says so.

func TestAssuranceEnforcementCannotBeForgotten(t *testing.T) {
	// The registry of factor-bearing event types is the tripwire. Enrolment,
	// removal and ceremony events cannot exist without the factors they
	// describe, so their appearance is the signal that the premise changed.
	factorEvents := []audit.EventType{
		"auth.factor_enrolled",
		"auth.factor_removed",
		"auth.passkey_added",
		"auth.passkey_removed",
		"auth.recovery_codes_generated",
		"auth.recovery_code_consumed",
		"auth.reauthenticated",
	}
	for _, et := range factorEvents {
		if _, registered := audit.Spec(et); registered && !authz.AssuranceEnforced {
			t.Fatalf(
				"%s is registered, so factors now exist — authz.AssuranceEnforced must become true and the "+
					"chokepoint must refuse an MFA-mandatory operation from a session that did not present one. "+
					"See docs/handoff/47-first-slice.md, scope decision 2, and #54.", et)
		}
	}

	// While the deferral stands, state exactly what is unenforced, so a reader
	// of this test knows the blast radius rather than having to derive it.
	if !authz.AssuranceEnforced {
		var deferred []authz.Operation
		for op := range facts.Operations() {
			if authz.FormulaDemandsMFA(op) {
				deferred = append(deferred, op)
			}
		}
		if len(deferred) == 0 {
			t.Error("no registered operation carries an MFA-mandatory capability — either the capability set " +
				"or the operation registry has drifted, and this guard is watching nothing")
		}
		t.Logf("assurance enforcement is deferred to #54; %d operation(s) currently carry an MFA-mandatory "+
			"capability and would be gated once it lands: %v", len(deferred), deferred)
	}
}

// The MFA-mandatory set is the ADR's, restated in Go. A capability quietly
// dropping out of it would silently ungate an operation the moment
// enforcement turns on, which is the worst possible time to discover it.
func TestMFAMandatorySetMatchesTheADR(t *testing.T) {
	// `instance-directory` is the multi-instance ADR's addition (#71). Its
	// amendment to #16 restates "every instance capability is MFA-mandatory" as
	// binding HUMAN SESSIONS, with the instance-connection machine principal as
	// the single named exemption — and that exemption is structural rather than
	// a row here: assuranceInadequate requires a non-empty SessionID, which a
	// machine principal never has.
	want := []string{
		"reveal", "reveal-history", "manage-members", "credential-reset",
		"instance-config", "instance-directory",
	}
	if len(authz.MFAMandatory) != len(want) {
		t.Fatalf("the MFA-mandatory set has %d members, the ADR names %d: %v",
			len(authz.MFAMandatory), len(want), authz.MFAMandatory)
	}
	for _, capability := range want {
		if !authz.MFAMandatory[domain.Capability(capability)] {
			t.Errorf("%q is MFA-mandatory in the ADR but not in authz.MFAMandatory", capability)
		}
	}
}
