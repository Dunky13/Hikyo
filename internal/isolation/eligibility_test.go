package isolation

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// The multi-instance ADR's acceptance criterion 4, second half, in the form
// the criterion itself demands — "refuses by artifact eligibility
// (CI-asserted)":
//
//	"the instance-connection credential presented to any endpoint other than
//	directory-serve refuses by artifact eligibility"
//
// The assertion ranges over the LIVE operation registry rather than a list
// restated here, which is the whole point: an operation added tomorrow is
// covered the moment it is registered, and a test naming its own operations
// would go on passing against a registry that had grown past it.

func TestInstanceConnectionCredentialReachesOnlyDirectoryServe(t *testing.T) {
	const allowed = authz.OpRemoteDirectoryServe

	ops := authz.RegistryFacts{}.Operations()
	if len(ops) == 0 {
		t.Fatal("the operation registry is empty — this check would be vacuously green")
	}

	// Both keys, because either alone is a way for the confinement to go inert
	// rather than wrong: the artifact key misses if a resolver copies the
	// machine leg's `Artifact: string(cred.Kind)`, and the class key misses if
	// a future artifact is reused across classes.
	conn := authz.Identity{
		Principal: "prn_instance_connection_probe",
		Class:     domain.ClassInstanceConn,
		Artifact:  string(crypto.ArtifactInstanceConn),
	}

	var sawAllowed bool
	for op := range ops {
		eligible := authz.ArtifactEligible(crypto.ArtifactInstanceConn, op)
		if authz.Eligible(conn, op) != eligible {
			t.Errorf("%s: the artifact key and the class key disagree — both must refuse", op)
		}
		// The class key alone must also refuse, so a resolver that sets the
		// wrong Artifact string cannot silently unconfine the credential.
		byClassOnly := authz.Identity{Principal: conn.Principal, Class: domain.ClassInstanceConn}
		if authz.Eligible(byClassOnly, op) != eligible {
			t.Errorf("%s: the class key alone does not confine — a resolver setting "+
				"Artifact to the credential kind would make the confinement inert", op)
		}
		if op == allowed {
			sawAllowed = true
			if !eligible {
				t.Errorf("%s: the instance-connection credential must be eligible for its one operation", op)
			}
			continue
		}
		if eligible {
			t.Errorf("%s: the instance-connection credential is eligible for an operation "+
				"other than %s — the ADR's artifact-eligibility matrix admits exactly one row",
				op, allowed)
		}
	}
	if !sawAllowed {
		t.Fatalf("%s is not in the operation registry — the confinement points at nothing", allowed)
	}
}

// Eligibility must be keyed per ARTIFACT PER OPERATION, not derived from the
// formula. The ADR is explicit about why: "a future operation reusing the
// `instance-directory` formula does NOT widen what this credential reaches."
//
// This is the test that would catch someone re-deriving eligibility from the
// capability — it registers no new operation and touches no production table,
// it simply asserts that sharing the formula is not sufficient. If a second
// `instance-directory` operation is ever added and this test starts failing,
// the eligibility table is what must be reviewed, not this assertion.
func TestSharingTheDirectoryFormulaDoesNotWidenTheCredential(t *testing.T) {
	formulas := authz.RegistryFacts{}.Formulas()

	var sharing []authz.Operation
	for op, formula := range formulas {
		for _, atom := range formula {
			if atom.Cap == domain.CapInstanceDirector {
				sharing = append(sharing, op)
				break
			}
		}
	}
	if len(sharing) == 0 {
		t.Fatal("no operation carries instance-directory — the confinement has nothing to confine")
	}

	for _, op := range sharing {
		if op == authz.OpRemoteDirectoryServe {
			continue
		}
		if authz.ArtifactEligible(crypto.ArtifactInstanceConn, op) {
			t.Errorf("%s shares the instance-directory formula and became reachable by the "+
				"instance-connection credential — eligibility must be per-artifact-per-operation, "+
				"never derived from the formula", op)
		}
	}
}

// The confinement table itself: exactly one artifact type is confined today,
// and it names exactly one operation. Enumerated from the table rather than
// restated, so a row silently lost fails here.
func TestArtifactConfinementTableShape(t *testing.T) {
	confined := authz.ConfinedArtifacts()
	if len(confined) != 1 || confined[0] != crypto.ArtifactInstanceConn {
		t.Fatalf("confined artifact types = %v, want exactly [%s]", confined, crypto.ArtifactInstanceConn)
	}

	eligible := authz.EligibleOperations(crypto.ArtifactInstanceConn)
	if len(eligible) != 1 || eligible[0] != authz.OpRemoteDirectoryServe {
		t.Fatalf("instance-connection eligible operations = %v, want exactly [%s]",
			eligible, authz.OpRemoteDirectoryServe)
	}

	// An unconfined artifact must stay unconfined: the table is an allowlist of
	// CONFINED types, and reading it as a total matrix would deny every human
	// session every operation.
	for op := range (authz.RegistryFacts{}).Operations() {
		if !authz.ArtifactEligible(crypto.ArtifactBrowserSession, op) {
			t.Fatalf("%s: a browser session became ineligible — the eligibility table is being "+
				"read as a total matrix rather than an allowlist of confined types", op)
		}
	}
}

// THE ENDPOINT HALF OF THE CONFINEMENT.
//
// The three tests above range over the live OPERATION registry, which is the
// right surface for the eligibility table — and is blind to a route that calls
// no operation. Those routes exist and are legitimate (pre-authentication
// identity protocol, account security, self-scoped projections), but they are
// exactly the doors the artifact-eligibility chokepoint never sees, so an
// instance-connection credential presented to one of them is confined by
// nothing the tests above assert.
//
// This is the invariant that closes it: EVERY route in the live wire registry
// either maps to at least one operation — and is therefore confined at the
// chokepoint — or is named here, in a pin whose entries were each reviewed for
// what artifact they admit. A new operation-less route fails this test until
// someone adds it and confirms that answer.
//
// The pin is a SET EQUALITY, not a subset check: a route that gains an
// operation must leave the list, so the list cannot quietly become a place
// where confinement questions go to be forgotten.
func TestEveryRouteIsConfinedByAnOperationOrPinnedAsSelfScoped(t *testing.T) {
	// Each entry is here because it admits no machine artifact. The three
	// groups differ in HOW:
	//
	//  1. pre-authentication (healthz/readyz/meta, the identity protocol, the
	//     workspace handoff endpoints): no artifact is resolved at all, or the
	//     artifact resolved is a handoff value that is not an authentication
	//     credential;
	//  2. account security (everything under /auth/ that mutates factors,
	//     passkeys, identities or recovery): reached through
	//     authz.Authenticate, whose admitting set is cli+browser, so a machine
	//     credential AND a workspace bearer are both refused by construction;
	//  3. self-scoped projections (/me/orgs, /me/sessions): reached through
	//     authz.AuthenticateSelfSurface, whose admitting set is the three
	//     SESSION artifacts, so an instance-connection credential is refused by
	//     construction there too. What a workspace bearer may see through them
	//     is narrowed to its own row by the service.
	pinned := map[string]bool{
		// 1. pre-authentication.
		"http:GET /healthz":                              true,
		"http:GET /metrics":                              true,
		"http:GET /readyz":                               true,
		"http:GET /api/v1/meta":                          true,
		"http:POST /api/v1/auth/credential/establish":    true,
		"http:POST /api/v1/auth/local/login":             true,
		"http:POST /api/v1/auth/logout":                  true,
		"http:GET /api/v1/auth/whoami":                   true,
		"http:GET /api/v1/auth/methods":                  true,
		"http:POST /api/v1/auth/recovery/begin":          true,
		"http:GET /api/v1/auth/oidc/{provider}/callback": true,
		"http:POST /api/v1/auth/oidc/{provider}/start":   true,
		"http:GET /api/v1/auth/saml/{provider}/metadata": true,
		"http:POST /api/v1/auth/saml/{provider}/acs":     true,
		"http:POST /api/v1/auth/saml/{provider}/start":   true,
		"http:POST /api/v1/auth/webauthn/login/finish":   true,
		"http:POST /api/v1/auth/webauthn/login/start":    true,
		"http:POST /api/v1/auth/workspace/approve":       true,
		"http:POST /api/v1/auth/workspace/redeem":        true,
		"http:POST /api/v1/auth/workspace/start":         true,
		// 2. account security, behind authz.Authenticate (cli+browser only).
		"http:DELETE /api/v1/auth/identities/{id}":           true,
		"http:DELETE /api/v1/auth/totp":                      true,
		"http:DELETE /api/v1/auth/webauthn/credentials/{id}": true,
		"http:GET /api/v1/auth/identities":                   true,
		"http:GET /api/v1/auth/webauthn/credentials":         true,
		"http:POST /api/v1/auth/identities/link":             true,
		"http:POST /api/v1/auth/recovery-codes/regenerate":   true,
		// The reveal ceremony's TOTP opener (#58) resolves its caller through
		// `az.Authenticate` like the rest of this group, so it admits cli and
		// browser only. That is the right door for it: opening a
		// reauthentication window is an act on the human's own account, and a
		// workspace bearer living in another origin's JavaScript must not be
		// able to perform one any more than it can enrol a factor.
		"http:POST /api/v1/auth/reauth/totp":             true,
		"http:POST /api/v1/auth/totp/enrol/confirm":      true,
		"http:POST /api/v1/auth/totp/enrol/start":        true,
		"http:POST /api/v1/auth/totp/step-up":            true,
		"http:POST /api/v1/auth/webauthn/enrol/finish":   true,
		"http:POST /api/v1/auth/webauthn/enrol/start":    true,
		"http:POST /api/v1/auth/webauthn/reauth/finish":  true,
		"http:POST /api/v1/auth/webauthn/reauth/start":   true,
		"http:POST /api/v1/auth/webauthn/step-up/finish": true,
		"http:POST /api/v1/auth/webauthn/step-up/start":  true,
		// 3. self-scoped, behind authz.AuthenticateSelfSurface.
		"http:GET /api/v1/me/orgs":                  true,
		"http:GET /api/v1/me/sessions":              true,
		"http:DELETE /api/v1/me/sessions/{session}": true,
	}

	routes := authz.RegistryFacts{}.WireRoutes()
	wire := authz.RegistryFacts{}.Wire()
	if len(wire) == 0 {
		t.Fatal("the wire registry is empty — this check would be vacuously green")
	}
	seen := map[string]bool{}
	for route := range wire {
		if !strings.HasPrefix(route, "http:") {
			continue // CLI verbs reach the chokepoint through the same operations.
		}
		if len(routes[route]) > 0 {
			if pinned[route] {
				t.Errorf("%s now resolves through an operation and must leave the "+
					"operation-less pin — the pin is where confinement is answered by "+
					"review, and a route the chokepoint covers must not sit in it", route)
			}
			continue
		}
		seen[route] = true
		if !pinned[route] {
			t.Errorf("%s resolves through NO operation, so the artifact-eligibility "+
				"chokepoint never sees it. Either give it an operation, or add it to the "+
				"pin above with a note on which authentication door it uses and therefore "+
				"which artifacts it admits. An instance-connection credential must not be "+
				"able to reach it.", route)
		}
	}
	for route := range pinned {
		if !seen[route] {
			t.Errorf("%s is pinned as operation-less but is not in the wire registry "+
				"(renamed or removed) — a stale pin hides the next route that needs review", route)
		}
	}
}
