package isolation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Machine identities (#61, machine-identities ADR): the mint/rotate/revoke
// lifecycle, the lifetime controls, the three-operation authorization table
// and the chokepoint's machine-credential resolution. Every one runs against
// a real datastore on both engines.

func identitySvc(db *store.DB) *service.Identities {
	return &service.Identities{DB: db, Auth: authWithWindow(db)}
}

// authWithWindow is an Auth whose instance reauthentication window is a real
// duration. The zero value means "no window at all", under which every
// sliding window fails closed — correct in production, and not the state the
// positive paths here are about.
func authWithWindow(db *store.DB) *service.Auth {
	return &service.Auth{DB: db, ReauthWindow: 5 * time.Minute, ReauthHardCap: time.Hour}
}

// grantSvcWithAuth is grantSvc plus the reauthentication seam a MACHINE
// widening consumes. The plain grantSvc deliberately has none, which is
// itself worth keeping: an ordinary human grant has never required
// reauthentication and must not start.
func grantSvcWithAuth(db *store.DB) *service.Grants {
	return &service.Grants{DB: db, Auth: authWithWindow(db)}
}

// identityFixtures seeds the two administrators the ADR's authorization table
// distinguishes, and nothing else:
//
//	usr_ident   manage-identities(prj_a1), and DELIBERATELY NO disclosure
//	            capability — the "manage identities without reveal" fixture
//	            the acceptance criteria name.
//	usr_idrev   the same, plus reveal(env_a1) and reveal-history(env_a1), so
//	            the refusals below are the rule firing rather than the whole
//	            surface being closed.
func identityFixtures(t *testing.T, db *store.DB) {
	t.Helper()
	for _, stmt := range []string{
		`INSERT INTO principals (id, kind, created_at) VALUES ('usr_ident', 'human', ` + ts + `)`,
		`INSERT INTO principals (id, kind, created_at) VALUES ('usr_idrev', 'human', ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_id_mi', 'usr_ident', 'manage-identities', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_idr_mi', 'usr_idrev', 'manage-identities', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_idr_rv', 'usr_idrev', 'reveal', 'org_a', 'prj_a1', 'env_a1', ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_idr_rh', 'usr_idrev', 'reveal-history', 'org_a', 'prj_a1', 'env_a1', ` + ts + `)`,
		// Both also manage members and hold `read` in the project, because a
		// GRANT is authorized by the grant route's own formula first: without
		// manage-members they never reach the widening gate, and a
		// project-scope member manager may grant only what it already holds.
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_id_mm', 'usr_ident', 'manage-members', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_id_rd', 'usr_ident', 'read', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		// A second, SEPARATE project grant, so the per-project-uniqueness probe
		// addresses a project this actor genuinely administers. It is granted
		// per project rather than at org scope on purpose: manage-identities is
		// a project capability, and an org-scope shortcut here would quietly
		// widen every other probe in this file.
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_id_mi2', 'usr_ident', 'manage-identities', 'org_a', 'prj_a2', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_idr_mm', 'usr_idrev', 'manage-members', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_idr_rd', 'usr_idrev', 'read', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_idr_rvp', 'usr_idrev', 'reveal', 'org_a', 'prj_a1', 'env_prod', ` + ts + `)`,
		// usr_rvonly holds `reveal` and NOT `reveal-history`: the fixture that
		// makes the per-class split observable rather than asserted.
		`INSERT INTO principals (id, kind, created_at) VALUES ('usr_rvonly', 'human', ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_rv_mi', 'usr_rvonly', 'manage-identities', 'org_a', 'prj_a1', NULL, ` + ts + `)`,
		`INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('g_rv_rv', 'usr_rvonly', 'reveal', 'org_a', 'prj_a1', 'env_a1', ` + ts + `)`,
	} {
		execRaw(t, db, stmt)
	}
	seedOrigins(t, db)
}

const (
	identAdmin  = domain.PrincipalID("usr_ident")
	identRevatr = domain.PrincipalID("usr_idrev")
	revealOnly  = domain.PrincipalID("usr_rvonly")
)

// seedMachineReveal writes a disclosure grant straight to the table.
//
// It has to bypass the grant API, and the reason is a real collision worth
// stating rather than hiding: the permission model's machine allowlists
// (#55, domain/permission.go) refuse `reveal` and `reveal-history` to a
// machine principal BY NAME until the source-of-truth ADR's per-project
// machine-reveal opt-in ships (#17/#58). So no API path can currently produce
// a reveal-reaching service account — and the ADR's mint and widen formulas
// are written against exactly that state.
//
// Rather than widen the allowlist (which would hand every automation
// credential a standing decryption capability, the thing the ADR insists must
// be a deliberate per-project act), the fixture seeds the row directly. The
// gates under test read the grant table, so they see the same state the
// opt-in will eventually produce through the API.
// seedMachineReveal writes a disclosure grant onto a machine principal by raw
// SQL AND turns the project's machine-reveal opt-in on: a machine `reveal`
// exists only under that opt-in (source-of-truth ADR), and the delivery path
// reads it live, so a fixture that seeded the grant alone would be seeding a
// state the product cannot reach.
func seedMachineReveal(t *testing.T, db *store.DB, id string, p domain.PrincipalID, cap domain.Capability, env domain.EnvID) {
	t.Helper()
	execRaw(t, db, `UPDATE projects SET machine_reveal = TRUE WHERE id = 'prj_a1'`)
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) VALUES ('`+
		id+`', '`+string(p)+`', '`+string(cap)+`', 'org_a', 'prj_a1', '`+string(env)+`', `+ts+`)`)
	seedOrigins(t, db)
}

func TestMachineIdentityLifecycleSQLite(t *testing.T) {
	runMachineIdentityLifecycle(t, seededDB(t, openSQLite))
}
func TestMachineIdentityLifecyclePostgres(t *testing.T) {
	runMachineIdentityLifecycle(t, seededDB(t, openPostgres))
}

// runMachineIdentityLifecycle is the mint / rotate / revoke arc, plus the
// display-once rule and the chokepoint resolution that makes revocation bite.
func runMachineIdentityLifecycle(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	actor := service.LocalPrincipal(identAdmin)

	sa, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "deployer", domain.ClassWorkload)
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	if sa.Kind != domain.ClassWorkload {
		t.Fatalf("kind %q, want workload", sa.Kind)
	}

	// MINT. The service account holds no grants, so its post-state reaches no
	// plaintext and the disclosure conjunct is vacuous — which is exactly why
	// a read-only workload credential is mintable by a project administrator
	// who holds no `reveal` at all.
	first, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := crypto.ParseArtifact(first.Value, crypto.ArtifactWorkload); err != nil {
		t.Fatalf("a workload credential must carry the `wl` grammar: %q -> %v", first.Value, err)
	}
	if first.Credential.Lifetime != domain.LifetimeFinite || first.Credential.ExpiresAt.IsZero() {
		t.Fatalf("the per-credential default must be FINITE, got %+v", first.Credential)
	}

	// DISPLAY-ONCE. Nothing in the system returns the value again: the
	// listing surface has no field for it, and the prefix hint is a hint.
	creds, err := svc.ListCredentials(ctx, actor, prjScope(), sa.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("want 1 credential, got %d", len(creds))
	}
	if !strings.HasPrefix(first.Value, creds[0].PrefixHint) {
		t.Fatalf("prefix hint %q is not a prefix of the minted value", creds[0].PrefixHint)
	}
	if len(creds[0].PrefixHint) >= len(first.Value) {
		t.Fatalf("the prefix hint is the whole value — display-once is defeated")
	}

	// The credential authenticates at the SAME chokepoint as a session, and
	// resolves to the service account's principal with its class attached.
	if id := authenticate(t, db, first.Value); id.Principal != sa.Principal || id.Class != domain.ClassWorkload {
		t.Fatalf("machine identity resolved to %+v, want principal %s class workload", id, sa.Principal)
	}

	// ROTATE — overlap-based, per the ADR: mint the second, then revoke the
	// first. Both are live in between, which is the point.
	second, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint replacement: %v", err)
	}
	if second.Value == first.Value {
		t.Fatal("two mints produced the same value")
	}
	if authenticate(t, db, first.Value).Principal == "" || authenticate(t, db, second.Value).Principal == "" {
		t.Fatal("overlap rotation requires both credentials live between mint and revoke")
	}

	// REVOKE. It bites at the next request, because the liveness predicate is
	// read in the authenticating transaction rather than cached anywhere.
	if err := svc.RevokeCredential(ctx, actor, prjScope(), sa.ID, first.Credential.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if id := authenticate(t, db, first.Value); id.Principal != "" {
		t.Fatal("a revoked credential still authenticated")
	}
	// Revoking one credential is NOT deprovisioning: the sibling keeps
	// working and the grants are untouched.
	if id := authenticate(t, db, second.Value); id.Principal != sa.Principal {
		t.Fatal("revoking one credential killed its sibling")
	}

	// An unknown credential and a revoked one are indistinguishable.
	bogus, _, err := crypto.NewArtifact(crypto.ArtifactWorkload)
	if err != nil {
		t.Fatal(err)
	}
	if id := authenticate(t, db, bogus); id.Principal != "" {
		t.Fatal("an unminted value authenticated")
	}

	// A machine credential is refused by the HUMAN session mechanism, which
	// is what keeps logout, factor enrolment, passkeys and identity linking
	// unreachable with a token: every one of them assumes a session row to
	// mutate, and a machine has none.
	if err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		if _, err := az.Authenticate(ctx, second.Value, time.Now().UTC()); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Fatalf("the human session mechanism accepted a machine credential: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	execRaw(t, db, "INSERT INTO pin_generations (principal_id, environment_id, generation) VALUES ('"+
		string(sa.Principal)+"', 'env_a1', 2)")

	// DELETE revokes every credential and releases every grant in one
	// transaction.
	if err := svc.DeleteServiceAccount(ctx, actor, prjScope(), sa.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if id := authenticate(t, db, second.Value); id.Principal != "" {
		t.Fatal("a deleted service account's credential still authenticated")
	}
	if got := queryInt(t, db, "SELECT COUNT(*) FROM pin_generations WHERE principal_id = '"+string(sa.Principal)+"'"); got != 0 {
		t.Fatalf("workload delete retained %d pin-generation rows", got)
	}
}

func TestMachineCredentialEpochSQLite(t *testing.T) {
	runMachineCredentialEpoch(t, seededDB(t, openSQLite))
}
func TestMachineCredentialEpochPostgres(t *testing.T) {
	runMachineCredentialEpoch(t, seededDB(t, openPostgres))
}

// runMachineCredentialEpoch is the restore mechanism, propagated onto
// machines: a credential carries the epoch it was minted under, and an epoch
// bump makes every one of them inert. Re-activating a restored bearer
// verifier is never offered, so this is the whole of the story.
func runMachineCredentialEpoch(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	actor := service.LocalPrincipal(identAdmin)

	sa, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "epoch-probe", domain.ClassAutomation)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.ParseArtifact(minted.Value, crypto.ArtifactAutomation); err != nil {
		t.Fatalf("an automation credential must carry the `au` grammar: %v", err)
	}
	if id := authenticate(t, db, minted.Value); id.Principal != sa.Principal {
		t.Fatal("a fresh credential must authenticate")
	}
	execRaw(t, db, `UPDATE auth_instance_state SET credential_epoch = credential_epoch + 1 WHERE id = 1`)
	if id := authenticate(t, db, minted.Value); id.Principal != "" {
		t.Fatal("an epoch-superseded machine credential must be inert")
	}
}

func TestMachineLifetimeControlsSQLite(t *testing.T) {
	runMachineLifetimeControls(t, seededDB(t, openSQLite))
}
func TestMachineLifetimeControlsPostgres(t *testing.T) {
	runMachineLifetimeControls(t, seededDB(t, openPostgres))
}

// runMachineLifetimeControls exercises both instance controls and the
// property that keeps them SEPARATE: raising the ceiling can never
// manufacture an indefinite credential.
func runMachineLifetimeControls(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	actor := service.LocalPrincipal(identAdmin)
	operator := service.LocalPrincipal(root)

	sa, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "lifetimes", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}

	policy, err := svc.Policy(ctx, operator)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if policy.AllowIndefinite {
		t.Fatal("allow_indefinite must ship OFF")
	}

	// The ceiling CLAMPS an over-long request rather than refusing it, and
	// says so, so the operator does not discover it when the credential dies
	// early.
	over, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID,
		service.MintRequest{Lifetime: policy.MaxFiniteLifetime + 30*24*time.Hour})
	if err != nil {
		t.Fatalf("mint over the ceiling: %v", err)
	}
	if !over.Clamped {
		t.Fatal("a request past the ceiling must report that it was clamped")
	}
	if over.Credential.ExpiresAt.After(time.Now().UTC().Add(policy.MaxFiniteLifetime + time.Minute)) {
		t.Fatalf("the clamp did not bind: expires %s", over.Credential.ExpiresAt)
	}

	// `indefinite` is a VALUE. It is refused by its OWN opt-in, and no
	// ceiling however large produces it.
	if _, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID,
		service.MintRequest{Indefinite: true}); !errors.Is(err, service.ErrIndefiniteNotAllowed) {
		t.Fatalf("indefinite mint: got %v, want ErrIndefiniteNotAllowed", err)
	}
	if _, err := svc.SetPolicy(ctx, operator, service.PolicyChange{
		MaxFiniteLifetime: 100 * 365 * 24 * time.Hour, AllowIndefinite: false,
		MaxLiveCredentials: policy.MaxLiveCredentials,
	}); err != nil {
		t.Fatalf("raise the ceiling: %v", err)
	}
	if _, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID,
		service.MintRequest{Indefinite: true}); !errors.Is(err, service.ErrIndefiniteNotAllowed) {
		t.Fatal("raising the ceiling manufactured an indefinite credential — the two controls are not separate")
	}

	// With the opt-in on, an indefinite credential is a typed choice.
	if _, err := svc.SetPolicy(ctx, operator, service.PolicyChange{
		MaxFiniteLifetime: 100 * 365 * 24 * time.Hour, AllowIndefinite: true,
		MaxLiveCredentials: policy.MaxLiveCredentials,
	}); err != nil {
		t.Fatalf("enable indefinite: %v", err)
	}
	forever, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{Indefinite: true})
	if err != nil {
		t.Fatalf("indefinite mint under the opt-in: %v", err)
	}
	if forever.Credential.Lifetime != domain.LifetimeIndefinite || !forever.Credential.ExpiresAt.IsZero() {
		t.Fatalf("indefinite must be typed, not a distant instant: %+v", forever.Credential)
	}

	// TIGHTENING enumerates every affected credential to the actor BEFORE it
	// commits, and refuses until acknowledged — a settings change never
	// silently kills a live credential.
	res, err := svc.SetPolicy(ctx, operator, service.PolicyChange{
		MaxFiniteLifetime: time.Hour, AllowIndefinite: false,
		MaxLiveCredentials: policy.MaxLiveCredentials,
	})
	if err != nil {
		t.Fatalf("the preview must answer with the enumeration, not an error: %v", err)
	}
	if res.Applied {
		t.Fatal("an unconfirmed tightening must write nothing")
	}
	if len(res.Affected) == 0 {
		t.Fatal("the preview must carry the enumeration it is previewing")
	}
	if res.Policy.MaxFiniteLifetime != policy.MaxFiniteLifetime && res.Policy.MaxFiniteLifetime == time.Hour {
		t.Fatal("the preview reported the proposed policy as if it were current")
	}
	var sawClamp, sawIndefinite bool
	for _, a := range res.Affected {
		switch a.Reason {
		case service.ReasonClamped:
			sawClamp = true
		case service.ReasonIndefiniteWithdrawn:
			sawIndefinite = true
		}
	}
	if !sawClamp || !sawIndefinite {
		t.Fatalf("both consequences must be enumerated separately: %+v", res.Affected)
	}

	confirmed, err := svc.SetPolicy(ctx, operator, service.PolicyChange{
		MaxFiniteLifetime: time.Hour, AllowIndefinite: false,
		MaxLiveCredentials: policy.MaxLiveCredentials, Confirm: true,
	})
	if err != nil {
		t.Fatalf("confirmed tightening: %v", err)
	}
	if !confirmed.Applied {
		t.Fatal("a confirmed tightening must apply")
	}
	if confirmed.Clamped == 0 {
		t.Fatal("the confirmed tightening clamped nothing")
	}
	after, err := svc.ListCredentials(ctx, actor, prjScope(), sa.ID)
	if err != nil {
		t.Fatal(err)
	}
	ceiling := time.Now().UTC().Add(time.Hour + time.Minute)
	for _, c := range after {
		if c.Lifetime == domain.LifetimeFinite && c.ExpiresAt.After(ceiling) {
			t.Fatalf("credential %s survived the clamp: expires %s", c.ID, c.ExpiresAt)
		}
		// Withdrawing the opt-in CLAMPS the credentials it withdraws: an
		// unbounded credential surviving the withdrawal would be the control
		// not being withdrawn.
		if c.ID == forever.Credential.ID {
			if c.Lifetime != domain.LifetimeFinite {
				t.Fatal("withdrawing the opt-in left an unbounded credential live")
			}
			// Clamped to the new ceiling, not revoked: the fleet gets the same
			// window to rotate that every other tightening gives it.
			if c.ExpiresAt.IsZero() || c.ExpiresAt.After(ceiling) || !c.ExpiresAt.After(time.Now().UTC()) {
				t.Fatalf("the withdrawn credential must be clamped to the ceiling, not killed: %s", c.ExpiresAt)
			}
		}
	}
}

func TestMachineCredentialCapSQLite(t *testing.T) {
	runMachineCredentialCap(t, seededDB(t, openSQLite))
}
func TestMachineCredentialCapPostgres(t *testing.T) {
	runMachineCredentialCap(t, seededDB(t, openPostgres))
}

// runMachineCredentialCap: overlap rotation needs room, a mint loop does not.
func runMachineCredentialCap(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	actor := service.LocalPrincipal(identAdmin)
	operator := service.LocalPrincipal(root)

	if _, err := svc.SetPolicy(ctx, operator, service.PolicyChange{
		MaxFiniteLifetime: 30 * 24 * time.Hour, AllowIndefinite: false, MaxLiveCredentials: 2,
	}); err != nil {
		t.Fatal(err)
	}
	sa, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "capped", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	var minted []service.MintResult
	for range 2 {
		m, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{})
		if err != nil {
			t.Fatalf("mint under the cap: %v", err)
		}
		minted = append(minted, m)
	}
	if _, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{}); !errors.Is(err, service.ErrCredentialCap) {
		t.Fatalf("mint past the cap: got %v, want ErrCredentialCap", err)
	}
	// Revoking one makes room — the cap counts LIVE credentials, so an
	// overlap rotation is never blocked by the credentials it retired.
	if err := svc.RevokeCredential(ctx, actor, prjScope(), sa.ID, minted[0].Credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{}); err != nil {
		t.Fatalf("mint after making room: %v", err)
	}
}

func TestMintDisclosureGateSQLite(t *testing.T) {
	runMintDisclosureGate(t, seededDB(t, openSQLite))
}
func TestMintDisclosureGatePostgres(t *testing.T) {
	runMintDisclosureGate(t, seededDB(t, openPostgres))
}

// runMintDisclosureGate is the acceptance criteria's "manage identities
// without reveal" fixture, and the reason the ADR amended #15's formula.
//
// A principal holding `manage-identities` and no `reveal` must be refused a
// mint over a reveal-reaching POST-STATE — including a replacement, which
// adds no environment at all. Under the superseded "every ADDED environment"
// reading they would rotate a production workload credential and walk away
// with a live production-reading bearer token: obtaining by rotation exactly
// what the permission model forbids them to obtain by minting.
func runMintDisclosureGate(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)

	sa, err := svc.CreateServiceAccount(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), "prod-reader", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	// The first mint succeeds: the account reaches nothing yet.
	if _, err := svc.MintCredential(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{}); err != nil {
		t.Fatalf("mint over an empty post-state must succeed: %v", err)
	}

	// Now the account reaches current plaintext in env_a1.
	seedMachineReveal(t, db, "g_sa_read", sa.Principal, domain.CapRead, envA1)
	seedMachineReveal(t, db, "g_sa_rv", sa.Principal, domain.CapReveal, envA1)

	// The REPLACEMENT adds no environment, and is refused anyway.
	_, err = svc.MintCredential(ctx, service.LocalPrincipal(identAdmin), prjScope(), sa.ID, service.MintRequest{})
	if !errors.Is(err, service.ErrDisclosureAuthority) {
		t.Fatalf("mint over a reveal-reaching post-state without reveal: got %v, want ErrDisclosureAuthority", err)
	}

	// The holder of `reveal` clears the disclosure conjunct and is then
	// stopped by the REAUTHENTICATION conjunct — which proves the second
	// conjunct is real rather than implied by the first. A local-authority
	// actor carries no session and therefore no window, which is the
	// fail-closed direction.
	_, err = svc.MintCredential(ctx, service.LocalPrincipal(identRevatr), prjScope(), sa.ID, service.MintRequest{})
	if !errors.Is(err, service.ErrReauthRequired) {
		t.Fatalf("mint with reveal but no reauthentication: got %v, want ErrReauthRequired", err)
	}

	// THE PER-CLASS SPLIT, and it is the ADR's named bypass. Give the account
	// read + reveal-history and NOT reveal, so only HISTORICAL plaintext is
	// reachable. An actor holding `reveal` there — but no `reveal-history` —
	// must still be refused: a single "can reach plaintext" boolean would see
	// their reveal grant, find the requirement satisfied, and hand a machine
	// principal the power to read superseded secrets that may still be live
	// in an external service. The permission model fixed the rule this
	// violates: reveal-history implies nothing about reveal, and vice versa.
	histSA, err := svc.CreateServiceAccount(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), "historian", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	seedMachineReveal(t, db, "g_h_read", histSA.Principal, domain.CapRead, envA1)
	seedMachineReveal(t, db, "g_h_rh", histSA.Principal, domain.CapRevealHistory, envA1)
	_, err = svc.MintCredential(ctx, service.LocalPrincipal(revealOnly), prjScope(), histSA.ID, service.MintRequest{})
	if !errors.Is(err, service.ErrDisclosureAuthority) {
		t.Fatalf("a historical-reaching post-state must not be cleared by `reveal`: got %v, want ErrDisclosureAuthority", err)
	}
	if !strings.Contains(err.Error(), string(domain.CapRevealHistory)) {
		t.Fatalf("the refusal must name reveal-history, not reveal: %v", err)
	}
	// The holder of reveal-history clears the disclosure conjunct there and
	// is stopped only by reauthentication — the positive control that makes
	// the refusal above the split firing rather than the surface being shut.
	_, err = svc.MintCredential(ctx, service.LocalPrincipal(identRevatr), prjScope(), histSA.ID, service.MintRequest{})
	if !errors.Is(err, service.ErrReauthRequired) {
		t.Fatalf("reveal-history must clear the historical conjunct: got %v, want ErrReauthRequired", err)
	}

	// THE POSITIVE CONTROL for the whole mint row: the same actor, over the
	// same reveal-reaching post-state, succeeds once it presents a session
	// carrying a live reauthentication window. Without this the refusals
	// above would be indistinguishable from a surface that is simply shut.
	minter := sessionWithWindows(t, db, identRevatr, envA1)
	full, err := svc.MintCredential(ctx, service.Bearer(minter), prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint with the full formula satisfied: %v", err)
	}
	if full.Value == "" {
		t.Fatal("a successful mint must return the value exactly once")
	}
	// The credential it produced authenticates, so the gate admitted a real
	// mint rather than a hollow one.
	if id := authenticate(t, db, full.Value); id.Principal != sa.Principal {
		t.Fatal("the minted credential does not authenticate")
	}

	// A NARROWING is never a widening: revoke and delete stay under the plain
	// capability, so incident response is not gated on disclosure rights.
	creds, err := svc.ListCredentials(ctx, service.LocalPrincipal(identAdmin), prjScope(), sa.ID)
	if err != nil {
		t.Fatalf("listing must stay under the plain capability: %v", err)
	}
	if err := svc.RevokeCredential(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, creds[0].ID); err != nil {
		t.Fatalf("revoking must stay under the plain capability: %v", err)
	}
	if err := svc.DeleteServiceAccount(ctx, service.LocalPrincipal(identAdmin), prjScope(), sa.ID); err != nil {
		t.Fatalf("deleting must stay under the plain capability: %v", err)
	}
}

func TestMachineGrantWideningSQLite(t *testing.T) {
	runMachineGrantWidening(t, seededDB(t, openSQLite))
}
func TestMachineGrantWideningPostgres(t *testing.T) {
	runMachineGrantWidening(t, seededDB(t, openPostgres))
}

// runMachineGrantWidening is the ADR's third authorization row — the one an
// implementer misses — and its per-class split, which is the named bypass.
func runMachineGrantWidening(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	g := grantSvcWithAuth(db)
	svc := identitySvc(db)

	sa, err := svc.CreateServiceAccount(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), "widener", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}

	// The account already carries the disclosure opt-in but cannot read
	// anything, so it reaches no plaintext.
	seedMachineReveal(t, db, "g_wd_rv", sa.Principal, domain.CapReveal, envA1)

	// Adding `read(env_a1)` makes CURRENT plaintext newly reachable. It is
	// refused for an actor with no `reveal` there, even though the ordinary
	// grant authorization would have allowed it (root grants at instance
	// scope and may grant what it does not hold). Stricter wins.
	_, err = g.Create(ctx, service.LocalPrincipal(identAdmin), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envA1),
	})
	if !errors.Is(err, service.ErrDisclosureAuthority) {
		t.Fatalf("widening to current plaintext without reveal: got %v, want ErrDisclosureAuthority", err)
	}
	if !strings.Contains(err.Error(), string(domain.CapReveal)) {
		t.Fatalf("the refusal must name the disclosure capability it wanted: %v", err)
	}
	if held(t, db, sa.Principal, domain.CapRead, envScope(envA1)) {
		t.Fatal("the refused widening wrote its grant anyway — the gate must run before the write")
	}

	// A DEVELOPMENT-only grant on an account that reaches nothing new is not
	// a widening, so it stays under the plain grant authorization. This is
	// what keeps the delta rule from being self-defeating: a delegated
	// administrator who deliberately holds no production `reveal` must still
	// be able to grant elsewhere.
	if _, err := g.Create(ctx, service.LocalPrincipal(identAdmin), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envProd),
	}); err != nil {
		t.Fatalf("a grant reaching no new plaintext must not be gated: %v", err)
	}

	// An ORG member manager who does not administer THIS project's identities
	// cannot re-scope its credentials by granting either: the widening row
	// carries manage-identities(project), and where the grant route's own
	// formula disagrees the stricter refuses. orgAdmin may grant capabilities
	// it does not hold — that is the escalation path the threat model accepts
	// for org-scope manage-members — and it is still refused here.
	_, err = g.Create(ctx, service.LocalPrincipal(orgAdmin), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envA1),
	})
	if !errors.Is(err, service.ErrDisclosureAuthority) {
		t.Fatalf("an org member manager without manage-identities: got %v, want ErrDisclosureAuthority", err)
	}
	if !strings.Contains(err.Error(), string(domain.CapManageIdentities)) {
		t.Fatalf("the refusal must name manage-identities: %v", err)
	}

	// The per-class split is exercised through the MINT gate rather than
	// here, and the reason is worth recording: #55's machine allowlist
	// refuses `reveal-history` to a workload principal BY NAME before this
	// gate runs, so the grant API cannot currently reach the historical case
	// at all. Both gates call the same Auth.RequireDisclosureAuthority, so
	// the split is proven once — see runMintDisclosureGate.

	// NARROWING is never a widening: the revoke needs no disclosure right.
	if err := g.Revoke(ctx, service.LocalPrincipal(identAdmin), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envProd),
	}); err != nil {
		t.Fatalf("revoking a machine grant must stay under the plain capability: %v", err)
	}
}

func TestMachineAuthIsUniformSQLite(t *testing.T) {
	runMachineAuthIsUniform(t, seededDB(t, openSQLite))
}
func TestMachineAuthIsUniformPostgres(t *testing.T) {
	runMachineAuthIsUniform(t, seededDB(t, openPostgres))
}

// runMachineAuthIsUniform is the tenant-isolation propagation's timing half:
// "MUST keep unknown and revoked credentials indistinguishable in responses
// AND TIMING".
//
// Timing itself is not assertable — a wall-clock test would be flaky and would
// measure the machine rather than the code. What IS assertable, and what a
// future edit is overwhelmingly likely to break, is the READ COUNT: an early
// return on the first miss is the natural thing to write and it drops this
// from three reads to one.
//
// Scope stated precisely, because the two halves are not the same property
// and this test only holds one of them. It does NOT catch a missing decoy
// decode: the SQL statement runs on a miss either way, so removing the decoy
// leaves the count at three and this test green. That half is carried by
// construction — both outcomes funnel through the same two decode helpers in
// internal/store/authn/machine.go — and is a diff-review obligation, not a
// runtime one. Verified by deliberately breaking each half against this test
// while writing it.
func runMachineAuthIsUniform(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	actor := service.LocalPrincipal(identAdmin)

	sa, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "uniform", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	live, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeCredential(ctx, actor, prjScope(), sa.ID, revoked.Credential.ID); err != nil {
		t.Fatal(err)
	}
	// A well-formed value that was never minted: the unknown case, which must
	// not be cheaper than the revoked one.
	unknown, _, err := crypto.NewArtifact(crypto.ArtifactWorkload)
	if err != nil {
		t.Fatal(err)
	}

	liveN, liveID := countedMachineAuth(t, db, live.Value)
	if liveID.Principal != sa.Principal {
		t.Fatal("the live credential must authenticate")
	}
	for _, tc := range []struct {
		name      string
		presented string
	}{
		{"revoked", revoked.Value},
		{"unknown", unknown},
	} {
		n, id := countedMachineAuth(t, db, tc.presented)
		if id.Principal != "" {
			t.Fatalf("%s authenticated", tc.name)
		}
		if n != liveN {
			t.Fatalf("%s credential issued %d reads, a live one %d — the outcome is countable",
				tc.name, n, liveN)
		}
	}
}

func TestMachineSubtreeConfinementSQLite(t *testing.T) {
	runMachineSubtreeConfinement(t, seededDB(t, openSQLite))
}
func TestMachineSubtreeConfinementPostgres(t *testing.T) {
	runMachineSubtreeConfinement(t, seededDB(t, openPostgres))
}

// runMachineSubtreeConfinement: "its grants are confined to its owning
// project's subtree. A grant naming a scope outside that project is refused,
// regardless of the granter's authority."
//
// The FIRST grant is the case that matters and the one an inference cannot
// cover. A freshly created service account holds no grants, so deriving its
// owning project from what it already holds has nothing to say — and the
// escape is silent afterwards, because the mint gate's post-state enumeration
// ranges over the OWNING project's environments and never sees the foreign
// grant at all.
func runMachineSubtreeConfinement(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	g := grantSvcWithAuth(db)
	svc := identitySvc(db)

	sa, err := svc.CreateServiceAccount(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), "confined-from-birth", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}

	// A sibling project in the SAME org, granted by an instance-scope member
	// manager who may grant anything anywhere. Authority is not the question:
	// the grant names a scope outside the account's owning project.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead,
		Scope: domain.Scope{Org: orgA, Project: prjA2, Env: envA2},
	}); !errors.Is(err, service.ErrMachineProject) {
		t.Fatalf("first grant into a sibling project: got %v, want ErrMachineProject", err)
	}
	// And across an org boundary, which #23 calls an isolation failure rather
	// than an authorization result.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead,
		Scope: domain.Scope{Org: orgB, Project: prjB1, Env: envB1},
	}); !errors.Is(err, service.ErrMachineProject) {
		t.Fatalf("first grant across an org boundary: got %v, want ErrMachineProject", err)
	}
	if held(t, db, sa.Principal, domain.CapRead, domain.Scope{Org: orgB, Project: prjB1, Env: envB1}) {
		t.Fatal("a refused cross-org grant was written anyway")
	}

	// The positive control: inside the owning project it lands.
	if _, err := g.Create(ctx, service.LocalPrincipal(root), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envA1),
	}); err != nil {
		t.Fatalf("a grant inside the owning project must land: %v", err)
	}
}

func TestMachineIdentityIsolationSQLite(t *testing.T) {
	runMachineIdentityIsolation(t, seededDB(t, openSQLite))
}
func TestMachineIdentityIsolationPostgres(t *testing.T) {
	runMachineIdentityIsolation(t, seededDB(t, openPostgres))
}

// runMachineIdentityIsolation: a service-account id from another project is
// not addressable, and `kind` has no update path.
func runMachineIdentityIsolation(t *testing.T, db *store.DB) {
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	actor := service.LocalPrincipal(identAdmin)

	sa, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "confined", domain.ClassWorkload)
	if err != nil {
		t.Fatal(err)
	}
	// Addressed through prj_a2, whose chain the caller cannot authorize for:
	// the refusal is the uniform nonexistent outcome, not a different one.
	other := domain.Scope{Org: orgA, Project: prjA2}
	if _, err := svc.ListCredentials(ctx, actor, other, sa.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-project addressing: got %v, want ErrNotFound", err)
	}
	// Kind is immutable because nothing can write it: the surface has no
	// update verb at all, which is stronger than a refusal.
	if _, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "confined", domain.ClassAutomation); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("a duplicate name must be a conflict, not a fault: got %v", err)
	}
	// The same name in a SIBLING project is not a duplicate: the uniqueness is
	// per project, which is what makes a service account project-owned.
	sibling := domain.Scope{Org: orgA, Project: prjA2}
	if _, err := svc.CreateServiceAccount(ctx, actor, sibling, "confined", domain.ClassWorkload); err != nil {
		t.Fatalf("a name is unique per project, not per instance: %v", err)
	}
	if _, err := svc.CreateServiceAccount(ctx, actor, prjScope(), "bad-kind", domain.PrincipalClass("provisioning-connection")); !errors.Is(err, service.ErrServiceAccountKind) {
		t.Fatalf("a class outside the service-account set: got %v, want ErrServiceAccountKind", err)
	}

	// Two lifetimes named at once is a REFUSAL, never a precedence rule. The
	// CLI refuses it too; the API must not be the softer door.
	if _, err := svc.MintCredential(ctx, actor, prjScope(), sa.ID,
		service.MintRequest{Indefinite: true, Lifetime: time.Hour}); !errors.Is(err, service.ErrCredentialLifetime) {
		t.Fatalf("indefinite plus a finite lifetime: got %v, want ErrCredentialLifetime", err)
	}
}

// authenticate resolves a presented value through the real chokepoint, in a
// real transaction, exactly as any request would. It uses AuthenticateCaller
// because that is the entry point an operation uses; Authenticate is the
// human session mechanism and refuses a machine credential by design. An unauthenticated result
// is the zero Identity rather than an error, so a caller can assert on
// liveness without branching on which failure it was — which is also the
// property the surface guarantees to the network.
func authenticate(t *testing.T, db *store.DB, presented string) authz.Identity {
	t.Helper()
	var out authz.Identity
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		id, err := az.AuthenticateCaller(ctx, presented, time.Now().UTC())
		if errors.Is(err, domain.ErrUnauthenticated) {
			return nil
		}
		if err != nil {
			return err
		}
		out = id
		return nil
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return out
}

// sessionWithWindows mints a real CLI session for one principal and opens a
// live reauthentication window over each named environment.
//
// It exists because the ADR's mint and widen rows carry a reauthentication
// conjunct, and a LocalPrincipal actor has no session and therefore no window
// — the fail-closed direction, and the one the refusal tests above rely on.
// The POSITIVE paths need the other side, and they need it through the same
// machinery human disclosure consumes rather than a test-only bypass.
func sessionWithWindows(t *testing.T, db *store.DB, p domain.PrincipalID, envs ...domain.EnvID) string {
	t.Helper()
	token, verifier, err := crypto.NewArtifact(crypto.ArtifactCLISession)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		generation, err := az.PrincipalGeneration(ctx, p)
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		sessionID := "ses_" + string(p)
		if err := az.MintSession(ctx, authz.NewSession{
			ID: sessionID, PrincipalID: p, Verifier: verifier, Artifact: "cli",
			SessionGeneration: generation, CredentialEpoch: epoch,
			// Two distinct factor classes: the chokepoint's MFA-mandatory rule
			// is enforced, and `reveal` is one of the mandatory capabilities.
			AuthMethod: "local", Factors: `["password","totp"]`,
			AuthenticatedAt: now, CreatedAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
			SourceIP: "127.0.0.1", UserAgent: "test",
		}); err != nil {
			return err
		}
		for _, env := range envs {
			if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{
				ID: "raw_" + string(p) + "_" + string(env), SessionID: sessionID,
				EnvironmentID: string(env), CeremonyID: "cer_test", FactorClass: "totp",
				AuthenticatedAt: now, WindowExpiresAt: now.Add(time.Hour),
				HardExpiresAt: now.Add(2 * time.Hour), CredentialEpoch: epoch, CreatedAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed session and windows for %s: %v", p, err)
	}
	return token
}

// runIdentityLifecycle drives every identity.* event type through a real
// emitter, so the audit suite's "declaration without an emitter" check has
// something behind each registration. It is the machine-identity half of
// runGrantLifecycle.
func runIdentityLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	identityFixtures(t, db)
	ctx := t.Context()
	svc := identitySvc(db)
	g := grantSvcWithAuth(db)
	admin := service.LocalPrincipal(identAdmin)

	sa, err := svc.CreateServiceAccount(ctx, admin, prjScope(), "audited-sa", domain.ClassWorkload)
	if err != nil {
		t.Fatalf("identity.service_account_created: %v", err)
	}
	minted, err := svc.MintCredential(ctx, admin, prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("identity.credential_minted: %v", err)
	}

	// #113's named authentication refusal: drive a live machine credential
	// through a human-session-only contract row before revoking it. This is the
	// real admission emitter the audit registry's runtime-closure check needs.
	request := httptest.NewRequest(http.MethodGet,
		api.PathPrefix+"/orgs/"+string(orgA)+"/projects/"+string(prjA1)+
			"/environments/"+string(envA1), nil)
	admissionCtx, ok := api.WithRequestOperation(ctx, request)
	if !ok {
		t.Fatal("getEnvironment did not resolve through the embedded contract")
	}
	if _, err := (&service.Environments{DB: db}).Get(admissionCtx,
		service.Bearer(minted.Value), envScope(envA1)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("auth.artifact_class_refused: %v", err)
	}
	if _, err := svc.ListCredentials(ctx, admin, prjScope(), sa.ID); err != nil {
		t.Fatalf("identity.credentials_listed: %v", err)
	}
	if err := svc.RevokeCredential(ctx, admin, prjScope(), sa.ID, minted.Credential.ID); err != nil {
		t.Fatalf("identity.credential_revoked: %v", err)
	}

	// The WIDENING, driven all the way through: the actor holds
	// manage-identities and reveal there, and presents a session carrying a
	// live reauthentication window — the full formula satisfied rather than
	// bypassed, so the event records an authorization that really happened.
	//
	// It runs over env_prod rather than env_a1 because the audit suite marks
	// env_a1 PROTECTED, whose effective window is 0 — and at a 0 window the
	// only live reauthentication is a WebAuthn single-decision ceremony bound
	// to an enumerated unit, which a grant mutation is not. A widening on a
	// protected environment is therefore refused under a sliding window, and
	// that is the guard working rather than a gap.
	widener := sessionWithWindows(t, db, identRevatr, envProd)
	seedMachineReveal(t, db, "g_aud_rv", sa.Principal, domain.CapReveal, envProd)
	if _, err := g.Create(ctx, service.Bearer(widener), service.GrantSpec{
		Target: sa.Principal, Capability: domain.CapRead, Scope: envScope(envProd),
	}); err != nil {
		t.Fatalf("identity.grant_widened: %v", err)
	}

	operator := service.LocalPrincipal(root)
	if _, err := svc.Policy(ctx, operator); err != nil {
		t.Fatalf("identity.lifetime_policy_read: %v", err)
	}
	if _, err := svc.SetPolicy(ctx, operator, service.PolicyChange{
		MaxFiniteLifetime: 60 * 24 * time.Hour, AllowIndefinite: false, MaxLiveCredentials: 5,
	}); err != nil {
		t.Fatalf("identity.lifetime_policy_changed: %v", err)
	}
	if err := svc.DeleteServiceAccount(ctx, admin, prjScope(), sa.ID); err != nil {
		t.Fatalf("identity.service_account_deleted: %v", err)
	}
}
