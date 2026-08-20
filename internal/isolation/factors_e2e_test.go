package isolation

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// The A1 factor slice end to end on a real datastore (#54, human-auth ADR §
// Factors, § Account-security mutations, § Recovery). These exercise the locked
// mechanisms the mvp-boundary A1 row names for the factor half: recovery
// single-use and its complete session-less flow, the account-security mutation
// that cannot self-authorize, and step-up elevation of an under-assured
// session.

// totpCode is the code an authenticator app would display for the seed carried
// in an otpauth URI at time at — the test playing the authenticator. Parameters
// match crypto/totp.go (30s period, 6 digits, SHA-1), so pquerna's default
// GenerateCode agrees with the server's ValidateTOTP.
func totpCode(t *testing.T, otpauthURI string, at time.Time) string {
	t.Helper()
	u, err := url.Parse(otpauthURI)
	if err != nil {
		t.Fatalf("otpauth uri %q: %v", otpauthURI, err)
	}
	code, err := totp.GenerateCode(u.Query().Get("secret"), at)
	if err != nil {
		t.Fatalf("computing a TOTP code: %v", err)
	}
	return code
}

// bootstrapFactorAdmin mints a first administrator and establishes its
// password, returning the acting service and the credential. One service (one
// root key) drives the whole flow so sealed material stays readable.
func bootstrapFactorAdmin(t *testing.T, db *store.DB) (*service.Auth, service.BootstrapResult, string) {
	t.Helper()
	auth := authService(t, db)
	boot, err := auth.BootstrapAdmin(t.Context(), "factor-admin", "Factor Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	const password = "correct horse battery staple factor"
	if err := auth.EstablishCredential(t.Context(), boot.Authority, password); err != nil {
		t.Fatal(err)
	}
	// See bootstrapWebAuthnAdmin: the reauth routes authorize the environment
	// under `read` before inspecting its policy, and bootstrap seeds no tenant
	// capability.
	grantRead(t, db, boot.PrincipalID)
	return auth, boot, password
}

// runFactorLifecycle drives every factor audit event once, so a suite sharing a
// datastore (audit_e2e's emitter check) finds each event actually reached a
// trail. It advances an injected clock across the confirm/step-up boundary so
// the step-up code is a later, unspent time step than the one confirmation
// consumed.
func runFactorLifecycle(t *testing.T, auth *service.Auth, ctx context.Context, username, password string) {
	t.Helper()
	orig := auth.Now
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	defer func() { auth.Now = orig }()

	login, err := auth.LocalLogin(ctx, username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// Recovery: regenerate a batch (password proof), then consume one code.
	codes, _, err := auth.GenerateRecoveryCodes(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	if _, err := auth.ConsumeRecoveryCode(ctx, username, codes[0]); err != nil {
		t.Fatalf("consume recovery code: %v", err)
	}
	// Consuming revoked every session; log in afresh to enrol.
	relog, err := auth.LocalLogin(ctx, username, password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("re-login after recovery: %v", err)
	}
	uri, err := auth.EnrolTOTPStart(ctx, relog.SessionToken, password)
	if err != nil {
		t.Fatalf("enrol start: %v", err)
	}
	// The confirming code must be a step strictly after enrolment's (single-use
	// floored at the creation step, finding B19), so advance a window first.
	clk = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(ctx, relog.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("enrol confirm: %v", err)
	}
	clk = base.Add(60 * time.Second)
	stepped, err := auth.StepUpTOTP(ctx, confirmed.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatalf("step-up: %v", err)
	}
	if _, err := auth.RemoveTOTP(ctx, stepped.SessionToken, password); err != nil {
		t.Fatalf("remove totp: %v", err)
	}
}

func TestRecoveryCompleteFlowSQLite(t *testing.T) { runRecoveryFlow(t, seededDB(t, openSQLite)) }

func TestRecoveryCompleteFlowPostgres(t *testing.T) { runRecoveryFlow(t, seededDB(t, openPostgres)) }

// runRecoveryFlow is the A1 recovery family: single-use, the complete
// session-less flow (code -> authority -> establish -> login), and the mid-reset
// invariant that the authority is not a session.
func runRecoveryFlow(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	ctx := t.Context()
	orgs := &service.Orgs{DB: db}

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	codes, _, err := auth.GenerateRecoveryCodes(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != service.RecoveryBatchSize {
		t.Fatalf("got %d recovery codes, want %d", len(codes), service.RecoveryBatchSize)
	}

	// Consume one code for a credential-establishment authority.
	rec, err := auth.ConsumeRecoveryCode(ctx, "factor-admin", codes[0])
	if err != nil {
		t.Fatalf("consuming a valid recovery code: %v", err)
	}
	if rec.Authority == "" {
		t.Fatal("recovery consumption returned no authority")
	}

	// The authority creates NO session: it does not resolve as one.
	if _, err := auth.Identity(ctx, rec.Authority); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("the recovery authority resolves as a session: %v", err)
	}
	// Mid-reset: an MFA-mandatory op attempted with the authority (which is not
	// a session) is refused — the authority carries no assurance and no session.
	if _, err := orgs.Create(ctx, service.Bearer(rec.Authority), "reveal-attempt", true, []byte(`{}`), nil); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("the recovery authority authorized an MFA-mandatory op: %v", err)
	}

	// Single-use: the same code cannot be consumed again.
	if _, err := auth.ConsumeRecoveryCode(ctx, "factor-admin", codes[0]); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("a recovery code was consumed twice: %v", err)
	}

	// Complete the flow: establish a new password with the authority, then log
	// in with it. The old password's sessions were revoked at consumption.
	const newPassword = "an entirely different passphrase now"
	if err := auth.EstablishCredential(ctx, rec.Authority, newPassword); err != nil {
		t.Fatalf("establishing a credential from the recovery authority: %v", err)
	}
	if _, err := auth.LocalLogin(ctx, "factor-admin", newPassword, service.ArtifactCLI); err != nil {
		t.Fatalf("login with the re-established password: %v", err)
	}
}

func TestAccountSecurityCannotSelfAuthorizeSQLite(t *testing.T) {
	runSelfAuthorize(t, seededDB(t, openSQLite))
}

func TestAccountSecurityCannotSelfAuthorizePostgres(t *testing.T) {
	runSelfAuthorize(t, seededDB(t, openPostgres))
}

// runSelfAuthorize asserts an account-security mutation cannot authorize itself:
// enrolling TOTP requires the PRE-EXISTING password, and the code of the factor
// being enrolled is not that proof.
func runSelfAuthorize(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	ctx := t.Context()

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}

	// A wrong password is refused: the pre-existing credential is the proof.
	if _, err := auth.EnrolTOTPStart(ctx, login.SessionToken, "not the password"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("enrolment start accepted a wrong password: %v", err)
	}

	// The correct password authorizes staging the seed.
	uri, err := auth.EnrolTOTPStart(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	// The new factor's own code cannot stand in for the account-security proof:
	// the proof is evaluated over credentials that predate the mutation.
	if _, err := auth.EnrolTOTPStart(ctx, login.SessionToken, totpCode(t, uri, base)); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("enrolment start accepted the new factor's own code as proof: %v", err)
	}

	clk = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(ctx, login.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatal(err)
	}
	// The reissued session carries ONLY the proof class — password, not totp:
	// confirming an enrolment is not presenting the factor.
	if len(confirmed.Assurance.Factors) != 1 || confirmed.Assurance.Factors[0] != "password" {
		t.Fatalf("the reissued session carries %v, want exactly [password] — enrolment must not self-elevate", confirmed.Assurance.Factors)
	}
}

func TestStepUpElevatesSQLite(t *testing.T) { runStepUpElevates(t, seededDB(t, openSQLite)) }

func TestStepUpElevatesPostgres(t *testing.T) { runStepUpElevates(t, seededDB(t, openPostgres)) }

// runStepUpElevates asserts a password-only session is refused an MFA-mandatory
// operation and that a TOTP step-up unlocks it.
func runStepUpElevates(t *testing.T, db *store.DB) {
	auth, _, password := bootstrapFactorAdmin(t, db)
	base := time.Now().UTC()
	clk := base
	auth.Now = func() time.Time { return clk }
	ctx := t.Context()
	orgs := &service.Orgs{DB: db}

	login, err := auth.LocalLogin(ctx, "factor-admin", password, service.ArtifactCLI)
	if err != nil {
		t.Fatal(err)
	}
	// The admin HOLDS instance-config, but a password-only session is short of
	// the MFA-mandatory rule: refused for want of assurance, not of the grant.
	if _, err := orgs.Create(ctx, service.Bearer(login.SessionToken), "too-weak", true, []byte(`{}`), nil); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("a password-only session created an org: %v", err)
	}

	uri, err := auth.EnrolTOTPStart(ctx, login.SessionToken, password)
	if err != nil {
		t.Fatal(err)
	}
	clk = base.Add(30 * time.Second)
	confirmed, err := auth.EnrolTOTPConfirm(ctx, login.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatal(err)
	}
	clk = base.Add(60 * time.Second)
	stepped, err := auth.StepUpTOTP(ctx, confirmed.SessionToken, totpCode(t, uri, clk))
	if err != nil {
		t.Fatal(err)
	}
	if !hasFactor(stepped.Assurance.Factors, "totp") || !hasFactor(stepped.Assurance.Factors, "password") {
		t.Fatalf("stepped-up session carries %v, want both password and totp", stepped.Assurance.Factors)
	}
	// The elevated session now satisfies the MFA-mandatory rule.
	if _, err := orgs.Create(ctx, service.Bearer(stepped.SessionToken), "now-elevated", true, []byte(`{}`), nil); err != nil {
		t.Fatalf("a two-factor session was still refused: %v", err)
	}
}

func hasFactor(factors []string, want string) bool {
	for _, f := range factors {
		if f == want {
			return true
		}
	}
	return false
}
