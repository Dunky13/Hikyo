package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/migrate"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

func TestSessionCompletionRejectsInvalidVariantFields(t *testing.T) {
	svc := &Auth{}
	now := time.Date(2026, time.August, 22, 7, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		completion SessionCompletion
	}{
		{name: "missing variant"},
		{
			name: "browser without CSRF decision",
			completion: CreateSession{
				artifact: ArtifactBrowser, csrf: sessionWithoutCSRF,
			},
		},
		{
			name: "CLI with browser CSRF decision",
			completion: CreateSession{
				artifact: ArtifactCLI, csrf: sessionWithCSRF,
			},
		},
		{
			name:       "rotation without live session",
			completion: RotateSession{},
		},
		{
			name: "rotation for another account",
			completion: RotateSession{
				session: authz.Identity{
					SessionID: "ses_one", Artifact: ArtifactBrowser.String(),
					Principal: domain.PrincipalID("hum_one"),
				},
				account: authz.Account{PrincipalID: domain.PrincipalID("hum_two")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.completeSession(t.Context(), nil, tt.completion, now)
			if !errors.Is(err, domain.ErrInvalid) {
				t.Fatalf("error = %v, want domain.ErrInvalid", err)
			}
		})
	}
}

func TestSessionCompletionCreatesFactorParity(t *testing.T) {
	db, account := sessionCompletionFixture(t)
	now := time.Date(2026, time.August, 22, 8, 0, 0, 0, time.UTC)
	svc := &Auth{}

	tests := []struct {
		name       string
		artifact   Artifact
		csrf       sessionCSRF
		assurance  Assurance
		providerID string
		wantCSRF   bool
	}{
		{
			name: "password CLI", artifact: ArtifactCLI, csrf: sessionWithoutCSRF,
			assurance: Assurance{Method: MethodLocalPassword, Factors: []string{"password"}, AuthenticatedAt: now},
		},
		{
			name: "OIDC browser", artifact: ArtifactBrowser, csrf: sessionWithCSRF,
			assurance: Assurance{Method: "oidc:https://idp.example", Factors: []string{"oidc", "mfa"}, AuthenticatedAt: now},
			wantCSRF:  true,
		},
		{
			name: "SAML browser", artifact: ArtifactBrowser, csrf: sessionWithCSRF,
			assurance: Assurance{Method: "saml:https://idp.example", Factors: []string{"saml", "mfa"}, AuthenticatedAt: now, CeremonyID: "smt_one"},
			wantCSRF:  true,
		},
		{
			name: "passkey browser", artifact: ArtifactBrowser, csrf: sessionWithCSRF,
			assurance: Assurance{Method: MethodLocalPasskey, Factors: []string{"webauthn"}, AuthenticatedAt: now, CeremonyID: "wac_one"},
			wantCSRF:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tx.WriteResult(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) (LoginResult, error) {
				return svc.completeSession(ctx, az, CreateSession{
					account: account, artifact: tt.artifact, assurance: tt.assurance,
					csrf: tt.csrf, providerID: tt.providerID,
				}, now)
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.SessionToken == "" || result.SessionID == "" {
				t.Fatal("completion must return the display-once token and session id")
			}
			if (result.CSRFToken != "") != tt.wantCSRF {
				t.Fatalf("CSRF token present = %v, want %v", result.CSRFToken != "", tt.wantCSRF)
			}
			if result.Artifact != tt.artifact || result.AccountID != account.ID || result.Principal != account.PrincipalID {
				t.Fatalf("projection = %#v", result)
			}
			if result.Assurance.Method != tt.assurance.Method || !equalStrings(result.Assurance.Factors, tt.assurance.Factors) || result.Assurance.CeremonyID != tt.assurance.CeremonyID {
				t.Fatalf("assurance = %#v, want %#v", result.Assurance, tt.assurance)
			}

			var live authz.Identity
			err = tx.Read(t.Context(), db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
				var err error
				live, err = az.Authenticate(ctx, result.SessionToken, now)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if live.SessionID != result.SessionID || live.Assurance.Method != tt.assurance.Method || !equalStrings(live.Assurance.Factors, tt.assurance.Factors) {
				t.Fatalf("stored session = %#v", live)
			}
		})
	}
}

func TestSessionCompletionRotationPreservesProjectionAndReplacesFactors(t *testing.T) {
	db, account := sessionCompletionFixture(t)
	now := time.Date(2026, time.August, 22, 9, 0, 0, 0, time.UTC)
	svc := &Auth{}
	created := createCompletionSession(t, db, svc, account, now)

	rotated, err := tx.WriteResult(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) (LoginResult, error) {
		live, err := az.Authenticate(ctx, created.SessionToken, now)
		if err != nil {
			return LoginResult{}, err
		}
		return svc.completeSession(ctx, az, RotateSession{
			session: live, account: account, factors: []string{"password", "totp"},
		}, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.SessionID != created.SessionID || rotated.CreatedAt != created.CreatedAt || rotated.IdleExpires != created.IdleExpires || rotated.AbsExpires != created.AbsExpires {
		t.Fatalf("rotation changed stable projection: before=%#v after=%#v", created, rotated)
	}
	if rotated.CSRFToken != "" {
		t.Fatal("rotation must preserve the stored CSRF verifier without minting a new synchronizer token")
	}
	if !equalStrings(rotated.Assurance.Factors, []string{"password", "totp"}) {
		t.Fatalf("factors = %v", rotated.Assurance.Factors)
	}
	assertSessionTokenRejected(t, db, created.SessionToken, now)
	assertSessionTokenAccepted(t, db, rotated.SessionToken, rotated.SessionID, now)
}

func TestSessionCompletionPublishesOnlyCommittedAttemptTokens(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		db, account := sessionCompletionFixture(t)
		now := time.Date(2026, time.August, 22, 10, 0, 0, 0, time.UTC)
		svc := &Auth{}
		var attempts []string
		result, err := tx.WriteResult(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) (LoginResult, error) {
			result, err := svc.completeSession(ctx, az, CreateSession{
				account: account, artifact: ArtifactCLI,
				assurance: Assurance{Method: MethodLocalPassword, Factors: []string{"password"}, AuthenticatedAt: now},
				csrf:      sessionWithoutCSRF,
			}, now)
			if err != nil {
				return LoginResult{}, err
			}
			attempts = append(attempts, result.SessionToken)
			if len(attempts) == 1 {
				return result, store.ErrRetrySerialization
			}
			return result, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertCommittedAttempt(t, db, attempts, result, now)
	})

	t.Run("rotate", func(t *testing.T) {
		db, account := sessionCompletionFixture(t)
		now := time.Date(2026, time.August, 22, 11, 0, 0, 0, time.UTC)
		svc := &Auth{}
		created := createCompletionSession(t, db, svc, account, now)
		var attempts []string
		result, err := tx.WriteResult(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) (LoginResult, error) {
			live, err := az.Authenticate(ctx, created.SessionToken, now)
			if err != nil {
				return LoginResult{}, err
			}
			result, err := svc.completeSession(ctx, az, RotateSession{session: live, account: account, factors: live.Assurance.Factors}, now)
			if err != nil {
				return LoginResult{}, err
			}
			attempts = append(attempts, result.SessionToken)
			if len(attempts) == 1 {
				return result, store.ErrRetrySerialization
			}
			return result, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertCommittedAttempt(t, db, attempts, result, now)
		assertSessionTokenRejected(t, db, created.SessionToken, now)
	})
}

func sessionCompletionFixture(t *testing.T) (*store.DB, authz.Account) {
	t.Helper()
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "session-completion.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	account := authz.Account{
		ID: "acc_completion", PrincipalID: domain.PrincipalID("hum_completion"),
		Username: "completion", DisplayName: "Completion Test", CreatedAt: time.Date(2026, time.August, 22, 7, 0, 0, 0, time.UTC),
	}
	if err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		if err := az.CreateHumanPrincipal(ctx, account.PrincipalID, account.CreatedAt); err != nil {
			return err
		}
		return az.CreateAccount(ctx, account)
	}); err != nil {
		t.Fatal(err)
	}
	return db, account
}

func createCompletionSession(t *testing.T, db *store.DB, svc *Auth, account authz.Account, now time.Time) LoginResult {
	t.Helper()
	result, err := tx.WriteResult(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) (LoginResult, error) {
		return svc.completeSession(ctx, az, CreateSession{
			account: account, artifact: ArtifactBrowser,
			assurance: Assurance{Method: MethodLocalPassword, Factors: []string{"password"}, AuthenticatedAt: now},
			csrf:      sessionWithCSRF,
		}, now)
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertCommittedAttempt(t *testing.T, db *store.DB, attempts []string, result LoginResult, now time.Time) {
	t.Helper()
	if len(attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(attempts))
	}
	if result.SessionToken != attempts[1] || result.SessionToken == attempts[0] {
		t.Fatalf("published token = %q, attempts = %q", result.SessionToken, attempts)
	}
	assertSessionTokenRejected(t, db, attempts[0], now)
	assertSessionTokenAccepted(t, db, result.SessionToken, result.SessionID, now)
}

func assertSessionTokenAccepted(t *testing.T, db *store.DB, token, sessionID string, now time.Time) {
	t.Helper()
	err := tx.Read(t.Context(), db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		live, err := az.Authenticate(ctx, token, now)
		if err == nil && live.SessionID != sessionID {
			t.Fatalf("session id = %q, want %q", live.SessionID, sessionID)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertSessionTokenRejected(t *testing.T, db *store.DB, token string, now time.Time) {
	t.Helper()
	err := tx.Read(t.Context(), db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		_, err := az.Authenticate(ctx, token, now)
		return err
	})
	if err == nil {
		t.Fatal("superseded or rolled-back token authenticated")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
