package isolation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The instance-connection principal end to end (#71, multi-instance ADR).
//
// The predicate-level closure lives in eligibility_test.go and ranges over the
// operation registry. This file is the other half, and it is the half that
// makes acceptance criterion 4 true rather than merely asserted: a REAL minted
// credential, resolved through the REAL chokepoint, presented against real
// operations. It also pins the resolver provenance consumed by the OpenAPI
// artifact-class mapping: a session carries the database artifact string,
// while the machine leg carries the credential artifact type.

// mintInstanceConnection creates the principal, its `instance-directory` grant
// and its credential as one unit — the shape `remote-credential create` writes
// — and returns the presented value, which exists exactly once, here.
func mintInstanceConnection(t *testing.T, db *store.DB, id string) string {
	t.Helper()

	value, verifier, err := crypto.NewArtifact(crypto.ArtifactInstanceConn)
	if err != nil {
		t.Fatalf("mint artifact: %v", err)
	}
	principal := domain.PrincipalID("mch_" + id)
	now := time.Now().UTC()

	err = tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		if err := az.CreateMachinePrincipal(ctx, principal, domain.ClassInstanceConn, now); err != nil {
			return err
		}
		return az.MintInstanceConnection(ctx, authn.NewInstanceConnection{
			ID: "icn_" + id, PrincipalID: principal, Label: "peer-a",
			Kind: domain.CredentialHikyoToken, Verifier: verifier,
			PrefixHint: value[:15], Lifetime: domain.LifetimeFinite,
			ExpiresAt: now.Add(24 * time.Hour), CredentialEpoch: 1,
			CreatedAt: now, CreatedBy: "usr_root",
		})
	})
	if err != nil {
		t.Fatalf("mint connection: %v", err)
	}

	// The grant is written directly, which is the production shape: the grants
	// API refuses `instance-directory` on a machine principal by name
	// (ErrSystemCreatedOnly), because the atom rides its credential binding and
	// must not be attachable by hand.
	execRaw(t, db, `INSERT INTO grants (id, principal_id, capability, org_id, project_id, env_id, created_at) `+
		`VALUES ('g_`+id+`', '`+string(principal)+`', 'instance-directory', NULL, NULL, NULL, `+ts+`)`)

	return value
}

func TestInstanceConnectionCredentialEndToEndSQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	runInstanceConnectionE2E(t, db)
}

func TestInstanceConnectionCredentialEndToEndPostgres(t *testing.T) {
	db := seededDB(t, openPostgres)
	runInstanceConnectionE2E(t, db)
}

func runInstanceConnectionE2E(t *testing.T, db *store.DB) {
	value := mintInstanceConnection(t, db, "e2e")

	// It authenticates, as its own class, carrying its own artifact type.
	id := authenticate(t, db, value)
	if id.Principal == "" {
		t.Fatal("a live instance-connection credential did not authenticate")
	}
	if id.Class != domain.ClassInstanceConn {
		t.Errorf("class = %q, want %q", id.Class, domain.ClassInstanceConn)
	}
	// THE assertion that keeps the confinement from going inert. If a future
	// refactor copies the machine leg's `Artifact: string(cred.Kind)`, this
	// fails here rather than silently unconfining the credential.
	if id.Artifact != string(crypto.ArtifactInstanceConn) {
		t.Fatalf("artifact = %q, want %q — artifact admission consumes this resolver provenance",
			id.Artifact, crypto.ArtifactInstanceConn)
	}

	// It reaches its one operation.
	if err := authorizeIdentity(t, db, id, authz.OpRemoteDirectoryServe, domain.Scope{}); err != nil {
		t.Fatalf("directory-serve refused for the credential that exists to perform it: %v", err)
	}

	// And nothing else — over the live registry, not a list restated here.
	//
	// Each operation is addressed at the depth its own registry row demands, so
	// the refusal that fires is the CONFINEMENT and not a scope-depth
	// programming error. The distinction matters: a depth mismatch is a loud
	// bug, and a test that accepted it would go green against a chokepoint that
	// had stopped confining anything.
	depths := (authz.RegistryFacts{}).TenantOperations()
	for op := range (authz.RegistryFacts{}).Operations() {
		if op == authz.OpRemoteDirectoryServe {
			continue
		}
		scope := domain.Scope{}
		if level, isTenant := depths[op]; isTenant {
			scope = scopeAtDepth(level)
		}

		err := authorizeIdentity(t, db, id, op, scope)
		if err == nil {
			t.Errorf("%s: the instance-connection credential was AUTHORIZED for an operation "+
				"other than directory-serve — the artifact-eligibility confinement is not "+
				"binding at the chokepoint", op)
			continue
		}
		// The refusal must wear the operation class's own uniform. Anything
		// else is a registry or addressing bug wearing a refusal's clothes.
		if !errors.Is(err, domain.ErrNotFound) && !errors.Is(err, domain.ErrUnauthorized) {
			t.Errorf("%s: refused with %v, want the class's uniform refusal — a loud error here "+
				"means the operation was never actually reached", op, err)
		}
	}
}

// scopeAtDepth addresses the fixture chain truncated to one level.
func scopeAtDepth(l domain.Level) domain.Scope {
	switch l {
	case domain.LevelOrg:
		return domain.Scope{Org: orgA}
	case domain.LevelProject:
		return domain.Scope{Org: orgA, Project: prjA1}
	case domain.LevelEnv:
		return domain.Scope{Org: orgA, Project: prjA1, Env: envA1}
	default:
		return domain.Scope{}
	}
}

// A revoked credential stops authenticating at the very next presentation,
// uncached — revocation is read in the authenticating transaction, so it bites
// on the next request rather than at some expiry.
func TestInstanceConnectionRevocationBitesImmediatelySQLite(t *testing.T) {
	db := seededDB(t, openSQLite)
	value := mintInstanceConnection(t, db, "rev")

	if authenticate(t, db, value).Principal == "" {
		t.Fatal("the credential did not authenticate before revocation")
	}

	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		revoked, err := az.RevokeInstanceConnection(ctx, "icn_rev", time.Now().UTC())
		if err != nil {
			return err
		}
		if !revoked {
			t.Error("revoke reported no live row to revoke")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if id := authenticate(t, db, value); id.Principal != "" {
		t.Fatal("a revoked directory credential still authenticated")
	}
}

// authorizeIdentity runs the real chokepoint for an already-resolved identity.
func authorizeIdentity(t *testing.T, db *store.DB, id authz.Identity, op authz.Operation, scope domain.Scope) error {
	t.Helper()
	var out error
	err := tx.Write(t.Context(), db, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		_, out = az.Authorize(ctx, id, op, scope)
		return nil
	})
	if err != nil {
		t.Fatalf("authorizeIdentity %s: %v", op, err)
	}
	return out
}
