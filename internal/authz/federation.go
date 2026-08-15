package authz

import (
	"context"
	"errors"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
)

// Federated machine identities at the chokepoint (#62, machine-identities ADR §
// Federation, § Authentication, authorization and the fetch path).
//
// A federated principal resolves HERE, at the same chokepoint, in the same
// transaction, uncached, exactly like its bearer-token sibling — the ADR's
// propagation to the architecture ticket does not distinguish the kinds. What it
// gets is the same Identity, so its authority is the union of the grants on the
// service account and nothing else. There is no per-credential scope on either
// kind, so there is nothing for federation to widen.
//
// What is deliberately NOT here: the cryptographic validation and the pinned
// -claim policy. Both need the network (a JWKS fetch) or a JSON claim
// vocabulary, and neither belongs inside a database transaction — a hung issuer
// must never become a held write lock. The service validates the token BEFORE it
// opens the transaction and passes the resulting predicate in; this function
// owns the row read, the binding predicate's INVOCATION, and the liveness rules.

// Re-exported so the service layer never names the resolution-surface package.
type (
	Binding             = authn.Binding
	FederationIssuer    = authn.FederationIssuer
	NewFederationIssuer = authn.NewFederationIssuer
)

// BindingPredicate is the binding-specific half of federated validation:
// audience, every pinned claim, the CI event rule and the post-restore `iat`
// predicate, evaluated against the rows that were actually resolved.
//
// It arrives as a function rather than as data because its inputs are the
// presented token's claims, which the caller already holds, and its
// implementation is in internal/oidcfed — a package the chokepoint deliberately
// does not import. Passing the check in keeps the protocol library behind its own
// wall while still making the check unskippable: AuthenticateFederated REFUSES a
// nil predicate rather than treating it as "no further conditions".
//
// It receives the ISSUER ROW READ IN THIS TRANSACTION, not the one the caller
// captured before validation, and that argument is the fix for a real
// time-of-check gap: the network half of federated authentication runs outside
// any transaction, so an administrator who adds a refused audience or switches
// the key source while a slow verification is in flight would otherwise have that
// request complete under the superseded policy. The predicate compares the two
// and refuses when they disagree.
type BindingPredicate func(iss FederationIssuer, b Binding) error

// AuthenticateFederated resolves a validated federated identity to its service
// account.
//
// The reads are FIXED in number and order, like the bearer path's, and every
// predicate is evaluated after all of them. Returning as soon as one failed
// would make an unbound identity cost one query and a revoked binding two — a
// query-count oracle for which bindings exist. The resolution-surface read
// performs the same row decode on a miss as on a hit (federation.go's decoy
// block), so the work above the storage engine is equal too.
//
// Two residuals, stated rather than discovered.
//
// An UNKNOWN ISSUER short-circuits earlier than an unbound subject, because the
// caller cannot look up a binding without an issuer id and cannot verify a
// signature without keys. What that discloses is which issuers the instance
// trusts — instance configuration an operator publishes to the platforms it
// federates with anyway, not which workloads exist, which is the fact the
// uniformity rule protects.
//
// The binding predicate's own COST varies with how far it gets: a token failing
// the audience check does less work than one failing the last pinned claim, and
// the miss path's decoy pins are three claims that will not match rather than
// this binding's. Equalising that would mean comparing every pin of every
// binding whatever the outcome, which is a different and larger machine than the
// one the ADR asks for; the request is uniformity "as far as practical, with
// residuals documented", and this is one. The response shape is identical in
// every case, which is the half that is not a residual.
func (a *TxAuthorizer) AuthenticateFederated(ctx context.Context, issuerID, subject string, check BindingPredicate, now time.Time) (Identity, error) {
	if check == nil {
		// Fail closed. A caller that forgot the predicate would otherwise
		// authenticate any identity the `(issuer, subject)` index resolves,
		// ignoring audience, pinned claims and the restore predicate.
		return Identity{}, domain.ErrUnauthenticated
	}
	if issuerID == "" || subject == "" {
		return Identity{}, domain.ErrUnauthenticated
	}

	// The issuer row, RE-READ inside this transaction. It is read
	// unconditionally and before the binding, so the read count is the same
	// whatever the outcome, and an issuer deleted mid-flight resolves to the zero
	// row — which the predicate refuses, because its policy fields will not match
	// the ones validation ran under.
	issuer, issErr := a.r.FederationIssuerByID(ctx, issuerID)
	if issErr != nil && !errors.Is(issErr, domain.ErrNotFound) {
		return Identity{}, issErr
	}

	cred, credErr := a.r.FederatedBindingByIdentity(ctx, issuerID, subject)
	if credErr != nil && !errors.Is(credErr, domain.ErrNotFound) {
		return Identity{}, credErr
	}

	// An unbound identity still resolves a service account, for the empty id —
	// which resolves to nothing, at the same cost.
	sa, saErr := a.r.ServiceAccountByID(ctx, cred.ServiceAccountID)
	if saErr != nil && !errors.Is(saErr, domain.ErrNotFound) {
		return Identity{}, saErr
	}

	epoch, err := a.r.CredentialEpoch(ctx)
	if err != nil {
		return Identity{}, err
	}

	// The binding predicate runs on EVERY outcome, including the miss — the
	// resolver hands back a decoy binding precisely so it has something to work
	// on — and its verdict is folded in below with the others rather than
	// returned early. On a miss the answer was already decided; running the
	// predicate anyway is what keeps an unbound identity from being the cheap
	// case.
	checkErr := check(issuer, cred.Binding)

	if credErr != nil || saErr != nil || issErr != nil || checkErr != nil {
		return Identity{}, domain.ErrUnauthenticated
	}
	// `oidc-federation` is the only kind this index can resolve — the partial
	// unique index is over `(issuer_id, subject)` and the table's shape CHECK
	// makes those NULL for a bearer credential — but the kind is checked anyway,
	// because a resolution path that infers the kind from the index it used is
	// one migration away from being wrong.
	if cred.Kind != domain.CredentialOIDCFederation {
		return Identity{}, domain.ErrUnauthenticated
	}
	if !cred.Live(now, epoch) {
		return Identity{}, domain.ErrUnauthenticated
	}
	if !domain.IsServiceAccountKind(sa.Kind) {
		return Identity{}, domain.ErrUnauthenticated
	}

	return Identity{
		Principal:    sa.PrincipalID,
		Artifact:     string(cred.Kind),
		Class:        sa.Kind,
		CredentialID: cred.ID,
		CreatedAt:    cred.CreatedAt,
		LastSeenAt:   cred.LastUsedAt,
	}, nil
}

// The federation administration surface. Authorization happens at the
// chokepoint first — every caller mints a proof through Authorize before
// reaching here — but the rows are `class=authn`, so the reads and writes ride
// the resolution surface, exactly as credential administration does.

func (a *TxAuthorizer) CreateFederationIssuer(ctx context.Context, iss NewFederationIssuer) error {
	return a.r.CreateFederationIssuer(ctx, iss)
}

// FederationIssuerByIssuer resolves a configuration by its BYTE-EXACT `iss`.
func (a *TxAuthorizer) FederationIssuerByIssuer(ctx context.Context, issuer string) (FederationIssuer, error) {
	return a.r.FederationIssuerByIssuer(ctx, issuer)
}

func (a *TxAuthorizer) FederationIssuerByID(ctx context.Context, id string) (FederationIssuer, error) {
	return a.r.FederationIssuerByID(ctx, id)
}

func (a *TxAuthorizer) FederationIssuers(ctx context.Context) ([]FederationIssuer, error) {
	return a.r.FederationIssuers(ctx)
}

func (a *TxAuthorizer) UpdateFederationIssuer(ctx context.Context, id string, mode domain.JWKSMode, staticJWKS string, refused []string, actor domain.PrincipalID, at time.Time) (bool, error) {
	return a.r.UpdateFederationIssuer(ctx, id, mode, staticJWKS, refused, actor, at)
}

func (a *TxAuthorizer) DeleteFederationIssuer(ctx context.Context, id string) (bool, error) {
	return a.r.DeleteFederationIssuer(ctx, id)
}

// BindingsForIssuer is the delete guard's census: removing the issuer of a
// live binding is an authorization change wearing a configuration change's
// clothes.
func (a *TxAuthorizer) BindingsForIssuer(ctx context.Context, id string) (int64, error) {
	return a.r.BindingsForIssuer(ctx, id)
}

// ReactivateBinding records a restore-time re-validation (§ Restore). #76 owns
// the operator ceremony; the write exists here because the refusal it drives
// exists now.
func (a *TxAuthorizer) ReactivateBinding(ctx context.Context, id string, at time.Time) (bool, error) {
	return a.r.ReactivateBinding(ctx, id, at)
}

// PinGeneration reads the conditional cursor's pin component.
func (a *TxAuthorizer) PinGeneration(ctx context.Context, p domain.PrincipalID, env domain.EnvID) (int64, error) {
	return a.r.PinGeneration(ctx, p, env)
}

// SetPinGeneration advances it. #52 owns pin creation, reassignment and release.
func (a *TxAuthorizer) SetPinGeneration(ctx context.Context, p domain.PrincipalID, env domain.EnvID, generation int64) error {
	return a.r.SetPinGeneration(ctx, p, env, generation)
}

// DeletePinGenerationsForPrincipal releases cursor rows during workload teardown.
func (a *TxAuthorizer) DeletePinGenerationsForPrincipal(ctx context.Context, p domain.PrincipalID) error {
	return a.r.DeletePinGenerationsForPrincipal(ctx, p)
}
