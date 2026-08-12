// Package authz is the authorization chokepoint (permission +
// tenant-isolation ADRs): authorize(principal, capability-formula, scope)
// evaluated in-transaction against current policy with no cache, returning a
// proof-carrying value the store accepts calls only with. This package, the
// resolution surface (internal/store/authn), the transaction package, and
// the store's query registry form the enumerated trusted set — changes here
// are the highest-scrutiny diffs in the repo.
package authz

import (
	"sync/atomic"

	"github.com/Dunky13/hikyo/internal/domain"
)

// Proof is evidence that authorize() ran, for one operation, inside one
// still-live transaction. It is an interface with an unexported method,
// implemented by exactly one unexported type in this package: outside code
// cannot implement it and cannot construct a non-nil value of it — the only
// forgeable value is nil, and the store boundary rejects that fail-closed
// (tenant-isolation ADR § chokepoint pattern). A proof is not a capability
// token: it dies with its transaction, so it cannot be stored, replayed, or
// reused across retries.
type Proof interface {
	// proof returns the canonical concrete value; unexported so no other
	// package can satisfy this interface, structurally or otherwise.
	proof() *proof
}

type proofKind int

const (
	kindTenant proofKind = iota
	kindInstance
	kindSystem
)

// proof is the single concrete Proof implementation. All three ADR proof
// kinds (tenant, instance, system) are this one type: what varies is the
// binding — tenant proofs carry a resolved chain, instance proofs carry a
// grant-evaluated instance formula and no chain, system proofs carry their
// mint site. Operation and transaction binding are identical across kinds.
type proof struct {
	kind  proofKind
	op    Operation
	site  SystemSite   // kindSystem only
	chain domain.Scope // kindTenant only: the resolved chain, never caller input
	tok   *TxToken
}

func (p *proof) proof() *proof { return p }

// TxToken is the transaction identity a proof is bound to. The transaction
// package mints one per transaction attempt and invalidates it at commit or
// rollback; a proof presented under any other token — a later retry attempt,
// a different transaction, or after its own transaction ended — dies at the
// store boundary. Constructing tokens is not privileged (a token without a
// matching proof authorizes nothing); minting proofs is.
type TxToken struct {
	dead atomic.Bool
}

// NewTxToken mints a live transaction identity.
func NewTxToken() *TxToken { return &TxToken{} }

// Invalidate marks the transaction ended. Idempotent; only ever tightens.
func (t *TxToken) Invalidate() { t.dead.Store(true) }

func (t *TxToken) alive() bool { return !t.dead.Load() }
