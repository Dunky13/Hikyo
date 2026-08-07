package authz

import (
	"errors"
	"fmt"

	"github.com/Dunky13/wenv/internal/domain"
)

// Verify is the store boundary check (tenant-isolation ADR: one check, in
// one package, not per endpoint). Every store method calls it first, passing
// its own registered StoreOp and the token of the transaction it is bound
// to, and binds its chain parameters exclusively from the returned scope —
// the proof's resolved chain, never caller arguments. Rejections are loud
// internal errors, not uniform responses: a proof failing here is a bug or
// an attack, and either way no query may run.
//
// Fail-closed rejections, per invariant 5: nil proof (the only forgeable
// value), foreign-transaction proof, committed/rolled-back-transaction
// proof, operation-mismatched proof — and for system proofs, any operation
// outside the mint site's closed set.
func Verify(p Proof, op StoreOp, tok *TxToken) (domain.Scope, error) {
	if p == nil {
		return domain.Scope{}, errors.New("authz: store call without a proof")
	}
	// Type-assert rather than calling proof() through the interface: an
	// outside package can embed Proof in a struct (`type forged struct
	// { authz.Proof }`), producing a non-nil value that satisfies the
	// interface by method promotion over a nil embedded field. Calling the
	// promoted method would panic; asserting to the one canonical concrete
	// type refuses it fail-closed, like every other non-canonical proof.
	c, ok := p.(*proof)
	if !ok || c == nil {
		return domain.Scope{}, errors.New("authz: non-canonical proof — proofs come only from authorize()")
	}
	if tok == nil || c.tok != tok {
		return domain.Scope{}, fmt.Errorf("authz: proof for operation %q presented outside its transaction", c.op)
	}
	if !tok.alive() {
		return domain.Scope{}, fmt.Errorf("authz: proof for operation %q presented after its transaction ended", c.op)
	}
	switch c.kind {
	case kindSystem:
		if !systemSites[c.site][op] {
			return domain.Scope{}, fmt.Errorf("authz: system proof from site %q may not invoke %q", c.site, op)
		}
	default:
		if !operations[c.op].storeOps[op] {
			return domain.Scope{}, fmt.Errorf("authz: proof minted for %q may not invoke %q", c.op, op)
		}
	}
	return c.chain, nil
}
