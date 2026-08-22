package authz

import (
	"errors"
	"fmt"
	"slices"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/domain"
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
		if !registry.permitsStoreOp(c.op, op) {
			return domain.Scope{}, fmt.Errorf("authz: proof minted for %q may not invoke %q", c.op, op)
		}
	}
	return c.chain, nil
}

// VerifyEvent is Verify for the audit-insert doors: on top of the ordinary
// checks it binds the EVENT TYPE to the operation that minted the proof.
// Without it a proof for any operation licensed to write the trail could
// insert any tenant-licensed event type — a project-create proof could
// persist an environment-note-changed event, forging the meaning of the
// record while every other guard succeeds. The registry already declares
// which types each operation emits; this makes that declaration binding at
// the write boundary.
// IsSystemProof reports whether p was minted at a no-principal system site.
// The audit write path uses it to decide whether an emitter may ASSERT an
// actor class: a principal-backed operation's events are attributed from
// principals.kind, never from what the emitter claims, so only a system
// proof may say "system" or "break-glass".
func IsSystemProof(p Proof) bool {
	c, ok := p.(*proof)
	return ok && c != nil && c.kind == kindSystem
}

func VerifyEvent(p Proof, op StoreOp, tok *TxToken, et audit.EventType) (domain.Scope, error) {
	chain, err := Verify(p, op, tok)
	if err != nil {
		return domain.Scope{}, err
	}
	c, ok := p.(*proof)
	if !ok || c == nil {
		return domain.Scope{}, errors.New("authz: non-canonical proof")
	}
	if c.kind == kindSystem {
		if slices.Contains(systemSiteEvents[c.site], et) {
			return chain, nil
		}
	} else if registry.permitsEvent(c.op, et) {
		return chain, nil
	}
	return domain.Scope{}, fmt.Errorf("authz: proof minted for %q may not emit audit event %q", c.op, et)
}
