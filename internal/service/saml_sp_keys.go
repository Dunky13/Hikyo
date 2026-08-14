package service

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

var (
	ErrSAMLSPKeyNotFound = errors.New("service: SAML SP key not found")
	ErrSAMLSPKeyState    = errors.New("service: SAML SP key is not in the required lifecycle state")
	ErrSAMLSPKeyRace     = errors.New("service: SAML SP key changed underneath this write")
)

// SAMLSPKeyView exposes only public key lifecycle metadata. Private material
// never crosses the service boundary.
type SAMLSPKeyView struct {
	Fingerprint string
	State       string
	CreatedAt   time.Time
}

func samlSPKeyView(key authz.SAMLSPKey) SAMLSPKeyView {
	return SAMLSPKeyView{Fingerprint: key.Fingerprint, State: key.State, CreatedAt: key.CreatedAt}
}

func generatedSPKeyInput(key generatedSAMLSPKey) authz.NewSAMLSPKey {
	return authz.NewSAMLSPKey{
		ID: key.ID, State: "active", EncryptedPrivateKey: key.EncryptedPrivateKey,
		CertificateDER: key.CertificateDER, Fingerprint: key.Fingerprint,
		DEKVersion: key.DEKVersion, CreatedAt: key.CreatedAt,
	}
}

func (s *SAMLProviders) ListSPKeys(ctx context.Context, actor Actor) ([]SAMLSPKeyView, error) {
	var output []SAMLSPKeyView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLSPKeyList, domain.Scope{})
		if err != nil {
			return err
		}
		keys, err := az.SAMLSPKeys(ctx)
		if err != nil {
			return err
		}
		slices.SortFunc(keys, func(a, b authz.SAMLSPKey) int {
			if a.State != b.State {
				if a.State == "active" {
					return -1
				}
				if b.State == "active" {
					return 1
				}
			}
			if ordered := a.CreatedAt.Compare(b.CreatedAt); ordered != 0 {
				return ordered
			}
			return cmp.Compare(a.Fingerprint, b.Fingerprint)
		})
		output = make([]SAMLSPKeyView, 0, len(keys))
		for _, key := range keys {
			output = append(output, samlSPKeyView(key))
		}
		event, err := newAuditEvent(ctx, audit.EventOIDCProviderRead, caller.Principal,
			audit.Object{Type: "saml_sp_key"}, audit.OutcomeSuccess, "",
			audit.Payload{"query": "list", "row_count": len(output)})
		if err != nil {
			return err
		}
		return repos.Audit().InsertInstance(ctx, proof, event)
	})
	return output, err
}

func (s *SAMLProviders) RotateSPKey(ctx context.Context, actor Actor) (SAMLSPKeyView, error) {
	// RSA-3072 generation is intentionally after a cheap authorization pass so
	// an invalid artifact cannot turn this admin endpoint into a CPU oracle.
	// The write transaction authorizes again to bind the mutation to live state.
	if err := s.authorize(ctx, actor, authz.OpSAMLSPKeyRotate); err != nil {
		return SAMLSPKeyView{}, err
	}
	generated, err := s.generateSPKey()
	if err != nil {
		return SAMLSPKeyView{}, err
	}
	var output SAMLSPKeyView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLSPKeyRotate, domain.Scope{})
		if err != nil {
			return err
		}
		active, err := az.ActiveSAMLSPKey(ctx)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSAMLSPKeyNotFound
		}
		if err != nil {
			return err
		}
		moved, err := az.MarkSAMLSPKeyRetiring(ctx, active.ID, active.RowVersion)
		if err != nil {
			return err
		}
		if !moved {
			return ErrSAMLSPKeyRace
		}
		if err := az.CreateSAMLSPKey(ctx, generatedSPKeyInput(generated)); err != nil {
			return err
		}
		output = SAMLSPKeyView{Fingerprint: generated.Fingerprint, State: "active", CreatedAt: generated.CreatedAt}
		return recordSAMLSPKeyEvent(ctx, repos, proof, caller.Principal, generated.ID, "rotate", generated.Fingerprint, active.Fingerprint)
	})
	return output, err
}

func (s *SAMLProviders) RetireSPKey(ctx context.Context, actor Actor, fingerprint string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLSPKeyRetire, domain.Scope{})
		if err != nil {
			return err
		}
		key, err := spKeyByFingerprint(ctx, az, fingerprint)
		if err != nil {
			return err
		}
		if key.State != "retiring" {
			return ErrSAMLSPKeyState
		}
		deleted, err := az.DeleteRetiringSAMLSPKey(ctx, key.ID)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrSAMLSPKeyRace
		}
		return recordSAMLSPKeyEvent(ctx, repos, proof, caller.Principal, key.ID, "retire", key.Fingerprint, "")
	})
}

func (s *SAMLProviders) CompromiseRetireSPKey(ctx context.Context, actor Actor, fingerprint string) (SAMLSPKeyView, error) {
	if err := s.authorize(ctx, actor, authz.OpSAMLSPKeyCompromiseRetire); err != nil {
		return SAMLSPKeyView{}, err
	}
	generated, err := s.generateSPKey()
	if err != nil {
		return SAMLSPKeyView{}, err
	}
	var output SAMLSPKeyView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLSPKeyCompromiseRetire, domain.Scope{})
		if err != nil {
			return err
		}
		active, err := az.ActiveSAMLSPKey(ctx)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSAMLSPKeyNotFound
		}
		if err != nil {
			return err
		}
		if active.Fingerprint != fingerprint {
			if _, lookupErr := spKeyByFingerprint(ctx, az, fingerprint); lookupErr == nil {
				return ErrSAMLSPKeyState
			} else if !errors.Is(lookupErr, ErrSAMLSPKeyNotFound) {
				return lookupErr
			}
			return ErrSAMLSPKeyNotFound
		}
		moved, err := az.MarkSAMLSPKeyRetiring(ctx, active.ID, active.RowVersion)
		if err != nil {
			return err
		}
		if !moved {
			return ErrSAMLSPKeyRace
		}
		deleted, err := az.DeleteRetiringSAMLSPKey(ctx, active.ID)
		if err != nil {
			return err
		}
		if !deleted {
			return ErrSAMLSPKeyRace
		}
		if err := az.CreateSAMLSPKey(ctx, generatedSPKeyInput(generated)); err != nil {
			return err
		}
		output = SAMLSPKeyView{Fingerprint: generated.Fingerprint, State: "active", CreatedAt: generated.CreatedAt}
		return recordSAMLSPKeyEvent(ctx, repos, proof, caller.Principal, generated.ID, "compromise_retire", generated.Fingerprint, active.Fingerprint)
	})
	return output, err
}

func spKeyByFingerprint(ctx context.Context, az *authz.TxAuthorizer, fingerprint string) (authz.SAMLSPKey, error) {
	keys, err := az.SAMLSPKeys(ctx)
	if err != nil {
		return authz.SAMLSPKey{}, err
	}
	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			return key, nil
		}
	}
	return authz.SAMLSPKey{}, ErrSAMLSPKeyNotFound
}

func recordSAMLSPKeyEvent(ctx context.Context, repos store.Repos, proof authz.Proof, principal domain.PrincipalID, keyID, action, fingerprint, priorFingerprint string) error {
	payload := audit.Payload{"action": action, "key_fingerprint": fingerprint}
	if priorFingerprint != "" {
		payload["prior_key_fingerprint"] = priorFingerprint
	}
	event, err := newAuditEvent(ctx, audit.EventSAMLSPKey, principal,
		audit.Object{Type: "saml_sp_key", ID: keyID}, audit.OutcomeSuccess, "", payload)
	if err != nil {
		return err
	}
	return repos.Audit().InsertInstance(ctx, proof, event)
}
