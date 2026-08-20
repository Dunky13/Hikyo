package store

import (
	"context"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// ReencryptRepo is the instance-credential reencrypt surface (#75/#187): the six
// instance-DEK ciphertext columns the `reencrypt --instance` walk moves onto the
// active version. They live on one repo rather than spread across auth, factors,
// providers, saml and remotes because they share one operation (OpReencryptInstance)
// and one walk shape. class=authn/instance: no tenant chain.
//
// Five tables carry dek_version + row_version, so their re-seal is a
// compare-and-swap on row_version (the anti-resurrection guard) that also stamps
// the new dek_version. remotes has neither, so its re-seal CASes on the old blob.
type ReencryptRepo interface {
	ListPasswordCredsForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error)
	ReencryptPasswordCred(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error)
	ListTotpCredsForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error)
	ReencryptTotpCred(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error)
	ListRecoveryCodesForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error)
	ReencryptRecoveryCodes(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error)
	ListOidcProvidersForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error)
	ReencryptOidcProvider(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error)
	ListSamlKeysForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error)
	ReencryptSamlKey(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error)
	ListRemotesForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error)
	ReencryptRemote(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error)
}

// ReencryptInstanceRow is one instance credential row the walk considers: its id
// (the AAD owner_row and CAS key), the sealed ciphertext, and — for the five
// versioned tables — the DEK version it is on and the row version to CAS against.
// DEKVersion is zero for remotes, signalling the walk to header-parse instead.
type ReencryptInstanceRow struct {
	ID         string
	Ciphertext []byte
	DEKVersion uint32
	RowVersion uint32
}

type sqliteReencrypt struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteRepos) Reencrypt() ReencryptRepo {
	return sqliteReencrypt{q: sqlitegen.New(r.db), tok: r.tok}
}

type pgReencrypt struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgRepos) Reencrypt() ReencryptRepo {
	return pgReencrypt{q: pggen.New(r.db), tok: r.tok}
}

// --- sqlite ---

func (r sqliteReencrypt) ListPasswordCredsForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListPasswordCreds, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListPasswordCredsForReencrypt(ctx, sqlitegen.ListPasswordCredsForReencryptParams{AccountID: cursor, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.AccountID, Ciphertext: x.Verifier, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r sqliteReencrypt) ReencryptPasswordCred(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptPasswordCred, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptPasswordCred(ctx, sqlitegen.ReencryptPasswordCredParams{Ct: newCiphertext, DekVersion: int64(dekVersion), AccountID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r sqliteReencrypt) ListTotpCredsForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListTotpCreds, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListTotpCredsForReencrypt(ctx, sqlitegen.ListTotpCredsForReencryptParams{ID: cursor, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.Seed, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r sqliteReencrypt) ReencryptTotpCred(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptTotpCred, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptTotpCred(ctx, sqlitegen.ReencryptTotpCredParams{Ct: newCiphertext, DekVersion: int64(dekVersion), ID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r sqliteReencrypt) ListRecoveryCodesForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListRecoveryCodes, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRecoveryCodesForReencrypt(ctx, sqlitegen.ListRecoveryCodesForReencryptParams{AccountID: cursor, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.AccountID, Ciphertext: x.Batch, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r sqliteReencrypt) ReencryptRecoveryCodes(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptRecoveryCodes, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptRecoveryCodes(ctx, sqlitegen.ReencryptRecoveryCodesParams{Ct: newCiphertext, DekVersion: int64(dekVersion), AccountID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r sqliteReencrypt) ListOidcProvidersForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListOidcProviders, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListOidcProvidersForReencrypt(ctx, sqlitegen.ListOidcProvidersForReencryptParams{ID: cursor, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.ClientSecret, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r sqliteReencrypt) ReencryptOidcProvider(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptOidcProvider, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptOidcProvider(ctx, sqlitegen.ReencryptOidcProviderParams{Ct: newCiphertext, DekVersion: int64(dekVersion), ID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r sqliteReencrypt) ListSamlKeysForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListSamlKeys, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListSamlKeysForReencrypt(ctx, sqlitegen.ListSamlKeysForReencryptParams{ID: cursor, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.EncryptedPrivateKey, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r sqliteReencrypt) ReencryptSamlKey(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptSamlKey, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptSamlKey(ctx, sqlitegen.ReencryptSamlKeyParams{Ct: newCiphertext, DekVersion: int64(dekVersion), ID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r sqliteReencrypt) ListRemotesForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListRemotes, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRemotesForReencrypt(ctx, sqlitegen.ListRemotesForReencryptParams{ID: cursor, Limit: int64(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.CredentialSealed})
	}
	return out, nil
}

func (r sqliteReencrypt) ReencryptRemote(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptRemote, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptRemote(ctx, sqlitegen.ReencryptRemoteParams{NewCt: newCiphertext, ID: id, OldCt: oldCiphertext})
	return n == 1, err
}

// --- postgres ---

func (r pgReencrypt) ListPasswordCredsForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListPasswordCreds, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListPasswordCredsForReencrypt(ctx, pggen.ListPasswordCredsForReencryptParams{Cursor: cursor, PageLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.AccountID, Ciphertext: x.Verifier, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r pgReencrypt) ReencryptPasswordCred(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptPasswordCred, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptPasswordCred(ctx, pggen.ReencryptPasswordCredParams{Ct: newCiphertext, DekVersion: int64(dekVersion), AccountID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r pgReencrypt) ListTotpCredsForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListTotpCreds, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListTotpCredsForReencrypt(ctx, pggen.ListTotpCredsForReencryptParams{Cursor: cursor, PageLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.Seed, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r pgReencrypt) ReencryptTotpCred(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptTotpCred, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptTotpCred(ctx, pggen.ReencryptTotpCredParams{Ct: newCiphertext, DekVersion: int64(dekVersion), ID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r pgReencrypt) ListRecoveryCodesForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListRecoveryCodes, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRecoveryCodesForReencrypt(ctx, pggen.ListRecoveryCodesForReencryptParams{Cursor: cursor, PageLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.AccountID, Ciphertext: x.Batch, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r pgReencrypt) ReencryptRecoveryCodes(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptRecoveryCodes, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptRecoveryCodes(ctx, pggen.ReencryptRecoveryCodesParams{Ct: newCiphertext, DekVersion: int64(dekVersion), AccountID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r pgReencrypt) ListOidcProvidersForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListOidcProviders, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListOidcProvidersForReencrypt(ctx, pggen.ListOidcProvidersForReencryptParams{Cursor: cursor, PageLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.ClientSecret, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r pgReencrypt) ReencryptOidcProvider(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptOidcProvider, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptOidcProvider(ctx, pggen.ReencryptOidcProviderParams{Ct: newCiphertext, DekVersion: int64(dekVersion), ID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r pgReencrypt) ListSamlKeysForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListSamlKeys, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListSamlKeysForReencrypt(ctx, pggen.ListSamlKeysForReencryptParams{Cursor: cursor, PageLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.EncryptedPrivateKey, DEKVersion: uint32(x.DekVersion), RowVersion: uint32(x.RowVersion)})
	}
	return out, nil
}

func (r pgReencrypt) ReencryptSamlKey(ctx context.Context, p authz.Proof, id string, newCiphertext []byte, dekVersion, rowVersion uint32) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptSamlKey, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptSamlKey(ctx, pggen.ReencryptSamlKeyParams{Ct: newCiphertext, DekVersion: int64(dekVersion), ID: id, RowVersion: int64(rowVersion)})
	return n == 1, err
}

func (r pgReencrypt) ListRemotesForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptInstanceRow, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptListRemotes, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRemotesForReencrypt(ctx, pggen.ListRemotesForReencryptParams{Cursor: cursor, PageLimit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptInstanceRow, 0, len(rows))
	for _, x := range rows {
		out = append(out, ReencryptInstanceRow{ID: x.ID, Ciphertext: x.CredentialSealed})
	}
	return out, nil
}

func (r pgReencrypt) ReencryptRemote(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreReencryptRemote, r.tok); err != nil {
		return false, err
	}
	n, err := r.q.ReencryptRemote(ctx, pggen.ReencryptRemoteParams{NewCt: newCiphertext, ID: id, OldCt: oldCiphertext})
	return n == 1, err
}
