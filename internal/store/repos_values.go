package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// The flat value model's binding layer (#50). Same discipline as repos.go:
// every method verifies the proof at the boundary against its own registered
// store operation and binds every chain parameter exclusively from the
// verified proof's resolved chain.
//
// `environment_id` is not a chain column of this table (see the migration),
// but every environment-addressed method below binds it from the proof's
// resolved chain anyway, through envOf. A caller argument never reaches it:
// the caller-facing signatures have no environment parameter at all.

// envOf reads the environment the proof resolved, and refuses a proof that has
// none. Without the refusal an environment-addressed statement minted under a
// project-depth proof would silently bind the empty string and match nothing —
// fail-closed, but silently, which is the wrong kind of closed. A proof of the
// wrong depth here is a registry or service bug, so it is loud.
func envOf(chain domain.Scope, op authz.StoreOp) (string, error) {
	if chain.Env == "" {
		return "", fmt.Errorf("store: %s addresses an environment, but its proof resolved none", op)
	}
	return string(chain.Env), nil
}

type sqliteValues struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteValues) Get(ctx context.Context, p authz.Proof, keyID string) (ValueEntry, error) {
	chain, err := authz.Verify(p, authz.StoreValuesGet, r.tok)
	if err != nil {
		return ValueEntry{}, err
	}
	env, err := envOf(chain, authz.StoreValuesGet)
	if err != nil {
		return ValueEntry{}, err
	}
	row, err := r.q.GetValueEntry(ctx, sqlitegen.GetValueEntryParams{
		OrgID:         string(chain.Org),     // chain column: proof-bound
		ProjectID:     string(chain.Project), // chain column: proof-bound
		EnvironmentID: env,                   // proof-bound
		KeyID:         keyID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		// ErrNotFound IS `absent`: the two-state presence model has no third
		// answer, and nothing underneath to fall back to.
		return ValueEntry{}, ErrNotFound
	}
	if err != nil {
		return ValueEntry{}, err
	}
	return valueFromSQLite(row)
}

func (r sqliteValues) List(ctx context.Context, p authz.Proof) ([]ValueEntry, error) {
	chain, err := authz.Verify(p, authz.StoreValuesList, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreValuesList)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListValueEntries(ctx, sqlitegen.ListValueEntriesParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ValueEntry, 0, len(rows))
	for _, row := range rows {
		entry, err := valueFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func (r sqliteValues) EnvironmentsWithValue(ctx context.Context, p authz.Proof, keyID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreValuesEnvironmentsWithValue, r.tok)
	if err != nil {
		return nil, err
	}
	return r.q.ListValueEnvironmentsForKey(ctx, sqlitegen.ListValueEnvironmentsForKeyParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		KeyID:     keyID,
	})
}

func (r sqliteValues) Put(ctx context.Context, p authz.Proof, entry NewValueEntry) error {
	chain, err := authz.Verify(p, authz.StoreValuesPut, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreValuesPut)
	if err != nil {
		return err
	}
	// Delete-then-insert, never an upsert: the superseded row's id is bound
	// into its ciphertext's AAD, and reusing it for new material is the one
	// thing the encryption ADR forbids outright.
	if _, err := r.q.DeleteValueEntry(ctx, sqlitegen.DeleteValueEntryParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		KeyID:         entry.KeyID,
	}); err != nil {
		return constraint(err)
	}
	return constraint(r.q.InsertValueEntry(ctx, sqlitegen.InsertValueEntryParams{
		ID:            entry.ID,
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		KeyID:         entry.KeyID,
		Ciphertext:    entry.Ciphertext,
		UpdatedAt:     CanonTime(entry.UpdatedAt).Format(timeFormat),
		UpdatedBy:     entry.UpdatedBy,
	}))
}

func (r sqliteValues) Clear(ctx context.Context, p authz.Proof, keyID string) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreValuesClear, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StoreValuesClear)
	if err != nil {
		return false, err
	}
	// Clearing an already-absent cell is a no-op success, not a missing row:
	// `absent` is the state, and the caller asked for that state. The rows-
	// affected count says whether a transition actually happened, so the caller
	// emits value.cleared only when one did.
	rows, err := r.q.DeleteValueEntry(ctx, sqlitegen.DeleteValueEntryParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		KeyID:         keyID,
	})
	if err != nil {
		return false, constraint(err)
	}
	return rows > 0, nil
}

func (r sqliteValues) ClearEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreValuesClearEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreValuesClearEnvironment)
	if err != nil {
		return err
	}
	_, err = r.q.DeleteValueEntriesForEnvironment(ctx, sqlitegen.DeleteValueEntriesForEnvironmentParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	})
	return constraint(err)
}

func valueFromSQLite(row sqlitegen.ValueEntry) (ValueEntry, error) {
	updated, err := parseTime("value entry", row.ID, row.UpdatedAt)
	if err != nil {
		return ValueEntry{}, err
	}
	return ValueEntry{
		ID:            row.ID,
		OrgID:         row.OrgID,
		ProjectID:     row.ProjectID,
		EnvironmentID: row.EnvironmentID,
		KeyID:         row.KeyID,
		Ciphertext:    row.Ciphertext,
		UpdatedAt:     updated,
		UpdatedBy:     row.UpdatedBy,
	}, nil
}

// --- postgres ---

type pgValues struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgValues) Get(ctx context.Context, p authz.Proof, keyID string) (ValueEntry, error) {
	chain, err := authz.Verify(p, authz.StoreValuesGet, r.tok)
	if err != nil {
		return ValueEntry{}, err
	}
	env, err := envOf(chain, authz.StoreValuesGet)
	if err != nil {
		return ValueEntry{}, err
	}
	row, err := r.q.GetValueEntry(ctx, pggen.GetValueEntryParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		KeyID:          keyID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ValueEntry{}, ErrNotFound
	}
	if err != nil {
		return ValueEntry{}, err
	}
	return valueFromPG(row), nil
}

func (r pgValues) List(ctx context.Context, p authz.Proof) ([]ValueEntry, error) {
	chain, err := authz.Verify(p, authz.StoreValuesList, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreValuesList)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListValueEntries(ctx, pggen.ListValueEntriesParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ValueEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, valueFromPG(row))
	}
	return out, nil
}

func (r pgValues) EnvironmentsWithValue(ctx context.Context, p authz.Proof, keyID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreValuesEnvironmentsWithValue, r.tok)
	if err != nil {
		return nil, err
	}
	return r.q.ListValueEnvironmentsForKey(ctx, pggen.ListValueEnvironmentsForKeyParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		KeyID:          keyID,
	})
}

func (r pgValues) Put(ctx context.Context, p authz.Proof, entry NewValueEntry) error {
	chain, err := authz.Verify(p, authz.StoreValuesPut, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreValuesPut)
	if err != nil {
		return err
	}
	if _, err := r.q.DeleteValueEntry(ctx, pggen.DeleteValueEntryParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		KeyID:          entry.KeyID,
	}); err != nil {
		return constraint(err)
	}
	return constraint(r.q.InsertValueEntry(ctx, pggen.InsertValueEntryParams{
		ID:             entry.ID,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		KeyID:          entry.KeyID,
		Ciphertext:     entry.Ciphertext,
		UpdatedAt:      pgtype.Timestamptz{Time: CanonTime(entry.UpdatedAt), Valid: true},
		UpdatedBy:      entry.UpdatedBy,
	}))
}

func (r pgValues) Clear(ctx context.Context, p authz.Proof, keyID string) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreValuesClear, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StoreValuesClear)
	if err != nil {
		return false, err
	}
	// Rows-affected reports whether the cell existed; an already-absent clear is
	// a no-op success and emits no event (see the sqlite twin).
	rows, err := r.q.DeleteValueEntry(ctx, pggen.DeleteValueEntryParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		KeyID:          keyID,
	})
	if err != nil {
		return false, constraint(err)
	}
	return rows > 0, nil
}

func (r pgValues) ClearEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreValuesClearEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreValuesClearEnvironment)
	if err != nil {
		return err
	}
	_, err = r.q.DeleteValueEntriesForEnvironment(ctx, pggen.DeleteValueEntriesForEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	})
	return constraint(err)
}

func valueFromPG(row pggen.ValueEntry) ValueEntry {
	return ValueEntry{
		ID:            row.ID,
		OrgID:         row.OrgID,
		ProjectID:     row.ProjectID,
		EnvironmentID: row.EnvironmentID,
		KeyID:         row.KeyID,
		Ciphertext:    row.Ciphertext,
		UpdatedAt:     row.UpdatedAt.Time.UTC(),
		UpdatedBy:     row.UpdatedBy,
	}
}
