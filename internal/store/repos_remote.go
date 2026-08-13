package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// The multi-instance directory's VIEWING side (#71, multi-instance ADR §
// The directory tier).
//
// These rows are class=instance: instance-scope configuration and foreign
// structure at rest, read only through proofs evaluated on `instance-directory`
// or `instance-config`. That is why they ride this proof-gated surface rather
// than internal/store/authn — unlike the instance-connection credential, which
// resolves WHO a caller is and therefore cannot run under a proof.

func (r sqliteRepos) Remotes() RemoteRepo { return sqliteRemotes{q: sqlitegen.New(r.db), tok: r.tok} }
func (r pgRepos) Remotes() RemoteRepo     { return pgRemotes{q: pggen.New(r.db), tok: r.tok} }

type sqliteRemotes struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

type pgRemotes struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r sqliteRemotes) Create(ctx context.Context, p authz.Proof, n NewRemote) error {
	if _, err := authz.Verify(p, authz.StoreRemotesCreate, r.tok); err != nil {
		return err
	}
	return constraint(r.q.CreateRemote(ctx, sqlitegen.CreateRemoteParams{
		ID: n.ID, Name: n.Name, Url: n.URL, SpkiPin: n.SPKIPin,
		CredentialSealed: n.CredentialSealed,
		CreatedAt:        CanonTime(n.CreatedAt).Format(timeFormat),
		CreatedBy:        string(n.CreatedBy),
	}))
}

func (r sqliteRemotes) List(ctx context.Context, p authz.Proof) ([]Remote, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesList, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRemotes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Remote, 0, len(rows))
	for _, row := range rows {
		rem, err := remoteFromSQLite(sqlitegen.GetRemoteRow(row))
		if err != nil {
			return nil, err
		}
		out = append(out, rem)
	}
	return out, nil
}

func (r sqliteRemotes) Get(ctx context.Context, p authz.Proof, id string) (Remote, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesGet, r.tok); err != nil {
		return Remote{}, err
	}
	row, err := r.q.GetRemote(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Remote{}, ErrNotFound
	}
	if err != nil {
		return Remote{}, err
	}
	return remoteFromSQLite(row)
}

func (r sqliteRemotes) GetByName(ctx context.Context, p authz.Proof, name string) (Remote, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesGetByName, r.tok); err != nil {
		return Remote{}, err
	}
	row, err := r.q.GetRemoteByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return Remote{}, ErrNotFound
	}
	if err != nil {
		return Remote{}, err
	}
	return remoteFromSQLite(sqlitegen.GetRemoteRow(row))
}

func (r sqliteRemotes) Count(ctx context.Context, p authz.Proof) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesCount, r.tok); err != nil {
		return 0, err
	}
	return r.q.CountRemotes(ctx)
}

func (r sqliteRemotes) SealedCredential(ctx context.Context, p authz.Proof, id string) ([]byte, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesSealed, r.tok); err != nil {
		return nil, err
	}
	sealed, err := r.q.SealedRemoteCredential(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sealed, err
}

func (r sqliteRemotes) Rename(ctx context.Context, p authz.Proof, id, name string) error {
	if _, err := authz.Verify(p, authz.StoreRemotesRename, r.tok); err != nil {
		return err
	}
	return renameOutcome(r.q.RenameRemote(ctx, sqlitegen.RenameRemoteParams{Name: name, ID: id}))
}

func (r sqliteRemotes) Delete(ctx context.Context, p authz.Proof, id string) error {
	if _, err := authz.Verify(p, authz.StoreRemotesDelete, r.tok); err != nil {
		return err
	}
	return affected(r.q.DeleteRemote(ctx, id))
}

func (r sqliteRemotes) WriteSnapshot(ctx context.Context, p authz.Proof, s RemoteSnapshot) error {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsWrite, r.tok); err != nil {
		return err
	}
	if err := validSnapshot(s); err != nil {
		return err
	}
	return constraint(r.q.WriteRemoteSnapshot(ctx, sqlitegen.WriteRemoteSnapshotParams{
		RemoteID:         s.RemoteID,
		LastAttemptAt:    CanonTime(s.LastAttemptAt).Format(timeFormat),
		LastOutcome:      s.LastOutcome,
		ObservedAt:       sql.NullString{String: CanonTime(s.ObservedAt).Format(timeFormat), Valid: true},
		InstanceIdentity: sql.NullString{String: s.InstanceIdentity, Valid: true},
		Version:          sql.NullString{String: s.Version, Valid: true},
		OrgCount:         sql.NullInt64{Int64: s.OrgCount, Valid: true},
		ProjectCount:     sql.NullInt64{Int64: s.ProjectCount, Valid: true},
		Listing:          sql.NullString{String: string(s.Listing), Valid: true},
	}))
}

func (r sqliteRemotes) RecordFetchFailure(ctx context.Context, p authz.Proof, id string, at time.Time, outcome string) error {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsFail, r.tok); err != nil {
		return err
	}
	if err := validFailure(outcome); err != nil {
		return err
	}
	return constraint(r.q.RecordRemoteFetchFailure(ctx, sqlitegen.RecordRemoteFetchFailureParams{
		RemoteID: id, LastAttemptAt: CanonTime(at).Format(timeFormat), LastOutcome: outcome,
	}))
}

func (r sqliteRemotes) Snapshots(ctx context.Context, p authz.Proof) ([]RemoteSnapshot, error) {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsList, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRemoteSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RemoteSnapshot, 0, len(rows))
	for _, row := range rows {
		s, err := snapshotFromSQLite(sqlitegen.RemoteSnapshot(row))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (r sqliteRemotes) Snapshot(ctx context.Context, p authz.Proof, id string) (RemoteSnapshot, error) {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsGet, r.tok); err != nil {
		return RemoteSnapshot{}, err
	}
	row, err := r.q.GetRemoteSnapshot(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return RemoteSnapshot{}, ErrNotFound
	}
	if err != nil {
		return RemoteSnapshot{}, err
	}
	return snapshotFromSQLite(sqlitegen.RemoteSnapshot(row))
}

func (r pgRemotes) Create(ctx context.Context, p authz.Proof, n NewRemote) error {
	if _, err := authz.Verify(p, authz.StoreRemotesCreate, r.tok); err != nil {
		return err
	}
	return constraint(r.q.CreateRemote(ctx, pggen.CreateRemoteParams{
		ID: n.ID, Name: n.Name, Url: n.URL, SpkiPin: n.SPKIPin,
		CredentialSealed: n.CredentialSealed,
		CreatedAt:        pgTimestamp(n.CreatedAt),
		CreatedBy:        string(n.CreatedBy),
	}))
}

func (r pgRemotes) List(ctx context.Context, p authz.Proof) ([]Remote, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesList, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRemotes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Remote, 0, len(rows))
	for _, row := range rows {
		out = append(out, remoteFromPG(pggen.GetRemoteRow(row)))
	}
	return out, nil
}

func (r pgRemotes) Get(ctx context.Context, p authz.Proof, id string) (Remote, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesGet, r.tok); err != nil {
		return Remote{}, err
	}
	row, err := r.q.GetRemote(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Remote{}, ErrNotFound
	}
	if err != nil {
		return Remote{}, err
	}
	return remoteFromPG(row), nil
}

func (r pgRemotes) GetByName(ctx context.Context, p authz.Proof, name string) (Remote, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesGetByName, r.tok); err != nil {
		return Remote{}, err
	}
	row, err := r.q.GetRemoteByName(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Remote{}, ErrNotFound
	}
	if err != nil {
		return Remote{}, err
	}
	return remoteFromPG(pggen.GetRemoteRow(row)), nil
}

func (r pgRemotes) Count(ctx context.Context, p authz.Proof) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesCount, r.tok); err != nil {
		return 0, err
	}
	return r.q.CountRemotes(ctx)
}

func (r pgRemotes) SealedCredential(ctx context.Context, p authz.Proof, id string) ([]byte, error) {
	if _, err := authz.Verify(p, authz.StoreRemotesSealed, r.tok); err != nil {
		return nil, err
	}
	sealed, err := r.q.SealedRemoteCredential(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sealed, err
}

func (r pgRemotes) Rename(ctx context.Context, p authz.Proof, id, name string) error {
	if _, err := authz.Verify(p, authz.StoreRemotesRename, r.tok); err != nil {
		return err
	}
	return renameOutcome(r.q.RenameRemote(ctx, pggen.RenameRemoteParams{Name: name, ID: id}))
}

func (r pgRemotes) Delete(ctx context.Context, p authz.Proof, id string) error {
	if _, err := authz.Verify(p, authz.StoreRemotesDelete, r.tok); err != nil {
		return err
	}
	return affected(r.q.DeleteRemote(ctx, id))
}

func (r pgRemotes) WriteSnapshot(ctx context.Context, p authz.Proof, s RemoteSnapshot) error {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsWrite, r.tok); err != nil {
		return err
	}
	if err := validSnapshot(s); err != nil {
		return err
	}
	return constraint(r.q.WriteRemoteSnapshot(ctx, pggen.WriteRemoteSnapshotParams{
		RemoteID:         s.RemoteID,
		LastAttemptAt:    pgTimestamp(s.LastAttemptAt),
		LastOutcome:      s.LastOutcome,
		ObservedAt:       pgTimestamp(s.ObservedAt),
		InstanceIdentity: pgtype.Text{String: s.InstanceIdentity, Valid: true},
		Version:          pgtype.Text{String: s.Version, Valid: true},
		OrgCount:         pgtype.Int8{Int64: s.OrgCount, Valid: true},
		ProjectCount:     pgtype.Int8{Int64: s.ProjectCount, Valid: true},
		Listing:          pgtype.Text{String: string(s.Listing), Valid: true},
	}))
}

func (r pgRemotes) RecordFetchFailure(ctx context.Context, p authz.Proof, id string, at time.Time, outcome string) error {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsFail, r.tok); err != nil {
		return err
	}
	if err := validFailure(outcome); err != nil {
		return err
	}
	return constraint(r.q.RecordRemoteFetchFailure(ctx, pggen.RecordRemoteFetchFailureParams{
		RemoteID: id, LastAttemptAt: pgTimestamp(at), LastOutcome: outcome,
	}))
}

func (r pgRemotes) Snapshots(ctx context.Context, p authz.Proof) ([]RemoteSnapshot, error) {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsList, r.tok); err != nil {
		return nil, err
	}
	rows, err := r.q.ListRemoteSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RemoteSnapshot, 0, len(rows))
	for _, row := range rows {
		s, err := snapshotFromPG(pggen.RemoteSnapshot(row))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (r pgRemotes) Snapshot(ctx context.Context, p authz.Proof, id string) (RemoteSnapshot, error) {
	if _, err := authz.Verify(p, authz.StoreRemoteSnapshotsGet, r.tok); err != nil {
		return RemoteSnapshot{}, err
	}
	row, err := r.q.GetRemoteSnapshot(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return RemoteSnapshot{}, ErrNotFound
	}
	if err != nil {
		return RemoteSnapshot{}, err
	}
	return snapshotFromPG(pggen.RemoteSnapshot(row))
}

// pgTimestamp is the canonical write encoding for this file's timestamps.
func pgTimestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: CanonTime(t), Valid: true}
}

// renameOutcome maps a rename's row count and error to the two outcomes the
// caller can act on: a duplicate display name is a conflict, a missing entry is
// not found. Both engines route through it so they cannot disagree.
func renameOutcome(n int64, err error) error {
	if err != nil {
		return constraint(err)
	}
	return affected(n, nil)
}

// validSnapshot refuses a success write that is not actually a success. The
// table's CHECK enforces the same pairing, but a Go refusal names the field:
// a snapshot whose observed_at is zero has no listing to record, and writing
// one would be a claim about a fetch that never returned.
func validSnapshot(s RemoteSnapshot) error {
	if s.LastOutcome != OutcomeOK {
		return errors.New("store: remote snapshot success write carries a non-ok outcome — the success path records what a fetch RETURNED, and labelling it a failure would mark a live listing dead")
	}
	if s.ObservedAt.IsZero() {
		return errors.New("store: remote snapshot success write has no observation time — use RecordFetchFailure for a failed fetch")
	}
	if s.InstanceIdentity == "" {
		return errors.New("store: remote snapshot success write has no instance identity — self-connection refusal depends on it")
	}
	if !json.Valid(s.Listing) {
		return errors.New("store: remote snapshot listing is not valid JSON")
	}
	return nil
}

// OutcomeOK is the one snapshot outcome that means "this fetch returned a
// listing". It is named here rather than spelled inline because both sides of
// the invariant read it: the success path requires it and the failure path
// refuses it.
const OutcomeOK = "ok"

// validFailure refuses a FAILURE write claiming success. The CHECK cannot catch
// this one — `RecordFetchFailure` touches only the attempt columns, so an 'ok'
// written there lands beside whatever listing was already stored and marks a
// stale (or absent) listing current. The refusal has to be here, where the
// caller's intent is visible.
func validFailure(outcome string) error {
	if outcome == OutcomeOK {
		return errors.New("store: remote fetch FAILURE recorded with outcome 'ok' — that would mark the last known listing current on a fetch that did not return one")
	}
	if outcome == "" {
		return errors.New("store: remote fetch failure recorded with no outcome")
	}
	return nil
}

func remoteFromSQLite(row sqlitegen.GetRemoteRow) (Remote, error) {
	created, err := parseTime("remote", row.ID, row.CreatedAt)
	if err != nil {
		return Remote{}, err
	}
	return Remote{
		ID: row.ID, Name: row.Name, URL: row.Url, SPKIPin: row.SpkiPin,
		CreatedAt: created, CreatedBy: domain.PrincipalID(row.CreatedBy),
	}, nil
}

func remoteFromPG(row pggen.GetRemoteRow) Remote {
	return Remote{
		ID: row.ID, Name: row.Name, URL: row.Url, SPKIPin: row.SpkiPin,
		CreatedAt: row.CreatedAt.Time, CreatedBy: domain.PrincipalID(row.CreatedBy),
	}
}

func snapshotFromSQLite(row sqlitegen.RemoteSnapshot) (RemoteSnapshot, error) {
	attempt, err := parseTime("remote snapshot", row.RemoteID, row.LastAttemptAt)
	if err != nil {
		return RemoteSnapshot{}, err
	}
	out := RemoteSnapshot{
		RemoteID: row.RemoteID, LastAttemptAt: attempt, LastOutcome: row.LastOutcome,
	}
	if !row.ObservedAt.Valid {
		return out, nil
	}
	observed, err := parseTime("remote snapshot", row.RemoteID, row.ObservedAt.String)
	if err != nil {
		return RemoteSnapshot{}, err
	}
	out.ObservedAt = observed
	out.InstanceIdentity = row.InstanceIdentity.String
	out.Version = row.Version.String
	out.OrgCount = row.OrgCount.Int64
	out.ProjectCount = row.ProjectCount.Int64
	out.Listing = json.RawMessage(row.Listing.String)
	return out, nil
}

func snapshotFromPG(row pggen.RemoteSnapshot) (RemoteSnapshot, error) {
	out := RemoteSnapshot{
		RemoteID: row.RemoteID, LastAttemptAt: row.LastAttemptAt.Time,
		LastOutcome: row.LastOutcome,
	}
	if !row.ObservedAt.Valid {
		return out, nil
	}
	out.ObservedAt = row.ObservedAt.Time
	out.InstanceIdentity = row.InstanceIdentity.String
	out.Version = row.Version.String
	out.OrgCount = row.OrgCount.Int64
	out.ProjectCount = row.ProjectCount.Int64
	out.Listing = json.RawMessage(row.Listing.String)
	return out, nil
}
