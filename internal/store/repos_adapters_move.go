package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

func closeMoveRows(rows adapterTargetRows) error {
	if closer, ok := rows.(interface{ Close() error }); ok {
		return closer.Close()
	}
	if closer, ok := rows.(interface{ Close() }); ok {
		closer.Close()
	}
	return nil
}

func (r sqliteAdapters) MoveTarget(ctx context.Context, p authz.Proof, mutation AdapterRouteMoveMutation) (AdapterRouteMoveResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMoveTarget, r.tok)
	if err != nil {
		return AdapterRouteMoveResult{}, err
	}
	return beginAdapterTargetMove(ctx, sqliteAdoptDB{db: r.db}, chain, mutation)
}

func (r pgAdapters) MoveTarget(ctx context.Context, p authz.Proof, mutation AdapterRouteMoveMutation) (AdapterRouteMoveResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMoveTarget, r.tok)
	if err != nil {
		return AdapterRouteMoveResult{}, err
	}
	return beginAdapterTargetMove(ctx, pgAdoptDB{db: r.db}, chain, mutation)
}

func (r sqliteAdapters) MoveOrigin(ctx context.Context, p authz.Proof, mutation AdapterOriginMoveMutation) (AdapterRouteMoveBatch, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMoveOrigin, r.tok)
	if err != nil {
		return AdapterRouteMoveBatch{}, err
	}
	return beginAdapterOriginMove(ctx, sqliteAdoptDB{db: r.db}, chain, mutation)
}

func (r pgAdapters) MoveOrigin(ctx context.Context, p authz.Proof, mutation AdapterOriginMoveMutation) (AdapterRouteMoveBatch, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMoveOrigin, r.tok)
	if err != nil {
		return AdapterRouteMoveBatch{}, err
	}
	return beginAdapterOriginMove(ctx, pgAdoptDB{db: r.db}, chain, mutation)
}

func (r sqliteAdapters) Move(ctx context.Context, p authz.Proof, moveID string) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMove, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return readAdapterMove(ctx, sqliteAdoptDB{db: r.db}, chain, moveID, false)
}

func (r pgAdapters) Move(ctx context.Context, p authz.Proof, moveID string) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMove, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return readAdapterMove(ctx, pgAdoptDB{db: r.db}, chain, moveID, false)
}

func (r sqliteAdapters) CancelMove(ctx context.Context, p authz.Proof, moveID, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersCancelMove, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return cancelAdapterMove(ctx, sqliteAdoptDB{db: r.db}, chain, moveID, authorityPrincipalID, at)
}

func (r pgAdapters) CancelMove(ctx context.Context, p authz.Proof, moveID, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersCancelMove, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return cancelAdapterMove(ctx, pgAdoptDB{db: r.db}, chain, moveID, authorityPrincipalID, at)
}

func (r sqliteAdapters) ReplaceMoveTarget(ctx context.Context, p authz.Proof, moveID string, target AdapterTargetMutation, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersReplaceMoveTarget, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return replaceAdapterMoveTarget(ctx, sqliteAdoptDB{db: r.db}, chain, moveID, target, authorityPrincipalID, at)
}

func (r pgAdapters) ReplaceMoveTarget(ctx context.Context, p authz.Proof, moveID string, target AdapterTargetMutation, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersReplaceMoveTarget, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return replaceAdapterMoveTarget(ctx, pgAdoptDB{db: r.db}, chain, moveID, target, authorityPrincipalID, at)
}

func (r sqliteAdapters) ReplaceMoveOrigin(ctx context.Context, p authz.Proof, moveID, origin string, pendingCredential []byte, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersReplaceMoveOrigin, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return replaceAdapterMoveOrigin(ctx, sqliteAdoptDB{db: r.db}, chain, moveID, origin, pendingCredential, authorityPrincipalID, at)
}

func (r pgAdapters) ReplaceMoveOrigin(ctx context.Context, p authz.Proof, moveID, origin string, pendingCredential []byte, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersReplaceMoveOrigin, r.tok)
	if err != nil {
		return AdapterMove{}, err
	}
	return replaceAdapterMoveOrigin(ctx, pgAdoptDB{db: r.db}, chain, moveID, origin, pendingCredential, authorityPrincipalID, at)
}

func readAdapterMove(ctx context.Context, db adoptDB, chain domain.Scope, moveID string, lock bool) (AdapterMove, error) {
	var out AdapterMove
	var keep bool
	var created adapterStoredTime
	query := db.SQL(
		`SELECT m.id,m.adapter_id,m.kind,m.state,m.keep_remote,COALESCE(m.pending_origin,a.origin),m.created_at,a.authority_principal_id FROM adapter_route_moves m JOIN adapters a ON a.id=m.adapter_id AND a.org_id=m.org_id AND a.project_id=m.project_id WHERE m.id=? AND m.org_id=? AND m.project_id=?`,
		`SELECT m.id,m.adapter_id,m.kind,m.state,m.keep_remote,COALESCE(m.pending_origin,a.origin),m.created_at,a.authority_principal_id FROM adapter_route_moves m JOIN adapters a ON a.id=m.adapter_id AND a.org_id=m.org_id AND a.project_id=m.project_id WHERE m.id=$1 AND m.org_id=$2 AND m.project_id=$3`)
	if lock {
		query += db.SQL(``, ` FOR UPDATE OF m,a`)
	}
	err := db.QueryRow(ctx, query, moveID, chain.Org, chain.Project).Scan(&out.ID, &out.AdapterID, &out.Kind, &out.State, &keep, &out.PendingOrigin, &created, &out.AuthorityPrincipalID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterMove{}, ErrNotFound
	}
	if err != nil {
		return AdapterMove{}, err
	}
	out.KeepRemote, out.CreatedAt = keep, created.value
	targetQuery := db.SQL(
		`SELECT target_id,environment_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,orphaned_names FROM adapter_route_move_targets WHERE move_id=? AND org_id=? AND project_id=? ORDER BY target_id`,
		`SELECT target_id,environment_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,orphaned_names FROM adapter_route_move_targets WHERE move_id=$1 AND org_id=$2 AND project_id=$3 ORDER BY target_id`)
	rows, err := db.Query(ctx, targetQuery, moveID, chain.Org, chain.Project)
	if err != nil {
		return AdapterMove{}, err
	}
	for rows.Next() {
		var target AdapterMoveTarget
		var orphanJSON []byte
		if err := rows.Scan(&target.TargetID, &target.EnvironmentID, &target.DestinationKind, &target.DestinationOwner, &target.DestinationName, &target.DestinationID, &target.NamePrefix, &orphanJSON); err != nil {
			_ = closeMoveRows(rows)
			return AdapterMove{}, err
		}
		if err := json.Unmarshal(orphanJSON, &target.Orphaned); err != nil {
			_ = closeMoveRows(rows)
			return AdapterMove{}, err
		}
		if target.Orphaned == nil {
			target.Orphaned = []string{}
		}
		out.Targets = append(out.Targets, target)
	}
	if err := closeMoveRows(rows); err != nil {
		return AdapterMove{}, err
	}
	jobQuery := db.SQL(
		`SELECT id,target_id,kind,state FROM adapter_outbox WHERE route_move_id=? AND org_id=? AND project_id=? ORDER BY created_at,id`,
		`SELECT id,target_id,kind,state FROM adapter_outbox WHERE route_move_id=$1 AND org_id=$2 AND project_id=$3 ORDER BY created_at,id`)
	jobRows, err := db.Query(ctx, jobQuery, moveID, chain.Org, chain.Project)
	if err != nil {
		return AdapterMove{}, err
	}
	jobs := map[string][]AdapterMoveJob{}
	for jobRows.Next() {
		var job AdapterMoveJob
		if err := jobRows.Scan(&job.ID, &job.TargetID, &job.Kind, &job.State); err != nil {
			_ = closeMoveRows(jobRows)
			return AdapterMove{}, err
		}
		jobs[job.TargetID] = append(jobs[job.TargetID], job)
	}
	if err := closeMoveRows(jobRows); err != nil {
		return AdapterMove{}, err
	}
	for i := range out.Targets {
		out.Targets[i].Jobs = jobs[out.Targets[i].TargetID]
		if out.Targets[i].Jobs == nil {
			out.Targets[i].Jobs = []AdapterMoveJob{}
		}
	}
	return out, nil
}

func cancelAdapterMove(ctx context.Context, db adoptDB, chain domain.Scope, moveID, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	if moveID == "" || authorityPrincipalID == "" || at.IsZero() {
		return AdapterMove{}, fmt.Errorf("%w: move cancellation requires move, authority, and timestamp", domain.ErrInvalid)
	}
	move, err := readAdapterMove(ctx, db, chain, moveID, true)
	if err != nil {
		return AdapterMove{}, err
	}
	if move.State != "attention_required" {
		return AdapterMove{}, fmt.Errorf("%w: only an attention-required route move can be canceled", domain.ErrConflict)
	}
	previousAuthority := move.AuthorityPrincipalID
	stamp := db.Stamp(at)
	for _, target := range move.Targets {
		var generation int64
		var providerBusy int
		lookup := db.SQL(
			`SELECT generation,CASE WHEN provider_lease_job_id IS NULL THEN 0 ELSE 1 END FROM adapter_targets WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND state='moving' AND active_job_id IS NULL`,
			`SELECT generation,CASE WHEN provider_lease_job_id IS NULL THEN 0 ELSE 1 END FROM adapter_targets WHERE id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4 AND state='moving' AND active_job_id IS NULL FOR UPDATE`)
		if err := db.QueryRow(ctx, lookup, target.TargetID, chain.Org, chain.Project, target.EnvironmentID).Scan(&generation, &providerBusy); err != nil {
			return AdapterMove{}, adapter.ErrSuperseded
		}
		if providerBusy != 0 {
			return AdapterMove{}, adapter.ErrProviderBusy
		}
		jobID := newAdapterID("job")
		nextGeneration := generation + 1
		insertJob := db.SQL(
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,'converge',?,?,?,?,0,?,'queued',?)`,
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,'converge',$6,$7,$8,$9,0,$10,'queued',$11)`)
		if rows, err := db.Exec(ctx, insertJob, jobID, chain.Org, chain.Project, target.EnvironmentID, target.TargetID, moveID, authorityPrincipalID, nextGeneration, target.TargetID, stamp, stamp); err != nil || rows != 1 {
			return AdapterMove{}, errors.Join(err, ErrConflict)
		}
		activateOld := db.SQL(
			`UPDATE adapter_targets SET generation=?,state='active',sync_status='converging',failure_names='[]',active_job_id=? WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND state='moving' AND active_job_id IS NULL AND provider_lease_job_id IS NULL`,
			`UPDATE adapter_targets SET generation=$1,state='active',sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2 WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7 AND state='moving' AND active_job_id IS NULL AND provider_lease_job_id IS NULL`)
		if rows, err := db.Exec(ctx, activateOld, nextGeneration, jobID, target.TargetID, chain.Org, chain.Project, target.EnvironmentID, generation); err != nil || rows != 1 {
			return AdapterMove{}, errors.Join(err, adapter.ErrSuperseded)
		}
	}
	restoreAdapter := db.SQL(
		`UPDATE adapters SET state='active',authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state IN ('active','moving')`,
		`UPDATE adapters SET state='active',authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state IN ('active','moving')`)
	if rows, err := db.Exec(ctx, restoreAdapter, authorityPrincipalID, move.AdapterID, chain.Org, chain.Project); err != nil || rows != 1 {
		return AdapterMove{}, errors.Join(err, adapter.ErrSuperseded)
	}
	deleteClaims := db.SQL(`DELETE FROM adapter_route_move_claims WHERE move_id=? AND org_id=? AND project_id=?`, `DELETE FROM adapter_route_move_claims WHERE move_id=$1 AND org_id=$2 AND project_id=$3`)
	if _, err := db.Exec(ctx, deleteClaims, moveID, chain.Org, chain.Project); err != nil {
		return AdapterMove{}, err
	}
	cancel := db.SQL(
		`UPDATE adapter_route_moves SET state='canceled',pending_origin=NULL,pending_credential_ciphertext=NULL WHERE id=? AND org_id=? AND project_id=? AND state='attention_required'`,
		`UPDATE adapter_route_moves SET state='canceled',pending_origin=NULL,pending_credential_ciphertext=NULL WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='attention_required'`)
	if rows, err := db.Exec(ctx, cancel, moveID, chain.Org, chain.Project); err != nil || rows != 1 {
		return AdapterMove{}, errors.Join(err, adapter.ErrSuperseded)
	}
	out, err := readAdapterMove(ctx, db, chain, moveID, false)
	if err != nil {
		return AdapterMove{}, err
	}
	out.PreviousAuthorityPrincipalID = previousAuthority
	return out, nil
}

func replaceAdapterMoveTarget(ctx context.Context, db adoptDB, chain domain.Scope, moveID string, target AdapterTargetMutation, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	if err := validatePendingTarget(target); err != nil {
		return AdapterMove{}, err
	}
	if moveID == "" || authorityPrincipalID == "" || at.IsZero() {
		return AdapterMove{}, fmt.Errorf("%w: pending target replacement requires move, authority, and timestamp", domain.ErrInvalid)
	}
	move, err := readAdapterMove(ctx, db, chain, moveID, true)
	if err != nil {
		return AdapterMove{}, err
	}
	if move.State != "attention_required" || move.Kind != "target" || len(move.Targets) != 1 || move.Targets[0].TargetID != target.ID || move.Targets[0].EnvironmentID != target.EnvironmentID || move.AdapterID != target.AdapterID {
		return AdapterMove{}, fmt.Errorf("%w: pending target replacement does not match the attention-required move", domain.ErrConflict)
	}
	previousAuthority := move.AuthorityPrincipalID
	deleteClaims := db.SQL(`DELETE FROM adapter_route_move_claims WHERE move_id=? AND org_id=? AND project_id=?`, `DELETE FROM adapter_route_move_claims WHERE move_id=$1 AND org_id=$2 AND project_id=$3`)
	if _, err := db.Exec(ctx, deleteClaims, moveID, chain.Org, chain.Project); err != nil {
		return AdapterMove{}, err
	}
	deleteKeys := db.SQL(`DELETE FROM adapter_route_move_keys WHERE move_id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=?`, `DELETE FROM adapter_route_move_keys WHERE move_id=$1 AND target_id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5`)
	if _, err := db.Exec(ctx, deleteKeys, moveID, target.ID, chain.Org, chain.Project, target.EnvironmentID); err != nil {
		return AdapterMove{}, err
	}
	updateTarget := db.SQL(
		`UPDATE adapter_route_move_targets SET destination_kind=?,destination_owner=?,destination_name=?,destination_id=0,name_prefix=? WHERE move_id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=?`,
		`UPDATE adapter_route_move_targets SET destination_kind=$1,destination_owner=$2,destination_name=$3,destination_id=0,name_prefix=$4 WHERE move_id=$5 AND target_id=$6 AND org_id=$7 AND project_id=$8 AND environment_id=$9`)
	if rows, err := db.Exec(ctx, updateTarget, target.DestinationKind, target.DestinationOwner, target.DestinationName, target.NamePrefix, moveID, target.ID, chain.Org, chain.Project, target.EnvironmentID); err != nil || rows != 1 {
		return AdapterMove{}, errors.Join(err, adapter.ErrSuperseded)
	}
	for _, keyID := range target.KeyIDs {
		insertKey := db.SQL(
			`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES (?,?,?,?,?,?)`,
			`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ($1,$2,$3,$4,$5,$6)`)
		if rows, err := db.Exec(ctx, insertKey, moveID, chain.Org, chain.Project, target.EnvironmentID, target.ID, keyID); err != nil || rows != 1 {
			return AdapterMove{}, errors.Join(err, ErrConflict)
		}
	}
	if err := reserveAdapterMoveClaims(ctx, db, chain, moveID, move.PendingOrigin, target); err != nil {
		return AdapterMove{}, err
	}
	if err := resumeAdapterMove(ctx, db, chain, move, authorityPrincipalID, at); err != nil {
		return AdapterMove{}, err
	}
	out, err := readAdapterMove(ctx, db, chain, moveID, false)
	if err != nil {
		return AdapterMove{}, err
	}
	out.PreviousAuthorityPrincipalID = previousAuthority
	return out, nil
}

func replaceAdapterMoveOrigin(ctx context.Context, db adoptDB, chain domain.Scope, moveID, origin string, pendingCredential []byte, authorityPrincipalID string, at time.Time) (AdapterMove, error) {
	if moveID == "" || origin == "" || len(pendingCredential) == 0 || authorityPrincipalID == "" || at.IsZero() {
		return AdapterMove{}, fmt.Errorf("%w: pending origin replacement requires move, origin, credential, authority, and timestamp", domain.ErrInvalid)
	}
	move, err := readAdapterMove(ctx, db, chain, moveID, true)
	if err != nil {
		return AdapterMove{}, err
	}
	if move.State != "attention_required" || move.Kind != "origin" {
		return AdapterMove{}, fmt.Errorf("%w: pending origin replacement requires an attention-required origin move", domain.ErrConflict)
	}
	previousAuthority := move.AuthorityPrincipalID
	var collisions int
	collisionQuery := db.SQL(
		`SELECT (SELECT COUNT(*) FROM adapters WHERE org_id=? AND project_id=? AND id<>? AND state<>'tombstoned' AND origin=?)+(SELECT COUNT(*) FROM adapter_route_moves WHERE org_id=? AND project_id=? AND id<>? AND state NOT IN ('completed','canceled') AND pending_origin=?)`,
		`SELECT (SELECT COUNT(*) FROM adapters WHERE org_id=$1 AND project_id=$2 AND id<>$3 AND state<>'tombstoned' AND origin=$4)+(SELECT COUNT(*) FROM adapter_route_moves WHERE org_id=$5 AND project_id=$6 AND id<>$7 AND state NOT IN ('completed','canceled') AND pending_origin=$8)`)
	if err := db.QueryRow(ctx, collisionQuery, chain.Org, chain.Project, move.AdapterID, origin, chain.Org, chain.Project, moveID, origin).Scan(&collisions); err != nil {
		return AdapterMove{}, err
	}
	if collisions != 0 {
		return AdapterMove{}, fmt.Errorf("%w: adapter origin is already configured or pending", domain.ErrConflict)
	}
	deleteClaims := db.SQL(`DELETE FROM adapter_route_move_claims WHERE move_id=? AND org_id=? AND project_id=?`, `DELETE FROM adapter_route_move_claims WHERE move_id=$1 AND org_id=$2 AND project_id=$3`)
	if _, err := db.Exec(ctx, deleteClaims, moveID, chain.Org, chain.Project); err != nil {
		return AdapterMove{}, err
	}
	updateMove := db.SQL(
		`UPDATE adapter_route_moves SET pending_origin=?,pending_credential_ciphertext=? WHERE id=? AND org_id=? AND project_id=? AND state='attention_required' AND kind='origin'`,
		`UPDATE adapter_route_moves SET pending_origin=$1,pending_credential_ciphertext=$2 WHERE id=$3 AND org_id=$4 AND project_id=$5 AND state='attention_required' AND kind='origin'`)
	if rows, err := db.Exec(ctx, updateMove, origin, pendingCredential, moveID, chain.Org, chain.Project); err != nil || rows != 1 {
		return AdapterMove{}, errors.Join(err, adapter.ErrSuperseded)
	}
	resetDestinations := db.SQL(`UPDATE adapter_route_move_targets SET destination_id=0 WHERE move_id=? AND org_id=? AND project_id=?`, `UPDATE adapter_route_move_targets SET destination_id=0 WHERE move_id=$1 AND org_id=$2 AND project_id=$3`)
	if _, err := db.Exec(ctx, resetDestinations, moveID, chain.Org, chain.Project); err != nil {
		return AdapterMove{}, err
	}
	for _, target := range move.Targets {
		keyQuery := db.SQL(
			`SELECT key_id FROM adapter_route_move_keys WHERE move_id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? ORDER BY key_id`,
			`SELECT key_id FROM adapter_route_move_keys WHERE move_id=$1 AND target_id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5 ORDER BY key_id`)
		rows, err := db.Query(ctx, keyQuery, moveID, target.TargetID, chain.Org, chain.Project, target.EnvironmentID)
		if err != nil {
			return AdapterMove{}, err
		}
		var keyIDs []string
		for rows.Next() {
			var keyID string
			if err := rows.Scan(&keyID); err != nil {
				_ = closeMoveRows(rows)
				return AdapterMove{}, err
			}
			keyIDs = append(keyIDs, keyID)
		}
		if err := closeMoveRows(rows); err != nil {
			return AdapterMove{}, err
		}
		if err := reserveAdapterMoveClaims(ctx, db, chain, moveID, origin, AdapterTargetMutation{
			ID: target.TargetID, AdapterID: move.AdapterID, EnvironmentID: target.EnvironmentID,
			DestinationKind: target.DestinationKind, DestinationOwner: target.DestinationOwner,
			DestinationName: target.DestinationName, NamePrefix: target.NamePrefix, KeyIDs: keyIDs,
		}); err != nil {
			return AdapterMove{}, err
		}
	}
	move.PendingOrigin = origin
	if err := resumeAdapterMove(ctx, db, chain, move, authorityPrincipalID, at); err != nil {
		return AdapterMove{}, err
	}
	out, err := readAdapterMove(ctx, db, chain, moveID, false)
	if err != nil {
		return AdapterMove{}, err
	}
	out.PreviousAuthorityPrincipalID = previousAuthority
	return out, nil
}

func resumeAdapterMove(ctx context.Context, db adoptDB, chain domain.Scope, move AdapterMove, authorityPrincipalID string, at time.Time) error {
	stamp := db.Stamp(at)
	activate := db.SQL(
		`UPDATE adapter_route_moves SET state='activating',authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state='attention_required'`,
		`UPDATE adapter_route_moves SET state='activating',authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state='attention_required'`)
	if rows, err := db.Exec(ctx, activate, authorityPrincipalID, move.ID, chain.Org, chain.Project); err != nil || rows != 1 {
		return errors.Join(err, adapter.ErrSuperseded)
	}
	for _, target := range move.Targets {
		var generation int64
		lookup := db.SQL(
			`SELECT generation FROM adapter_targets WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND state='moving' AND active_job_id IS NULL AND provider_lease_job_id IS NULL`,
			`SELECT generation FROM adapter_targets WHERE id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4 AND state='moving' AND active_job_id IS NULL AND provider_lease_job_id IS NULL FOR UPDATE`)
		if err := db.QueryRow(ctx, lookup, target.TargetID, chain.Org, chain.Project, target.EnvironmentID).Scan(&generation); err != nil {
			return adapter.ErrSuperseded
		}
		jobID := newAdapterID("job")
		nextGeneration := generation + 1
		insertJob := db.SQL(
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,'activate',?,?,?,?,0,?,'queued',?)`,
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,'activate',$6,$7,$8,$9,0,$10,'queued',$11)`)
		if rows, err := db.Exec(ctx, insertJob, jobID, chain.Org, chain.Project, target.EnvironmentID, target.TargetID, move.ID, authorityPrincipalID, nextGeneration, target.TargetID, stamp, stamp); err != nil || rows != 1 {
			return errors.Join(err, ErrConflict)
		}
		mark := db.SQL(
			`UPDATE adapter_targets SET generation=?,sync_status='converging',failure_names='[]',active_job_id=? WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND state='moving' AND active_job_id IS NULL AND provider_lease_job_id IS NULL`,
			`UPDATE adapter_targets SET generation=$1,sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2 WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7 AND state='moving' AND active_job_id IS NULL AND provider_lease_job_id IS NULL`)
		if rows, err := db.Exec(ctx, mark, nextGeneration, jobID, target.TargetID, chain.Org, chain.Project, target.EnvironmentID, generation); err != nil || rows != 1 {
			return errors.Join(err, adapter.ErrSuperseded)
		}
	}
	updateAdapter := db.SQL(`UPDATE adapters SET authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state IN ('active','moving')`, `UPDATE adapters SET authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state IN ('active','moving')`)
	if rows, err := db.Exec(ctx, updateAdapter, authorityPrincipalID, move.AdapterID, chain.Org, chain.Project); err != nil || rows != 1 {
		return errors.Join(err, adapter.ErrSuperseded)
	}
	return nil
}

func beginAdapterOriginMove(ctx context.Context, db adoptDB, chain domain.Scope, mutation AdapterOriginMoveMutation) (AdapterRouteMoveBatch, error) {
	if mutation.AdapterID == "" || mutation.Origin == "" || len(mutation.PendingCredentialCiphertext) == 0 || mutation.AuthorityPrincipalID == "" || mutation.At.IsZero() {
		return AdapterRouteMoveBatch{}, fmt.Errorf("%w: origin move requires adapter, origin, sealed credential, authority, and timestamp", domain.ErrInvalid)
	}
	if mutation.MoveID == "" {
		mutation.MoveID = newAdapterID("arm")
	}
	stamp := db.Stamp(mutation.At)
	var currentOrigin string
	var providerBusy int
	lookupAdapter := db.SQL(
		`SELECT a.origin,(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active' AND t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>?) FROM adapters a WHERE a.id=? AND a.org_id=? AND a.project_id=? AND a.state='active'`,
		`SELECT a.origin,(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active' AND t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1) FROM adapters a WHERE a.id=$2 AND a.org_id=$3 AND a.project_id=$4 AND a.state='active' FOR UPDATE`)
	err := db.QueryRow(ctx, lookupAdapter, stamp, mutation.AdapterID, chain.Org, chain.Project).Scan(&currentOrigin, &providerBusy)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterRouteMoveBatch{}, ErrNotFound
	}
	if err != nil {
		return AdapterRouteMoveBatch{}, err
	}
	if providerBusy != 0 {
		return AdapterRouteMoveBatch{}, adapter.ErrProviderBusy
	}
	if currentOrigin == mutation.Origin {
		return AdapterRouteMoveBatch{}, fmt.Errorf("%w: adapter origin is unchanged", domain.ErrInvalid)
	}
	var collision int
	collisionQuery := db.SQL(
		`SELECT (SELECT COUNT(*) FROM adapters WHERE org_id=? AND project_id=? AND id<>? AND state<>'tombstoned' AND origin=?)+(SELECT COUNT(*) FROM adapter_route_moves WHERE org_id=? AND project_id=? AND state<>'completed' AND pending_origin=?)`,
		`SELECT (SELECT COUNT(*) FROM adapters WHERE org_id=$1 AND project_id=$2 AND id<>$3 AND state<>'tombstoned' AND origin=$4)+(SELECT COUNT(*) FROM adapter_route_moves WHERE org_id=$5 AND project_id=$6 AND state<>'completed' AND pending_origin=$7)`)
	if err := db.QueryRow(ctx, collisionQuery, chain.Org, chain.Project, mutation.AdapterID, mutation.Origin, chain.Org, chain.Project, mutation.Origin).Scan(&collision); err != nil {
		return AdapterRouteMoveBatch{}, err
	}
	if collision != 0 {
		return AdapterRouteMoveBatch{}, fmt.Errorf("%w: adapter origin is already configured or pending", domain.ErrConflict)
	}
	type originTarget struct {
		id, environmentID, kind, owner, name, prefix, activeJob string
		destinationID, generation                               int64
		orphaned                                                []string
	}
	targetQuery := db.SQL(
		`SELECT t.id,t.environment_id,t.destination_kind,t.destination_owner,t.destination_name,t.destination_id,t.name_prefix,t.generation,COALESCE(t.active_job_id,''),COALESCE((SELECT json_group_array(value) FROM (SELECT surface||':'||effective_name AS value FROM adapter_ledger WHERE target_id=t.id AND org_id=t.org_id AND project_id=t.project_id AND environment_id=t.environment_id AND state IN ('owned','dispatched') ORDER BY surface,effective_name)),'[]') FROM adapter_targets t WHERE t.adapter_id=? AND t.org_id=? AND t.project_id=? AND t.state='active' ORDER BY t.id`,
		`SELECT t.id,t.environment_id,t.destination_kind,t.destination_owner,t.destination_name,t.destination_id,t.name_prefix,t.generation,COALESCE(t.active_job_id,''),COALESCE((SELECT jsonb_agg(surface||':'||effective_name ORDER BY surface,effective_name) FROM adapter_ledger WHERE target_id=t.id AND org_id=t.org_id AND project_id=t.project_id AND environment_id=t.environment_id AND state IN ('owned','dispatched')),'[]'::jsonb) FROM adapter_targets t WHERE t.adapter_id=$1 AND t.org_id=$2 AND t.project_id=$3 AND t.state='active' ORDER BY t.id FOR UPDATE`)
	rows, err := db.Query(ctx, targetQuery, mutation.AdapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterRouteMoveBatch{}, err
	}
	var targets []originTarget
	for rows.Next() {
		var target originTarget
		var orphanRaw []byte
		if err := rows.Scan(&target.id, &target.environmentID, &target.kind, &target.owner, &target.name, &target.destinationID, &target.prefix, &target.generation, &target.activeJob, &orphanRaw); err != nil {
			_ = closeMoveRows(rows)
			return AdapterRouteMoveBatch{}, err
		}
		if err := json.Unmarshal(orphanRaw, &target.orphaned); err != nil {
			_ = closeMoveRows(rows)
			return AdapterRouteMoveBatch{}, err
		}
		targets = append(targets, target)
	}
	if err := closeMoveRows(rows); err != nil {
		return AdapterRouteMoveBatch{}, err
	}
	if len(targets) == 0 {
		return AdapterRouteMoveBatch{}, fmt.Errorf("%w: origin move requires at least one active target", domain.ErrInvalid)
	}
	moveState, jobKind := "scrubbing", "scrub"
	if mutation.KeepRemote {
		moveState, jobKind = "activating", "activate"
	}
	insertMove := db.SQL(
		`INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,kind,pending_origin,pending_credential_ciphertext,authority_principal_id,state,keep_remote,created_at) VALUES (?,?,?,?,'origin',?,?,?,?,?,?)`,
		`INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,kind,pending_origin,pending_credential_ciphertext,authority_principal_id,state,keep_remote,created_at) VALUES ($1,$2,$3,$4,'origin',$5,$6,$7,$8,$9,$10)`)
	if affected, err := db.Exec(ctx, insertMove, mutation.MoveID, chain.Org, chain.Project, mutation.AdapterID, mutation.Origin, mutation.PendingCredentialCiphertext, mutation.AuthorityPrincipalID, moveState, mutation.KeepRemote, stamp); err != nil || affected != 1 {
		if err != nil {
			return AdapterRouteMoveBatch{}, err
		}
		return AdapterRouteMoveBatch{}, ErrConflict
	}
	batch := AdapterRouteMoveBatch{MoveID: mutation.MoveID}
	for _, target := range targets {
		pendingOrphans := []string{}
		if mutation.KeepRemote {
			pendingOrphans = target.orphaned
		}
		orphanJSON, _ := json.Marshal(pendingOrphans)
		insertTarget := db.SQL(
			`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,orphaned_names) VALUES (?,?,?,?,?,?,?,?,0,?,?)`,
			`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,orphaned_names) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,$9,$10)`)
		if affected, err := db.Exec(ctx, insertTarget, mutation.MoveID, chain.Org, chain.Project, target.environmentID, target.id, target.kind, target.owner, target.name, target.prefix, string(orphanJSON)); err != nil || affected != 1 {
			if err != nil {
				return AdapterRouteMoveBatch{}, err
			}
			return AdapterRouteMoveBatch{}, ErrConflict
		}
		keyQuery := db.SQL(
			`SELECT key_id FROM adapter_target_keys WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=? ORDER BY key_id`,
			`SELECT key_id FROM adapter_target_keys WHERE target_id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4 ORDER BY key_id`)
		keyRows, err := db.Query(ctx, keyQuery, target.id, chain.Org, chain.Project, target.environmentID)
		if err != nil {
			return AdapterRouteMoveBatch{}, err
		}
		keyCount := 0
		var keyIDs []string
		for keyRows.Next() {
			var keyID string
			if err := keyRows.Scan(&keyID); err != nil {
				_ = closeMoveRows(keyRows)
				return AdapterRouteMoveBatch{}, err
			}
			insertKey := db.SQL(
				`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES (?,?,?,?,?,?)`,
				`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ($1,$2,$3,$4,$5,$6)`)
			if _, err := db.Exec(ctx, insertKey, mutation.MoveID, chain.Org, chain.Project, target.environmentID, target.id, keyID); err != nil {
				_ = closeMoveRows(keyRows)
				return AdapterRouteMoveBatch{}, err
			}
			keyCount++
			keyIDs = append(keyIDs, keyID)
		}
		_ = closeMoveRows(keyRows)
		if keyCount == 0 {
			return AdapterRouteMoveBatch{}, fmt.Errorf("%w: adapter target has no keys", domain.ErrInvalid)
		}
		if err := reserveAdapterMoveClaims(ctx, db, chain, mutation.MoveID, mutation.Origin, AdapterTargetMutation{
			ID: target.id, AdapterID: mutation.AdapterID, EnvironmentID: target.environmentID,
			DestinationKind: target.kind, DestinationOwner: target.owner, DestinationName: target.name,
			NamePrefix: target.prefix, KeyIDs: keyIDs,
		}); err != nil {
			return AdapterRouteMoveBatch{}, err
		}
		if target.activeJob != "" {
			supersede := db.SQL(
				`UPDATE adapter_outbox SET state='superseded',finished_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state IN ('queued','running')`,
				`UPDATE adapter_outbox SET state='superseded',finished_at=$1,lease_owner=NULL,lease_expires_at=NULL WHERE id=$2 AND target_id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND state IN ('queued','running')`)
			if affected, err := db.Exec(ctx, supersede, stamp, target.activeJob, target.id, chain.Org, chain.Project, target.environmentID); err != nil || affected != 1 {
				if err != nil {
					return AdapterRouteMoveBatch{}, err
				}
				return AdapterRouteMoveBatch{}, adapter.ErrSuperseded
			}
		}
		if mutation.KeepRemote {
			release := db.SQL(
				`UPDATE adapter_ledger SET state='released',updated_at=? WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state<>'released'`,
				`UPDATE adapter_ledger SET state='released',updated_at=$1 WHERE target_id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5 AND state<>'released'`)
			if _, err := db.Exec(ctx, release, stamp, target.id, chain.Org, chain.Project, target.environmentID); err != nil {
				return AdapterRouteMoveBatch{}, err
			}
		}
		jobID := newAdapterID("job")
		generation := target.generation + 1
		insertJob := db.SQL(
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?,'queued',?)`,
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,'queued',$12)`)
		if _, err := db.Exec(ctx, insertJob, jobID, chain.Org, chain.Project, target.environmentID, target.id, jobKind, mutation.MoveID, mutation.AuthorityPrincipalID, generation, target.id, stamp, stamp); err != nil {
			return AdapterRouteMoveBatch{}, err
		}
		mark := db.SQL(
			`UPDATE adapter_targets SET generation=?,state='moving',sync_status='converging',failure_names='[]',active_job_id=? WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND state='active' AND provider_lease_job_id IS NULL`,
			`UPDATE adapter_targets SET generation=$1,state='moving',sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2 WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7 AND state='active' AND provider_lease_job_id IS NULL`)
		if affected, err := db.Exec(ctx, mark, generation, jobID, target.id, chain.Org, chain.Project, target.environmentID, target.generation); err != nil || affected != 1 {
			if err != nil {
				return AdapterRouteMoveBatch{}, err
			}
			return AdapterRouteMoveBatch{}, adapter.ErrProviderBusy
		}
		result := AdapterRouteMoveResult{MoveID: mutation.MoveID, TargetID: target.id, JobID: jobID, SupersededJobID: target.activeJob, Generation: generation}
		if mutation.KeepRemote {
			result.Orphaned = append([]string(nil), target.orphaned...)
			batch.Orphaned = append(batch.Orphaned, target.orphaned...)
		}
		batch.Targets = append(batch.Targets, result)
	}
	markAdapter := db.SQL(
		`UPDATE adapters SET state='moving',authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state='active'`,
		`UPDATE adapters SET state='moving',authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state='active'`)
	if affected, err := db.Exec(ctx, markAdapter, mutation.AuthorityPrincipalID, mutation.AdapterID, chain.Org, chain.Project); err != nil || affected != 1 {
		if err != nil {
			return AdapterRouteMoveBatch{}, err
		}
		return AdapterRouteMoveBatch{}, ErrNotFound
	}
	return batch, nil
}

func validatePendingTarget(m AdapterTargetMutation) error {
	if m.ID == "" || m.AdapterID == "" || m.EnvironmentID == "" || m.DestinationOwner == "" || len(m.KeyIDs) == 0 {
		return fmt.Errorf("%w: pending adapter target requires ids, environment, destination, and keys", domain.ErrInvalid)
	}
	switch m.DestinationKind {
	case string(adapter.Repository):
		if m.DestinationName == "" {
			return fmt.Errorf("%w: repository target requires repository name", domain.ErrInvalid)
		}
	case string(adapter.Organization):
		if m.DestinationName != "" {
			return fmt.Errorf("%w: organization target does not take repository name", domain.ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported adapter destination kind", domain.ErrInvalid)
	}
	seen := make(map[string]bool, len(m.KeyIDs))
	for _, keyID := range m.KeyIDs {
		if keyID == "" || seen[keyID] {
			return fmt.Errorf("%w: adapter target key ids must be non-empty and unique", domain.ErrInvalid)
		}
		seen[keyID] = true
	}
	return nil
}

func beginAdapterTargetMove(ctx context.Context, db adoptDB, chain domain.Scope, mutation AdapterRouteMoveMutation) (AdapterRouteMoveResult, error) {
	if err := validatePendingTarget(mutation.Target); err != nil {
		return AdapterRouteMoveResult{}, err
	}
	if mutation.ExpectedGeneration <= 0 || mutation.AuthorityPrincipalID == "" || mutation.At.IsZero() {
		return AdapterRouteMoveResult{}, fmt.Errorf("%w: target move requires generation, authority, and timestamp", domain.ErrInvalid)
	}
	if mutation.MoveID == "" {
		mutation.MoveID = newAdapterID("arm")
	}
	stamp := db.Stamp(mutation.At)
	var current struct {
		adapterID, origin, environmentID, kind, owner, name, prefix, activeJob string
		destinationID, generation                                              int64
		providerBusy                                                           int
	}
	var orphanRaw []byte
	lookup := db.SQL(
		`SELECT t.adapter_id,a.origin,t.environment_id,t.destination_kind,t.destination_owner,t.destination_name,t.destination_id,t.name_prefix,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>? THEN 1 ELSE 0 END,COALESCE((SELECT json_group_array(value) FROM (SELECT surface||':'||effective_name AS value FROM adapter_ledger WHERE target_id=t.id AND org_id=t.org_id AND project_id=t.project_id AND environment_id=t.environment_id AND state IN ('owned','dispatched') ORDER BY surface,effective_name)),'[]') FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=? AND t.org_id=? AND t.project_id=? AND t.state='active' AND a.state='active'`,
		`SELECT t.adapter_id,a.origin,t.environment_id,t.destination_kind,t.destination_owner,t.destination_name,t.destination_id,t.name_prefix,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1 THEN 1 ELSE 0 END,COALESCE((SELECT jsonb_agg(surface||':'||effective_name ORDER BY surface,effective_name) FROM adapter_ledger WHERE target_id=t.id AND org_id=t.org_id AND project_id=t.project_id AND environment_id=t.environment_id AND state IN ('owned','dispatched')),'[]'::jsonb) FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=$2 AND t.org_id=$3 AND t.project_id=$4 AND t.state='active' AND a.state='active' FOR UPDATE OF t,a`)
	err := db.QueryRow(ctx, lookup, stamp, mutation.Target.ID, chain.Org, chain.Project).Scan(
		&current.adapterID, &current.origin, &current.environmentID, &current.kind, &current.owner, &current.name,
		&current.destinationID, &current.prefix, &current.generation, &current.activeJob,
		&current.providerBusy, &orphanRaw)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterRouteMoveResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterRouteMoveResult{}, err
	}
	if current.providerBusy != 0 {
		return AdapterRouteMoveResult{}, adapter.ErrProviderBusy
	}
	if current.generation != mutation.ExpectedGeneration {
		return AdapterRouteMoveResult{}, adapter.ErrSuperseded
	}
	if current.adapterID != mutation.Target.AdapterID {
		return AdapterRouteMoveResult{}, fmt.Errorf("%w: target does not belong to adapter", domain.ErrConflict)
	}
	if current.environmentID != mutation.Target.EnvironmentID {
		return AdapterRouteMoveResult{}, fmt.Errorf("%w: moving a target between environments requires a replacement target identity", domain.ErrConflict)
	}
	if current.kind == mutation.Target.DestinationKind && current.owner == mutation.Target.DestinationOwner && current.name == mutation.Target.DestinationName {
		return AdapterRouteMoveResult{}, fmt.Errorf("%w: target update does not move its route", domain.ErrInvalid)
	}
	var orphaned []string
	if err := json.Unmarshal(orphanRaw, &orphaned); err != nil {
		return AdapterRouteMoveResult{}, fmt.Errorf("store: adapter move orphan list: %w", err)
	}
	moveState, jobKind := "scrubbing", "scrub"
	if mutation.KeepRemote {
		moveState, jobKind = "activating", "activate"
	}
	insertMove := db.SQL(
		`INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,target_id,kind,authority_principal_id,state,keep_remote,created_at) VALUES (?,?,?,?,?,'target',?,?,?,?)`,
		`INSERT INTO adapter_route_moves (id,org_id,project_id,adapter_id,target_id,kind,authority_principal_id,state,keep_remote,created_at) VALUES ($1,$2,$3,$4,$5,'target',$6,$7,$8,$9)`)
	if rows, err := db.Exec(ctx, insertMove, mutation.MoveID, chain.Org, chain.Project, current.adapterID, mutation.Target.ID, mutation.AuthorityPrincipalID, moveState, mutation.KeepRemote, stamp); err != nil || rows != 1 {
		if err != nil {
			return AdapterRouteMoveResult{}, err
		}
		return AdapterRouteMoveResult{}, ErrConflict
	}
	insertTarget := db.SQL(
		`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,orphaned_names) VALUES (?,?,?,?,?,?,?,?,0,?,?)`,
		`INSERT INTO adapter_route_move_targets (move_id,org_id,project_id,environment_id,target_id,destination_kind,destination_owner,destination_name,destination_id,name_prefix,orphaned_names) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,$9,$10)`)
	pendingOrphans := []string{}
	if mutation.KeepRemote {
		pendingOrphans = orphaned
	}
	pendingOrphanJSON, _ := json.Marshal(pendingOrphans)
	if rows, err := db.Exec(ctx, insertTarget, mutation.MoveID, chain.Org, chain.Project, mutation.Target.EnvironmentID, mutation.Target.ID, mutation.Target.DestinationKind, mutation.Target.DestinationOwner, mutation.Target.DestinationName, mutation.Target.NamePrefix, string(pendingOrphanJSON)); err != nil || rows != 1 {
		if err != nil {
			return AdapterRouteMoveResult{}, err
		}
		return AdapterRouteMoveResult{}, ErrConflict
	}
	for _, keyID := range mutation.Target.KeyIDs {
		insertKey := db.SQL(
			`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES (?,?,?,?,?,?)`,
			`INSERT INTO adapter_route_move_keys (move_id,org_id,project_id,environment_id,target_id,key_id) VALUES ($1,$2,$3,$4,$5,$6)`)
		if rows, err := db.Exec(ctx, insertKey, mutation.MoveID, chain.Org, chain.Project, mutation.Target.EnvironmentID, mutation.Target.ID, keyID); err != nil || rows != 1 {
			if err != nil {
				return AdapterRouteMoveResult{}, err
			}
			return AdapterRouteMoveResult{}, ErrConflict
		}
	}
	if err := reserveAdapterMoveClaims(ctx, db, chain, mutation.MoveID, current.origin, mutation.Target); err != nil {
		return AdapterRouteMoveResult{}, err
	}
	if current.activeJob != "" {
		supersede := db.SQL(
			`UPDATE adapter_outbox SET state='superseded',finished_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state IN ('queued','running')`,
			`UPDATE adapter_outbox SET state='superseded',finished_at=$1,lease_owner=NULL,lease_expires_at=NULL WHERE id=$2 AND target_id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND state IN ('queued','running')`)
		if rows, err := db.Exec(ctx, supersede, stamp, current.activeJob, mutation.Target.ID, chain.Org, chain.Project, current.environmentID); err != nil || rows != 1 {
			if err != nil {
				return AdapterRouteMoveResult{}, err
			}
			return AdapterRouteMoveResult{}, adapter.ErrSuperseded
		}
	}
	if mutation.KeepRemote {
		release := db.SQL(
			`UPDATE adapter_ledger SET state='released',updated_at=? WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state<>'released'`,
			`UPDATE adapter_ledger SET state='released',updated_at=$1 WHERE target_id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5 AND state<>'released'`)
		if _, err := db.Exec(ctx, release, stamp, mutation.Target.ID, chain.Org, chain.Project, current.environmentID); err != nil {
			return AdapterRouteMoveResult{}, err
		}
	}
	jobID := newAdapterID("job")
	generation := current.generation + 1
	insertJob := db.SQL(
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?,'queued',?)`,
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,route_move_id,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,0,$11,'queued',$12)`)
	if rows, err := db.Exec(ctx, insertJob, jobID, chain.Org, chain.Project, current.environmentID, mutation.Target.ID, jobKind, mutation.MoveID, mutation.AuthorityPrincipalID, generation, mutation.Target.ID, stamp, stamp); err != nil || rows != 1 {
		if err != nil {
			return AdapterRouteMoveResult{}, err
		}
		return AdapterRouteMoveResult{}, ErrConflict
	}
	markTarget := db.SQL(
		`UPDATE adapter_targets SET generation=?,state='moving',sync_status='converging',failure_names='[]',active_job_id=? WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND state='active' AND provider_lease_job_id IS NULL`,
		`UPDATE adapter_targets SET generation=$1,state='moving',sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2 WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7 AND state='active' AND provider_lease_job_id IS NULL`)
	if rows, err := db.Exec(ctx, markTarget, generation, jobID, mutation.Target.ID, chain.Org, chain.Project, current.environmentID, current.generation); err != nil || rows != 1 {
		if err != nil {
			return AdapterRouteMoveResult{}, err
		}
		return AdapterRouteMoveResult{}, adapter.ErrProviderBusy
	}
	setAuthority := db.SQL(
		`UPDATE adapters SET authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state='active'`,
		`UPDATE adapters SET authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state='active'`)
	if rows, err := db.Exec(ctx, setAuthority, mutation.AuthorityPrincipalID, current.adapterID, chain.Org, chain.Project); err != nil || rows != 1 {
		if err != nil {
			return AdapterRouteMoveResult{}, err
		}
		return AdapterRouteMoveResult{}, ErrNotFound
	}
	result := AdapterRouteMoveResult{MoveID: mutation.MoveID, TargetID: mutation.Target.ID, JobID: jobID, SupersededJobID: current.activeJob, Generation: generation}
	if mutation.KeepRemote {
		result.Orphaned = orphaned
	}
	return result, nil
}

func reserveAdapterMoveClaims(ctx context.Context, db adoptDB, chain domain.Scope, moveID, origin string, target AdapterTargetMutation) error {
	keyQuery := db.SQL(
		`SELECT id,name,classification FROM keys WHERE org_id=? AND project_id=? AND id IN (`+placeholders(len(target.KeyIDs), false, 3)+`) ORDER BY id`,
		`SELECT id,name,classification FROM keys WHERE org_id=$1 AND project_id=$2 AND id IN (`+placeholders(len(target.KeyIDs), true, 3)+`) ORDER BY id`)
	args := []any{chain.Org, chain.Project}
	for _, keyID := range target.KeyIDs {
		args = append(args, keyID)
	}
	rows, err := db.Query(ctx, keyQuery, args...)
	if err != nil {
		return err
	}
	type claim struct{ keyID, surface, effective string }
	claims := []claim{{surface: string(adapter.Secret), effective: target.NamePrefix + adapter.SentinelName}, {surface: string(adapter.Variable), effective: target.NamePrefix + adapter.SentinelName}}
	for rows.Next() {
		var keyID, name, classification string
		if err := rows.Scan(&keyID, &name, &classification); err != nil {
			_ = closeMoveRows(rows)
			return err
		}
		surface := adapter.Secret
		if adapter.Classification(classification) == adapter.ConfigClassification {
			surface = adapter.Variable
		}
		claims = append(claims, claim{keyID: keyID, surface: string(surface), effective: target.NamePrefix + name})
	}
	if err := closeMoveRows(rows); err != nil {
		return err
	}
	if len(claims) != len(target.KeyIDs)+2 {
		return ErrNotFound
	}
	for _, pending := range claims {
		var configured int
		configuredCollision := db.SQL(
			`SELECT COUNT(*) FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id LEFT JOIN adapter_target_keys tk ON tk.target_id=t.id AND tk.org_id=t.org_id AND tk.project_id=t.project_id AND tk.environment_id=t.environment_id LEFT JOIN keys k ON k.id=tk.key_id AND k.org_id=tk.org_id AND k.project_id=tk.project_id WHERE t.org_id=? AND t.project_id=? AND t.id<>? AND t.state='active' AND a.state='active' AND a.origin=? AND t.destination_kind=? AND t.destination_owner=? AND t.destination_name=? AND (?=t.name_prefix||? OR (?=CASE WHEN k.classification='config' THEN 'variable' ELSE 'secret' END AND ?=t.name_prefix||k.name))`,
			`SELECT COUNT(*) FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id LEFT JOIN adapter_target_keys tk ON tk.target_id=t.id AND tk.org_id=t.org_id AND tk.project_id=t.project_id AND tk.environment_id=t.environment_id LEFT JOIN keys k ON k.id=tk.key_id AND k.org_id=tk.org_id AND k.project_id=tk.project_id WHERE t.org_id=$1 AND t.project_id=$2 AND t.id<>$3 AND t.state='active' AND a.state='active' AND a.origin=$4 AND t.destination_kind=$5 AND t.destination_owner=$6 AND t.destination_name=$7 AND ($8=t.name_prefix||$9 OR ($10=CASE WHEN k.classification='config' THEN 'variable' ELSE 'secret' END AND $11=t.name_prefix||k.name))`)
		if err := db.QueryRow(ctx, configuredCollision, chain.Org, chain.Project, target.ID, origin, target.DestinationKind, target.DestinationOwner, target.DestinationName, pending.effective, adapter.SentinelName, pending.surface, pending.effective).Scan(&configured); err != nil {
			return err
		}
		if configured != 0 {
			return fmt.Errorf("%w: effective name %q is already configured on the pending destination", domain.ErrConflict, pending.effective)
		}
		insert := db.SQL(
			`INSERT INTO adapter_route_move_claims (move_id,org_id,project_id,environment_id,target_id,key_id,provider_origin,destination_kind,destination_owner,destination_name,surface,effective_name,normalized_name) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			`INSERT INTO adapter_route_move_claims (move_id,org_id,project_id,environment_id,target_id,key_id,provider_origin,destination_kind,destination_owner,destination_name,surface,effective_name,normalized_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`)
		var keyID any
		if pending.keyID != "" {
			keyID = pending.keyID
		}
		if _, err := db.Exec(ctx, insert, moveID, chain.Org, chain.Project, target.EnvironmentID, target.ID, keyID, origin, target.DestinationKind, target.DestinationOwner, target.DestinationName, pending.surface, pending.effective, strings.ToUpper(pending.effective)); err != nil {
			if constraint(err) != nil {
				return fmt.Errorf("%w: pending effective name %q is already claimed", domain.ErrConflict, pending.effective)
			}
			return err
		}
	}
	return nil
}
