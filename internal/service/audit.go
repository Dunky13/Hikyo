package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
)

// Audits is the audit trail's read surface (#45, audit-model ADR § Storage
// and export). Reading the trail is itself audited, unconditionally: a query
// commits its own event in the same transaction as the page read (durable
// before the response); an export takes the INTENT/OUTCOME pair with every
// page read in its own transaction under a fresh proof.
type Audits struct {
	DB *store.DB
}

func auditQueryOp(scope domain.Scope) (authz.Operation, error) {
	level, err := scope.Level()
	if err != nil {
		return "", err
	}
	switch level {
	case domain.LevelOrg:
		return authz.OpAuditQueryOrg, nil
	case domain.LevelProject:
		return authz.OpAuditQueryProject, nil
	case domain.LevelEnv:
		return authz.OpAuditQueryEnv, nil
	default:
		return "", fmt.Errorf("service: tenant audit query needs a tenant scope; use InstanceQuery for the instance trail")
	}
}

func auditExportOp(scope domain.Scope) (authz.Operation, error) {
	level, err := scope.Level()
	if err != nil {
		return "", err
	}
	switch level {
	case domain.LevelOrg:
		return authz.OpAuditExportOrg, nil
	case domain.LevelProject:
		return authz.OpAuditExportProject, nil
	case domain.LevelEnv:
		return authz.OpAuditExportEnv, nil
	default:
		return "", fmt.Errorf("service: tenant audit export needs a tenant scope; use InstanceExport for the instance trail")
	}
}

// queryEvent builds the audit.query event: normalized filters plus the
// materialized page's row count — one event per query, never one per row.
func queryEvent(ctx context.Context, principal domain.PrincipalID, f store.AuditFilter, rows int) (audit.Event, error) {
	payload := f.Normalized()
	payload["row_count"] = rows
	return newAuditEvent(ctx, audit.EventAuditQuery, principal, audit.Object{}, audit.OutcomeSuccess, "", payload)
}

// Query returns one bounded page of the tenant trail addressed by scope. The
// page is materialized, the query event inserted, and both commit in one
// transaction — the event is durable before any byte of the response exists
// outside it.
func (s *Audits) Query(ctx context.Context, principal domain.PrincipalID, scope domain.Scope, f store.AuditFilter) ([]store.AuditEvent, error) {
	op, err := auditQueryOp(scope)
	if err != nil {
		return nil, err
	}
	var page []store.AuditEvent
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: principal}, op, scope)
		if err != nil {
			return err
		}
		page, err = r.Audit().PageTenant(ctx, p, f)
		if err != nil {
			return err
		}
		ev, err := queryEvent(ctx, principal, f, len(page))
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return nil, err
	}
	return page, nil
}

// InstanceQuery is Query for the instance trail, under an instance-scope
// audit-read grant — grant-evaluated, never route-implied.
func (s *Audits) InstanceQuery(ctx context.Context, principal domain.PrincipalID, f store.AuditFilter) ([]store.AuditEvent, error) {
	var page []store.AuditEvent
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: principal}, authz.OpAuditInstanceQuery, domain.Scope{})
		if err != nil {
			return err
		}
		page, err = r.Audit().PageInstance(ctx, p, f)
		if err != nil {
			return err
		}
		ev, err := queryEvent(ctx, principal, f, len(page))
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if err != nil {
		return nil, err
	}
	return page, nil
}

// exportLine is the JSONL export shape: one schema-versioned event per line,
// exactly what the table holds — payloads included, plaintext excluded by
// construction because it was never written.
type exportLine struct {
	Seq              int64           `json:"seq"`
	ID               string          `json:"id"`
	Type             string          `json:"type"`
	SchemaVersion    int             `json:"schema_version"`
	OccurredAt       string          `json:"occurred_at"`
	OccurredAsserted bool            `json:"occurred_asserted"`
	RecordedAt       string          `json:"recorded_at"`
	ActorID          string          `json:"actor_id,omitempty"`
	ActorClass       string          `json:"actor_class"`
	ActorCredential  string          `json:"actor_credential_id,omitempty"`
	AuthorityID      string          `json:"authority_id,omitempty"`
	ScopeClass       string          `json:"scope_class"`
	OrgID            string          `json:"org_id,omitempty"`
	ProjectID        string          `json:"project_id,omitempty"`
	EnvID            string          `json:"env_id,omitempty"`
	ObjectType       string          `json:"object_type,omitempty"`
	ObjectID         string          `json:"object_id,omitempty"`
	Outcome          string          `json:"outcome"`
	CorrelationID    string          `json:"correlation_id,omitempty"`
	SourceIP         string          `json:"source_ip,omitempty"`
	UserAgent        string          `json:"user_agent,omitempty"`
	Origin           string          `json:"origin"`
	Payload          json.RawMessage `json:"payload"`
}

func writeLine(w io.Writer, e store.AuditEvent) error {
	line := exportLine{
		Seq: e.Seq, ID: e.ID, Type: string(e.Type), SchemaVersion: e.SchemaVersion,
		OccurredAt:       audit.FormatTime(e.OccurredAt),
		OccurredAsserted: e.OccurredAsserted,
		RecordedAt:       audit.FormatTime(e.RecordedAt),
		ActorID:          e.Actor.ID, ActorClass: string(e.Actor.Class),
		ActorCredential: e.Actor.CredentialID, AuthorityID: e.AuthorityID,
		ScopeClass: e.ScopeClass,
		OrgID:      e.OrgID, ProjectID: e.ProjectID, EnvID: e.EnvID,
		ObjectType: e.Object.Type, ObjectID: e.Object.ID,
		Outcome: string(e.Outcome), CorrelationID: e.CorrelationID,
		SourceIP: e.SourceIP, UserAgent: e.UserAgent, Origin: string(e.Origin),
		Payload: json.RawMessage(e.RawPayload),
	}
	b, err := json.Marshal(line)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ErrExportUnpaired marks an export that stopped without its terminal
// OUTCOME event: mid-export revocation. The started event without a
// completed event is the ADR's visible reconciliation case, and the denial
// event the revoked page-authorization flushed records the cause. A
// completed event cannot be written here without fabricating authority the
// principal no longer holds — proofs are grant-evaluated per page, and the
// audit-model ADR's single enumerated proof-free writer is the denial
// writer alone (amendment part 4). Stated as a deviation in the handoff.
var ErrExportUnpaired = fmt.Errorf("service: audit export stopped by authorization loss; started event has no completed pair")

// Export streams the addressed slice of the tenant trail as JSONL:
// export_started durable BEFORE the first byte; each page read in its own
// transaction under a fresh proof (revoking audit-read stops the stream at
// the next page boundary); only committed page data is emitted; a terminal
// export_completed on success, page failure and sink disconnect. pageSize
// bounds each page read (the ops spec owns defaults).
func (s *Audits) Export(ctx context.Context, principal domain.PrincipalID, scope domain.Scope, f store.AuditFilter, pageSize int, w io.Writer) error {
	op, err := auditExportOp(scope)
	if err != nil {
		return err
	}
	if pageSize <= 0 {
		return fmt.Errorf("service: export page size must be positive")
	}
	insertTenant := func(ctx context.Context, r store.Repos, p authz.Proof, ev audit.Event) error {
		return r.Audit().InsertTenant(ctx, p, ev)
	}
	page := func(ctx context.Context, r store.ReadRepos, p authz.Proof, pf store.AuditFilter) ([]store.AuditEvent, error) {
		return r.Audit().PageTenant(ctx, p, pf)
	}
	return s.export(ctx, principal, op, scope, f, pageSize, w, insertTenant, page)
}

// InstanceExport is Export for the instance trail.
func (s *Audits) InstanceExport(ctx context.Context, principal domain.PrincipalID, f store.AuditFilter, pageSize int, w io.Writer) error {
	if pageSize <= 0 {
		return fmt.Errorf("service: export page size must be positive")
	}
	insertInstance := func(ctx context.Context, r store.Repos, p authz.Proof, ev audit.Event) error {
		return r.Audit().InsertInstance(ctx, p, ev)
	}
	page := func(ctx context.Context, r store.ReadRepos, p authz.Proof, pf store.AuditFilter) ([]store.AuditEvent, error) {
		return r.Audit().PageInstance(ctx, p, pf)
	}
	return s.export(ctx, principal, authz.OpAuditInstanceExport, domain.Scope{}, f, pageSize, w, insertInstance, page)
}

func (s *Audits) export(
	ctx context.Context,
	principal domain.PrincipalID,
	op authz.Operation,
	scope domain.Scope,
	f store.AuditFilter,
	pageSize int,
	w io.Writer,
	insert func(context.Context, store.Repos, authz.Proof, audit.Event) error,
	page func(context.Context, store.ReadRepos, authz.Proof, store.AuditFilter) ([]store.AuditEvent, error),
) error {
	snapshotTime, err := s.DB.AuditExportSnapshotTime(ctx)
	if err != nil {
		return err
	}
	if f.To.IsZero() || f.To.After(snapshotTime) {
		f.To = snapshotTime
	}
	started, err := newAuditEvent(ctx, audit.EventAuditExportStarted, principal, audit.Object{}, audit.OutcomeIntent, "", f.Normalized())
	if err != nil {
		return err
	}

	// INTENT: export_started, durable before the first byte. Postgres assigns
	// database-owned commit_seq immediately before commit; every page advances
	// that cursor instead of allocation-ordered seq. sqlite's single writer
	// makes commit_seq equivalent to seq.
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, authz.Identity{Principal: principal}, op, scope)
		if err != nil {
			return err
		}
		return insert(ctx, r, p, started)
	})
	if err != nil {
		return err
	}

	// The terminal OUTCOME must be able to commit even when the request
	// context is already dead — a client disconnect cancels ctx, and the
	// `disconnected` outcome exists precisely for that case. WithoutCancel
	// keeps the request's values (wire metadata) but drops its cancellation;
	// the transaction layer applies its own bounded deadline.
	terminalCtx := context.WithoutCancel(ctx)
	completed := func(outcome audit.Outcome, cause string, rows int) error {
		payload := audit.Payload{"rows_streamed": rows}
		if cause != "" {
			payload["cause"] = cause
		}
		ev, err := newAuditEvent(terminalCtx, audit.EventAuditExportCompleted, principal, audit.Object{}, outcome, started.ID, payload)
		if err != nil {
			return err
		}
		return tx.Write(terminalCtx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			p, err := az.Authorize(ctx, authz.Identity{Principal: principal}, op, scope)
			if err != nil {
				return err
			}
			return insert(ctx, r, p, ev)
		})
	}

	streamed := 0
	commitCursor := store.AuditCommitSeq(0)
	writersSettled := false
	for {
		// Each page: its own transaction, its own freshly minted proof —
		// #15's re-authorize-before-every-sensitive-step and #23's
		// proof-dies-with-its-transaction, applied literally.
		var rows []store.AuditEvent
		pf := f
		pf.Limit = pageSize
		pf.Order = store.AuditPageByCommit
		pf.AfterCommitSeq = commitCursor
		err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
			p, err := az.Authorize(ctx, authz.Identity{Principal: principal}, op, scope)
			if err != nil {
				return err
			}
			rows, err = page(ctx, r, p, pf)
			return err
		})
		if err != nil {
			if isDenial(err) {
				// Authorization lost at a page boundary: the stream stops,
				// the flushed denial event records the probe, and the
				// started event stands unpaired (see ErrExportUnpaired).
				return fmt.Errorf("%w: %w", ErrExportUnpaired, err)
			}
			// Internal page failure: terminal OUTCOME with cause, under the
			// still-held authorization.
			if cerr := completed(audit.OutcomeFailure, "page-read-failed", streamed); cerr != nil {
				return fmt.Errorf("service: export failed and its terminal event failed too: %w", fmt.Errorf("%w; %w", cerr, err))
			}
			return err
		}
		// Only committed page data is ever emitted: rows left the read
		// transaction after its commit, so no byte crosses the response
		// boundary ahead of its transaction.
		for _, e := range rows {
			if werr := writeLine(w, e); werr != nil {
				if cerr := completed(audit.OutcomeDisconnected, "sink-error", streamed); cerr != nil {
					return fmt.Errorf("service: export sink failed and its terminal event failed too: %w", fmt.Errorf("%w; %w", cerr, werr))
				}
				return fmt.Errorf("service: export sink: %w", werr)
			}
			streamed++
			commitCursor = e.CommitSeq
		}
		if len(rows) < pageSize {
			if !writersSettled {
				if err := s.DB.AwaitAuditExportWriters(ctx); err != nil {
					if cerr := completed(audit.OutcomeFailure, "writer-barrier-failed", streamed); cerr != nil {
						return fmt.Errorf("service: export writer barrier failed and its terminal event failed too: %w", fmt.Errorf("%w; %w", cerr, err))
					}
					return err
				}
				writersSettled = true
				continue
			}
			return completed(audit.OutcomeSuccess, "", streamed)
		}
	}
}

func isDenial(err error) bool {
	return err != nil && (errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrUnauthorized))
}
