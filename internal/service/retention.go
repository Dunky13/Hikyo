package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

const (
	DefaultRetentionAge       = 90 * 24 * time.Hour
	DefaultRetentionRevisions = int64(10)
	RetentionBatchSize        = 100
	PruneStaleAfter           = 24 * time.Hour
)

// RetentionPolicy keeps a payload when either bound still admits it. Unlimited
// is valid only for an organization policy.
type RetentionPolicy struct {
	Unlimited     bool
	MaxAge        time.Duration
	LastRevisions int64
}

// ProjectRetention is the effective project policy and whether it is inherited
// from the organization rather than stored on the project.
type ProjectRetention struct {
	Inherited bool
	Policy    RetentionPolicy
}

// PruneHealth is the persisted payload-pruner health state.
type PruneHealth struct {
	LastSuccess time.Time
	Recorded    bool
	Stale       bool
}

// Retention owns tenant policy settings and the scheduler's payload sweep.
type Retention struct {
	DB  *store.DB
	Now func() time.Time
}

func (s *Retention) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func storePolicy(policy RetentionPolicy) store.RetentionPolicy {
	return store.RetentionPolicy{
		Unlimited: policy.Unlimited, MaxAge: policy.MaxAge,
		LastRevisions: policy.LastRevisions,
	}
}

func servicePolicy(policy store.RetentionPolicy) RetentionPolicy {
	return RetentionPolicy{
		Unlimited: policy.Unlimited, MaxAge: policy.MaxAge,
		LastRevisions: policy.LastRevisions,
	}
}

func validateOrgRetention(policy RetentionPolicy) error {
	if policy.Unlimited {
		return nil
	}
	if policy.MaxAge <= 0 || policy.LastRevisions <= 0 {
		return fmt.Errorf("%w: org retention age and revision count must both be positive", domain.ErrInvalid)
	}
	if policy.MaxAge%time.Second != 0 {
		return fmt.Errorf("%w: org retention age must be whole seconds", domain.ErrInvalid)
	}
	return nil
}

func validateProjectRetention(org, project RetentionPolicy) error {
	if project.Unlimited {
		return invalidDetail("project retention cannot be unlimited; the org retention cap is %s", formatRetentionPolicy(org))
	}
	if project.MaxAge <= 0 || project.LastRevisions <= 0 {
		return fmt.Errorf("%w: project retention age and revision count must both be positive", domain.ErrInvalid)
	}
	if project.MaxAge%time.Second != 0 {
		return fmt.Errorf("%w: project retention age must be whole seconds", domain.ErrInvalid)
	}
	if org.Unlimited {
		return nil
	}
	if project.MaxAge > org.MaxAge || project.LastRevisions > org.LastRevisions {
		return invalidDetail("project retention exceeds the org retention cap %s", formatRetentionPolicy(org))
	}
	return nil
}

func formatRetentionPolicy(policy RetentionPolicy) string {
	if policy.Unlimited {
		return "unlimited"
	}
	return fmt.Sprintf("keep-if-either(max_age=%s,last_revisions=%d)", policy.MaxAge, policy.LastRevisions)
}

// GetOrg reads the organization default. The schema default makes a freshly
// created organization keep-if-either(90 days, 10 revisions).
func (s *Retention) GetOrg(ctx context.Context, actor Actor, orgID domain.OrgID) (RetentionPolicy, error) {
	var out RetentionPolicy
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgRetentionRead, domain.Scope{Org: orgID})
		if err != nil {
			return err
		}
		org, err := r.Orgs().Get(ctx, p)
		if err != nil {
			return err
		}
		out = servicePolicy(org.Retention)
		return nil
	})
	return out, err
}

// SetOrg changes the organization cap and records the security event in the
// same transaction. Unlimited is an explicit mode; its dormant bounded values
// retain the previous values so switching back never invents a new policy.
func (s *Retention) SetOrg(ctx context.Context, actor Actor, orgID domain.OrgID, want RetentionPolicy) (RetentionPolicy, error) {
	if err := validateOrgRetention(want); err != nil {
		return RetentionPolicy{}, err
	}
	var out RetentionPolicy
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgRetentionUpdate, domain.Scope{Org: orgID})
		if err != nil {
			return err
		}
		if err := r.Orgs().Lock(ctx, p); err != nil {
			return err
		}
		org, err := r.Orgs().Get(ctx, p)
		if err != nil {
			return err
		}
		before := servicePolicy(org.Retention)
		if want.Unlimited {
			want.MaxAge, want.LastRevisions = before.MaxAge, before.LastRevisions
		} else {
			projects, err := r.Projects().List(ctx, p)
			if err != nil {
				return err
			}
			for _, project := range projects {
				if project.RetentionOverride == nil {
					continue
				}
				if err := validateProjectRetention(want, servicePolicy(*project.RetentionOverride)); err != nil {
					return invalidDetail("org retention cap %s is below project %s override %s",
						formatRetentionPolicy(want), project.ID,
						formatRetentionPolicy(servicePolicy(*project.RetentionOverride)))
				}
			}
		}
		out = want
		if before == want {
			return nil
		}
		if err := r.Orgs().SetRetention(ctx, p, storePolicy(want)); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgRetentionChanged, caller.Principal,
			audit.Object{Type: "organization", ID: string(orgID)}, audit.Payload{
				"previous_policy": formatRetentionPolicy(before),
				"policy":          formatRetentionPolicy(want),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

// GetProject returns the project override when present, otherwise the live org
// default. Inheritance is evaluated at read time, so an org change immediately
// applies to every unmodified project.
func (s *Retention) GetProject(ctx context.Context, actor Actor, scope domain.Scope) (ProjectRetention, error) {
	var out ProjectRetention
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectRetentionRead, scope)
		if err != nil {
			return err
		}
		org, err := r.Orgs().Get(ctx, p)
		if err != nil {
			return err
		}
		project, err := r.Projects().Get(ctx, p)
		if err != nil {
			return err
		}
		out = ProjectRetention{Inherited: project.RetentionOverride == nil, Policy: servicePolicy(org.Retention)}
		if project.RetentionOverride != nil {
			out.Policy = servicePolicy(*project.RetentionOverride)
		}
		return nil
	})
	return out, err
}

// SetProject writes a bounded override, or nil to resume inheritance. Every
// override is capped by both organization dimensions before any write occurs.
func (s *Retention) SetProject(ctx context.Context, actor Actor, scope domain.Scope, want *RetentionPolicy) (ProjectRetention, error) {
	var out ProjectRetention
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectRetentionUpdate, scope)
		if err != nil {
			return err
		}
		if err := r.Orgs().Lock(ctx, p); err != nil {
			return err
		}
		org, err := r.Orgs().Get(ctx, p)
		if err != nil {
			return err
		}
		orgPolicy := servicePolicy(org.Retention)
		if want != nil {
			if err := validateProjectRetention(orgPolicy, *want); err != nil {
				return err
			}
		}
		project, err := r.Projects().Get(ctx, p)
		if err != nil {
			return err
		}
		before := ProjectRetention{Inherited: project.RetentionOverride == nil, Policy: orgPolicy}
		if project.RetentionOverride != nil {
			before.Policy = servicePolicy(*project.RetentionOverride)
		}
		out = ProjectRetention{Inherited: want == nil, Policy: orgPolicy}
		var stored *store.RetentionPolicy
		if want != nil {
			out.Policy = *want
			converted := storePolicy(*want)
			stored = &converted
		}
		if before == out {
			return nil
		}
		if err := r.Projects().SetRetention(ctx, p, stored); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventProjectRetentionChanged, caller.Principal,
			audit.Object{Type: "project", ID: string(scope.Project)}, audit.Payload{
				"previous_policy":    formatRetentionPolicy(before.Policy),
				"policy":             formatRetentionPolicy(out.Policy),
				"previous_inherited": before.Inherited,
				"inherited":          out.Inherited,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

// Sweep collects eligible payloads in bounded chunks. The caller supplies the
// 10-minute run deadline. Each chunk owns one transaction, bounding its lock
// window before the next chunk begins.
func (s *Retention) Sweep(ctx context.Context) (int64, error) {
	startedAt := store.CanonTime(s.now())
	var total, totalCandidates int64
	for {
		if err := ctx.Err(); err != nil {
			return total, s.recordFailedPruneRun(ctx, startedAt, store.CanonTime(s.now()), totalCandidates, total, err)
		}
		now := store.CanonTime(s.now())
		var candidates int
		var collected int64
		err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			candidates, collected = 0, 0
			p, err := authz.SystemAuthority(authz.SiteScheduler, az.Token())
			if err != nil {
				return err
			}
			rows, err := r.Retention().Eligible(ctx, p, now, RetentionBatchSize)
			if err != nil {
				return err
			}
			candidates = len(rows)
			for _, row := range rows {
				policy := formatRetentionPolicy(servicePolicy(row.Policy))
				marked, err := r.Retention().MarkCollected(ctx, p, row.ID, policy, now)
				if err != nil {
					return err
				}
				if !marked {
					continue
				}
				if _, err := r.Retention().DeleteCollectedEntries(ctx, p, row.ID); err != nil {
					return err
				}
				auditProof, err := az.ScopedSystemAuthority(ctx, authz.SiteScheduler, domain.Scope{
					Org: domain.OrgID(row.OrgID), Project: domain.ProjectID(row.ProjectID), Env: domain.EnvID(row.EnvironmentID),
				})
				if err != nil {
					return err
				}
				ev, err := newAuditEvent(ctx, audit.EventRetentionPayloadGC, "",
					audit.Object{Type: "snapshot", ID: row.ID}, audit.OutcomeSuccess, "", audit.Payload{
						"org": row.OrgID, "project": row.ProjectID, "environment": row.EnvironmentID,
						"revision": row.Revision, "snapshot_id": row.ID, "policy": policy,
						"collected_at": now.Format(time.RFC3339Nano),
					})
				if err != nil {
					return err
				}
				ev.Actor.Class = audit.ActorSystem
				ev.OccurredAt = now
				if err := r.Audit().InsertTenant(ctx, auditProof, ev); err != nil {
					return err
				}
				collected++
			}
			if candidates < RetentionBatchSize {
				finishedAt := store.CanonTime(s.now())
				if err := r.Retention().SetLastPruneSuccess(ctx, p, finishedAt); err != nil {
					return err
				}
				ev, err := pruneRunEvent(ctx, audit.OutcomeSuccess, startedAt, finishedAt,
					totalCandidates+int64(candidates), total+collected, "")
				if err != nil {
					return err
				}
				return r.Audit().InsertInstance(ctx, p, ev)
			}
			return nil
		})
		if err != nil {
			return total, s.recordFailedPruneRun(ctx, startedAt, store.CanonTime(s.now()),
				totalCandidates+int64(candidates), total, err)
		}
		total += collected
		totalCandidates += int64(candidates)
		if candidates < RetentionBatchSize {
			return total, nil
		}
	}
}

func pruneRunEvent(ctx context.Context, outcome audit.Outcome, startedAt, finishedAt time.Time, candidates, collected int64, errorClass string) (audit.Event, error) {
	payload := audit.Payload{
		"started_at": startedAt.Format(time.RFC3339Nano), "finished_at": finishedAt.Format(time.RFC3339Nano),
		"candidates": candidates,
		"collected":  audit.Payload{"revision_payloads": collected},
	}
	if errorClass != "" {
		payload["error_class"] = errorClass
	}
	ev, err := newAuditEvent(ctx, audit.EventRetentionPruneRun, "",
		audit.Object{Type: "retention_sweep", ID: "payload_gc"}, outcome, "", payload)
	if err != nil {
		return audit.Event{}, err
	}
	ev.Actor.Class = audit.ActorSystem
	ev.OccurredAt = finishedAt
	return ev, nil
}

func pruneErrorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "internal"
	}
}

func (s *Retention) recordFailedPruneRun(ctx context.Context, startedAt, finishedAt time.Time, candidates, collected int64, runErr error) error {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := tx.Write(recordCtx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		proof, err := authz.SystemAuthority(authz.SiteScheduler, az.Token())
		if err != nil {
			return err
		}
		ev, err := pruneRunEvent(ctx, audit.OutcomeFailure, startedAt, finishedAt,
			candidates, collected, pruneErrorClass(runErr))
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, proof, ev)
	})
	return errors.Join(runErr, err)
}

// LastPruneSuccess returns the persisted health timestamp. false means this
// datastore has never completed a payload prune.
func (s *Retention) LastPruneSuccess(ctx context.Context) (time.Time, bool, error) {
	var at time.Time
	var ok bool
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		p, err := authz.SystemAuthority(authz.SiteScheduler, az.Token())
		if err != nil {
			return err
		}
		at, ok, err = r.Retention().LastPruneSuccess(ctx, p)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return time.Time{}, false, nil
	}
	return at, ok, err
}

func (s *Retention) health(at time.Time, recorded bool) PruneHealth {
	return PruneHealth{
		LastSuccess: at,
		Recorded:    recorded,
		Stale:       !recorded || s.now().Sub(at) > PruneStaleAfter,
	}
}

// OperationalHealth reads scheduler health for local operational surfaces.
func (s *Retention) OperationalHealth(ctx context.Context) (PruneHealth, error) {
	at, recorded, err := s.LastPruneSuccess(ctx)
	if err != nil {
		return PruneHealth{}, err
	}
	return s.health(at, recorded), nil
}

// GetHealth authorizes and audits the instance API read in one transaction.
func (s *Retention) GetHealth(ctx context.Context, actor Actor) (PruneHealth, error) {
	var out PruneHealth
	now := s.now()
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpRetentionHealthRead, domain.Scope{})
		if err != nil {
			return err
		}
		at, recorded, err := r.Retention().LastPruneSuccess(ctx, proof)
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		}
		if err != nil {
			return err
		}
		out = s.health(at, recorded)
		ev, err := domainEvent(ctx, audit.EventRetentionHealthRead, caller.Principal,
			audit.Object{Type: "retention_health", ID: "payload_gc"}, audit.Payload{
				"recorded": out.Recorded, "stale": out.Stale,
				"stale_after_seconds": int64(PruneStaleAfter / time.Second),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, proof, ev)
	})
	return out, err
}
