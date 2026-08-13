package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// The live-update advisory channel (revision-model ADR § Live updates;
// system-architecture ADR § Real-time, which fixes SSE as the transport and
// requires a documented polling fallback).
//
// FOUR CONSTRAINTS, all binding, all held here rather than at the transport:
//
//  1. METADATA ONLY. An event says that something changed, never what it
//     changed to. It carries no value in any form and NO CHANGE TOKEN -- the
//     token is derived from a keyed secret and is change-detection material for
//     the workload path, not chatter for a browser channel. AdvisoryEvent has
//     no field that could hold either, which is the cheapest way to keep the
//     rule.
//
//  2. AUTHORIZED PER EVENT AND PER REFERENCED OBJECT, projected per recipient.
//     Checking that the subscriber may view the project is not enough: a user
//     with `dev` but not `prod` would otherwise learn that prod exists, which
//     keys it holds and when it changed. Every event is authorized against the
//     environment it names, inside a transaction, at emit time -- so a grant
//     revoked mid-session bites on the NEXT event, not at the next reconnect.
//
//  3. ADVISORY ONLY. Correctness never depends on delivery. The serialized
//     publish and the version-id freshness check are the authority; a client
//     that missed every event still cannot publish a stale change. That is what
//     makes dropping a slow subscriber (below) a safe thing to do rather than a
//     correctness bug.
//
//  4. NO REPLAY. Nothing is retained for `Last-Event-ID`; a reconnecting client
//     performs a normal authorized refetch. Retaining event history would be a
//     second audit log with weaker rules.
//
// THE POLLING FALLBACK is Revisions.Signals: the same facts, pulled under the
// caller's own authorization. It is not a degraded mode bolted on for proxies
// -- it is the matrix's ordinary read, and the stream only saves it a poll.

// advisoryBuffer bounds one subscriber's queue. A client that cannot keep up is
// DROPPED rather than buffered without limit: the events are advisory, the
// client refetches on reconnect, and an unbounded per-connection buffer is a
// memory-exhaustion primitive any authenticated principal could trigger by
// opening a stream and not reading it.
const (
	advisoryBuffer            = 32
	advisoryPrincipalLimit    = 4
	advisoryOrgLimit          = 128
	advisoryInstanceWideLimit = 1024
)

// AdvisoryEvent is one metadata-only fact about a change.
type AdvisoryEvent struct {
	// Type is one of the three the ADR enumerates: an environment advanced, a
	// principal staged a draft, or a draft went stale under a publish.
	Type string
	// EnvironmentID is the object every event is authorized against. There is
	// no event that references no environment.
	EnvironmentID string
	KeyID         string
	KeyName       string
	// Revision is the environment's new revision, 0 on draft events.
	Revision int64
	// ActorID is the principal whose act produced the event, so the matrix can
	// distinguish "your pending change" from "someone else's".
	ActorID string
}

// The advisory event types.
const (
	AdvisoryPublished = "revision.published"
	AdvisoryStaged    = "pending.staged"
	// AdvisoryChanged fires once per changed key when an environment advances.
	// It claims exactly what the emitter knows: THIS CELL MOVED. It does not
	// claim any draft went stale -- the publisher's transaction does not read
	// other principals' markers, so a "pending.stale" event here would assert
	// a fact nobody checked. A subscriber that holds a draft on the named cell
	// derives staleness itself: its own draft plus this event IS the fact.
	AdvisoryChanged = "cell.changed"
)

// Advisory is the in-process fan-out. There is no cross-process bus and none is
// needed: v1 is a single node (system-architecture ADR), and a channel that
// must survive a second node is a different design, not a bigger buffer.
type Advisory struct {
	mu   sync.Mutex
	next int64
	subs map[int64]*subscriber
}

type subscriber struct {
	org       domain.OrgID
	project   domain.ProjectID
	principal domain.PrincipalID
	ch        chan AdvisoryEvent
	dropped   bool
}

// NewAdvisory constructs the channel. A nil *Advisory is a working no-op, so a
// build that does not wire one simply has no live updates.
func NewAdvisory() *Advisory { return &Advisory{subs: map[int64]*subscriber{}} }

func (a *Advisory) emit(scope domain.Scope, ev AdvisoryEvent) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, sub := range a.subs {
		if sub.project != scope.Project || sub.dropped {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			// Slow-client disconnect: close the queue and forget the
			// subscriber. The reader sees the closed channel, ends the stream,
			// and reconnects into a full refetch.
			sub.dropped = true
			close(sub.ch)
			delete(a.subs, id)
		}
	}
}

// published announces one or more environments advancing. It deliberately
// takes PublishedEnvironment and copies only the revision out of it: the change
// token travels no further than the publisher's own response.
func (a *Advisory) published(scope domain.Scope, envs []PublishedEnvironment) {
	if a == nil {
		return
	}
	for _, env := range envs {
		a.emit(scope, AdvisoryEvent{
			Type: AdvisoryPublished, EnvironmentID: env.EnvironmentID, Revision: env.Revision,
		})
		// One event per changed key so a matrix can invalidate exactly the
		// cells that moved instead of the whole environment.
		for _, changed := range env.ChangedKeys {
			a.emit(scope, AdvisoryEvent{
				Type: AdvisoryChanged, EnvironmentID: env.EnvironmentID,
				KeyID: changed.KeyID, KeyName: changed.Name, Revision: env.Revision,
			})
		}
	}
}

// staged announces a draft. The owner is named because the matrix's quieter
// "another user has a pending change here" marker is exactly this fact.
func (a *Advisory) staged(scope domain.Scope, keyID, keyName string, owner domain.PrincipalID) {
	a.emit(scope, AdvisoryEvent{
		Type: AdvisoryStaged, EnvironmentID: string(scope.Env),
		KeyID: keyID, KeyName: keyName, ActorID: string(owner),
	})
}

func (a *Advisory) subscribe(org domain.OrgID, project domain.ProjectID, principal domain.PrincipalID) (<-chan AdvisoryEvent, func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.subs) >= advisoryInstanceWideLimit {
		return nil, nil, ErrAdvisoryInstanceLimit
	}
	principalConnections, orgConnections := 0, 0
	for _, existing := range a.subs {
		if existing.principal == principal {
			principalConnections++
		}
		if existing.org == org {
			orgConnections++
		}
	}
	if principalConnections >= advisoryPrincipalLimit {
		return nil, nil, ErrAdvisoryPrincipalLimit
	}
	if orgConnections >= advisoryOrgLimit {
		return nil, nil, ErrAdvisoryOrgLimit
	}
	a.next++
	id := a.next
	sub := &subscriber{org: org, project: project, principal: principal, ch: make(chan AdvisoryEvent, advisoryBuffer)}
	a.subs[id] = sub
	return sub.ch, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if existing, ok := a.subs[id]; ok && !existing.dropped {
			existing.dropped = true
			close(existing.ch)
			delete(a.subs, id)
		}
	}, nil
}

// ErrNoAdvisoryChannel refuses a subscription on a build with no channel wired.
// A stream that silently never delivers is worse than one that refuses: the
// client cannot tell it from a quiet project, so it stops polling too.
var ErrNoAdvisoryChannel = errors.New("service: this instance serves no advisory channel")

var (
	ErrAdvisoryPrincipalLimit = fmt.Errorf("%w: service: advisory connection cap reached for this principal", admission.ErrOverloaded)
	ErrAdvisoryOrgLimit       = fmt.Errorf("%w: service: advisory connection cap reached for this organization", admission.ErrOverloaded)
	ErrAdvisoryInstanceLimit  = fmt.Errorf("%w: service: instance-wide advisory connection cap reached", admission.ErrOverloaded)
)

// Watch subscribes to the project's advisory events, authorized twice: once at
// connect, for the project, and once PER EVENT against the environment that
// event names. Events the recipient may not see are dropped, and an event
// reduced to nothing is never sent.
//
// The returned channel closes when ctx ends, when the subscriber falls behind,
// or when the instance shuts down. It never carries an error: a stream that
// dies is a reconnect, and a reconnect is a refetch.
func (s *Revisions) Watch(ctx context.Context, actor Actor, scope domain.Scope) (<-chan AdvisoryEvent, error) {
	if s.Advisory == nil {
		return nil, ErrNoAdvisoryChannel
	}
	if scope.Project == "" {
		return nil, domain.ErrNotFound
	}
	// Connect-time authorization. It is NOT the control -- per-event
	// authorization below is -- but it is what makes an unauthorized connect
	// answer the uniform nonexistent shape instead of hanging open forever.
	caller, err := s.authorizeIdentity(ctx, actor, authz.OpAdvisoryWatch, scope)
	if err != nil {
		return nil, err
	}
	raw, cancel, err := s.Advisory.subscribe(scope.Org, scope.Project, caller.Principal)
	if err != nil {
		return nil, err
	}
	out := make(chan AdvisoryEvent, advisoryBuffer)
	go func() {
		defer close(out)
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-raw:
				if !ok {
					return
				}
				envScope := domain.Scope{
					Org: scope.Org, Project: scope.Project,
					Env: domain.EnvID(ev.EnvironmentID),
				}
				if err := s.authorize(ctx, actor, authz.OpAdvisoryEvent, envScope); err != nil {
					// Projection: an unauthorized reference is dropped, and an
					// event that references only unauthorized objects is
					// therefore not sent at all. A refusal is not an error on
					// this path -- it is the whole mechanism.
					continue
				}
				// The same projection the signals contract keeps: another
				// principal's draft is write-presence and nothing more -- no
				// id, no owner. The actor survives only on the recipient's OWN
				// events, where "your draft" is the fact being delivered; a
				// stream that named other editors would disclose what the
				// polling surface deliberately withholds.
				if ev.ActorID != "" && ev.ActorID != string(caller.Principal) {
					ev.ActorID = ""
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// authorize evaluates one operation's formula against one scope, in its own
// transaction, uncached -- the same chokepoint every other read uses. The
// advisory path calls it twice per subscriber: once at connect against the
// project, and once per event against the environment that event names.
//
// The connect check is `read` at PROJECT scope, which is the same grant the
// matrix's key catalogue read already needs, so it excludes nobody who could
// use the channel. It is not the control: per-event authorization is, which is
// why a grant revoked mid-session bites on the next event.
func (s *Revisions) authorize(ctx context.Context, actor Actor, op authz.Operation, scope domain.Scope) error {
	_, err := s.authorizeIdentity(ctx, actor, op, scope)
	return err
}

func (s *Revisions) authorizeIdentity(ctx context.Context, actor Actor, op authz.Operation, scope domain.Scope) (authz.Identity, error) {
	var out authz.Identity
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		_, err = az.Authorize(ctx, caller, op, scope)
		if err == nil {
			out = caller
		}
		return err
	})
	return out, err
}
