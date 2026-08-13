package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/remotefetch"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// The multi-instance directory tier, VIEWING side (#71, multi-instance ADR §
// The directory tier).
//
// One structural rule governs everything here: this server reaches DIRECTORY
// METADATA and nothing else. There is no method on this type that returns a
// remote's values, and there is no store query that could feed one — the
// value-bearing tier is the browser's, and it never passes through here.

// ErrRemoteCap is the refusal at the configured-entry cap.
var ErrRemoteCap = fmt.Errorf("%w: the configured remote cap is reached", domain.ErrLimitExceeded)

// ErrSelfConnected is `remote add` pointed at this instance. It is refused at
// the AUTHENTICATED FETCH, by instance identity — never guessed from the URL,
// which a DNS change can make wrong in either direction.
var ErrSelfConnected = fmt.Errorf("%w: that URL is this instance — a remote cannot be its own remote", domain.ErrConflict)

// ErrRemoteUnverified is `remote add` whose verifying fetch did not return a
// usable listing. The entry is NOT committed: an entry that has never
// authenticated once is a credential nobody has checked.
var ErrRemoteUnverified = fmt.Errorf("%w: the verifying directory fetch did not succeed — the entry was not created", domain.ErrConflict)

// Remotes is the viewing side's service.
type Remotes struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// Fetch is the outbound client. A nil Fetch is a hard error at the first
	// fetch rather than a silent skip: a directory that quietly stopped
	// fetching would show stale data as current, which is the one thing the
	// freshness model exists to prevent.
	Fetch *remotefetch.Client
	Now   func() time.Time

	// gate carries the three fan-out bounds that are not remotefetch.Config
	// fields: the coalescing window and the two trigger-rate budgets. It is
	// lazily built so a zero-value Remotes still works in tests.
	gateOnce sync.Once
	gate     *fetchGate
}

func (s *Remotes) fetchGate() *fetchGate {
	s.gateOnce.Do(func() { s.gate = newFetchGate() })
	return s.gate
}

func (s *Remotes) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// RemoteView is one directory card entry: the stored configuration plus the
// last-known state. Never the credential — there is no field for it.
type RemoteView struct {
	ID        string
	Name      string
	URL       string
	SPKIPin   string
	CreatedAt time.Time
	CreatedBy domain.PrincipalID

	// State is the operator-visible outcome of the most recent fetch, from
	// remotefetch's closed enum. Empty only for an entry that has somehow
	// never been fetched, which `remote add` makes unreachable.
	State string
	// LastAttemptAt is when the most recent fetch ran, successful or not.
	LastAttemptAt time.Time
	// ObservedAt is when the listing below was actually observed. Zero means
	// there has never been a successful fetch.
	ObservedAt time.Time
	// Stale reports that the listing is a SNAPSHOT rather than current — the
	// card's "unreachable 2h, last known state shown". It is computed from the
	// outcome, not from the age: a fetch that just failed makes even a
	// one-second-old snapshot stale.
	Stale bool
	// StaleFor is the snapshot's age at read time, the number the card prints
	// beside "unreachable". Zero when not stale.
	StaleFor time.Duration

	Identity     string
	Version      string
	OrgCount     int64
	ProjectCount int64
	Orgs         []RemoteOrg
}

// RemoteOrg is one organisation's name and its projects', as served.
type RemoteOrg struct {
	Name     string
	Projects []string
}

// AddRemote runs the connection ceremony's server half and commits the entry
// only if it verifies.
//
// ORDER IS LOAD-BEARING and it is the ADR's. The steps before this one are the
// caller's because they are interactive: the CLI displays the SPKI fingerprint,
// takes the human's confirmation, and then reads the remote's pre-auth meta
// endpoint over that pinned connection to check protocol revision — all before
// it asks for the credential (`internal/cli/remotes.go`, addRemote).
//
// The web add form does NOT perform a meta read, and does not need one: it
// posts an already-pasted credential, and what decides whether the entry exists
// is the authenticated fetch below — a peer too old to serve the directory
// fails it. The CLI's meta read buys the ORDER (refuse before a secret is
// typed), not a check this method depends on.
//
// What happens HERE is the authenticated directory fetch — which returns the
// remote's instance identity, at which point self-connection and
// duplicate-identity refusal fire — BEFORE the row is written.
//
// The fetch therefore runs OUTSIDE the write transaction, deliberately: a
// ten-second network deadline inside a write transaction would hold sqlite's
// single writer for ten seconds per add. The identity checks that depend on
// stored state are re-done inside the transaction, so the window between the
// two cannot produce a self-connected or duplicated entry.
func (s *Remotes) AddRemote(ctx context.Context, actor Actor, name, rawURL, pin, credential string) (RemoteView, error) {
	if err := checkName("remote name", name); err != nil {
		return RemoteView{}, err
	}
	// ONE spelling from here down. `https://peer.example/` and
	// `https://peer.example` are the same origin and a human types either, but
	// only the slash-free one concatenates correctly onto the directory path —
	// the other produces `//api/v1/instance/directory`, which reads as an
	// unreachable remote and is not one.
	canonicalURL, err := remotefetch.CanonicalRemoteURL(rawURL)
	if err == nil {
		rawURL = canonicalURL
	}
	if err := remotefetch.ValidateRemoteURL(rawURL); err != nil {
		return RemoteView{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err.Error())
	}
	if pin == "" || credential == "" {
		return RemoteView{}, fmt.Errorf("%w: pin and credential are both required", domain.ErrInvalid)
	}
	if s.Fetch == nil {
		return RemoteView{}, errors.New("service: the directory surface has no outbound client wired")
	}
	id, err := newID("rmt")
	if err != nil {
		return RemoteView{}, err
	}
	now := s.now()

	// Phase 1: authorize, and read the state the identity checks need. The
	// cap is checked here too so a caller at the cap pays no network round
	// trip to be refused.
	var (
		selfIdentity string
		known        map[string]string // remote identity -> entry name
	)
	if err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteAdd, domain.Scope{})
		if err != nil {
			return err
		}
		count, err := r.Remotes().Count(ctx, p)
		if err != nil {
			return err
		}
		if count >= remotefetch.RemoteCount {
			return fmt.Errorf("%w (%d)", ErrRemoteCap, remotefetch.RemoteCount)
		}
		selfIdentity, err = az.InstanceIdentity(ctx)
		if err != nil {
			return err
		}
		known, err = knownIdentities(ctx, r.Remotes(), p)
		return err
	}); err != nil {
		return RemoteView{}, err
	}

	// Phase 2: the verifying fetch. This is the moment the ADR names — the
	// credential is checked once, by using it, before anything is stored.
	fetchCtx, cancel := context.WithTimeout(ctx, remotefetch.Deadline)
	defer cancel()
	listing, outcome, ferr := s.Fetch.Directory(fetchCtx, rawURL, pin, credential)
	if outcome != remotefetch.OutcomeOK {
		return RemoteView{}, fmt.Errorf("%w (%s): %v", ErrRemoteUnverified, outcome, ferr)
	}
	if listing.Identity == selfIdentity {
		return RemoteView{}, ErrSelfConnected
	}
	if other, dup := known[listing.Identity]; dup {
		return RemoteView{}, fmt.Errorf("%w: %q already names that instance", domain.ErrConflict, other)
	}

	// Phase 3: commit. Both identity checks are re-run against the state this
	// transaction sees, so a concurrent add of the same instance cannot slip
	// between phases 1 and 3.
	sealed, err := s.Keyring.ForInstance().SealField(remoteCredentialAAD(id), []byte(credential))
	if err != nil {
		return RemoteView{}, err
	}
	var out RemoteView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteAdd, domain.Scope{})
		if err != nil {
			return err
		}
		// THE CENSUS LOCK. Everything below is a read-then-write decision about
		// the instance as a whole — how many remotes it holds, and which
		// instances it already knows — and postgres runs READ COMMITTED, so two
		// concurrent adds each read the pre-state and each commit. Two adds
		// could therefore both admit the 50th remote, or both record the same
		// foreign identity the duplicate check exists to refuse. There is no
		// per-remote row to lock (the row being decided about does not exist
		// yet), so they serialize on the instance singleton.
		if err := az.LockInstanceIdentityRow(ctx); err != nil {
			return err
		}
		count, err := r.Remotes().Count(ctx, p)
		if err != nil {
			return err
		}
		if count >= remotefetch.RemoteCount {
			return fmt.Errorf("%w (%d)", ErrRemoteCap, remotefetch.RemoteCount)
		}
		selfNow, err := az.InstanceIdentity(ctx)
		if err != nil {
			return err
		}
		if listing.Identity == selfNow {
			return ErrSelfConnected
		}
		knownNow, err := knownIdentities(ctx, r.Remotes(), p)
		if err != nil {
			return err
		}
		if other, dup := knownNow[listing.Identity]; dup {
			return fmt.Errorf("%w: %q already names that instance", domain.ErrConflict, other)
		}
		if err := r.Remotes().Create(ctx, p, store.NewRemote{
			ID: id, Name: name, URL: rawURL, SPKIPin: pin,
			CredentialSealed: sealed, CreatedAt: now, CreatedBy: caller.Principal,
		}); err != nil {
			return err
		}
		snap, err := snapshotOf(id, listing, now)
		if err != nil {
			return err
		}
		if err := r.Remotes().WriteSnapshot(ctx, p, snap); err != nil {
			return err
		}
		out, err = viewOf(store.Remote{
			ID: id, Name: name, URL: rawURL, SPKIPin: pin,
			CreatedAt: now, CreatedBy: caller.Principal,
		}, snap, now)
		if err != nil {
			return err
		}

		e, err := domainEvent(ctx, audit.EventRemoteAdded, caller.Principal,
			audit.Object{Type: "remote", ID: id}, audit.Payload{
				"remote_id": id, "name": name, "url": rawURL,
				"spki_pin": pin, "remote_identity": listing.Identity,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	if err != nil {
		return RemoteView{}, err
	}
	return out, nil
}

// ListRemotes is the directory card: every entry, fetched on view.
//
// ON-VIEW FETCH, no poller. The fetch happens because a holder of
// `instance-directory` is looking, and at no other moment — which is also what
// bounds the credential's use to human-initiated moments.
//
// The fetch runs BETWEEN two transactions for the reason AddRemote's does: a
// fan-out of ten-second deadlines must not hold a write transaction. The read
// transaction takes the entries and their sealed credentials; the write
// transaction records the outcomes and the audit event.
func (s *Remotes) ListRemotes(ctx context.Context, actor Actor) ([]RemoteView, error) {
	now := s.now()
	entries, targets, snaps, fetched, err := s.loadForFetch(ctx, actor, now, "")
	if err != nil {
		return nil, err
	}
	results := s.fetchRound(ctx, targets)
	return s.settle(ctx, actor, authz.OpRemoteList, now, entries, snaps, results, fetched)
}

// ShowRemote is one entry, same ceremony.
func (s *Remotes) ShowRemote(ctx context.Context, actor Actor, name string) (RemoteView, error) {
	now := s.now()
	entries, targets, snaps, fetched, err := s.loadForFetch(ctx, actor, now, name)
	if err != nil {
		return RemoteView{}, err
	}
	results := s.fetchRound(ctx, targets)
	views, err := s.settle(ctx, actor, authz.OpRemoteShow, now, entries, snaps, results, fetched)
	if err != nil {
		return RemoteView{}, err
	}
	if len(views) != 1 {
		return RemoteView{}, store.ErrNotFound
	}
	return views[0], nil
}

// loadForFetch is the read half shared by list and show. An empty `only` reads
// every entry; a non-empty one reads exactly the named entry.
func (s *Remotes) loadForFetch(ctx context.Context, actor Actor, now time.Time, only string) (
	[]store.Remote, []remotefetch.Target, map[string]store.RemoteSnapshot, bool, error,
) {
	if s.Fetch == nil {
		return nil, nil, nil, false, errors.New("service: the directory surface has no outbound client wired")
	}
	mayFetch := false
	op := authz.OpRemoteList
	if only != "" {
		op = authz.OpRemoteShow
	}
	var (
		entries []store.Remote
		targets []remotefetch.Target
		snaps   = map[string]store.RemoteSnapshot{}
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, op, domain.Scope{})
		if err != nil {
			return err
		}
		// Charged AFTER authorization, so an unauthorized caller cannot spend
		// another principal's budget, and before any connection is originated.
		//
		// Exhausting the budget is NOT an error to the caller: the bounds
		// limit fetch TRIGGERS, not views, and the freshness model already has
		// the honest answer for "we did not refresh" — serve the snapshot,
		// marked stale with its age. Failing the whole view instead would make
		// a poll cadence slightly over budget look like an outage.
		mayFetch = s.fetchGate().admit(caller.Principal, now)
		if only != "" {
			one, err := r.Remotes().GetByName(ctx, p, only)
			if err != nil {
				return err
			}
			entries = []store.Remote{one}
			snap, err := r.Remotes().Snapshot(ctx, p, one.ID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if err == nil {
				snaps[one.ID] = snap
			}
		} else {
			entries, err = r.Remotes().List(ctx, p)
			if err != nil {
				return err
			}
			rows, err := r.Remotes().Snapshots(ctx, p)
			if err != nil {
				return err
			}
			for _, row := range rows {
				snaps[row.RemoteID] = row
			}
		}
		sealer := s.Keyring.ForInstance()
		for _, e := range entries {
			sealed, err := r.Remotes().SealedCredential(ctx, p, e.ID)
			if err != nil {
				return err
			}
			plain, err := sealer.OpenField(remoteCredentialAAD(e.ID), sealed)
			if err != nil {
				return err
			}
			targets = append(targets, remotefetch.Target{
				ID: e.ID, Origin: e.URL, Pin: e.SPKIPin, Credential: string(plain),
			})
		}
		return nil
	})
	if !mayFetch {
		targets = nil
	}
	return entries, targets, snaps, mayFetch, err
}

// fetchRound is the bounded fan-out under the coalescing window.
//
// Zero targets means zero connections, and that is the air-gap statement
// holding by construction rather than by a flag.
//
// A viewer arriving while a round is in flight WAITS for it, and one arriving
// within CoalesceWindow of a finished round shares its results — so a card open
// on several screens is one connection per remote, not one per human. The
// per-viewer and instance-wide trigger budgets are charged by the caller before
// this runs; this is the sharing half, not the rationing half.
//
// Sharing is SCOPED: a round is reusable only by a request every one of whose
// remotes it fetched. Waiting on an in-flight round therefore re-enters the
// loop rather than taking its results on trust — the round it was waiting for
// may have been a narrower one, and inheriting it would settle this request's
// unfetched entries as failures nobody observed.
func (s *Remotes) fetchRound(ctx context.Context, targets []remotefetch.Target) map[string]remotefetch.Result {
	if len(targets) == 0 {
		return map[string]remotefetch.Result{}
	}
	want := make([]string, len(targets))
	for i, t := range targets {
		want[i] = t.ID
	}
	g := s.fetchGate()
	for {
		shared, wait, release := g.coalesce(s.now(), want)
		switch {
		case shared != nil:
			return shared
		case release != nil:
			return s.runRound(ctx, targets, release)
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return map[string]remotefetch.Result{}
		}
	}
}

// runRound is the fan-out itself, split out so the claim's release can be
// deferred without deferring inside fetchRound's loop.
func (s *Remotes) runRound(
	ctx context.Context, targets []remotefetch.Target, release func(map[string]remotefetch.Result),
) map[string]remotefetch.Result {
	out := map[string]remotefetch.Result{}
	// The claim is released on EVERY path, including a panic, or waiting
	// viewers would block until their own context expired.
	defer func() { release(out) }()
	// The budget is DERIVED from the fleet size and the fan-out cap, not a flat
	// multiple of the per-remote deadline: see remotefetch.RoundBudget for what
	// the flat version fabricated at fleet scale.
	fetchCtx, cancel := context.WithTimeout(ctx, s.Fetch.RoundBudget(len(targets)))
	defer cancel()
	for _, res := range s.Fetch.FetchAll(fetchCtx, targets) {
		out[res.ID] = res
	}
	return out
}

// settle writes each fetch's outcome and the directory-view event, then builds
// the views. Identity conflicts are decided HERE, across the whole round: an
// identity arriving from two entries makes BOTH duplicated, and neither is
// served as current.
func (s *Remotes) settle(
	ctx context.Context, actor Actor, op authz.Operation, now time.Time,
	entries []store.Remote, snaps map[string]store.RemoteSnapshot,
	results map[string]remotefetch.Result, fetched bool,
) ([]RemoteView, error) {
	// The operation is THREADED from the caller, never re-inferred from the
	// entry count: a directory holding exactly one remote is still a list, and
	// inferring it would put the wrong operation name on the audit trail.
	var views []RemoteView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, op, domain.Scope{})
		if err != nil {
			return err
		}
		selfIdentity, err := az.InstanceIdentity(ctx)
		if err != nil {
			return err
		}
		conflicted := conflictingIdentities(results)

		views = make([]RemoteView, 0, len(entries))
		stale := 0
		for _, e := range entries {
			res, got := results[e.ID]
			if !fetched || !got {
				// No round covered this entry — the trigger budget was
				// exhausted, or the shared round's scope did not include it.
				// The snapshot is served AS a snapshot: nothing is written, and
				// nothing is claimed to be current. There is deliberately no
				// outcome invented here; `unreachable` would name a connection
				// nobody attempted, and the closed enum has no member for "we
				// did not look".
				v, err := viewOf(e, snaps[e.ID], now)
				if err != nil {
					return err
				}
				if !v.ObservedAt.IsZero() {
					v.Stale, v.StaleFor = true, now.Sub(v.ObservedAt)
				}
				if v.Stale {
					stale++
				}
				views = append(views, v)
				continue
			}
			outcome := res.Outcome
			switch {
			case outcome == remotefetch.OutcomeOK && res.Listing.Identity == selfIdentity:
				outcome = remotefetch.OutcomeSelfConnected
			case outcome == remotefetch.OutcomeOK && conflicted[res.Listing.Identity]:
				outcome = remotefetch.OutcomeIdentityConflict
			}

			if outcome == remotefetch.OutcomeOK {
				snap, err := snapshotOf(e.ID, res.Listing, now)
				if err != nil {
					return err
				}
				if err := r.Remotes().WriteSnapshot(ctx, p, snap); err != nil {
					return err
				}
				snaps[e.ID] = snap
			} else {
				stale++
				if err := r.Remotes().RecordFetchFailure(ctx, p, e.ID, now, string(outcome)); err != nil {
					return err
				}
				prev := snaps[e.ID]
				prev.RemoteID, prev.LastAttemptAt, prev.LastOutcome = e.ID, now, string(outcome)
				snaps[e.ID] = prev
				ev, err := newAuditEvent(ctx, audit.EventRemoteFetchFailed, caller.Principal,
					audit.Object{Type: "remote", ID: e.ID}, audit.OutcomeFailure, "", audit.Payload{
						"remote_id": e.ID, "name": e.Name, "fetch_outcome": string(outcome),
					})
				if err != nil {
					return err
				}
				if err := r.Audit().InsertInstance(ctx, p, ev); err != nil {
					return err
				}
			}
			v, err := viewOf(e, snaps[e.ID], now)
			if err != nil {
				return err
			}
			views = append(views, v)
		}

		ev, err := domainEvent(ctx, audit.EventRemoteDirectoryViewed, caller.Principal,
			audit.Object{Type: "directory", ID: "instance"}, audit.Payload{
				"remote_count": len(entries), "stale_count": stale,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	return views, err
}

// RenameRemote changes the display name — the ADR's one mutable field. There
// is no URL or pin edit anywhere, by construction: re-pointing a stored
// credential at a different host is the credential-redirect attack, so
// re-pointing is remove + add, which re-runs the full human ceremony.
func (s *Remotes) RenameRemote(ctx context.Context, actor Actor, name, newName string) (RemoteView, error) {
	if err := checkName("remote name", newName); err != nil {
		return RemoteView{}, err
	}
	now := s.now()
	var out RemoteView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteRename, domain.Scope{})
		if err != nil {
			return err
		}
		entry, err := r.Remotes().GetByName(ctx, p, name)
		if err != nil {
			return err
		}
		if err := r.Remotes().Rename(ctx, p, entry.ID, newName); err != nil {
			return err
		}
		entry.Name = newName
		snapshot, err := r.Remotes().Snapshot(ctx, p, entry.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		out, err = viewOf(entry, snapshot, now)
		if err != nil {
			return err
		}

		e, err := domainEvent(ctx, audit.EventRemoteRenamed, caller.Principal,
			audit.Object{Type: "remote", ID: entry.ID}, audit.Payload{
				"remote_id": entry.ID, "old_name": name, "new_name": newName,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
	return out, err
}

// RemoveRemote destroys the entry, its credential and its snapshot.
//
// It does NOT revoke anything on the serving side, and the surfaces say so
// every time: destroying the local copy is not revocation, and pretending
// otherwise would leave a live credential the operator believes is dead.
func (s *Remotes) RemoveRemote(ctx context.Context, actor Actor, name string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRemoteRemove, domain.Scope{})
		if err != nil {
			return err
		}
		entry, err := r.Remotes().GetByName(ctx, p, name)
		if err != nil {
			return err
		}
		// The snapshot goes with it by ON DELETE CASCADE, so there is no
		// second delete here that could be forgotten or could fail alone.
		if err := r.Remotes().Delete(ctx, p, entry.ID); err != nil {
			return err
		}
		e, err := domainEvent(ctx, audit.EventRemoteRemoved, caller.Principal,
			audit.Object{Type: "remote", ID: entry.ID}, audit.Payload{
				"remote_id": entry.ID, "name": entry.Name, "url": entry.URL,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, e)
	})
}

// RemoteOrigins is the viewing side's own CSP input: the origins of every
// configured remote, for the dynamic `connect-src` extension. A closed list
// read from the entries themselves, never a wildcard.
//
// It takes NO ACTOR and mints no proof, deliberately. Its only consumer is the
// CSP header on the pre-authentication document response, where no caller
// exists to authorize — and the value it returns is one the response then
// publishes to every browser that loads the SPA. The knowing deviation is
// recorded on the resolver method; see internal/store/authn/workspace.go.
func (s *Remotes) RemoteOrigins(ctx context.Context) ([]string, error) {
	var out []string
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var e error
		out, e = az.RemoteOrigins(ctx)
		return e
	})
	return out, err
}

// knownIdentities maps every already-observed remote identity to the entry
// naming it, so a duplicate is refused at add time rather than discovered as a
// conflict at the next view.
func knownIdentities(ctx context.Context, rr store.RemoteReader, p authz.Proof) (map[string]string, error) {
	entries, err := rr.List(ctx, p)
	if err != nil {
		return nil, err
	}
	byID := map[string]string{}
	for _, e := range entries {
		byID[e.ID] = e.Name
	}
	snaps, err := rr.Snapshots(ctx, p)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, sn := range snaps {
		if sn.InstanceIdentity != "" {
			out[sn.InstanceIdentity] = byID[sn.RemoteID]
		}
	}
	return out, nil
}

// conflictingIdentities finds identities that arrived from more than one entry
// in ONE round. Both entries are marked duplicated and neither is served as
// current — a restored clone left running is a detectable misconfiguration,
// not a supported state, and picking a winner would hide it.
func conflictingIdentities(results map[string]remotefetch.Result) map[string]bool {
	seen := map[string]int{}
	for _, res := range results {
		if res.Outcome == remotefetch.OutcomeOK {
			seen[res.Listing.Identity]++
		}
	}
	out := map[string]bool{}
	for id, n := range seen {
		if n > 1 {
			out[id] = true
		}
	}
	return out
}

func snapshotOf(remoteID string, l remotefetch.Listing, now time.Time) (store.RemoteSnapshot, error) {
	// Sorted before storage so two fetches of the same fleet produce the same
	// bytes — a snapshot that churned on map order would look like change.
	orgs := make([]remotefetch.OrgEntry, len(l.Orgs))
	copy(orgs, l.Orgs)
	sort.Slice(orgs, func(i, j int) bool { return orgs[i].Name < orgs[j].Name })
	for i := range orgs {
		ps := make([]string, len(orgs[i].Projects))
		copy(ps, orgs[i].Projects)
		sort.Strings(ps)
		orgs[i].Projects = ps
	}
	raw, err := json.Marshal(orgs)
	if err != nil {
		return store.RemoteSnapshot{}, err
	}
	return store.RemoteSnapshot{
		RemoteID:      remoteID,
		LastAttemptAt: now,
		LastOutcome:   string(remotefetch.OutcomeOK),
		ObservedAt:    now,

		InstanceIdentity: l.Identity,
		Version:          l.Version,
		OrgCount:         int64(len(orgs)),
		ProjectCount:     int64(l.CountProjects()),
		Listing:          raw,
	}, nil
}

// viewOf renders one entry plus its snapshot.
//
// A stored snapshot that does not parse is an INVARIANT BREAK, not an empty
// directory: this instance wrote those bytes itself, from a listing it had
// already bounded and sorted. Swallowing the parse error would render the
// remote as reachable with zero organisations — a plausible-looking answer that
// is simply false, and the one failure mode a directory must never produce.
func viewOf(e store.Remote, sn store.RemoteSnapshot, now time.Time) (RemoteView, error) {
	v := RemoteView{
		ID: e.ID, Name: e.Name, URL: e.URL, SPKIPin: e.SPKIPin,
		CreatedAt: e.CreatedAt, CreatedBy: e.CreatedBy,
		State: sn.LastOutcome, LastAttemptAt: sn.LastAttemptAt,
		ObservedAt: sn.ObservedAt, Identity: sn.InstanceIdentity,
		Version: sn.Version, OrgCount: sn.OrgCount, ProjectCount: sn.ProjectCount,
	}
	// Staleness is decided by the OUTCOME, not by the age: a fetch that just
	// failed makes even a one-second-old snapshot stale, and a fetch that just
	// succeeded makes a week-old row current again.
	if sn.LastOutcome != "" && sn.LastOutcome != string(remotefetch.OutcomeOK) && !sn.ObservedAt.IsZero() {
		v.Stale = true
		v.StaleFor = now.Sub(sn.ObservedAt)
	}
	if len(sn.Listing) > 0 {
		var orgs []remotefetch.OrgEntry
		if err := json.Unmarshal(sn.Listing, &orgs); err != nil {
			return RemoteView{}, fmt.Errorf(
				"service: the stored directory snapshot for remote %s is corrupt: %w", e.ID, err)
		}
		v.Orgs = make([]RemoteOrg, 0, len(orgs))
		for _, o := range orgs {
			v.Orgs = append(v.Orgs, RemoteOrg{Name: o.Name, Projects: o.Projects})
		}
	}
	return v, nil
}

// remoteCredentialAAD binds a sealed directory credential to the row that owns
// it, so a ciphertext moved between rows fails to open.
func remoteCredentialAAD(remoteID string) crypto.InstanceFieldAAD {
	return crypto.InstanceFieldAAD{
		OwnerTable: "remotes", OwnerRowID: remoteID, FieldTag: "credential",
	}
}
