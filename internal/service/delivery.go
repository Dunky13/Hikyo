package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/oidcfed"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The machine fetch surface and its conditional cursor (#62, machine-identities
// ADR § Authentication, authorization and the fetch path; revision-model ADR §
// Revision identity as amended by the schema-model ADR).
//
// WHAT IS DELIVERED TODAY, stated first because it bounds everything below. A
// fetch projects one committed snapshot: config plaintext under read, secret
// plaintext under reveal (or reveal-history for pinned non-current material),
// and secret presence otherwise. The full manifest still keys the change token.
//
// THE CURSOR IS BOUND TO FIVE THINGS, never to content alone, and the ADR's
// reasoning for each is in internal/delivery. The mechanism here is deliberately
// the dullest one that works: the server recomputes the cursor for the state it
// is about to serve and compares it to the one presented. A match means
// "current"; anything else means a full authorized delivery. There is no cursor
// decoding, no cursor versioning, and no upgrade path to maintain — which is
// exactly what makes replacing the manifest computation safe when real revisions
// land, because every outstanding cursor mismatches once and every caller
// re-syncs.

// FetchResult is one machine fetch.
type FetchResult struct {
	// CredentialID is the authenticated caller's immutable credential id. It is
	// returned on BOTH dispositions because clients bind it into snapshot AAD
	// and offline disclosure records rather than guessing their wire identity.
	CredentialID string
	// Current reports that the presented cursor named the state the server was
	// about to serve. NO CONTENT accompanies it — that is the whole point: only
	// a fetch that actually delivers is a disclosure.
	Current bool
	// Cursor is the opaque cursor for the state this answer describes. It is
	// returned on BOTH dispositions: a caller told "current" must be able to
	// keep polling without having to re-fetch to learn its own cursor.
	Cursor string
	// ChangeToken is the keyed delivery-manifest token, `v1:`-prefixed. It is
	// non-secret metadata by construction (keyed, not a digest of content), so
	// it may flow into pod annotations and logs — which is what the Kubernetes
	// operator's hash-annotation restart mechanism consumes.
	ChangeToken string
	// SchemaRevision is the project's monotonic key-catalogue revision, the
	// human-facing ordering the ADR pairs with the opaque token.
	SchemaRevision int64
	// Keys is the delivered projection, empty when Current.
	Keys []DeliveredKey
	// PinnedRevision is non-zero when a durable pin selected the snapshot.
	PinnedRevision int64
	// PinExpired is a loud status condition only. Expiry ends retention
	// protection; it never changes delivery while the payload survives.
	PinExpired bool
	// IssuedAt and SnapshotExpiresAt are server assertions bound into the
	// client's offline-snapshot AAD. They are present on both dispositions.
	IssuedAt          time.Time
	SnapshotExpiresAt time.Time
}

// DeliveredKey is one key as the machine surface delivers it. Value is absent
// for an unrevealed secret and present for config or authorized secret material.
type DeliveredKey struct {
	KeyID          string
	Name           string
	Classification string
	Presence       delivery.Presence
	Value          *string
}

var (
	// ErrDeliveryKeyring refuses a fetch on a build with no keyring wired. The
	// change token is KEYED; computing one without a key is not a degraded
	// answer, it is a forgeable one.
	ErrDeliveryKeyring = errors.New("service: the delivery surface has no keyring wired")
	// ErrNotMaterialized refuses a fetch against an environment that has no
	// committed snapshot. Delivery reads only committed, valid snapshots or
	// FAILS CLOSED (flat-model ADR) — it never falls back to live state, which
	// is exactly the unvalidated read the snapshot exists to replace.
	ErrNotMaterialized = errors.New("service: this environment has no published revision yet")
)

// Delivery owns the machine fetch surface.
type Delivery struct {
	DB *store.DB
	// Keyring derives the scoped change-token and cursor keys. Nil refuses
	// every fetch.
	Keyring *crypto.Keyring
	// Federation validates a presented OIDC ID token BEFORE the transaction
	// opens. Nil means only bearer credentials may fetch, which is what a build
	// that did not wire federation should do.
	Federation *Federation
	Now        func() time.Time
	// FetchProbe is a conformance-only retry seam. Production leaves it nil;
	// it is invoked immediately after attempt-local response state is reset.
	FetchProbe DeliveryConformanceProbe
}

type DeliveryConformanceProbe interface {
	AfterAttemptReset(out *FetchResult) error
}

// OfflineRecord is one client-durable disclosure record produced before an
// offline snapshot released plaintext.
type OfflineRecord struct {
	RecordID       string
	KeyID          string
	KeyName        string
	Classification string
	OccurredAt     time.Time
	CredentialID   string
	Generation     string
	ServedFrom     time.Time
}

// ReconcileResult reports the idempotent outcome of one bounded batch.
type ReconcileResult struct {
	Accepted   int
	Duplicates int
}

func (s *Delivery) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// Fetch delivers the authorized projection of the addressed environment, or
// reports that the caller's cursor is current.
//
// `presented` is the raw artifact, because this is the one surface where the
// ARTIFACT CLASS decides how the caller is resolved: a `hik_` bearer credential
// resolves at the chokepoint from its verifier, while an OIDC ID token needs its
// signature checked against a cached JWKS first, outside any transaction. The
// branch is on the shape the caller sent, never on anything the server has yet
// decided to trust.
//
// HTTP admission makes this surface machine-only from #113 onward. FetchAs
// remains available to below-the-network local authority so operators and
// conformance fixtures can exercise the delivery mechanism without forging a
// machine artifact.
func (s *Delivery) Fetch(ctx context.Context, presented string, scope domain.Scope, cursor string) (FetchResult, error) {
	return s.FetchMode(ctx, presented, scope, cursor, false)
}

// FetchMode is Fetch with the authorized delivery mode made explicit.
func (s *Delivery) FetchMode(ctx context.Context, presented string, scope domain.Scope, cursor string, configOnly bool) (FetchResult, error) {
	if s.Keyring == nil {
		return FetchResult{}, ErrDeliveryKeyring
	}
	actor, err := s.callerActor(ctx, presented)
	if err != nil {
		return FetchResult{}, err
	}
	return s.FetchAsMode(ctx, actor, scope, cursor, configOnly)
}

// FetchAs is Fetch with the caller already decided.
//
// The split is where the artifact-class branch ends: everything past it is
// identical for a bearer credential, a federated binding and a human session,
// which is the ADR's "identical authority" made structural rather than asserted.
// It is exported because the below-the-network callers — the isolation harness
// and, later, any local-authority verb — resolve their principal by other means
// and must not have to forge an artifact to reach the same code.
func (s *Delivery) FetchAs(ctx context.Context, actor Actor, scope domain.Scope, cursor string) (FetchResult, error) {
	return s.FetchAsMode(ctx, actor, scope, cursor, false)
}

// FetchAsMode is FetchMode with the caller already decided.
func (s *Delivery) FetchAsMode(ctx context.Context, actor Actor, scope domain.Scope, cursor string, configOnly bool) (FetchResult, error) {
	if s.Keyring == nil {
		return FetchResult{}, ErrDeliveryKeyring
	}
	// The project sealer is resolved BEFORE the transaction, under this
	// operation's own formula, for the reason #50 recorded: minting a project
	// DEK opens transactions of its own, and sqlite serves writes on a single
	// connection. The window carries a key handle and no state; the transaction
	// re-authorizes and re-reads everything.
	// A refusal HERE takes the same recorded path a refusal inside the
	// transaction does. Without that, moving the sealer ahead of the
	// transaction would silently move every federated refusal off the audited
	// path: the pre-transaction window authorizes the same operation, so it
	// refuses the same callers, and a refusal that is not recorded is exactly
	// what fail-closed forbids.
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpDeliveryFetch, scope)
	if err != nil {
		return FetchResult{}, s.recordUnbound(ctx, actor, err)
	}

	var out FetchResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		resetDeliveryAttempt(&out)
		if s.FetchProbe != nil {
			if err := s.FetchProbe.AfterAttemptReset(&out); err != nil {
				return err
			}
		}
		// The clock is read INSIDE the transaction: the sealer preflight above
		// can take real time, and a credential whose idle, absolute or expiry
		// deadline passes during it must be refused by the authentication this
		// delivery actually rides, not admitted on a stale instant.
		issuedAt := s.now()
		caller, err := actor.resolve(ctx, az, issuedAt)
		if err != nil {
			return err
		}
		// The SAME authorization the delivering path performs, because it IS the
		// delivering path: a caller who has lost `read` gets
		// authorize()'s uniform nonexistent answer, never "current". A separate
		// cheap check on the conditional branch is exactly the shape the ADR
		// forbids.
		p, err := az.Authorize(ctx, caller, authz.OpDeliveryFetch, scope)
		if err != nil {
			return err
		}

		var selected *store.Snapshot
		historical := false
		pin, pinErr := r.Pins().GetForWorkload(ctx, p, string(caller.Principal))
		switch {
		case errors.Is(pinErr, store.ErrNotFound):
		case pinErr != nil:
			return pinErr
		default:
			authority := domain.PrincipalID(pin.AuthorityPrincipalID)
			holds, err := az.RecordedPrincipalHolds(ctx, caller, authority, authz.OpPinSet, scope)
			if err != nil {
				return err
			}
			if !holds {
				return invalidDetail("pinned delivery is refused because the recorded authority no longer holds pin and publish grants")
			}
			snapshot, err := r.Snapshots().AtRevision(ctx, p, pin.Revision)
			if err != nil {
				return err
			}
			latest, err := r.Snapshots().Latest(ctx, p)
			if err != nil {
				return err
			}
			if snapshot.Revision != latest.Revision {
				historical = true
				holds, err := az.RecordedPrincipalHolds(ctx, caller, authority, authz.OpPinSetHistory, scope)
				if err != nil {
					return err
				}
				if !holds {
					return invalidDetail("pinned delivery of revision %d is refused because the recorded authority no longer holds reveal-history", pin.Revision)
				}
			}
			if !snapshot.PayloadPresent {
				return collectedRevisionError(snapshot)
			}
			selected = &snapshot
			out.PinnedRevision = pin.Revision
			out.PinExpired = !pin.ExpiresAt.After(issuedAt)
		}

		// The non-content cursor components and the authorized value projection.
		grants, err := az.GrantRowsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		canReveal := holds(grants, domain.CapReveal, scope)
		if historical {
			canReveal = holds(grants, domain.CapRevealHistory, scope)
		}
		rows, manifest, schemaRevision, snapshotRevision, err := deliveryRows(
			ctx, r, p, sealer, selected, canReveal, configOnly)
		if err != nil {
			return err
		}
		changeToken, err := s.Keyring.ChangeToken(string(scope.Org), string(scope.Project), string(scope.Env), delivery.Manifest(manifest))
		if err != nil {
			return err
		}

		revisionOfAuthority, err := az.PrincipalGeneration(ctx, caller.Principal)
		if err != nil {
			return err
		}
		pinGeneration, err := az.PinGeneration(ctx, caller.Principal, scope.Env)
		if err != nil {
			return err
		}
		computed, err := s.Keyring.DeliveryCursor(
			string(scope.Org), string(scope.Project), string(scope.Env),
			delivery.EncodeCursor(delivery.Cursor{
				ChangeToken:           changeToken,
				Projection:            projectionOf(grants, scope),
				AuthorizationRevision: revisionOfAuthority,
				PinGeneration:         pinGeneration,
				ConfigOnly:            configOnly,
			}))
		if err != nil {
			return err
		}

		// Constant-time, like every other comparison against a
		// caller-controlled value in this codebase. A cursor is not a secret,
		// but it is a value an attacker can guess at, and a byte-at-a-time
		// comparison on a guessable value is a habit worth not having.
		current := cursor != "" &&
			subtle.ConstantTimeCompare([]byte(cursor), []byte(computed)) == 1

		out = FetchResult{
			CredentialID: caller.CredentialID,
			Current:      current, Cursor: computed, ChangeToken: changeToken,
			SchemaRevision: schemaRevision, PinnedRevision: out.PinnedRevision,
			PinExpired: out.PinExpired, IssuedAt: issuedAt,
			SnapshotExpiresAt: issuedAt.Add(delivery.SnapshotMaxAge),
		}
		if !current {
			out.Keys = rows
			for _, key := range rows {
				if key.Classification != string(schema.Secret) || key.Value == nil {
					continue
				}
				ev, err := domainEvent(ctx, audit.EventValueRevealed, caller.Principal,
					audit.Object{Type: "key", ID: key.KeyID}, audit.Payload{
						"key_id": key.KeyID, "name": audit.SanitizeFreeText(key.Name),
						"surface": "delivery", "revision": snapshotRevision,
					})
				if err != nil {
					return err
				}
				if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
					return err
				}
			}
		}

		disposition := "full"
		if current {
			disposition = "current"
		}
		e, err := domainEvent(ctx, audit.EventDeliveryFetched, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{
				"disposition":          disposition,
				"credential_id":        caller.CredentialID,
				"credential_kind":      caller.Artifact,
				"principal_class":      string(caller.Class),
				"scope":                renderScope(scope),
				"key_count":            len(out.Keys),
				"change_token_version": crypto.TokenVersion,
				"cursor_presented":     cursor != "",
				"config_only":          configOnly,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, e)
	})
	if err != nil {
		// The chokepoint's own federated refusals — an unbound identity, a revoked
		// binding, a failed binding predicate — are recorded HERE rather than
		// inside the transaction above, and the placement is the whole point: that
		// transaction rolled back, so an event staged inside it would be a durable
		// record that is not durable. It rides its own committing transaction, the
		// same shape #54's refuseOIDC uses, and it can only run now that the first
		// transaction has ended — a nested one would deadlock sqlite's single
		// writer until the retry deadline elapsed.
		return FetchResult{}, s.recordUnbound(ctx, actor, err)
	}
	return out, nil
}

// ReconcileOfflineRecords authenticates a live presenter and persists the
// client-side disclosure facts that were fsynced before offline plaintext was
// released. Dedupe is scoped to the presenting principal, so retries are safe.
func (s *Delivery) ReconcileOfflineRecords(ctx context.Context, presented string, scope domain.Scope, records []OfflineRecord) (ReconcileResult, error) {
	actor, err := s.callerActor(ctx, presented)
	if err != nil {
		return ReconcileResult{}, err
	}
	return s.ReconcileOfflineRecordsAs(ctx, actor, scope, records)
}

// ReconcileOfflineRecordsAs is ReconcileOfflineRecords with the caller decided.
func (s *Delivery) ReconcileOfflineRecordsAs(ctx context.Context, actor Actor, scope domain.Scope, records []OfflineRecord) (ReconcileResult, error) {
	if len(records) == 0 || len(records) > 1000 {
		return ReconcileResult{}, invalidDetail("offline reconciliation requires between 1 and 1000 records")
	}
	for _, record := range records {
		if record.RecordID == "" || len(record.RecordID) > 64 || record.KeyID == "" || len(record.KeyID) > 64 ||
			record.KeyName == "" || len(record.KeyName) > 256 || record.CredentialID == "" || len(record.CredentialID) > 64 ||
			record.Generation == "" || len(record.Generation) > 64 || record.OccurredAt.IsZero() || record.ServedFrom.IsZero() ||
			(record.Classification != string(schema.Config) && record.Classification != string(schema.Secret)) {
			return ReconcileResult{}, invalidDetail("offline reconciliation record %q is invalid", record.RecordID)
		}
	}

	var out ReconcileResult
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out = ReconcileResult{}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDeliveryReconcileOffline, scope)
		if err != nil {
			return err
		}
		// A production presenter is a machine credential. Resolve every credential
		// row for its service account without applying liveness: the served one may
		// have been revoked since the offline disclosure, but it must still belong
		// to the SAME account. LocalPrincipal remains the below-network authority
		// seam used by conformance and carries no credential to compare.
		servedCredentials := map[string]bool{}
		if caller.CredentialID != "" {
			sa, err := az.ServiceAccountByPrincipal(ctx, caller.Principal)
			if err != nil {
				return err
			}
			credentials, err := az.MachineCredentialsFor(ctx, sa.ID)
			if err != nil {
				return err
			}
			for _, credential := range credentials {
				servedCredentials[credential.ID] = true
			}
		}
		for _, record := range records {
			if caller.CredentialID != "" && !servedCredentials[record.CredentialID] {
				return invalidDetail("offline record %q names a credential outside the presenting service account", record.RecordID)
			}
			claimed, err := r.Audit().ClaimOfflineRecord(ctx, p, string(caller.Principal), record.RecordID, s.now())
			if err != nil {
				return err
			}
			if !claimed {
				out.Duplicates++
				continue
			}
			ev, err := newAuditEvent(ctx, audit.EventValueRevealed, caller.Principal,
				audit.Object{Type: "key", ID: record.KeyID}, audit.OutcomeSuccess, "", audit.Payload{
					"key_id": record.KeyID, "name": audit.SanitizeFreeText(record.KeyName),
					"classification": record.Classification, "surface": "offline-serve",
					"served_credential_id": record.CredentialID, "generation": record.Generation,
					"served_from": audit.FormatTime(record.ServedFrom),
				})
			if err != nil {
				return err
			}
			ev.OccurredAt = record.OccurredAt.UTC()
			ev.OccurredAsserted = true
			ev.Actor.CredentialID = caller.CredentialID
			ev.SourceIP, ev.UserAgent, ev.Origin = "", "", audit.OriginOfflineRecon
			if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
				return err
			}
			out.Accepted++
		}
		ev, err := domainEvent(ctx, audit.EventOfflineRecordsReconciled, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{
				"accepted": out.Accepted, "duplicates": out.Duplicates,
				"credential_id": caller.CredentialID, "scope": renderScope(scope),
			})
		if err != nil {
			return err
		}
		ev.Actor.CredentialID = caller.CredentialID
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return ReconcileResult{}, s.recordUnbound(ctx, actor, err)
	}
	return out, nil
}

// resetDeliveryAttempt keeps response state attempt-local. tx.Write may rerun
// its closure after a serialization failure; metadata observed by a rolled-back
// attempt must not survive into the successful attempt.
func resetDeliveryAttempt(out *FetchResult) { *out = FetchResult{} }

// callerActor picks how the presented artifact resolves.
//
// The federated branch runs its whole network half here, before any transaction
// exists. That placement is the one structural decision in this file: on sqlite a
// JWKS fetch inside a write transaction would hold the single writer for the
// duration of an unreachable issuer's timeout, turning an issuer outage into an
// instance-wide write outage — the exact self-inflicted failure the ADR's
// stale-but-valid rule exists to avoid.
func (s *Delivery) callerActor(ctx context.Context, presented string) (Actor, error) {
	if !oidcfed.LooksLikeToken(presented) {
		return Bearer(presented), nil
	}
	if s.Federation == nil {
		// A build without federation refuses a federated presentation rather
		// than falling through to the bearer path, where the token would be
		// hashed into a verifier that matches nothing and answer the same
		// uniform refusal by accident rather than by decision.
		return Actor{}, domain.ErrUnauthenticated
	}
	fed, err := s.Federation.Authenticate(ctx, presented)
	if err != nil {
		return Actor{}, err
	}
	return FederatedActor(fed), nil
}

// recordUnbound records the chokepoint's own federated refusals.
//
// It returns the ORIGINAL error unchanged unless the audit write itself failed,
// so the refusal keeps its uniform shape and a trail that cannot be written is a
// loud fault rather than a quiet refusal.
//
// A refusal that is NOT ErrUnauthenticated passes straight through: an
// authorization refusal is the uniform nonexistent answer, which authorize()
// already recorded through the denial writer, and a second row here would double
// -count it.
func (s *Delivery) recordUnbound(ctx context.Context, actor Actor, cause error) error {
	if actor.federated == nil || s.Federation == nil {
		return cause
	}
	if !errors.Is(cause, domain.ErrUnauthenticated) {
		return cause
	}
	refusalCause := ""
	if actor.federated.refusalCause != nil {
		refusalCause = actor.federated.refusalCause.load()
	}
	if auditErr := s.Federation.RecordBindingRefusal(ctx, actor.federated.IssuerID, refusalCause); auditErr != nil {
		return auditErr
	}
	return cause
}

// deliveryRows reads what the environment's LATEST COMMITTED SNAPSHOT
// delivers, and builds the manifest the change token is computed over.
//
// It reads the snapshot rather than live values, which is the flat-model ADR's
// "delivery reads only committed, valid snapshots" made structural: an
// environment with no published revision fails closed here rather than serving
// a state no publish ever validated.
//
// The manifest always carries the FULL plaintext state while the response is an
// authorized projection. The token must move when any value moves even when the
// caller cannot reveal it; its keyed construction discloses nothing about the
// values it covers.
func deliveryRows(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	selected *store.Snapshot, canReveal, configOnly bool) ([]DeliveredKey, []delivery.Row, int64, int64, error) {
	var snapshot store.Snapshot
	if selected == nil {
		var err error
		snapshot, err = r.Snapshots().Latest(ctx, p)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, 0, 0, ErrNotMaterialized
		}
		if err != nil {
			return nil, nil, 0, 0, err
		}
	} else {
		snapshot = *selected
	}
	entries, err := r.Snapshots().Entries(ctx, p, snapshot)
	if err != nil {
		return nil, nil, 0, 0, err
	}
	keys := make([]DeliveredKey, 0, len(entries))
	rows := make([]delivery.Row, 0, len(entries))
	for _, entry := range entries {
		plain, err := sealer.OpenField(snapshotAAD(
			entry.OrgID, entry.ProjectID, entry.EnvironmentID, entry.KeyID, entry.SnapshotID, entry.ID), entry.Ciphertext)
		if err != nil {
			return nil, nil, 0, 0, fmt.Errorf("service: snapshot entry %s: %w", entry.ID, err)
		}
		rows = append(rows, delivery.Row{
			Key: entry.KeyName, Classification: entry.Classification, Value: string(plain),
		})
		// Config-only is a distinct authorized projection. Secret rows are
		// omitted entirely; read already confers their presence, so this choice
		// creates no new existence probe and keeps the response unambiguous.
		if configOnly && entry.Classification == string(schema.Secret) {
			continue
		}
		key := DeliveredKey{
			KeyID: entry.KeyID, Name: entry.KeyName, Classification: entry.Classification,
			Presence: delivery.PresenceSet,
		}
		if entry.Classification == string(schema.Config) || canReveal {
			value := string(plain)
			key.Value = &value
		}
		keys = append(keys, key)
	}
	// The PINNED schema revision, not the live one: what this snapshot was
	// validated against is a property of the snapshot, and a schema that has
	// moved since must not make history claim it was validated at the new one.
	slices.SortFunc(keys, func(a, b DeliveredKey) int { return strings.Compare(a.Name, b.Name) })
	return keys, rows, snapshot.SchemaRevision, snapshot.Revision, nil
}

// projectionOf is the caller's AUTHORIZED DELIVERY PROJECTION: which of the
// three delivery-relevant capabilities it holds at the addressed environment.
//
// It is the cursor's second component, and the ADR's reasoning is worth
// restating because it fails in both directions without it. A workload granted
// `reveal` polls, the content has not changed, a content-only token matches, and
// it is told "current" — so it runs indefinitely without the secrets it is now
// entitled to, silently. And for a caller LACKING `reveal`, a cursor derived
// from secret-bearing content becomes a comparison oracle for whether hidden
// values changed.
//
// `reveal` and `reveal-history` change which secret values are delivered, so a
// movement in either capability must invalidate the prior cursor.
func projectionOf(grants []authz.GrantRow, scope domain.Scope) []string {
	at := domain.Scope{Org: scope.Org, Project: scope.Project, Env: scope.Env}
	var out []string
	for _, cap := range []domain.Capability{domain.CapRead, domain.CapReveal, domain.CapRevealHistory} {
		if holds(grants, cap, at) {
			out = append(out, string(cap))
		}
	}
	return out
}
