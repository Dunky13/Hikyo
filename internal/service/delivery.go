package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
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
// WHAT IS DELIVERED, stated first because it bounds everything below. A fetch
// delivers the authorized projection of the addressed environment's committed
// snapshot: each key's name, classification, presence, and — where the caller
// is authorized to receive it — its PLAINTEXT value. The per-key value rule is
// evaluated server-side, in-transaction, from the grant rows already loaded: a
// `config` value crosses under `read`, a `secret` value under `read ∧ reveal`
// (or `read ∧ reveal-history` for a pinned non-current revision), and a secret
// the caller may not reveal arrives presence-only with no value. That is the
// surface #63 (Compose) and #64 (the Kubernetes operator) consume to converge
// their delivery targets: a value moving changes the change token and therefore
// fires the consumer's rollout.
//
// THE CURSOR IS BOUND TO MORE THAN CONTENT ALONE, and the ADR's
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
	// Current reports that the presented cursor named the state the server was
	// about to serve. NO CONTENT accompanies it — that is the whole point: only
	// a fetch that actually delivers is a disclosure.
	Current bool
	// Cursor is the opaque cursor for the state this answer describes. It is
	// returned on BOTH dispositions: a caller told "current" must be able to
	// keep polling without having to re-fetch to learn its own cursor.
	Cursor string
	// ChangeToken is the keyed delivery-manifest token, `v1:`-prefixed. It is
	// change-detection material ONLY — the conditional-fetch cursor's input —
	// and is never itself a workload-visible value (k8s ADR § Declared
	// amendment): what reaches a pod annotation is the consumer's client-side
	// per-target keyed stamp, not this token. It is non-secret metadata by
	// construction (keyed, not a digest of content), so it may flow into logs
	// and change-detection caches.
	ChangeToken string
	// CredentialExpiresAt is the presenting credential's expiry when finite
	// (bearer credential `expires_at`; federated binding expiry), and the zero
	// time for an indefinite credential. The operator surfaces it as the ADR's
	// ahead-of-time expiry condition.
	CredentialExpiresAt time.Time
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
	// CredentialID is the authenticated caller's immutable credential id. It is
	// returned on BOTH dispositions because clients bind it into snapshot AAD
	// and offline disclosure records rather than guessing their wire identity.
	CredentialID string
	// IssuedAt and SnapshotExpiresAt are server assertions bound into the
	// client's offline-snapshot AAD. They are present on both dispositions;
	// SnapshotExpiresAt is IssuedAt + delivery.SnapshotMaxAge.
	IssuedAt          time.Time
	SnapshotExpiresAt time.Time
}

// DeliveredKey is one key as the machine surface delivers it: its name, its
// classification, its presence, and — iff the caller was authorized to receive
// it — its plaintext Value.
type DeliveredKey struct {
	// KeyID is the immutable key id (entry.KeyID), delivered so a client can
	// bind per-key offline disclosure records to a stable identity.
	KeyID          string
	Name           string
	Classification string
	Presence       delivery.Presence
	// Value is the delivered plaintext, non-nil IFF it actually crossed to this
	// caller. A nil Value on a `set` key is presence-only: the snapshot delivers
	// the key, but this caller may not receive its plaintext. A pointer, not a
	// string, because the empty string is a legitimate delivered value and
	// "delivered empty" must be distinguishable from "not delivered".
	Value *string
}

// FetchOptions carries the per-request delivery controls that are not the
// cursor: the projection mode and the acknowledged loader-control keys. It is a
// struct rather than positional arguments so the two can grow without churning
// every caller again, and its zero value is the default fetch — `full`
// projection, no acknowledgement — which is what the below-the-network callers
// that do not care about either want.
type FetchOptions struct {
	// Projection is the delivery projection. The empty value means `full`.
	Projection delivery.Mode
	// AcknowledgedKeys is the loader-control acknowledgement, recorded on the
	// fetch audit record AS PRESENTED and otherwise ignored — the server filters
	// nothing and refuses nothing on it (k8s ADR § Loader-control).
	AcknowledgedKeys []string
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
func (s *Delivery) Fetch(ctx context.Context, presented string, scope domain.Scope, cursor string, opts FetchOptions) (FetchResult, error) {
	if s.Keyring == nil {
		return FetchResult{}, ErrDeliveryKeyring
	}
	actor, err := s.callerActor(ctx, presented)
	if err != nil {
		return FetchResult{}, err
	}
	return s.FetchAs(ctx, actor, scope, cursor, opts)
}

// FetchAs is Fetch with the caller already decided.
//
// The split is where the artifact-class branch ends: everything past it is
// identical for a bearer credential, a federated binding and a human session,
// which is the ADR's "identical authority" made structural rather than asserted.
// It is exported because the below-the-network callers — the isolation harness
// and, later, any local-authority verb — resolve their principal by other means
// and must not have to forge an artifact to reach the same code.
func (s *Delivery) FetchAs(ctx context.Context, actor Actor, scope domain.Scope, cursor string, opts FetchOptions) (FetchResult, error) {
	if s.Keyring == nil {
		return FetchResult{}, ErrDeliveryKeyring
	}
	// Normalized once, here, so both the value/manifest projection and the
	// cursor bind-tuple use the same canonical mode and can never disagree. An
	// unrecognized mode is refused loudly BEFORE any work — the exported
	// below-the-network path has no OpenAPI enum in front of it, so validating
	// here is what keeps a bogus projection from reaching the cursor and the
	// audit schema as a value neither can name.
	mode := delivery.NormalizeMode(opts.Projection)
	if mode != delivery.ModeFull && mode != delivery.ModeConfigOnly {
		return FetchResult{}, invalidDetail("unknown delivery projection %q", opts.Projection)
	}
	// acknowledged_keys is CALLER-CONTROLLED: the operator sends its
	// loader-control acknowledgement, which the server records and otherwise
	// ignores (k8s ADR § Loader-control). "Records and ignores" is not "accepts
	// anything" — a list over the bound or carrying a name outside the key-name
	// grammar is a malformed REQUEST, so it is refused as domain.ErrInvalid (400
	// on the wire) HERE, before the sealer preflight opens any transaction. The
	// alternative is worse than a bad answer: an over-long or malformed list
	// would otherwise reach the closed audit schema mid-transaction, where the
	// MaxLen/sanitize bound is a fail-LOUD (500) invariant, so a caller typo
	// would masquerade as a server fault after work had already run. The bound
	// and the grammar are the same the audit registry enforces; refusing them up
	// front is what makes the wire answer a clean 400.
	if len(opts.AcknowledgedKeys) > delivery.MaxAcknowledgedKeys {
		return FetchResult{}, invalidDetail("acknowledged_keys carries %d entries, at most %d are allowed",
			len(opts.AcknowledgedKeys), delivery.MaxAcknowledgedKeys)
	}
	for _, name := range opts.AcknowledgedKeys {
		if err := schema.CheckKeyName(name); err != nil {
			return FetchResult{}, invalidDetail("acknowledged_keys entry %q is not a valid key name", name)
		}
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
		// issuedAt is captured ONCE here so the credential-liveness clock, the
		// pin-expiry check, and the server-asserted snapshot issuance/expiry all
		// name the same instant.
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
		// pinnedNonCurrent gates the secret-value rule below: a pinned delivery
		// of a revision that is NOT the environment's latest discloses history,
		// so a `secret` value crosses only under `reveal-history`, not `reveal`.
		pinnedNonCurrent := false
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
				pinnedNonCurrent = true
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

		// The caller's grant rows, loaded BEFORE the projection because the
		// per-key value rule reads them too: whether a `secret` value crosses is
		// `holds(reveal)` (or `holds(reveal-history)` for a pinned non-current
		// revision) over exactly these rows. There is no second authorization
		// path — the operation formula stays `read@environment`, and value
		// disclosure is a projection of the grants that formula already required.
		grants, err := az.GrantRowsForPrincipal(ctx, caller.Principal)
		if err != nil {
			return err
		}
		// The per-project machine-reveal opt-in is the second half of the
		// per-key secret rule for a machine caller: `reveal` rows deliver
		// plaintext only while the project has opted in (source-of-truth ADR).
		// Read live on every fetch, like the grants; it is part of the
		// authorized projection, so flipping it moves every machine cursor.
		revealOptIn, revealGeneration, err := az.MachineRevealOptIn(ctx, caller, scope.Project)
		if err != nil {
			return err
		}
		if !revealOptIn {
			grants = withoutReveal(grants)
		}

		rows, manifest, revision, snapshotRevision, err := deliveryRows(
			ctx, r, p, sealer, scope, selected, grants, mode, pinnedNonCurrent)
		if err != nil {
			return err
		}
		changeToken, err := s.Keyring.ChangeToken(string(scope.Org), string(scope.Project), string(scope.Env), delivery.Manifest(manifest))
		if err != nil {
			return err
		}

		// The other two non-content components.
		revisionOfAuthority, err := az.PrincipalGeneration(ctx, caller.Principal)
		if err != nil {
			return err
		}
		pinGeneration, err := az.PinGeneration(ctx, caller.Principal, scope.Env)
		if err != nil {
			return err
		}
		// The pinned revision only when it is NON-CURRENT: a pinned-current
		// delivery is content- and authority-identical to an unpinned latest,
		// so binding 0 there keeps their cursors equal, and the moment a later
		// publish makes this pin historical the term goes 0 -> pin.Revision and
		// the cursor moves exactly once — which is the transition where the
		// secret-value authority flips from `reveal` to `reveal-history`.
		pinnedHistoricalRevision := int64(0)
		if pinnedNonCurrent {
			pinnedHistoricalRevision = out.PinnedRevision
		}
		computed, err := s.Keyring.DeliveryCursor(
			string(scope.Org), string(scope.Project), string(scope.Env),
			delivery.EncodeCursor(delivery.Cursor{
				ChangeToken:              changeToken,
				Projection:               projectionOf(grants, scope, revealGeneration),
				AuthorizationRevision:    revisionOfAuthority,
				PinGeneration:            pinGeneration,
				Mode:                     mode,
				PinnedHistoricalRevision: pinnedHistoricalRevision,
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
			Current: current, Cursor: computed, ChangeToken: changeToken,
			CredentialExpiresAt: caller.CredentialExpiresAt,
			SchemaRevision:      revision, PinnedRevision: out.PinnedRevision,
			PinExpired:        out.PinExpired,
			CredentialID:      caller.CredentialID,
			IssuedAt:          issuedAt,
			SnapshotExpiresAt: issuedAt.Add(delivery.SnapshotMaxAge),
		}
		if !current {
			out.Keys = rows
		}

		disposition := "full"
		if current {
			disposition = "current"
		}
		// The values actually delivered — config plus any authorized secrets —
		// which is the count of disclosure events this fetch emits, and is
		// distinct from key_count because presence-only keys carry no value.
		// A "current" answer delivers nothing, so both counts are zero.
		delivered := 0
		for i := range out.Keys {
			if out.Keys[i].Value != nil {
				delivered++
			}
		}
		// acknowledged_keys is recorded AS PRESENTED — the k8s ADR's audit
		// obligation is "which acknowledgement was in force", so it is neither
		// sorted nor deduped here. A nil slice records as an empty list.
		acknowledged := opts.AcknowledgedKeys
		if acknowledged == nil {
			acknowledged = []string{}
		}
		fetchEvent, err := domainEvent(ctx, audit.EventDeliveryFetched, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{
				"disposition":          disposition,
				"credential_id":        caller.CredentialID,
				"credential_kind":      caller.Artifact,
				"principal_class":      string(caller.Class),
				"scope":                renderScope(scope),
				"key_count":            len(out.Keys),
				"projection":           string(mode),
				"acknowledged_keys":    acknowledged,
				"delivered_count":      delivered,
				"change_token_version": crypto.TokenVersion,
				"cursor_presented":     cursor != "",
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, fetchEvent); err != nil {
			return err
		}
		// One immutable disclosure record per delivered VALUE, referencing the
		// fetch record by correlation id: the fetch is the envelope, these are
		// its contents. Presence-only keys emit nothing (no value crossed), and
		// a "current" answer carries no keys at all.
		for i := range out.Keys {
			k := out.Keys[i]
			if k.Value == nil {
				continue
			}
			disclosure, err := newAuditEvent(ctx, audit.EventDisclosure, caller.Principal,
				audit.Object{Type: "environment", ID: string(scope.Env)}, audit.OutcomeSuccess,
				fetchEvent.ID, audit.Payload{
					"key":             k.Name,
					"classification":  k.Classification,
					"revision":        snapshotRevision,
					"credential_id":   caller.CredentialID,
					"credential_kind": caller.Artifact,
					"principal_class": string(caller.Class),
					"scope":           renderScope(scope),
					"projection":      string(mode),
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, disclosure); err != nil {
				return err
			}
		}
		return nil
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
//
// The per-key event stays audit.EventValueRevealed (disclosure.value_revealed,
// surface: offline-serve) rather than #64's audit.EventDisclosure: that event
// requires a snapshot `revision` an offline record does not carry, references a
// fetch envelope this path has no equivalent for, and lacks the served_credential
// _id/generation/served_from fields the offline disclosure records. Extending
// EventValueRevealed's schema with those (optional) fields is the clean home.
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

// deliveryRows reads what the environment's committed snapshot delivers, builds
// the manifest the change token is computed over, and decides per key whether
// the caller receives the plaintext.
//
// It reads the snapshot rather than live values, which is the flat-model ADR's
// "delivery reads only committed, valid snapshots" made structural: an
// environment with no published revision fails closed here rather than serving
// a state no publish ever validated.
//
// Two projections come out of one pass and the split is the whole design.
//
//   - The MANIFEST carries plaintext for every delivered key (under `full`) so
//     the KEYED change token moves whenever any value moves — the token is
//     unforgeable and un-invertible, so it discloses nothing about the values it
//     covers. Under `config-only` the manifest carries CONFIG keys only, so the
//     token a config-only consumer holds is stable across secret rotations it
//     was never meant to see.
//   - The KEYS the caller receives carry plaintext only where the caller is
//     authorized: config under `read` (already held), secret under
//     `holds(reveal)` — or `holds(reveal-history)` for a pinned non-current
//     revision — and otherwise presence-only. Under `config-only`, secret keys
//     are omitted entirely rather than delivered presence-only.
//
// snapshotRevision (the delivered revision, pinned or latest) rides out for the
// per-value disclosure records; schemaRevision is the human-facing catalogue
// ordering.
func deliveryRows(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	scope domain.Scope, selected *store.Snapshot, grants []authz.GrantRow, mode delivery.Mode,
	pinnedNonCurrent bool) (keys []DeliveredKey, manifest []delivery.Row, schemaRevision, snapshotRevision int64, err error) {
	var snapshot store.Snapshot
	if selected == nil {
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
	// The capability that authorizes a secret VALUE for this fetch: history for
	// a pinned non-current revision (it discloses the past), reveal otherwise.
	secretCap := domain.CapReveal
	if pinnedNonCurrent {
		secretCap = domain.CapRevealHistory
	}
	at := domain.Scope{Org: scope.Org, Project: scope.Project, Env: scope.Env}
	revealsSecret := holds(grants, secretCap, at)

	keys = make([]DeliveredKey, 0, len(entries))
	manifest = make([]delivery.Row, 0, len(entries))
	for _, entry := range entries {
		secret := entry.Classification == string(schema.Secret)
		// config-only is a server-side authorized term: a secret key is not in
		// the delivery and not in the manifest the token covers, so a secret's
		// existence or value never leaks into a config-only consumer's token.
		if secret && mode == delivery.ModeConfigOnly {
			continue
		}
		plain, err := sealer.OpenField(snapshotAAD(
			entry.OrgID, entry.ProjectID, entry.EnvironmentID, entry.KeyID, entry.SnapshotID, entry.ID), entry.Ciphertext)
		if err != nil {
			return nil, nil, 0, 0, fmt.Errorf("service: snapshot entry %s: %w", entry.ID, err)
		}
		key := DeliveredKey{
			KeyID: entry.KeyID, Name: entry.KeyName, Classification: entry.Classification,
			Presence: delivery.PresenceSet,
		}
		// Config crosses under the read the operation already required; a secret
		// crosses only under reveal / reveal-history, else presence-only.
		if !secret || revealsSecret {
			value := string(plain)
			key.Value = &value
		}
		keys = append(keys, key)
		manifest = append(manifest, delivery.Row{
			Key: entry.KeyName, Classification: entry.Classification, Value: string(plain),
		})
	}
	// The PINNED schema revision, not the live one: what this snapshot was
	// validated against is a property of the snapshot, and a schema that has
	// moved since must not make history claim it was validated at the new one.
	return keys, manifest, snapshot.SchemaRevision, snapshot.Revision, nil
}

// withoutReveal is the grant set a machine caller effectively holds while its
// project's machine-reveal opt-in is off: every `reveal` and `reveal-history`
// row is inert for delivery, so both the per-key rule and the cursor's
// projection are computed as if they were not there.
func withoutReveal(grants []authz.GrantRow) []authz.GrantRow {
	out := make([]authz.GrantRow, 0, len(grants))
	for _, g := range grants {
		if g.Grant.Capability == domain.CapReveal || g.Grant.Capability == domain.CapRevealHistory {
			continue
		}
		out = append(out, g)
	}
	return out
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
// It is computed from the caller's real grant rows, so it moves the moment a
// disclosure capability is granted or revoked — which is exactly when what the
// caller may receive changes, now that `reveal` and `reveal-history` gate
// whether a secret's plaintext crosses (deliveryRows).
//
// The machine-reveal opt-in's generation is the projection's last term for a
// machine caller: the opt-in is part of what the caller is authorized to
// receive, and binding its generation rather than its value makes every flip
// move the cursor - also for a read-only principal the flip does not yet
// affect, and across an off-on-off pair between two polls. Humans carry
// generation 0 and no term.
func projectionOf(grants []authz.GrantRow, scope domain.Scope, revealGeneration int64) []string {
	at := domain.Scope{Org: scope.Org, Project: scope.Project, Env: scope.Env}
	var out []string
	for _, cap := range []domain.Capability{domain.CapRead, domain.CapReveal, domain.CapRevealHistory} {
		if holds(grants, cap, at) {
			out = append(out, string(cap))
		}
	}
	if revealGeneration > 0 {
		out = append(out, fmt.Sprintf("machine-reveal-generation:%d", revealGeneration))
	}
	return out
}
