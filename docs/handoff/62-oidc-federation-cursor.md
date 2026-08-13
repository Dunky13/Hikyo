# Handoff: #62 OIDC federation + conditional fetch cursor

Issue: https://github.com/Dunky13/hikyo/issues/62 (parent #41; the M1 federation
portion of the machine-identities ADR, `docs/adr/machine-identities.md` on the
`wayfinder-docs` branch, plus the revision ADR's change token as amended by the
schema ADR). Blocked-by #61 is merged; this builds directly on its credential
-kind discriminator.

## What shipped

### A. OIDC federation — the `oidc-federation` credential kind

- **Issuer configuration is instance-scoped**, under `instance-config`
  (`internal/service/federation.go`, four operations:
  `federation.issuer-{create,list,update,delete}`). The `iss` string is stored
  and matched **byte-exact** — no case folding, no URL resolution, no
  trailing-slash stripping — under a `UNIQUE` index. `issuer_type` and
  `jwks_mode` are closed sets; `refused_audiences` is a **required non-empty
  list**, because the whole default-audience rule turns on the instance knowing
  what the default is and the Kubernetes API-server audience is
  operator-supplied rather than derivable. `issuer` and `issuer_type` are
  immutable (an update moves only the JWKS source and the refused list): moving
  either would silently re-point every binding underneath at a different
  external authority.
- **Discovery *and* static JWKS.** Discovery is the default and goes through
  go-oidc's `NewProvider`, which re-asserts the byte-exact issuer against the
  document it fetched. Static is the air-gap alternative, parsed on the way past
  and never fetched; its documented failure mode (the issuer rotates, the
  configuration does not) is a **loud refusal**, exercised by
  `TestFederationStaticJWKSSQLite`.
- **Federated bindings are rows of `machine_credentials`**, under #61's
  credential-kind discriminator, with five nullable columns (`issuer_id`,
  `subject`, `audience`, `required_claims`, `reactivated_at`) and two total
  shape `CHECK`s so a half-shaped row of either kind is unrepresentable.
  Migration `00017_oidc_federation.sql` on both engines: sqlite through the
  documented table rebuild (00006/00009 precedent — it can neither widen a
  `CHECK` nor make a column nullable), postgres through `ALTER`.
  *Justification for the row rather than a sibling table is in the migration's
  header:* the ADR puts a binding under the same lifetime rules as a bearer
  credential, so a sibling would have duplicated `lifetime`, `expires_at`,
  `credential_epoch` and `revoked_at` plus every clamp and enumeration query —
  and the **liveness-aware uniqueness** a replacement needs
  (`UNIQUE (issuer_id, subject) WHERE revoked_at IS NULL`) cannot span two
  tables.
- **Byte-exact `(issuer, subject)`, one service account.** No wildcards, no
  namespace patterns, no path prefixes, no case folding, no JIT. An unbound
  identity resolves nothing. The CLI grammar has no flag that could express a
  pattern.
- **Required claims are mandatory and typed.** The wire shape is a
  *discriminated* scalar (`string_value` | `number_value` | `bool_value`,
  exactly one) rather than free-form JSON, so "a string is never folded to a
  number" holds at the wire boundary and an int64 repository id survives without
  passing through a float. Validation compares the canonical JSON scalar
  byte-exactly. `TestFederationClaimTypeIsNotFoldedSQLite` pins it.
- **Every CI binding must pin `event_name`**, refused at *creation*
  (`ErrBindingEventName`) and re-checked at *validation*.
  `pull_request`/`pull_request_target` are refused unless one of them is what the
  binding deliberately pinned. The fixture asserts the load-bearing fact first —
  that a Forgejo `pull_request_target` subject *equals* the production
  `push` subject — so the refusal cannot be a subject mismatch in disguise.
- **Where the issuer exposes immutable identifiers, pinning them is ENFORCED at
  binding creation** — `repository_id` + `repository_owner_id` for GitHub Actions,
  the nested `/kubernetes.io/serviceaccount/uid` for Kubernetes, with no override
  flag. Forgejo Actions exposes no immutable numeric identifiers, so its rule is
  `repository` + `event_name`; that ceiling is recorded in the deviations below.
- **Audience binding is mandatory and the issuer's default is refused** at both
  enforcement points — a binding may not *name* a refused audience, and a token
  may not *carry* one even alongside the bound audience (a Kubernetes token
  minted for the API server that also lists Hikyo is still a token the API server
  could have been handed).
- **Complete validation through go-oidc, no hand-rolled JWT or signature code**
  (`internal/oidcfed`). Exact `iss`, signature under a pinned algorithm
  allowlist (`none` never in it), `exp`/`iat`/`nbf` within a bounded skew, every
  pinned claim, the bound `sub`. `nbf` is read explicitly because go-oidc does
  not. Plus **two Hikyo-side caps independent of the issuer**: maximum accepted
  token age and maximum `exp - iat` span.
- **Bindings are immutable.** No PUT, no PATCH, no `update` verb, no
  `binding-update` operation. A change is a **replacement mint** through the
  same route naming `replaces`: revoke plus insert in one transaction, carrying
  the full § *Minting and widening* formula — `manage-identities(project)` ∧ a
  per-class disclosure capability over the whole post-state ∧ reauthentication,
  reusing #61's `Auth.RequireDisclosureAuthority` unchanged. Delete and list ride
  `identity.credential-revoke` / `identity.credential-list`, because a binding
  *is* a credential row.
- **Binding lifetime** is #61's machinery unchanged: the same instance ceiling
  clamp, the same default-off `allow_indefinite`, the same
  `resolveLifetime`. Renewal is a mint.
- **JWKS cache** (`internal/oidcfed.Cache`): process-wide, in-memory, no table.
  Lazy refresh (no background ticker — this binary still has no scheduler; #61
  took the same disposition for expiry-threshold events). Three phases, all
  exercised: inside the refresh interval the cache is used; past it with the
  issuer down validation **continues from cache**; past the staleness bound it
  **fails closed, loudly** and recovers without operator action when the issuer
  returns. **Both** refresh triggers — staleness and unknown `kid` — pass the
  existing admission limiter (`AllowIssuerRefresh`, per issuer per minute), and a
  failed fetch backs the issuer off for `RefreshBackoff`. Locking is per issuer,
  never process-wide across a network call, so a dead issuer degrades itself and
  nothing else. The tests assert the *outbound fetch count* rather than the
  refusal, because the bounded outbound work is the property. (See round 1 below —
  all four of those properties are round-1 fixes.)
- **All key material is fetched over HTTPS only**, on the issuer, on the
  discovery-supplied `jwks_uri`, and on every redirect hop.
- **iat-skew restore predicate.** `reactivated_at` on the binding; when set the
  binding permanently refuses any token whose `iat` is not **strictly greater
  than `reactivated_at + MaxClockSkew`**. `Federation.Reactivate` is the write
  #76's ceremony will call. The fixture mints exactly the dangerous artifact — a
  captured pre-restore token whose `iat` is in Hikyo's *future*, inside the
  accepted skew, which a naive `iat > reactivated_at` test would admit — and the
  last phase presents a matched PAIR at one instant, differing only in whether
  `iat` sits above or below the floor, to prove the predicate is **permanent, not
  a quarantine window** (round-1 rework; the original last phase was vacuous).
- **Two-phase authentication, and this is the one structural decision.** The
  network half (peek unverified `iss`/`kid`, read the issuer row, refresh the
  JWKS cache, validate the token completely) runs **before any transaction
  opens**; the binding lookup, liveness and binding predicate run **inside the
  authorizing transaction, uncached**, at the same chokepoint
  (`authz.AuthenticateFederated`). On sqlite a JWKS fetch inside a write
  transaction would hold the single writer for an unreachable issuer's whole
  timeout, turning an issuer outage into an instance-wide write outage — the
  exact self-inflicted failure the ADR's stale-but-valid rule exists to avoid.
  What crosses the boundary is a validated set of *external claims*, never a
  resolved principal, so it is not the cross-transaction authorization cache the
  permission model forbids.
- **Uniformity.** The federated read is fixed in count and order like #61's
  bearer read, and the resolution surface hands the binding predicate a **decoy
  binding** on a miss — with a plausible three-pin claim document, not `{}` — so
  an unbound identity performs the same parse and comparison work a bound one
  does. Residuals are documented in `internal/authz/federation.go` and listed
  below.

### B. Conditional fetch cursor

- **New machine fetch endpoint**, spec-first:
  `GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery`,
  operation `delivery.fetch`, tenant-class at environment depth under bare
  `read`. It is the first route in the contract to declare
  `x-hikyo-artifacts: [human-session, machine-credential]`.
- **What is delivered today**: the authorized projection of what exists — the
  project's key catalogue and each key's declared presence for the addressed
  environment. `DeliveredKey` has **no value member**, so the ticket that adds
  values has to add it deliberately. No plaintext crosses this surface.
- **Change token**: `HMAC(scopedTokenKey, versioned canonical delivery manifest)`,
  `v1:`-prefixed, in `internal/crypto/delivery.go` (where `crypto/hmac` and
  `crypto/hkdf` are confined by the boundary test). The key is #14's existing
  `Keyring.ScopedTokenKey`, derived per `(org, project, environment)`. The
  manifest encoding (`internal/delivery`) is ordered, length-prefixed
  `(key, classification, presence)` triples — classification is in it, per the
  schema ADR's amendment, so a reclassification fires a rollout.
  `TestDeliveryChangeTokenTracksTheManifestSQLite` proves classification and
  presence both move it, and that two environments produce different tokens.
- **Cursor bound to the four-tuple** `(change token, the caller's authorized
  delivery projection, the principal's authorization revision, pin generation)`,
  keyed with its **own** HKDF-derived key (distinct info label from the change
  token). The mechanism is deliberately the dullest one that works: the server
  recomputes the cursor for the state it is about to serve and compares in
  constant time. That makes it opaque by construction, unforgeable, and — because
  a mismatch always produces a full delivery — **needs no cursor-versioning
  machinery at all**.
- **Authorization revision is `principals.session_generation`**, which #55's
  grant writers already advance on every *effective* authority change (a row
  created, a row deleted) and deliberately not on a bookkeeping-only origin
  change. No new counter was added because the existing one already moves on
  exactly the events the ADR names.
- **Pin generation** is a real stored counter (`pin_generations`, absent row = 0)
  with a real writer (`SetPinGeneration`). #52 owns pin creation, reassignment
  and release; the counter each of those must advance exists now because the
  cursor is bound to it now. Both the forged-cursor and the
  real-counter-advance paths are tested.
- **The conditional path authorizes exactly like the delivering path** — one
  `az.Authorize(OpDeliveryFetch)` before anything is compared, so a caller who
  lost `read` gets the uniform nonexistent response. The test presents a cursor
  that *was* current, revokes `read`, presents it again, and asserts the refusal
  is byte-identical to the cursor-less refusal **and** to a genuinely missing
  environment.
- **One immutable access record per fetch**, `identity.delivery_fetched`, with
  `disposition: full|current`, the credential id and kind, and
  `cursor_presented` so repeated cursor-less fetching by one credential stays
  visible (the ADR's honest bound on what conditional fetch buys). A "current"
  answer carries **no key names**.
- **Falsification**: each of the four components is falsified *independently*
  from the server's own reconstructed tuple, and the fixture first asserts the
  reconstruction matches the served cursor — without that, a forged cursor
  forcing a full fetch would prove only that the test cannot build a cursor.

## Review round 1 — what changed

Codex returned BLOCKING with five findings; all are fixed, plus the Standards and
Spec axes. The decisions that changed, because they change how the design reads:

- **Nested claim paths (JSON Pointer).** A pinned claim NAME beginning with `/`
  is a **full RFC 6901** pointer into nested claims (objects and array indices,
  strict `~0`/`~1` escaping, anything else refused at creation — see round 2);
  anything else is a top-level name.
  This is not a convenience: a real Kubernetes projected ServiceAccount token
  nests everything under the single literal claim `kubernetes.io`, so the
  immutable UID lives at `/kubernetes.io/serviceaccount/uid` and nowhere else.
  Without pointers the ADR's immutable-identifier rule is unsatisfiable against a
  real token. A dotted path was rejected because it is ambiguous on exactly this
  claim — `kubernetes.io` already contains a dot. The pointer leaf must be a
  scalar, so a pin can never be satisfied by a structural match. **The K8s fixture
  previously invented flattened scalars no cluster emits; it now mints the real
  nested document, and a test asserts the absence of the flattened alias.**
- **Immutable identifiers are a MUST, enforced per issuer type at creation**
  (`oidcfed.RequiredPins`), with **no override flag**: `github-actions` requires
  `repository_id` + `repository_owner_id` + `event_name`; `kubernetes` requires
  `/kubernetes.io/serviceaccount/uid`; `forgejo` requires `repository` +
  `event_name`. Previously only `event_name` was required, so a binding pinning
  nothing else was accepted and a renamed-then-reused repository path inherited
  the principal. An override would be the thing set once during a migration and
  never removed, and the ADR offers none.
- **JWKS transport is HTTPS-only, on every hop.** The scheme is checked on the
  issuer, on the discovery-supplied `jwks_uri`, and — through a `CheckRedirect`
  installed on a *copy* of the configured client — on every redirect target. The
  URL check alone was defeatable: an HTTPS `jwks_uri` that 302s to `http://`
  passed it, and a plaintext key fetch means an on-path attacker substitutes the
  whole key set and forges tokens for any bound identity.
- **JWKS cache concurrency model rewritten.** `Cache.mu` now guards the map only
  and is never held across a network call; each issuer's `entry.mu` serializes
  that issuer's fetches (singleflight). A failed fetch records `lastAttempt` and
  `RefreshBackoff` (30 s) suppresses the next attempt — **only after a failure**,
  so a legitimate key rotation still recovers immediately through the
  unknown-`kid` trigger. The instance-wide allowance now gates **both** refresh
  triggers; previously the staleness trigger bypassed it entirely. Together these
  turn what was an unauthenticated cross-issuer denial-of-service lever — one
  dead issuer stalling every federated authentication for `fetchTimeout` per
  request — into a bounded, per-issuer degradation.
- **Issuer policy is re-read in the authorizing transaction.**
  `BindingPredicate` now receives the in-transaction issuer row;
  `issuerPolicyMoved` compares it field-by-field against the snapshot validation
  ran under and refuses on drift, and `CheckBinding` evaluates against the
  **in-transaction** row rather than the snapshot. Fields, not `updated_at`: a
  timestamp is a proxy that moves on changes that do not matter and can fail to
  move on ones that do.
- **Admission now covers federated validation**, per the ADR's "pre-authentication
  admission limits apply to credential presentation and to federated validation,
  under the same instance-wide budget". `Federation.Authenticate` takes a slot
  before any parse, database read or signature check, and answers the uniform
  overload refusal. *Bearer presentation remains unadmitted — that is #61's path
  and out of this ticket's scope; flagged here so it is not mistaken for covered.*
- **The restore-permanence test was vacuous and is now falsifiable.** Its
  "captured" token had a 24-hour span and was over an hour old, so `MaxTokenSpan`
  and `MaxTokenAge` rejected it before the predicate ran — deleting the predicate
  would have left the phase green. It now presents two tokens at the same instant,
  both inside both caps, differing only in whether `iat` sits above or below
  `reactivated_at + MaxClockSkew`: the one above is accepted, the one below
  refused. That pair is the delete-and-it-fails property.
- **`federation-issuer update` requires an explicit `--jwks`.** It defaulted to
  `discovery`, so `update --refuse-audience X` silently flipped a static issuer to
  discovery and dropped its key document — a configuration change arriving through
  a flag nobody typed.
- Smaller: `entry.lastError` is now genuinely read (reported on a
  backoff-suppressed refresh, so an operator sees why keys are stale even on
  requests that did not themselves try); `MintShape`/`MintShapeMultiAudience`
  merged (`aud any`, which is what `aud` legitimately is); `checkTiming` lost its
  redundant `raw` parameter.

## Review round 2 — the two residuals

- **Cache eviction ownership (C3).** Eviction read `entry.fetchedAt` under
  `Cache.mu` while it was written under `entry.mu` — a data race, and worse than a
  race: an **in-flight** entry has a zero `fetchedAt`, so it looked like the
  oldest and was chosen **first**, which recreated it and started a duplicate
  concurrent fetch for the same issuer. The singleflight was defeated exactly when
  it mattered.

  Fixed by narrowing what eviction may read to two fields that are safe to read
  without `entry.mu`: `admitted` (written once, before the entry is published into
  the map, never again) and `inflight` (an `atomic.Int32`, incremented inside
  `entryFor` **under `Cache.mu`**, so an entry cannot be created, handed out and
  then evicted before its user is counted). Eviction skips any entry with a live
  user; if every candidate is busy nothing is evicted and the map briefly exceeds
  the ceiling — which is fine, because that ceiling is a sanity bound on
  operator-configured issuers, not a defence against attacker-chosen keys.
  `fetchedAt` is no longer read outside `entry.mu` at all. The lock order is
  stated in the code: `Cache.mu` may be taken with no `entry.mu` held, and
  `entry.mu` is never taken while `Cache.mu` is held — `entryFor` is the only
  function that touches the map and it returns before any entry lock is taken.

  `TestEntryForIsRaceFreeUnderEviction` drives the eviction path **directly**, and
  it has to: eviction only fires past `maxTrackedIssuers` (64) and no end-to-end
  fixture configures that many issuers, so `-race` on the isolation suite would
  never reach this code. It runs 192 concurrent `entryFor` calls against a cache
  holding one deliberately in-flight entry, and asserts that entry survives **as
  the same object** — a replacement would be a different pointer and a second
  concurrent fetch.

- **Bounded outbound work is now asserted directly.** `Fetches()` counts JWKS
  reads the fixture *served*, so during an outage it counts zero whether one
  request tried or twenty did — the assertion was unfalsifiable, and the test said
  so in a comment. `oidctest.IdP` gained `Attempts()`, incremented in `down()`
  before the offline decision, counting every discovery and JWKS request that
  reached the fixture including the ones answered 503. The outage test now asserts
  20 concurrent requests produce **at most one** outbound attempt.

- **Full RFC 6901 traversal (C2a).** The objects-only resolver could not resolve
  array indices (`/amr/0`), and accepted invalid escapes (`~2`) **literally** —
  which is a fail-open shape: the pin is stored, can never match any token, and its
  inertness is invisible until someone audits the binding.

  Chose full traversal over a documented subset, because a subset needed a
  creation-time validator and a documented exception anyway — the same amount of
  code — and because `aud` and `amr` are array-valued claims that already exist, so
  "objects only" would have been a rule with counterexamples in the specification
  it implements. `descend` handles object members and array elements; the array
  branch is tried only for well-formed RFC 6901 index syntax, so `/a/01` addresses
  the object member `"01"` rather than element 1 (getting that backwards would make
  two different pointers resolve to the same place). `-` is not accepted: it
  addresses a position holding no value, so it can never satisfy a pin.
  `unescapePointer` now **refuses** anything other than `~0`/`~1`, and
  `ValidatePointer` — called from `ParseRequiredClaims`, which both the creation
  and validation paths go through — refuses a malformed pointer at binding
  creation. Leaves must still be scalars, so a structural match can never satisfy
  a pin.

  `internal/oidcfed/oidcfed_test.go` is new and covers the edges the review named:
  escapes (`~0`, `~1`, `~01`, `~2`, trailing `~`), empty segments (`/` and a
  trailing slash both address the member `""`), array indices including
  out-of-range, leading-zero and `-`, descending into a scalar, structural leaves,
  and the top-level/pointer discriminator. It also closes the earlier "no
  package-local unit tests" open item, adding `requireHTTPS` and the
  never-fold-a-scalar rule.

## Downstream obligations this ticket creates

Named here because the cursor's correctness depends on tickets that have not
landed, and a seam nobody is told about is a seam nobody advances:

- **#17/#58 (machine-`reveal` per-project opt-in)** — the ADR names an opt-in
  change as a cursor invalidator. The opt-in MUST move a cursor component when it
  toggles. Today the projection component is computed from the principal's real
  grant rows at the addressed environment, so an opt-in implemented as a grant
  moves it for free; an opt-in implemented as a project *setting* must either
  feed the projection or bump the authorization revision. Whichever it is, it is
  that ticket's obligation, not an emergent property.
- **#52 (pins)** — pin creation, reassignment and release MUST advance
  `pin_generations` for the affected `(principal, environment)`, through
  `SetPinGeneration`. The column, the store method and the cursor binding all
  exist; only the callers are missing.
- **#50/#51 (values and revisions)** — `deliveryRows` is the single seam.
  `Presence` gains `set`, rows gain the config plaintext and the secret
  write-presence, and every outstanding cursor mismatches exactly once. The
  per-key disclosure event's cardinality obligation transfers with them.
- **Restore ceremony (#76 shipped in parallel, gap now real)** — #76's
  reconciliation re-activates principals and moves the epoch but never calls
  `Federation.Reactivate`, so the ADR's per-binding re-validation (§ Restore:
  bindings may be re-activated per binding, bearer verifiers never) has no
  operator verb yet. The write, the `reactivated_at` predicate and its E2E
  fixture all exist; the ceremony integration needs a small follow-up on the
  restore surface, and it must BOTH set `reactivated_at` AND refresh the
  binding row's `credential_epoch` — `Live` requires the current epoch, so
  `Reactivate` alone leaves the binding dead. Until it lands, a restored
  binding stays inert via the epoch — fail-closed, never fail-open.

## Fog values for ratification

| Value | Chosen | Where |
|---|---|---|
| JWKS proactive refresh interval | 15 min | `oidcfed.RefreshInterval` |
| JWKS staleness bound (serve-from-cache ceiling) | 6 h | `oidcfed.StalenessBound` |
| outbound refresh limit (**both** triggers) | 5 / issuer / min | `admission.IssuerRefreshPerMinute` |
| refresh backoff after a FAILED fetch | 30 s | `oidcfed.RefreshBackoff` |
| max accepted federated token age (`now - iat`) | 1 h | `oidcfed.MaxTokenAge` |
| max accepted `exp - iat` span | 2 h | `oidcfed.MaxTokenSpan` |
| max accepted positive clock skew (**= restore-predicate margin**) | 2 min | `oidcfed.MaxClockSkew` |
| default binding lifetime | 30 days | reuses `service.DefaultCredentialLifetime` |
| JWKS document size cap | 1 MiB | `oidcfed.maxJWKSBytes` |
| discovery / JWKS HTTP timeout | 5 s | `oidcfed.fetchTimeout` |
| tracked issuers in the JWKS cache | 64 | `oidcfed.maxTrackedIssuers` |

**`MaxTokenAge` deserves a sentence, because it is a compromise with reality
rather than a preference.** A Kubernetes projected ServiceAccount token defaults
to a one-hour lifetime and the kubelet refreshes at 80% of it, so a legitimate
token on disk can be ~48 minutes old. A tighter cap would refuse the platform's
default configuration, which is a cap that gets turned off rather than a cap that
holds. `MaxTokenSpan` at 2 h leaves headroom above that without admitting the
day-long tokens some CI platforms can be configured to mint. The K8s operator
(#64) can and should request much shorter tokens; these are ceilings, not
targets.

**One constant does double duty on purpose.** `MaxClockSkew` bounds how far into
Hikyo's future an `iat` may sit *and* is the margin in the post-restore
predicate. Two constants would let the margin drift below the skew validation
accepts, which is precisely the gap the predicate exists to close.

## Deviations and interpretations needing ratification

1. **Federated presentation is wired on the machine delivery surface only.**
   `service.FederatedActor` is the seam and `AuthenticateFederated` is at the
   chokepoint, so a federated principal has *identical authority* to a bearer
   sibling — same grants, same formulas, same uniform refusals. What differs is
   *transport reach*: today only `Delivery.Fetch` classifies the presented
   artifact and runs the pre-transaction validation, so a federated token cannot
   currently call, say, `environment.list` (which a bearer machine token can).
   Generalising it is one middleware that validates once and stashes the claims
   in the request context; it was not done here because the audit event for a
   federated refusal would then have no honest wire-entry home. **Flagged for
   ratification.**
2. **Pin generation is a real column with no production writer yet.** #52 owns
   pin creation/reassignment/release. The counter, its store methods and its
   place in the bind-tuple land now; the test drives the writer.
3. **The change-token seam is over catalogue + presence, not values.** #50's
   value tables merged mid-review (this branch is rebased onto them), but the
   machine delivery surface deliberately does not read them: wiring values into
   delivery is #51's (revisions/publish, the real change token) and #63's
   (Compose delivery) work. `deliveryRows` is the single seam: when values land,
   its input grows, `Presence` gains `set`, and every outstanding cursor
   mismatches exactly once. No cursor-versioning machinery, deliberately.
4. **Per-key disclosure events remain deferred**, per #61's accepted
   disposition. The fetch path now exists but delivers **no plaintext**, so a
   disclosure event naming a key whose value was not disclosed would be a false
   record. Reasoning is recorded in `internal/audit/registry.go`.
5. **The in-transaction refusal leg records ONE cause (`unbound`).** Which of
   "unbound identity", "revoked binding" and "failed binding predicate" happened
   is exactly what the uniform response withholds — and, more concretely, the
   resolution surface hands the predicate a *decoy* binding on a miss (so the
   unbound case is not the cheap case), which means the predicate's verdict on a
   miss is the decoy's. Reporting it as a cause would sometimes report the decoy.
   The pre-transaction causes (unknown issuer, unavailable keys, stale keys,
   signature, token age, audience) *are* reported individually, because nothing
   decoy-shaped produces them.
6. **Bindings share `max_live_credentials` and the lifetime clamp/enumeration
   with bearer tokens.** That is what the ADR asks for (same ceiling, same
   opt-in), and it is a consequence of the one-table decision: a service account
   with five live bearer credentials cannot add a binding until one is revoked.
   Recorded as an interpretation.
7. **Issuer delete is refused while ANY binding names it, revoked ones
   included.** A cascade would deprovision N workloads under an operation whose
   name says "configuration"; refusing only on live bindings would leave
   historical rows pointing at a vanished issuer, so the trail could no longer
   answer what a past binding trusted — and the foreign key would refuse anyway,
   with a driver message instead of a reason. The operator deletes the service
   accounts, which removes their credential rows. The API field is still called
   `live_bindings`; its description says it counts both.
8. **Postgres migration leaves 00014's anonymous verifier `CHECK` in place.**
   The new bearer-shape constraint implies it strictly, so it is redundant rather
   than wrong — and dropping it would mean naming a constraint postgres generated
   *positionally* (`machine_credentials_check1`), which is a guess about DDL
   ordering rather than a fact about the schema. The `kind` `CHECK` **is** dropped
   by name (`machine_credentials_kind_check`, which postgres derives
   deterministically for a single-column inline check). That name is verified by
   mechanism rather than by assertion: the isolation and conformance harnesses
   drop and re-migrate the whole schema on every postgres run, so 00014→00017
   (renumbered 00015→00016→00017 as #50 and #76 took those slots on main)
   executes end to end each time and a wrong constraint name would fail the
   migration loudly on the first PG test.
8a. **`last_used_at` is never stamped for a federated binding.** The post-response
   `SlideSessionClocks` middleware feeds the raw presented value to
   `Auth.SlideIdleClock`, which resolves through `AuthenticateCaller` — and a JWT
   matches neither bearer artifact type, so it lands on the human-session leg,
   answers `ErrUnauthenticated`, and is **correctly swallowed** (no fault log, no
   500). The consequence is that a bearer credential's last-used stamp moves on a
   delivery fetch and a binding's does not. It is pure observability — nothing
   reads it to decide anything — and the honest fix is the same transport
   generalisation as deviation #1, so it is named rather than patched with a
   second write path.
9. **Contract guard inverted rather than deleted.**
   `TestContractSecuredOperationsTakeAnArtifact` used to refuse *any*
   `machine-credential` eligibility ("which no code serves yet (#61)"). It now
   requires that a route declaring it have a formula **some machine class may
   satisfy** under #55's normative allowlists — a stronger property than the
   blanket refusal, and one that fails on a stale or aspirational declaration.
10. **`oidctest` gained a TLS constructor.** The federation fixtures configure an
    issuer through the real API, which refuses a non-`https` issuer. Rather than
    carve a loopback exception into production validation to suit a test, the
    fixture speaks TLS (`oidctest.NewTLS`) and hands the cache the client that
    trusts its certificate. No verification is disabled anywhere.
11. **`go-jose/v4` promoted from indirect to direct.** It is go-oidc's own
    dependency and was already in the module graph; it is used for JWKS parsing
    and the unverified header read, both of which are *parsing*, not verification.
12. **Isolation harness keyring is now memoized per database**
    (`harnessKeyring`). Two services in one test needing a keyring is now
    ordinary (auth and delivery), and a second `LoadKeyring` with a fresh root key
    against the same datastore correctly answers "root key does not match" — the
    encryption model working and the old helper being wrong.
12a. **Forgejo Actions exposes no immutable numeric identifiers** for a repository
   or its owner — its Actions claim set carries `repository` and
   `repository_owner` as names only. So a Forgejo binding is name-based by
   necessity, and a repository renamed with its path reused inherits the binding.
   The strictest available rule (`repository` + `event_name`) is enforced; closing
   the gap needs Forgejo to emit ids upstream. Recorded as a known ceiling rather
   than papered over, and re-check it whenever the Forgejo claim set grows.
12b. **`Federation.OnValidated` is a test-only seam** — a nil-in-production hook
   between the pre-transaction validation and the authorizing transaction. It
   exists so the issuer-policy race is a deterministic proof rather than a flaky
   goroutine test. Flagged because a test hook on a security path is exactly the
   sort of thing that should be noticed, not discovered.
13. **No `hikyo fetch` CLI verb.** The delivery surface is machine-facing and its
    consumers are #63 (Compose) and #64 (the operator), which speak HTTP. Adding
    a verb now would ship a CLI surface with no caller and a second place for the
    cursor contract to drift. Say the word if it should exist for debugging.
14. **`sqlc`'s sqlite parser mis-slices statements when a query file contains
    non-ASCII characters.** `§` in a comment silently produced a truncated
    generated statement (a runtime `unrecognized token` error, not a codegen
    failure). The existing `machine.sql` header already warns about this;
    `federation.sql` now keeps to ASCII. Worth a lint rule in a later ticket —
    the failure mode is a working build that breaks at runtime.

## Files touched

**New:** `internal/oidcfed/oidcfed.go`, `internal/delivery/delivery.go`,
`internal/crypto/delivery.go`, `internal/store/authn/federation.go`,
`internal/authz/federation.go`, `internal/service/federation.go`,
`internal/service/delivery.go`, `internal/server/federation.go`,
`internal/server/delivery.go`, `internal/cli/federation.go`,
`internal/oidctest/federation.go`,
`internal/store/migrations/{sqlite,postgres}/00017_oidc_federation.sql`,
`internal/store/queries/{sqlite,postgres}/federation.sql`,
`internal/isolation/{federation,delivery}_e2e_test.go`.

**Modified (non-generated):** `api/openapi.yaml`, `internal/domain/permission.go`,
`internal/audit/registry.go`, `internal/authz/{registry,classify}.go`,
`internal/admission/admission.go`, `internal/lint/appendonly.go`,
`internal/store/authn/machine.go`,
`internal/store/queries/{sqlite,postgres}/machine.sql`,
`internal/service/{identities,service}.go`,
`internal/server/{api,identities}.go`, `internal/cli/{identities,verbs,provider}.go`,
`internal/app/app.go`, `internal/oidctest/idp.go`, `go.mod`,
`internal/cli/testdata/help.txt`, `internal/isolation/testdata/{annotated_queries,operation_formulas}.json`,
`internal/isolation/{harness,invariants,contract,audit_e2e}_test.go`,
`internal/conformance/conformance_test.go`.

**Generated (committed, CI diffs them):** `api/apigen/apigen.gen.go`,
`internal/store/{sqlitegen,pggen}/*`, `clients/ts/src/generated/*`.

## Registry additions

- **Operations (6):** `federation.issuer-{create,list,update,delete}`,
  `identity.binding-create`, `delivery.fetch`.
- **Audit event types (7):** `identity.binding_created`,
  `identity.binding_reactivated`, `identity.federation_issuer_changed`,
  `identity.federation_issuer_read`, `identity.federation_refused`,
  `identity.jwks_refresh_failed`, `identity.delivery_fetched`. Every one has a
  real emitter, driven by `runFederationLifecycle` inside the audit suite's
  emitter walk. `identity.credential_revoked` gained an optional
  `credential_kind` member and the `replaced` cause.
- **Wire entries (6 routes)**, all in `wireRegistry` and `wireRoutes`. The
  delivery route is deliberately in `wireEvents` **as well** — the
  credential-reset precedent — because the federated-refusal and JWKS events
  happen before a principal exists and ride the resolution surface's proof-free
  audit writer.
- **Cache registry:** `oidcfed.jwks`, keyed by the byte-exact issuer string,
  explicitly **not** proof-gated (its contents are the issuer's public signing
  keys, read pre-authentication by construction).
- **Resolution-surface write list:** `CreateFederationIssuer`,
  `UpdateFederationIssuer`, `DeleteFederationIssuer`, `ReactivateBinding`,
  `SetPinGeneration`.

## Verification

```
go build ./...                                  # clean
go vet ./...                                    # clean
gofmt -l .                                      # empty
go tool sqlc generate                           # no diff after commit
go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml   # no diff
cd clients/ts && pnpm run generate && pnpm run typecheck && pnpm run test   # 4/4
go test ./...                                   # green (sqlite leg)
HIKYO_TEST_POSTGRES_DSN='postgres://hikyo:hikyo@127.0.0.1:5432/hikyo_62?sslmode=disable' \
  go test ./... -count=1                        # green (both engines)
```

The postgres leg ran against a **dedicated `hikyo_62` database** (the shared one
carries other branches' schemas), created on the dbugit dev container
(`issue-444-postgres-1`, postgres 18) already running on this host. That is a
side effect on shared infrastructure, stated out loud: the `hikyo` role already
existed; `CREATE DATABASE hikyo_62 OWNER hikyo` is the only thing this ticket
added, and it can be dropped once the branch merges.

Final run: **1713 tests passed, 0 failed, 36 packages**, both engines (post review round 2).

`internal/server/federation_test.go` was added after the handoff's first draft to
close the HTTP-leg gap named in the open items; it is included in that count.

## Open items

- Item 1 above (generalising federated presentation past the delivery surface) is
  the one deliberate functional gap; everything else is either an interpretation
  or a downstream ticket's.
- **The HTTP leg is tested with a stub service, not with a real JWT.**
  `internal/server/federation_test.go` drives the router — both dispositions, the
  non-null empty `keys` array, the byte-identical unauthorized refusals, the
  discriminated pin round trip, and the absence of `static_jwks` on the read
  shape — against stubbed services. The federation/delivery **behaviour** is
  tested end to end against a live TLS issuer and a real datastore in
  `internal/isolation`, but at the service seam. Nothing drives the chi route
  with an actual federated token; the middleware interaction that would matter
  there (`SlideSessionClocks`) is reasoned about in 8a rather than exercised.
- `internal/oidcfed` gained package-local table tests in round 2
  (`oidcfed_test.go`: pointer resolution edges, `ValidatePointer`, `requireHTTPS`,
  the never-fold rule, and the eviction race). `checkTiming` is still covered only
  end to end, through `FederationTokenCaps`; a table test for it would be cheap.
- **Which federation fixtures are sqlite-only, and why.** Both engines:
  `FederationAgainstEachIssuerType`, `FederationRefusesPullRequestEvents`,
  `FederationJWKSStalenessBound`, `FederationRestorePredicate`,
  `FederationBindingImmutability`, `FederationIssuerDeleteGuard`, and all four
  delivery/cursor fixtures. The last two gained postgres legs in round 1 because
  their subject genuinely *is* storage behaviour — the live-row partial unique
  index and the 23505 fold for one, the FK from `machine_credentials` to
  `federation_issuers` for the other.

  sqlite only, deliberately: `FederationOutageDoesNotSerializeIssuers`,
  `FederationUnknownKIDRefreshIsRateLimited`, `FederationRefusesPlaintextJWKS`,
  `FederationStaticJWKS`, `FederationIssuerPolicyCannotGoStale`,
  `FederationRequiresImmutableIdentifiers`,
  `FederationPinsNestedKubernetesUID`, `FederationClaimTypeIsNotFolded`,
  `FederationTokenCaps`, `DeliveryChangeTokenTracksTheManifest`. Every one of
  these lives in the JWKS cache, the admission limiter, the claim-pin validator or
  the transaction-split comparison — none touches a storage behaviour that differs
  between engines, so a second leg would re-run identical assertions against the
  same in-memory objects. Adding legs is cheap if a reviewer disagrees about any
  specific one.
