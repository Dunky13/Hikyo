# Handoff: #61 machine identities — service accounts, tokens, display-once mint

Issue: https://github.com/Dunky13/hikyo/issues/61 (parent #41; M1 token portion
of the machine-identities ADR, `docs/adr/machine-identities.md` on the
`wayfinder-docs` branch). Blocked-by #55 (permission model) is merged.

## What shipped

- **Service accounts** — project-owned principals, `kind` ∈
  {workload, automation} immutable at creation, grants confined to the owning
  project's subtree (`service_accounts.(org_id, project_id)` is the ownership
  source; prior-grant inference survives only as a stricter fallback for
  machine principals with no SA row). Migration `00014_machine_identities.sql`
  (both engines): `service_accounts`, `machine_credentials` (with a
  credential-kind discriminator so `oidc-federation` fits later without schema
  churn), single-row `credential_policy`.
- **Bearer credentials** — the repo's bearer grammar (rebranded `ew_` →
  `hik_` in this PR) extended with `wl`/`au` artifact types
  (`internal/crypto/bearer.go`); unsalted SHA-256 verifier,
  unique index, constant-time compare on the resolved row; server trusts
  nothing inside the token. Resolution at the same authz chokepoint as
  `authorize()`, in-transaction, uncached; fixed read count keeps
  unknown/revoked/expired indistinguishable.
- **Mint / rotate / revoke** — mint gate = `manage-identities(project)` ∧
  per-class disclosure capability over the whole post-state ∧ reauthentication
  (`internal/service/identities.go`); grant-widening gate = delta only,
  computed per authority class (`reveal` vs `reveal-history` never collapsed),
  in the same transaction as the grant write, stricter wins
  (`internal/service/grants.go` `checkMachineWidening`). Narrowing, revoke,
  delete, list under plain `manage-identities`. Rotation is overlap-based
  (CLI composition: mint, deliver, then revoke; fails toward two live
  credentials with a loud warning). SA delete revokes credentials and grants
  in one transaction. Mint serializes via row locks: `credential_policy` row
  then SA principal row — the same principal lock every grant writer takes.
- **Display-once delivery** — `internal/disclose`: controlling-terminal write
  (not stdout-isatty — a PTY is CI-allocatable), `--output-file` via parent
  dirfd `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW` 0600, explicit
  `--dangerously-print` for stdout. Bare non-TTY refused, never downgraded.
  No `--token` flag exists (test-enforced). Preflight runs before any network
  call. Consumption: `--token-file` beats `HIKYO_TOKEN` with a loud warning.
- **Lifetime** — finite default with instance ceiling clamp; `indefinite` a
  typed value behind default-off `allow_indefinite`; tightening either
  control enumerates affected credentials first (200 preview with
  `applied:false`), then clamps — including converting indefinite credentials
  to finite at the ceiling on opt-in withdrawal. Both controls audited, plus
  a `identity.lifetime_policy_read` event on the preview enumeration.
- **Credential epoch** carried on machine credentials (restore inertness
  mechanism; restore UX itself is out of scope here).
- **Human/machine split** — `authz.Authenticate` is human-session-only;
  `AuthenticateCaller` is the single opt-in admitting machine credentials
  (used by the operation chokepoint and idle-clock slide), so every
  account-security verb refuses machine tokens by construction.

## Cross-cutting hardening picked up during review (campsite rule)

- Machine authentication is work-shape uniform across unknown / revoked /
  expired / live: miss paths decode precomputed decoy rows and run the same
  constant-time compare, so every outcome is 3 queries + same decodes +
  1 compare (`internal/store/authn/machine.go`;
  `TestMachineAuthIsUniform{SQLite,Postgres}` pins the read-count half). The
  storage engine's B-tree probe is the named accepted residual. The human
  session path keeps #16's shape (count + compare, no decode symmetry) —
  deliberate, out of #61's obligation.
- Constant-time verifier compare added to **every** `*ByVerifier` resolver
  (sessions, credential authorities, OIDC state, SAML relay-state, WebAuthn
  challenge, machine) via one `verifierMatches` helper
  (`internal/store/authn/human.go`), plus `subtle.ConstantTimeCompare` on the
  OIDC browser-binding cookie and nonce (`internal/service/oidc_flow.go`).
  Password/recovery/TOTP already correct; WebAuthn user handle and SAML cert
  drift deliberately not changed (not secrets).
- PG test-harness drop lists (`internal/conformance/conformance_test.go`,
  `internal/isolation/harness_test.go`) taught the 00013 tables; conformance
  also gained the SAML tables it had been missing since #92.

## Fog values needing ratification (ops-spec placeholders)

| Value | Chosen | Where |
|---|---|---|
| instance max finite lifetime | 90 days | migration 00014 seed |
| `allow_indefinite` | off | migration 00014 seed |
| concurrent live credentials / SA | 5 | migration 00014 seed |
| default credential lifetime | 30 days | `service.DefaultCredentialLifetime` |
| expiry-warning window | 14 days | `service.ExpiryWarningWindow` |
| prefix-hint characters | 6 | `service.prefixHintChars` |

## Deviations and open items

1. **Token prefix is `hik_`, per the hikyo rebranding (Marc, 2026-08-12).**
   The locked ADR's text still reads `ew_` and predates the rebrand; this PR
   rebrands the whole bearer grammar (`internal/crypto/bearer.go`) and the
   audit redaction filter (`internal/audit/sanitize.go`) in one step — one
   grammar, one scanner rule, no `ew_` values were ever released. The ADR
   text needs a matching editorial amendment on `wayfinder-docs`.
2. **`--dangerously-print`, not `--print-token`** — repo's locked CLI output
   grammar.
3. **Per-key disclosure event cardinality: the one unmet acceptance
   criterion.** The repo has no secret-fetch path yet (no secret-values
   tables exist), so there is no key to disclose; the audit registry's own
   closure test refuses an event type with no emitting operation. Reasoning
   recorded in `internal/audit/registry.go`; lands with the values/fetch
   surface (#11/#12/#13). Same disposition for a machine auth-failure event.
4. **Expiry-threshold audit event deferred** — no scheduler/ticker exists in
   the binary; a poll-triggered event would fire on listing, not expiry.
   Recorded at `service.ExpiryWarningWindow`. In-product `expiring_soon`
   badge/field is complete.
5. **Reauth conjunct ranges over the disclosure environments and is vacuous
   when that set is empty** — interpretation, flagged for ratification (reauth
   windows are per-(session, environment); an operation reaching no plaintext
   has an empty `reveal` conjunct too).
6. **Test fixtures seed machine `reveal` grants at the store layer** — #55's
   allowlist refuses `reveal` to machines until the per-project opt-in ships
   (#17/#58); the allowlist was deliberately not widened.
7. **Mint TOCTOU locks are untestable deterministically** on sqlite (single
   writer); PG leg exercises them but not under adversarial concurrency.
   Lock ordering documented at both sites.

## Dispositions (Marc, 2026-08-12)

- **Per-key disclosure deferral: accepted.** Criterion transfers to the
  fetch-surface work (#11/#12/#13); #61 closes with this PR.
- **Fog defaults: all six ratified** as listed above.
- **Interpretations accepted as recorded**: reauth-vacuous-when-no-disclosure;
  store-layer `reveal` fixture seeding (allowlist unwidened pending #17/#58);
  human session path keeps #16's decode asymmetry.
- **Post-R3 fixes: fresh focused codex pass ran and returned CLEAN** —
  engine-matched decoy decoders verified (correct generated row types incl.
  `pgtype.Timestamptz`), sink confirmed to consume decode + compare results
  (atomic RMW; boolean selection retained in ARM64 assembly), driver errors
  still propagate. Cross-model review is now CLEAN end to end.

## Review trail

Three-axis review: standards + spec sub-agents (all findings fixed or
dispositioned above) and a blocking cross-model Codex pass (gpt-5.6-sol,
high effort). Codex R1: BLOCKING, 5 findings — subtree-confinement escape via
first grant, mint TOCTOU, indefinite-withdrawal non-clamp, missing
constant-time compare, machine token entering human logout. All five fixed
(see above). R2 verified four complete, held one residual (miss/hit work
asymmetry) — fixed with engine-matched decoy decode work. R3 (final round)
named two mechanical residuals — PG misses ran the sqlite decoy decoder, and
the decoy compare was compiler-eliminable — both fixed post-R3
(engine-matched decoy rows through each hit path's own decoder; an
`atomic.Uint64` sink consuming decode + compare results). Round cap reached;
these two post-R3 fixes are presented for human disposition at the merge
gate rather than re-reviewed.

Verification: `go build ./... && go vet ./...` clean; full suite green on
both engines (`HIKYO_TEST_POSTGRES_DSN` set, dedicated `wenv_61` database —
the shared `wenv_test` DB carried another branch's SCIM schema).
