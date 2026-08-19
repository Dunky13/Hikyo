# Handoff: #63 Compose delivery — `hikyo run --`, rendered `env_file`, offline snapshot, `compose doctor`

Issue: https://github.com/Hikyo-Org/hikyo/issues/63 (parent #41; mvp-boundary row
**M2**). Binds [compose-integration.md](../adr/compose-integration.md) (the
locked Compose ADR), [system-architecture.md § Client local state](../adr/system-architecture.md),
[ops-spec.md § 6](../adr/ops-spec.md) (7 d snapshot age, current+3 generations,
runtime/state directory conventions, flush-before-fetch, ARG_MAX preflight),
[audit-model.md](../adr/audit-model.md) (offline-reconciled origin), and the
api-cli-surface ADR (verb taxonomy: `run --` top-level, `compose render|sync|doctor`).

Blockers #51 (revisions/publish) and #62 (OIDC federation + conditional cursor)
are merged.

## Scope

**In:**

- **Server — values on the delivery surface.** `DeliveredKey` gains `value`
  (config always; secret iff the caller's projection holds `reveal` for the
  current snapshot / `reveal-history` for a pinned non-current one — the
  `values export` rule mirrored). One `disclosure.value_revealed` event per
  delivered secret, `surface: "delivery"`. `config_only` query parameter = a
  distinct authorized projection, bound into the cursor and recorded in the
  fetch event. Server-asserted snapshot `issued_at` / `expires_at` on the
  response (7 d; the client AAD binds them). Offline-record reconciliation
  endpoint (authenticated, idempotent, `origin: offline-reconciled`,
  since-revoked credentials accepted).
- **Client library** (`internal/compose` + client-side crypto in
  `internal/crypto`): raw-dotenv encoder with refusal-by-name for the
  unrepresentable class; loader-control baseline; project config file
  (committed, non-secret, targets by key id, per-target acknowledgements);
  local keys (one 256-bit local key, HKDF-separated stamp key + snapshot key),
  stamp `v1-<32 hex>` grammar; generation directories + completion marker +
  single atomic-rename stamp file + per-project writer lock + GC (current+3);
  XChaCha20-Poly1305 snapshot container with the normative AAD tuple, issuance
  high-water mark, expiry refusal, opt-in per stack; offline per-key audit
  records fsynced before plaintext release; cursor state with the three-part
  eligibility test; doctor checks as pure functions.
- **CLI verbs**: `hikyo run -- <cmd>` (machine-only, exec semantics with
  126/127, merge-collision hard error with named escape hatch, loader-control
  refusal, ARG_MAX preflight), `hikyo compose render`, `hikyo compose sync`
  (one-shot), `hikyo compose doctor` (floor 2.30 via `docker compose version`,
  stamp grammar, `:?`, `format: raw`, token-file mode, state-dir mode,
  config/stamp/generation/server agreement). Spellings + help golden.
- **E2E + CI fixtures**: round-trip over the representable domain, refusal by
  name, stamp-driven recreate, crash consistency at a deterministic seam,
  snapshot expiry + tmpfs-only, doctor floor refusal. Demo compose stack
  (`install/compose/`): a container echoes a hikyo-delivered value.

**Out (stated, not dropped):**

- `hikyo compose adopt` / scaffold-first rewrite — depends on the definitions
  flow (#70); the project config file is hand-authored and documented here.
- Per-project machine-`reveal` opt-in (grant API) — #67's handoff says "ships
  with #17/#18"; no open ticket owns it. E2E seeds reveal grants at the store
  layer (`seedMachineReveal`). **Marc's call to reclaim.**
- `run --use-human-session` exception (needs the bound reauth ceremony) —
  machine credentials only in this build; the human-session fallback is a
  refusal.
- systemd unit generator (the ADR ships none); reference unit + timer are
  documentation.

## Streams

A (server) ∥ B (client lib) → C (CLI wiring) → D (e2e, demo, docs). A and B
were built in sibling worktrees and merged before C.

(Filled in as the streams land.)
