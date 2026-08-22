# Issue #249 handoff — implementation-status authority

## Outcome

`docs/status/ledger.json` is the sole mutable authority for current capability
and obligation status. Stable `CAP-*` and `OBL-*` IDs connect the ledger to
generated user-facing summaries and immutable specification obligations.

## Contract

- `scripts/ci/check-doc-status.mjs --check` validates ledger schema, unique IDs,
  capability-blocking obligations, source references, local evidence, immutable
  ADR/spec checkboxes, and generated-output freshness.
- `README.md` and `docs/status/README.md` are generated from the ledger.
- `docs/spec/open-items.md` states obligations without mutable implementation
  status; each obligation ID must occur exactly once in its source document.
- Existing handoffs were not rewritten. Ledger entries link them as historical
  evidence.

## Fail-closed coverage

`scripts/ci/check-doc-status_test.sh` accepts a valid fixture and refuses:

- a generated summary that contradicts the ledger;
- an implemented capability with a blocking open obligation;
- an unresolved obligation without a blocking or non-blocking disposition;
- an orphan ledger obligation or unknown obligation ID;
- missing repository evidence; and
- mutable status added back to any ADR/spec source.

`scripts/ci/verify-docs.sh` runs the checker and fixtures before building the
documentation site. The site publishes the generated ledger at
`/implementation-status/`; the OSS policy gate requires that route and the new
governance authority wording.

## Validation

```text
./scripts/ci/verify-docs.sh
  ledger: 31 entries verified
  Astro: 0 errors, 0 warnings, 0 hints
  site: 35 pages built
  PWA/offline, O4-O6 policy, live-doc fixture, and fallback-channel fixtures: passed

git diff --check
  passed
```
