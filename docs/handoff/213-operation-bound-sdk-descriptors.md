# Issue 213: operation-bound SDK response descriptors

## Outcome

The SPA no longer supplies an SDK promise and a response schema independently.
Generated descriptors bind each SDK operation to its complete success-status
set and generated Zod response parser. `parsed` and `ok` accept only those
descriptors plus the operation's typed request options.

## Contract choices

- `operations.gen.ts` is derived deterministically from the canonical Hey API
  SDK, response types, and Zod outputs after every `openapi-ts` run.
- Body-bearing, bodyless, and streaming operations use distinct nominal
  descriptor types. Module-private generated classes prevent callers from
  constructing, spreading, or manually re-pairing them.
- Multiple successes remain closed and explicit; for example,
  `updateAdapterTarget` carries `[200, 202]` and its generated union parser.
- Mixed body-bearing/bodyless success sets fail generation because one
  descriptor could not represent them honestly.
- Existing SPA-only security refinements parse the already generated-parsed
  value, preserving their narrower disclosure invariants.
- Non-2xx results from both request descriptor types parse `zError` and throw
  `ApiError`; unexpected 2xx statuses fail before returning data.

## Generated ownership

Run:

```sh
pnpm --dir clients/ts run generate
```

This recreates `clients/ts/src/generated/operations.gen.ts` after Hey API
recreates its five generated files. CI's existing generated-tree freshness
gate therefore covers the registry and its no-hand-edit marker.

## Verification

- `pnpm --dir clients/ts run verify`: 11/11 tests, typecheck green.
- `pnpm --dir web run typecheck`: green, including negative mismatch fixture.
- `pnpm --dir web run test`: 248/248 tests across 21 files.
- `pnpm --dir web run build`: green; unused generated descriptors tree-shake.
- Repeated generation produced byte-identical `operations.gen.ts` with SHA-256
  `bea087ce404ba2adee4bf7bb78b3419808ab088518ed47c40b98146ab6a39e35`.
- `go build ./...`, `go vet ./...`, and `go build -tags ui ./...`: green.
- `go test -count=1 ./...`: 2,903 tests passed across 56 packages (SQLite).

Local PostgreSQL was unavailable. CI remains the authoritative dual-engine
conformance gate. This checkout has no ESLint dependency or web lint script;
TypeScript typecheck is its configured static TypeScript gate.
