# Handoff: #244 machine-credential mint lifecycle

Issue #244 replaces `MachineAccess`'s independent mint flags with one closed,
display-once lifecycle:

```text
idle → reviewing(request) → submitting(request) → disclosed(request, result)
                                      ↘ failed(request, error) → submitting(request)
```

## What changed

- `mintLifecycle.ts` owns review, submit, disclosure, failure, retry,
  confirmation, dismissal, and clearing transitions. Only `disclosed` can hold
  the minted value; no transition history is retained.
- `MachineAccess` keeps a synchronous lifecycle ref beside React state. A
  second submit is rejected before another transport starts, and async success,
  failure, and clipboard completion are addressed to the request that began
  them. Completion from an obsolete request is ignored.
- Requests freeze only the non-secret fields needed by review and retry:
  session and project address, account id/name, rotation intent, and
  disclosure-environment id/name pairs.
- Close returns the lifecycle to `idle`; project navigation clears it; a new
  review replaces it; and `MachineAccess` observes the current session id so a
  session transition clears the lifecycle without remounting unrelated routes.
- The mint transport remains a plain async call. It does not use TanStack
  QueryCache or MutationCache, and a focused test inspects both caches after a
  sentinel mint.

## Contract and migration

No HTTP, generated-client, persistence, or migration change. Credential
metadata is still refreshed from the ordinary listing after the display-once
response. No generated output changed.

## Validation

Run with the repository-pinned Node version (`.nvmrc`):

```sh
pnpm --dir clients/ts install --frozen-lockfile
pnpm --dir web install --frozen-lockfile
pnpm --dir web run typecheck
pnpm --dir web run test
pnpm --dir web run build
pnpm --dir web exec playwright test e2e/flows/machine-access.spec.ts
```

The lifecycle transition table covers sentinel plaintext, close/navigation/
session clearing, new review, double submit, obsolete completion, failure retry,
and stored-confirmation dismissal. The existing browser mint flow covers real
delayed responses, Escape/Back remasking, and display-once removal.

Pre-commit results on Node 24:

- web typecheck passed;
- 25 web test files and 257 tests passed;
- the production web build passed;
- TypeScript client typecheck and all 12 client tests passed.

After integrating current `main`, web typecheck, the production build, all 269
web tests, client typecheck, and all 12 client tests passed. The rebuilt binary
passed the machine-access flow in both desktop and mobile projects. One
mobile-light pinned-assertion run hit the 30-second harness timeout after 20
passes; that case passed alone in 1.8 seconds, and the display-once case it had
skipped passed alone in 995 milliseconds.
