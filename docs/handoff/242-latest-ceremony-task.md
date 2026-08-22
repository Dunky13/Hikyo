# Handoff: #242 latest-only ceremony tasks

Issue: https://github.com/Hikyo-Org/Hikyo/issues/242 (parent #205; programme
#203; audit ID `FE02-A`).

## Contract

- `useCeremonyTask` owns one generation-tagged, abortable ceremony task for a
  mounted route/target scope. A scope change, unmount, cancellation, or newer
  run aborts and releases the previous task.
- Guard responses, protected continuations, and Values disclosure/publish UI
  updates commit only while their exact task remains current. Network abort is
  best-effort; task identity is the mandatory late-result guard.
- Modal callbacks are task-bound. A passkey completion retained by an obsolete
  modal cannot authorise the continuation belonging to a newer modal.
- Values keys task ownership by organisation, project, current environment,
  destination, addressed key ids, and operation targets. Shared publish flows
  include their current environment/key selection in the owning scope.
- Current-task success, refusal, single-decision sequencing, and no-retry
  behavior are unchanged. No server or generated-client contract changed.

## Regression evidence

Deferred-promise tests cover environment navigation, publish-target changes,
unmount, cancellation without replay, same-target double runs, current-run
success/refusal, late disclosure completion, obsolete modal callbacks, and the
React StrictMode effect probe. Both the Values surface and shared protected
publish hook exercise the controller through their public behavior.

Generated outputs: none.

## Validation

```text
pnpm --dir web run typecheck
  passed

pnpm --dir web run test
  27 files, 261 tests passed

pnpm --dir web run build
  passed

go build -tags ui -o /tmp/hikyo-242 ./cmd/hikyo
  passed

HIKYO_E2E_BINARY=/tmp/hikyo-242 pnpm --dir web exec playwright test \
  e2e/flows/reveal.spec.ts --project=desktop --project=mobile
  28 passed (desktop and mobile)
```

Review evidence is recorded in the pull request after the final two-axis
review against issue #242 and repository standards. The three-round review
finished CLEAN on both axes: zero Standards findings and zero Spec findings.
