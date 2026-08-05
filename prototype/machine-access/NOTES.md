# PROTOTYPE — workload integration & machine-identity surfaces (wayfinder ticket #31)

**Question:** how do the workload-integration setup and service-account/credential
screens look and behave — against the locked machine-identity (#17), Compose (#18)
and Kubernetes (#19) ADRs, in the env-matrix-31 design language with the
app-chrome 15/16/18 reference chrome and the #21 ceremony vocabulary.

**Status: WIP.** Sibling of `prototype/env-matrix/` (frozen 31), `prototype/reveal-edit/`
(#21), `prototype/revision-history/` (#30) and `prototype/app-chrome/` (#29).
Design language locked; this prototype varies **structure**, not skin.

**Run:** `./prototype/serve.sh` then open `/machine-access/1/`. Every change is a
new numbered iteration — published ones never mutate.

## ADR surfaces under test

- **Write-only credential list** (#17): prefix (`ew_1_wl_…` / `ew_1_au_…`), kind,
  scope, expiry, created, last-used — never the value; rotation never returns
  the prior value. Expiry badges in-product first (email never the only signal).
- **Display-once mint** (#17): value shown exactly once; mint/rotate formula is
  `manage-identities(project)` ∧ `reveal(E)` over the **whole post-state** + reauth
  (the rotation-attack amendment).
- **Grant-mutation warning** (#17 amends #15): a grant on a machine principal
  re-scopes every credential in circulation — warning names the **newly-reachable
  plaintext set**; formula over the newly reachable environments.
- **Machine-`reveal` opt-in** (#18): per-project standing decryption capability;
  fresh workload SA delivers config + secret-presence only — step 4 of the
  five-step journey.
- **Five-step journey** (#18, mirrored in #19 docs): mint → grant `read` →
  delivery fails naming undeliverable keys → per-project opt-in → grant `reveal`
  (post-state formula + reauth).
- **Federation issuer/binding management** (#17/#19): byte-exact `(issuer, subject)`
  → exactly one SA; mandatory audience; binding has its own lifetime (renewal =
  mint); `pull_request`/`pull_request_target` refused unless deliberately bound.
- **Restore reconciliation** (#17): recovery mode, per-SA re-activation, **no
  bulk-accept**; every bearer credential permanently dead; federated bindings
  survive under the post-restore clock-skew quarantine; fleet re-established by
  minting fresh.
- **K8s CR-condition vocabulary** (#19): all-or-nothing refusal naming keys +
  required opt-in, loader-control acknowledgement (baseline-key list carried on
  the fetch), stalled/ignored rollout (delivered-but-not-rolled is visible),
  designation-missing, adoption refusal, target conflict — reading the same in
  `kubectl` and the UI.

## Iteration 2 — structure decided: a + b's journey on expansion

Marc's it-1 verdict: **variant a wins, with b's journey rail as the row
expansion.** Iteration 2 bakes it in: the tabbed inventory is the surface;
expanding a service-account row shows the five-step journey (left, CLI or
CR-condition voice per delivery mode) beside credentials / federated
bindings / delivery targets (right). Variant switcher removed; c discarded.
Everything else (ceremonies, scenarios, tabs) unchanged from iteration 1.

## Iteration 1 — baseline

Three **structural variants** of the Machine access surface, switchable via the
floating bottom bar, `←`/`→`, or `?variant=`:

- **a — inventory**: flat SA table under tabs (Service accounts / Federation /
  Kubernetes targets). Credentials expand per row. Classic admin console; the
  journey lives in a per-SA "setup" column chip.
- **b — journey board**: one card per SA organized around the five-step journey —
  step rail with the failing step voiced by the CR condition / CLI error verbatim.
  Kubernetes targets and their conditions ride on the owning SA's card.
- **c — master-detail**: compact SA list left; detail pane right with sticky
  jump index (Identity & grants · Credentials · Federation · Delivery targets),
  ceremonies inline in context.

Shared across variants: scenario simulator in the header (**normal / expiring /
post-restore** — post-restore swaps the whole surface into the reconciliation
screen), display-once mint modal, grant-mutation warning, reveal opt-in warning,
federation binding form with the GitHub Actions `pull_request` refusal, K8s
condition detail showing the same condition as `kubectl describe` output and as
UI copy, theme toggle.
