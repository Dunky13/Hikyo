# Handoff: #66 GitHub Actions deployment adapter

Issue: https://github.com/Hikyo-Org/Hikyo/issues/66. The locked contract is
`docs/adr/github-adapter.md` at Git commit `f2f951b`, composed with the #65
deployment-module seam already present on `main`. This handoff describes the
implementation on this branch; it does not claim a merge, deployment, or
live-provider pass.

## Implemented locally

- **GitHub provider module and HTTP boundary** — repository, organization, and
  repository-environment destinations; immutable numeric identity pins; exact
  URL encoding; exhaustive secret-name pagination; structurally absent
  variable reads; sealed-box secret writes; POST-409 and PATCH-404 variable
  state machines; fresh-key retry; 201/204 capture classification; selected
  repository full-set replacement; environment GET/empty-PUT/GET creation;
  classic-PAT refusal; minimum-permission and expiry metadata messages; and
  GitHub-specific workflow-name/value validation.
- **Durable lifecycle** — migration `00025_github_actions_adapter.sql` on both
  engines adds provider/destination routing, repo+environment identity,
  visibility/selected repository IDs, credential expiry, warnings,
  owned-missing custody, and continuation cursor state without changing applied
  migration `00024`. SQLite rebuilds are atomic and retry-safe with foreign-key
  checks. Provider writes retain dispatched custody through ambiguous failures,
  possible capture, and selected-recipient replacement failure.
- **Rate and continuation behavior** — one credential-wide serialized mutation
  pacer uses only a SHA-256 credential fingerprint, survives client/job reloads,
  retains the last mutation deadline, and evicts idle state after a bounded TTL
  and capacity. Headerless 403/429 fallback doubles from one minute through the
  shared bounded cap and resets after provider success. In-job waits resume at
  a names-only completed cursor after discarding loaded value material; only
  the wall-clock boundary returns work to outbox retry. Both activation and
  converge wait limits are anchored to the original durable claim deadline,
  before authorization, so a slow gate cannot wait beyond the lease and turn a
  rate response into a terminal supersede failure.
- **Service, public API, and CLI** — create/add/test/move/activation use the
  persisted provider rather than credential-prefix inference; GitHub destination
  kind, environment locator, identities, visibility, selected repositories,
  warnings, and credential expiry round-trip through store/OpenAPI/generated
  clients/server/CLI. Recipient-set ceremony classification is a shared domain
  helper used by service and CLI. Configure-time environment creation is
  fenced and emits correlated push INTENT/OUTCOME audit facts.
- **Contract harness and docs** — the real-github.com test is one all-or-nothing
  opt-in harness. It requires distinct documented-minimum and one-permission-less
  tokens per destination, a dedicated harness token/repository, a protected
  unattended environment, and the exact embedded workflow fixture
  `internal/adapter/githubactions/testdata/hikyo-contract-consume.yml`. It pins
  POST-409, PATCH-404, no-variable-read, settings-free protected-environment
  PUT invariance, auto-create identity, adoption conflict, and hash-only
  workflow consumption for empty, CRLF, lone-CR, trailing-whitespace, Unicode,
  and 48-KB secret/variable values at repo/org/environment scope. Artifacts
  contain hashes only; provider values are never logged or read back.

## Local evidence

Focused review-round regressions:

```text
rtk go test ./internal/adapter/githubactions \
  -run 'Test(SequentialProductionClients|CredentialState|HeaderlessRateExponentSurvives)' \
  -count=1
Go test: 4 passed in 1 package

rtk go test ./internal/service \
  -run 'TestAdapter(TargetConnectionReauthorizesEveryProviderRequest|TargetMoveActivationTestsPendingRouteThenEnqueuesConverge|TargetAdd.*Authority|CreateAtomically)' \
  -count=1
Go test: 4 passed in 1 package

rtk go test ./internal/store ./internal/adapter/githubactions -count=1
Go test: 72 passed in 2 packages

rtk go test ./internal/adapter \
  -run 'TestWorker(SlowInitialGateCannotWaitPastOriginalDurableLease|RateWaitReleasesPlaintextAndResumesAfterCompletedName|HonorsProviderRetryDeadline|ActivationRequiresAttention)' \
  -count=1
Go test: 10 passed in 1 package
```

Generated/public-contract and static checks:

```text
rtk go tool sqlc generate
rtk go tool oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml
rtk pnpm --dir clients/ts run generate
rtk git diff --check
test -z "$(gofmt -l .)"
All succeeded.

rtk pnpm --dir clients/ts run verify
4 TypeScript contract tests passed; generation and typecheck succeeded.

rtk pnpm --dir docs/site run check
Astro: 0 errors, 0 warnings, 0 hints.

rtk go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 \
  internal/adapter/githubactions/testdata/hikyo-contract-consume.yml
Succeeded with no diagnostics.

rtk go build ./...
rtk go vet ./...
Both succeeded.
```

```text
rtk go test -count=1 ./...
Go test: 2145 passed in 45 packages.
```

`git diff -- internal/store/migrations/{sqlite,postgres}/00024*` produced no
output: applied migration `00024` is untouched.

OpenCode adversarial review used
`openrouter/deepseek/deepseek-v4-flash`. Round 1 found one valid error-reporting
defect: environment identity changes were wrapped as permission failures. The
fix preserves `ErrDestinationID`, names target reconfiguration, and has a public
behavior regression. Round 2 verified the fix and the evidence-backed
disposition of the remaining candidates: `CLEAN`.

## Deliberately unexecuted external legs

- **Real GitHub contract/E2E** was not run because
  `HIKYO_GITHUB_CONTRACT` and its dedicated token/repository/environment
  variables are absent. The ordinary test suite skips the entire harness with
  a loud all-or-nothing message; no partial live-provider pass is claimed.
- **PostgreSQL conformance** was not run because
  `HIKYO_TEST_POSTGRES_DSN` is absent. Deterministic SQLite migration tests and
  compile-time Postgres query/model coverage ran locally; CI must execute the
  real PostgreSQL migration and lifecycle leg.
- No push, pull request, merge, deployment, or production verification was
  performed.
