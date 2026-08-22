# Handoff: #233 service-owned target mutation classification

Issue: https://github.com/Hikyo-Org/Hikyo/issues/233 (parent #204; programme
#203; audit ID `BE16-A`). Base: `32018f096e6eae5695fcb43046c7f1b52eec051d`.

## Contract

- `Adapters.ApplyTargetMutation` accepts requested target state plus
  `keepRemote` and returns the closed `TargetMutationUpdated |
  TargetMutationMoveStarted` result.
- Destination kind, owner, name, or destination-environment changes select the
  scrub-before-switch move path. Visibility, selected repositories, prefix,
  and key changes remain metadata updates. Target environment stays immutable.
- Classification checks the caller-authorized current generation first, then
  rechecks generation and destination identity inside the selected write
  transaction. A concurrent change is refused; it cannot cross from update to
  move without scrub ceremony.
- HTTP and CLI send one update-target intent. HTTP maps the service result to
  the existing `200 AdapterTarget` or `202 AdapterMove` contract; CLI renders
  the returned variant instead of choosing a response workflow itself.
- CLI browser reauthentication remains a transport pre-step because it owns
  the interactive handoff. Service ceremony checks stay authoritative and run
  in the mutation transaction. Remote scrub ordering, protected-environment
  authorization, audit identities, and `keep_remote` semantics are unchanged.

OpenAPI and generated outputs: unchanged.

## Regression evidence

- Service tables cover metadata update versus destination move and reject
  update-only `keep_remote` plus environment changes without mutation.
- A concurrent update/move test proves one expected generation wins and the
  stale request is refused.
- CLI result tables cover both existing HTTP response variants, independent of
  the CLI's pre-request snapshot.
- HTTP service-boundary and CLI transport tables prove both variants submit one
  intent without a transport-supplied move decision.
- Public-operation ceremony tables cover protected update and move refusals;
  existing scrub, keep-remote, and audit tests now route through the public
  classifier.

Two-axis Codex review reached `CLEAN` in round 2 after classification moved
into the mutation write transaction and transport/concurrency/ceremony coverage
became deterministic.

## Validation

```text
go test -count=1 ./internal/service/... ./internal/server/... ./internal/cli/... -run Adapter
                                                        passed
go test -count=1 ./internal/service/... ./internal/server/... ./internal/cli/...
                                                        passed
go test -race -count=1 ./internal/service -run TestApplyTargetMutation
                                                        passed
go test -count=1 ./internal/isolation/                  passed (76.828s)
go build ./...                                          passed
go vet ./...                                            passed
go test -p 4 -count=1 -timeout=20m ./...                passed
```
