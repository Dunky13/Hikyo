# Issue #251: stable bound fixture references

Issue: https://github.com/Hikyo-Org/Hikyo/issues/251 (parent #206; programme
#203; audit ID `QA01-B`). Base: `7e3dd0f6c13ce98572f4cd4f7f6015c2339bce77`.

## Contract

- Every conformance bound row has a stable slug ID, retained human-readable
  evidence, and at least one typed `FixtureRef` naming its exact Go package,
  test/helper/subtest name, and supported kind.
- `internal/testutil/fixtureref` resolves package ownership with `go list` and
  indexes `_test.go` declarations through the Go AST. Build-tagged files are
  included rather than silently disappearing under the host's active tags.
- Top-level tests follow the Go tool's name and signature rules. Literal
  subtests bind to the exact `*testing.T` parameter object, so unrelated or
  shadowed `Run` methods cannot satisfy a reference. Duplicate, missing,
  renamed, wrong-package, and wrong-kind references fail.
- Pending explanations remain separate from executable identity. Generated
  outputs: none.

## Coverage and review

- Fixture-reference and conformance suites: 89 tests passed.
- New exact boundary regressions for remote-count, adapter outbox depth, and
  API paging passed; the previously failing importer live test passed alone.
- `go vet ./...` passed. The local uncached full run reached 3,314 passes and
  then reported the importer live-test flake plus the known long-running local
  isolation-package failure; all changed/failed seams passed on focused rerun.
  Exact-head CI remains the authoritative full gate.
- Three review rounds completed after fixes for false Go-test signatures,
  unrelated/shadowed `Run` receivers, and weak row bindings. Standards and
  spec both returned `CLEAN` in round 3.
