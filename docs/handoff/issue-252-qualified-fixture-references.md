# Handoff: #252 qualified scanning fixture references

Issue: https://github.com/Hikyo-Org/Hikyo/issues/252 (parent #206; programme
#203; audit ID `QA02-A`). Base: `fef78235b9e55a30c2cae72d1396238cce66771b`.

## Contract

- Scanning acceptance clauses use typed `fixtureref.FixtureRef` values. Go
  references identify an exact repository package, name, and executable kind;
  Playwright references additionally identify one exact source file and one
  complete static test title.
- Supported Go kinds are top-level test, benchmark, helper, and nested subtest.
  Helpers are top-level non-entrypoint functions in `_test.go`. Subtests use
  `TestParent/literal child/literal grandchild`; computed or shadowed `t.Run`
  titles do not resolve.
- Supported Playwright declarations are static string titles passed through a
  binding imported from `@playwright/test` to `test()`, `test.only()`, or
  `test.fail()`. Computed templates, `test.skip()`, and `test.fixme()` do not
  resolve. `test.describe()` titles are containers, not executable fixtures.
- The existing `SS3.ui` blocked clause stays explicitly not covered. Every
  non-blocked clause must have at least one validated executable reference.
- The shared `go list`/AST validator landed by #251 remains the canonical Go
  implementation; #252 extends it with file, benchmark, and Playwright kinds.

## Coverage

- Validator negatives pin renamed Go functions, same-name/wrong-package,
  same-function/wrong-file, wrong kind, dynamic subtests, same-title/wrong-file,
  missing Playwright file qualification, and dynamic Playwright titles.
- The scanning matrix validates all Go references from exact package ASTs and
  both UI clauses from `web/e2e/flows/scanning.spec.ts` metadata.
- Local validation passed: focused scanning/validator/conformance tests, `go
  vet ./...`, all Go packages sharded around the local five-minute process
  limit (3,377 tests across 58 packages), web Vitest (282 tests in 28 files),
  and `git diff --check`. The monolithic Go command emitted no failures before
  the harness ended it with status 143; the same package set passed in shards.
- Generated outputs: none.
