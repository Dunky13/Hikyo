# Handoff: #223 transaction-local session completion

Issue: https://github.com/Hikyo-Org/Hikyo/issues/223 (parent #204; programme
#203; audit ID `BE06-B`). Immediate stack base: PR #291 at
`176039eeaabf6635be2a68f906e7d0a37622d8d0`.

## Contract

- `service.SessionCompletion` is closed over explicit `CreateSession` and
  `RotateSession` variants. Creation requires an account, artifact, assurance,
  and an explicit browser/CLI CSRF decision. Rotation requires the live session,
  its owning account, and the exact replacement factor projection.
- The executor alone creates display-once bearer/CSRF artifacts, reads the
  principal generation and credential epoch for new sessions, inserts or
  rotates the verifier, serializes factors, and builds `LoginResult`.
- Callers still own password/federation/WebAuthn/TOTP verification, ceremony and
  provider binding, reauthentication-window policy/cardinality, and audit event
  construction. Rotation preserves the original session identity, clocks,
  authentication method, authentication time, ceremony, and CSRF verifier.
- Human local, CLI handoff, OIDC, SAML, WebAuthn, TOTP, factor enrolment/removal,
  and recovery paths publish display-once results through `tx.WriteResult`.
  Failed/retried attempts cannot publish their token or result projection.
- Workspace sessions remain separate because they are a distinct transport and
  projection owned by the multi-instance flow. Generated outputs: none.

## Review

The Standards axis checked the locked human-auth and system-architecture ADRs
plus the committed-result contract from #218. The Spec axis checked every #223
acceptance criterion against the PR #289 fixed point. Review added direct
negative variant/CSRF coverage and made the rotation account mandatory so all
rotations have one projection contract. Final result: clean on both axes.

## Validation

```text
go test -count=1 ./internal/service/... ./internal/authz/... ./internal/store/...
                                                             290 passed
go test -race -count=1 ./internal/service/...                174 passed
go test -count=1 ./internal/isolation/...                    1090 passed
go test -count=1 ./...                                       3169 passed / 57 packages
go vet ./...                                                 passed
gofmt -l <changed Go files>                                  clean
git diff --check                                             clean
```

The isolation run used the available SQLite path; no
`HIKYO_TEST_POSTGRES_DSN` was configured in this worktree.
