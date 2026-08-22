# Handoff: #253 WebAuthn test enrolment precondition

Issue: https://github.com/Hikyo-Org/Hikyo/issues/253 (parent #206; programme
#203; audit ID `QA02-B`).

## Contract

- `webauthntest.Device.Assert` returns `ErrNotEnrolled` before parsing ceremony
  options when no credential has been enrolled.
- Credential-dependent accessors (`SetCounter`, `Counter`, and `CredentialID`)
  panic with the same fixture-specific sentinel before enrolment. Tests cannot
  continue against zero-value credential state.
- Pre-enrolment authenticator configuration remains valid:
  `SetUserVerified`, `SetBackupEligible`, and `SuppressCredProps` still configure
  the credential that `Enrol` creates.
- One `Device` still represents one credential. Multi-credential account
  fixtures use separate devices enrolled from the same account handle.

No production WebAuthn code, database migration, API contract, or generated
output changed.

## Regression evidence

- Package tests cover immediate assertion refusal, fail-fast credential
  accessors, distinct credentials sharing one account handle, and post-enrolment
  counter mutation reaching signed authenticator data.
- The isolation UV-refusal test restores UV on the same enrolled credential and
  proves the control login succeeds. This distinguishes the intended server UV
  refusal from malformed or zero-value fixture failure.

## Validation

```text
go test -count=1 ./internal/webauthntest/...       7 passed
go test -count=1 ./internal/isolation/ -run WebAuthn
                                                   18 passed
go test -count=1 ./...                             3216 passed in 57 packages
go vet ./...                                       passed
git diff --check                                   passed
```

## Review

Two-axis review against issue #253 and repository standards found one possible
duplicated-precondition smell. The three accessors now share
`mustBeEnrolled`; review round 2 was clean. Spec behavior review found no code
finding; final PR metadata includes the generated-output disposition and full
validation evidence required by the issue.
