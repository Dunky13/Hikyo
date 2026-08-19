# Contributing to Hikyo

Open an issue and get maintainer agreement before starting a large change.

## Developer Certificate of Origin

Every commit in a pull request must carry a Developer Certificate of Origin
sign-off. Add it with:

```sh
git commit -s
```

The sign-off certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
CI checks the pull request's commit history; a sign-off added only to a squash
message does not satisfy the gate. Hikyo uses DCO, never a CLA, so contributors
retain their copyright.

## Security-sensitive contributions

Contributions touching cryptography, authentication, deployment adapters, or
delivery paths require maintainer security review. Maintainer-authored changes
use adversarial cross-model review until a second maintainer exists; this is a
compensating check, not independent human review.

Do not report vulnerabilities in public issues. Use the private channels in
[SECURITY.md](./SECURITY.md).

## Design decisions

The locked architecture decision records live in [`docs/adr/`](./docs/adr/README.md)
and the build-ready specification set in [`docs/spec/`](./docs/spec/README.md).
Code comments cite them by file stem ("the encryption-model ADR" is
`docs/adr/encryption-model.md`); `docs/adr/README.md` maps every short name to
its file. A change that contradicts a locked ADR reopens the ADR (amendment
banner) rather than silently diverging — see
[`oss-mechanics.md`](./docs/adr/oss-mechanics.md) § Governance.

## Local verification

Run the checks relevant to the changed package and the full test suite before
requesting review. CI is the source of truth for the complete release gates.
