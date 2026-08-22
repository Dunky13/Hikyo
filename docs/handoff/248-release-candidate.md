# Issue #248: trusted release candidate

Issue: https://github.com/Hikyo-Org/Hikyo/issues/248. Fixed point before this
work: `275dae54ce1e372d07ba7a7781cd2e8bd37f75eb`.

## Contract

`scripts/release/resolve-candidate.sh` is the only release-build selector for a
version, release sequence, and signing key. It emits one compact, sorted JSON
record containing exactly `version`, `sequence`, `commit`, `key_id`, and
`public_key`. The release workflow records its SHA-256 and checks that hash
before every later filesystem consumer.

Trust metadata v1 does not carry the source commit. The resolver therefore
takes the immutable tag commit as a separate input and binds it into the
record. Release CI adds the `pending` mode, which requires the selected version
to be the zero-manifest-hash `pending_release`; offline verification accepts
the same record after recovery binding moves that row into `releases`.

Inclusive key intervals are deterministic. Missing or duplicate versions and
sequences, interval gaps or overlaps, pending keys, and revoked keys are
refused. The serialized record is a signed release artifact, so manifest
creation, recovery binding, primary signing, and verification all compare
against identical bytes rather than selecting metadata again in local scripts.
GoReleaser receives the record's version and commit through explicit release
environment variables, and its generated metadata is compared to the record
before packaging continues.

## Generated output

`release-candidate.json` is generated during tagged release CI and uploaded
with the draft. It is not checked in. Its hash is recorded in
`release-manifest.json`, and `sign-bundle.sh` signs it like every other release
artifact.

## Validation

- Resolver fixtures: canonical output; missing, duplicate, overlap, pending,
  revoked, out-of-range, boundary, finalized, noncanonical, and hash-tamper
  cases.
- Manifest, binding, installer, tag, OCI, and release-channel fixtures.
- Full cosign chain including candidate tamper, wrong private key, rotation,
  superseded publication key, and revocation refusal.
- ShellCheck, actionlint, changed-path and required-job policy fixtures, and
  `git diff --check`.
