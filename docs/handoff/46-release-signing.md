# Handoff: #46 release and signing pipeline

Issue: https://github.com/Hikyo-Org/Hikyo/issues/46. Fixed-point commit before
this work: `8bfeef1`.

## What exists

- `.github/workflows/release.yml` builds an unsigned draft from immutable `v*`
  tags: GoReleaser Linux/macOS/Windows amd64+arm64 archives, a pinned
  distroless GHCR amd64/arm64 image, a digest-pinned OCI Helm chart, source
  dependency SPDX (Go plus any frontend lockfile) and image SPDX, a pinned-root
  installer, and a release manifest binding commit, version, all artifact
  hashes, and both OCI digests. CI never signs.
- `scripts/release/verify-bundle.sh` verifies recovery-signed trust metadata,
  release ranges, revocation, latest-vs-explicit-historical intent, the
  recovery-bound manifest hash, primary-signed manifest, every artifact hash,
  cross-bound image/chart/OCI digests, chart version/image mapping,
  and a cosign bundle for every artifact. Persistent verification state refuses
  signed metadata rollback. `sign-bundle.sh` is the offline signing half;
  `publish-oci-signatures.sh` attaches and verifies the offline image and chart
  signatures against their already-published digest subjects.
- CI fixtures prove valid-chain acceptance plus refusal of tampering, a valid
  signature over the wrong image digest, contradictory OCI identities,
  downgrade-as-latest, a superseded primary beyond its release cutoff,
  primary-signed trust-root change, and a revoked primary for a formerly valid
  release. The installer fetches current recovery-signed revocation metadata
  while keeping its root and verifier pinned to the immutable tag.
- Candidate metadata increments its trust sequence without advancing
  `highest_release`; the current installer remains usable during the draft.
  Recovery binding finalizes the manifest hash and advances latest atomically.
- First-release bootstrap metadata is valid in `--trust-only` mode and persists
  rollback state without inventing a latest release; binding must advance its
  trust sequence before any release can verify.
- The release workflow probes the live immutable-tag rule by trying to move the
  permanent non-release `v-ruleset-probe` tag to a different commit, checks
  recovery-signed metadata, and distinguishes stable 1.x releases from
  0.x/prereleases. CI snapshots GoReleaser before any release tag.
- DCO is checked per PR commit by `scripts/ci/check-dco.sh`. Fixture coverage
  proves signed commits pass and unsigned commits block.
- Live repository policy is active: ruleset `20539249` forbids `v*` update and
  deletion with no bypass; ruleset `20539250` restricts `v*` creation to the
  admin repository role; the checked-in desired state for main ruleset
  `20539346` requires an up-to-date PR with the aggregate `ci-required` context;
  immutable releases and full-SHA-only Actions are enabled. The permanent
  `v-ruleset-probe` tag is pinned at `8bfeef1a80cceae0aea178cfda12bed1819e36c8`;
  a real changed-SHA update was refused by ruleset `20539249`.
- Image and chart publication also fail closed if their version tag already
  exists, or if registry lookup cannot prove absence, so a rerun cannot replace
  OCI bytes under an already-used release version.
- The release chart carries the pinned root, active primary key, and an optional
  Kyverno image-verification policy. Its non-loopback listener cannot render
  without explicit trusted proxy CIDRs.
- `HIKYO_TRUSTED_PROXY_CIDRS` currently enforces the non-loopback startup gate;
  no handler trusts forwarded headers yet. The transport ticket must consume
  the parsed CIDRs before adding any forwarded-header behavior.

## Verified

- Full Go suite passed against SQLite and a real pinned PostgreSQL 18 container.
- Release fixture chain, DCO fixture, manifest/installer/channel fixtures,
  Helm lint/render, shellcheck, actionlint,
  `go vet`, GoReleaser config validation, and `git diff --check` passed.
- A local OCI export produced both `linux/amd64` and `linux/arm64` manifests
  from the pinned distroless index. The arm64 container ran as built and printed
  its injected version/commit/date.

## Required human ceremony before first tag

Production private keys do not exist in this checkout by design. The locked ADR
requires network-disabled generation, tmpfs plaintext handling, separate USB
custody, and separate passphrases. Follow `docs/release/signing.md`, replace the
two `.example` trust files, commit only public material, and recovery-sign the
initial metadata. Release CI fails closed until those files exist.

No production tag, image, draft release, or signing key was created by #46.
