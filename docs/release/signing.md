# Release signing runbook

CI builds and publishes an **unsigned draft**. It never receives either private
key. The maintainer signs locally; only verified, already-published bytes become
an official release.

## Pinned tools

- GoReleaser `v2.17.1`
- cosign `v3.1.3`
- Syft `v1.50.0`
- Helm `v4.2.3`
- Go `1.26.2` from `go.mod`

Verify downloaded tool archives against the checksum asset attached to that
exact upstream release. GitHub Actions are full-SHA pinned in each workflow;
the repository setting rejects tag-form action references.

## One-time trust bootstrap

1. Disconnect networking. Run `ulimit -c 0`. Mount a memory-backed working
   directory; do not use a normal disk, synced folder, indexed folder, or a
   location covered by workstation backups.
2. Run `cosign generate-key-pair --output-key-prefix primary-1` and separately
   `cosign generate-key-pair --output-key-prefix recovery-1`, using different
   password-manager passphrases. Copy each encrypted `.key` to two USB devices
   in separate locations; recovery media must be separate from primary media.
3. Commit only both `.pub` files, `release/trust/root.json`, and the initial
   `metadata.json`. `root.json` pins each public-key filename and SHA-256.
   Sequence 1 metadata pins the bootstrap primary from the root and records the
   first version as `pending_release`; it does not claim that draft is current.
4. Sign `metadata.json` with the recovery root using `cosign sign-blob
   --new-bundle-format=false --tlog-upload=false --use-signing-config=false
   --bundle metadata.sigstore.json`. The legacy-output switches are required by
   pinned cosign v3.1.3: they keep the operation offline and allow the OCI
   ceremony to emit a raw signature. Commit the bundle. Re-encrypt/eject media,
   wipe the tmpfs, then reconnect networking.
5. Before the first tag, verify the recovery signature, pinned bootstrap key,
   and every public-key hash with
   `scripts/release/verify-bundle.sh --root release/trust/root.json --metadata
   release/trust/metadata.json --metadata-signature
   release/trust/metadata.sigstore.json --state PATH --trust-only`. This writes
   trust sequence 1 with null latest-release fields. The later bound metadata
   must advance to sequence 2 before it can replace that state. Separately run
   `scripts/release/test-fixtures.sh` for the complete signed-bundle rehearsal.
   A real release tag remains blocked until all production trust files exist.

The recovery key signs trust-metadata changes only. A primary signature can
never replace the recovery root. Current v1 verification deliberately requires
recovery authorization for rotation and revocation; this is stricter than
allowing a routine old-primary rotation and keeps the recovery direction
one-way.

Cosign performs every cryptographic operation and defines the OCI signature
payload; the shell code only enforces the project-specific release-range and
recovery policy locked by the ADR. TUF was not substituted for that policy:
doing so would replace the mandated long-lived cosign root, recovery-only
authority, and release-range revocation semantics. Changing those semantics is
an ADR amendment, not an implementation refactor.

## Per-release ceremony

1. For every release after the bootstrap release, before tagging, increment the
   trust-metadata `sequence`, set `event.type` to `release-candidate`, and add
   `pending_release` with the exact version, monotonic release sequence, and 64
   zeroes as its `manifest_sha256`. Do **not** change `releases`,
   `highest_release`, or `highest_release_sequence`: the currently published
   installer must remain current while the new release is only a draft.
   Recovery-sign this candidate metadata offline, commit it, and merge it to
   `main`. For the first release, sequence 1 bootstrap metadata is already the
   candidate; skip this step and bind it directly to sequence 2 after CI builds
   the draft.
2. Create `vX.Y.Z` at that merged commit. CI verifies reachability and prior
   non-use, proves a changed-SHA update to the permanent non-release
   `v-ruleset-probe` tag is rejected, builds GoReleaser archives for
   Linux/macOS/Windows on amd64/arm64,
   pushes the distroless amd64/arm64 image and digest-pinned Helm chart, emits
   source and image SPDX SBOMs, renders an installer containing the exact trust
   root and verifier hashes, and opens a draft GitHub release. CI also makes the
   cosign OCI payloads while it has registry access; it never signs them.
3. With networking on and no decrypted key present, download every draft asset.
   Recompute `checksums.txt`, compare the GHCR index digest with
   `image-index.digest` and `chart-index.digest`. Confirm both prepared OCI
   payloads name those exact published subjects.
4. Disconnect networking, mount tmpfs, decrypt only the recovery key, and run
   `scripts/release/bind-manifest.sh release-manifest.json metadata.json
   metadata.bound.json`. Recovery-sign `metadata.bound.json`, then re-encrypt
   and eject recovery media. Reconnect only after plaintext is gone; commit the
   bound file as `release/trust/metadata.json` plus its signature to `main`.
   `bind-manifest.sh` increments the trust sequence again, converts the pending
   row into a finalized release row, and only then advances `highest_release`.
   The release remains a draft. This makes rebuilding different bytes under an
   already-used version fail verification even if a primary key signs them.
5. Disconnect networking again, set `ulimit -c 0`, mount tmpfs, decrypt only the
   primary key there, disable core dumps, and run
   `scripts/release/sign-bundle.sh`. It creates a cosign bundle for every asset
   and raw signatures for both prepared OCI payloads. Remove plaintext,
   unmount tmpfs, and eject the key media before networking returns.
6. With networking restored and no private key mounted, run
   `scripts/release/publish-oci-signatures.sh BUNDLE PRIMARY.pub`. It attaches
   the offline signatures to the exact image and chart digests, then requires
   `cosign verify` to succeed for both published subjects. Upload the manifest
   and every `*.sigstore.json` bundle to the draft; raw OCI signatures are
   transport scratch and are not release assets.
7. Redownload the complete draft and verify it through
   `verify-bundle.sh --published --state
   "$XDG_STATE_HOME/wenv/release-trust.json"`; then publish the draft. The
   installer fetches current recovery-signed metadata from `main`, then runs the
   same published-subject check before extracting a binary. The pinned root and
   verifier code still come from the immutable release tag.
   GitHub immutable releases locks its assets at publication. Preserve that
   state file; deleting it discards locally remembered rollback protection.

`checksums.txt` is GoReleaser's bare-binary checksum list. The signed release
manifest is authoritative for binaries, SBOMs, installer, chart, digest files,
and OCI payloads.

Hash agreement proves asset consistency, not an honest CI build. Reproducible
build comparison is the named future control for compromised-CI risk.

## Rotation, revocation, and loss

- Rotation: recovery-sign metadata that closes the old primary at a named
  release sequence and activates the new primary at the next. No overlap.
- Primary compromise or workstation compromise: recovery-sign a distinct
  revocation event. `verify-bundle.sh` refuses that primary for old releases too.
- Lost primary: conservatively recovery-revoke it, then rotate; this prevents a
  later recovery of the old private key from fabricating a historical bundle.
  Lost recovery: out-of-band
  recovery-root rebootstrap; a primary-signed replacement is invalid. Both lost:
  full out-of-band trust bootstrap.
- Run restore/decrypt/sign/verify from each USB copy yearly and before first use
  after any storage change.
