# #246 canonical release binary handoff

## Outcome

GoReleaser is the sole producer for release-architecture binaries. Release
archives consume its build outputs directly; `prepare-image-root.sh` selects
those same Linux amd64/arm64 outputs from `dist/artifacts.json`, copies them to
the Docker context, compares their bytes and hashes, and writes
`dist/binary-provenance.json`.

The signed release manifest now requires and validates that provenance. It
binds the GoReleaser configuration hash, candidate commit, version, supported
architectures, archive-input digests, and OCI-input digests. The release
bundle verifier requires exactly one provenance artifact and applies the same
candidate/digest validator before accepting its signature chain. The release
workflow's separate `go build` loop was deleted, so build tags, ldflags, CGO,
and toolchain settings have one source in `.goreleaser.yaml`.

## Generated outputs

- `dist/binary-provenance.json` — signed-manifest input with candidate/config
  identity and per-architecture hash equality.
- `image-root/amd64/hikyo` — byte copy of GoReleaser's Linux amd64 build output.
- `image-root/arm64/hikyo` — byte copy of GoReleaser's Linux arm64 build output.
- Main-branch development snapshots upload `binary-provenance.json` beside the
  archives and `checksums.txt`.

GoReleaser's internal `dist/artifacts.json`, `dist/config.yaml`, and
`dist/metadata.json` remain transient and are removed after canonical image
inputs and provenance are prepared.

## Validation evidence

Pinned GoReleaser v2.17.1 snapshot at candidate
`26ddd03b14f5e31aa966e73236bbdbfa19102690` built all six targets. Observed
Linux hashes:

- amd64 archive input = OCI input:
  `0fbfd828b2ef99fcd16a0566a2db8f0e0f204ead1eb7ff2ae1e97e74c1639764`
- arm64 archive input = OCI input:
  `ecb0dcd6228d2fcb6f09613fcba23cb154ca61ca71172556363e450ab8177b3b`

Passed locally:

```text
./scripts/ci/build-spa.sh
go test -count=1 -tags ui ./internal/server/... ./internal/webui/...
go test -count=1 ./...
goreleaser v2.17.1 release --snapshot --clean --skip=publish
./scripts/release/prepare-image-root.sh dist image-root <commit> .goreleaser.yaml
./scripts/release/snapshot-manifest_test.sh
docker build --build-arg TARGETARCH=arm64 --file Dockerfile.release .
docker run --rm <candidate-image> version
./scripts/release/test-fixtures.sh
./scripts/release/check-oci-unused_test.sh
ShellCheck and repo-pinned actionlint
```

The arm64 candidate image reported snapshot version, full source commit, and
commit date. CI repeats the image smoke with amd64 on `ubuntu-latest`.

## Scope boundary

This resolves #246's canonical-build and provenance requirements. The exact
binary now carries the existing `ui` tag into OCI packaging, coordinating the
root cause with #197. #197's browser-level HTML and hashed-asset acceptance is
not duplicated here and remains independently testable.
