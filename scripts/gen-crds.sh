#!/usr/bin/env bash
# Regenerate the operator's deepcopy methods and CRD manifests from the
# kubebuilder markers in internal/operator/api/v1alpha1. Same pattern as the
# oapi-codegen / sqlc generation the `generated` CI job runs: controller-gen is
# pinned as a `go tool` in go.mod, so the version is reproducible.
#
# The CI `generated` job (or a plain `go test ./internal/operator/api/...`, which
# drift-checks) calls this and then `git diff --exit-code -- chart/hikyo/crds`.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# deepcopy methods next to the types.
go tool controller-gen object:headerFile=/dev/null paths=./internal/operator/api/v1alpha1/...

# CRD YAML into the chart.
go tool controller-gen crd paths=./internal/operator/api/v1alpha1/... output:crd:dir=chart/hikyo/crds
