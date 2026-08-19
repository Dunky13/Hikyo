#!/usr/bin/env bash
# Provision an ephemeral kind cluster and run the operator kind-e2e suite
# against it. Runnable both in CI (the k8s-e2e job) and locally. The `kind`
# binary comes from PATH; the node image is digest-pinned to the default for the
# pinned kind release (v0.32.0), so the API-server version is reproducible.
#
# The cluster is created fresh and deleted in a trap. It never adopts or deletes
# a pre-existing `hikyo-e2e` cluster: a parallel session might own it, and
# deleting something this script did not create is the one move that is never
# safe.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

CLUSTER=hikyo-e2e
# kindest/node for kind v0.32.0 (kubernetes-sigs/kind v0.32.0 release notes).
# Digest-pinned: the tag alone is not a stable identity for a given kind build.
NODE_IMAGE="kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"

if ! command -v kind >/dev/null 2>&1; then
	echo "k8s-e2e: kind not found on PATH" >&2
	exit 1
fi

# Refuse to touch a cluster we did not create.
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
	echo "k8s-e2e: a kind cluster named '$CLUSTER' already exists; refusing to reuse or delete it" >&2
	exit 1
fi

kubeconfig="$(mktemp -t hikyo-e2e-kubeconfig.XXXXXX)"
config="$(mktemp -t hikyo-e2e-kind.XXXXXX)"
created=false
cleanup() {
	if [ "$created" = true ]; then
		kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
	fi
	rm -f "$kubeconfig" "$config"
}
trap cleanup EXIT HUP INT TERM

cat >"$config" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
EOF

echo "k8s-e2e: creating kind cluster '$CLUSTER' ($NODE_IMAGE)"
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" \
	--config "$config" --kubeconfig "$kubeconfig" --wait 120s
created=true

export HIKYO_K8S_E2E_KUBECONFIG="$kubeconfig"

echo "k8s-e2e: running operator kind e2e suite"
go test -count=1 -tags k8se2e -run 'TestK8sOperator' ./internal/isolation/ -timeout 25m
