#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
	printf 'usage: %s [CHART]\n' "$0" >&2
	exit 2
fi

chart=${1:-chart/hikyo}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-chart-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

fail() {
	printf 'Chart check: %s\n' "$1" >&2
	exit 1
}

assert_contains() {
	grep -F -- "$2" "$1" >/dev/null || fail "$3"
}

assert_absent() {
	if grep -F -- "$2" "$1" >/dev/null; then
		fail "$3"
	fi
}

render_mode() {
	name=$1
	shift
	helm lint "$chart" \
		--set database.existingSecret=fixture \
		--set 'network.trustedProxyCIDRs={10.42.0.0/16}' \
		"$@" >/dev/null
	helm template fixture "$chart" \
		--set database.existingSecret=fixture \
		--set 'network.trustedProxyCIDRs={10.42.0.0/16}' \
		"$@" >"$tmp/$name.yaml"
}

render_mode cluster-wide
render_mode namespaced \
	--set 'operator.namespaces={ns-a,ns-b}' \
	--set 'operator.designatedServiceAccounts.ns-a={sa-a,sa-shared}' \
	--set 'operator.designatedServiceAccounts.ns-b={sa-b}'
render_mode no-rollouts --set operator.triggerRollouts=false

# Cluster-wide authority includes workload patching but no unrestricted TokenRequest grant.
assert_contains "$tmp/cluster-wide.yaml" 'kind: ClusterRole' 'default mode did not render a ClusterRole'
assert_contains "$tmp/cluster-wide.yaml" 'resources: ["deployments", "statefulsets", "daemonsets"]' 'default ClusterRole lacks rollout resources'
assert_absent "$tmp/cluster-wide.yaml" 'resources: ["serviceaccounts/token"]' 'default mode rendered an unrestricted TokenRequest grant'

# A cluster-wide TokenRequest rule is present only for the honest union of configured names.
helm template fixture "$chart" \
	--set database.existingSecret=fixture \
	--set 'network.trustedProxyCIDRs={10.42.0.0/16}' \
	--set 'operator.designatedServiceAccounts.ns-a={sa-a,sa-shared}' \
	--set 'operator.designatedServiceAccounts.ns-b={sa-b,sa-shared}' \
	>"$tmp/cluster-wide-designated.yaml"
assert_contains "$tmp/cluster-wide-designated.yaml" 'resources: ["serviceaccounts/token"]' 'designated cluster-wide mode lacks TokenRequest grant'
for service_account in sa-a sa-b sa-shared; do
	assert_contains "$tmp/cluster-wide-designated.yaml" "- \"$service_account\"" "cluster-wide TokenRequest union lacks $service_account"
done

watched_roles=$(awk 'BEGIN { RS = "---" } /(^|\n)kind: Role(\n|$)/ && /namespace: "ns-(a|b)"/ { count++ } END { print count + 0 }' "$tmp/namespaced.yaml")
[ "$watched_roles" -eq 2 ] || fail "namespaced mode rendered $watched_roles watched Roles, expected 2"
awk 'BEGIN { RS = "---" } /(^|\n)kind: Role(\n|$)/ && /namespace: "ns-a"/ { print }' "$tmp/namespaced.yaml" >"$tmp/ns-a-role.yaml"
awk 'BEGIN { RS = "---" } /(^|\n)kind: Role(\n|$)/ && /namespace: "ns-b"/ { print }' "$tmp/namespaced.yaml" >"$tmp/ns-b-role.yaml"
assert_contains "$tmp/namespaced.yaml" 'value: "ns-a,ns-b"' 'operator namespace env does not match RBAC input'
assert_contains "$tmp/ns-a-role.yaml" 'resources: ["serviceaccounts/token"]' 'ns-a Role lacks TokenRequest rule'
assert_contains "$tmp/ns-a-role.yaml" '- "sa-a"' 'ns-a TokenRequest rule lacks sa-a'
assert_contains "$tmp/ns-a-role.yaml" '- "sa-shared"' 'ns-a TokenRequest rule lacks sa-shared'
assert_absent "$tmp/ns-a-role.yaml" '- "sa-b"' 'ns-a TokenRequest rule includes ns-b ServiceAccount'
assert_contains "$tmp/ns-b-role.yaml" '- "sa-b"' 'ns-b TokenRequest rule lacks sa-b'
assert_absent "$tmp/ns-b-role.yaml" '- "sa-a"' 'ns-b TokenRequest rule includes ns-a ServiceAccount'

for workload in deployments statefulsets daemonsets; do
	assert_absent "$tmp/no-rollouts.yaml" "resources: [\"$workload\"" "triggerRollouts=false retained $workload authority"
	assert_absent "$tmp/no-rollouts.yaml" ", \"$workload\"" "triggerRollouts=false retained $workload authority"
done

for mode in cluster-wide namespaced no-rollouts; do
	manifest="$tmp/$mode.yaml"
	operator_manifest="$tmp/$mode-operator.yaml"
	awk 'BEGIN { RS = "---" } /(^|\n)kind: Deployment(\n|$)/ && /- name: operator\n/ { print }' "$manifest" >"$operator_manifest"
	[ "$(grep -c '^kind: Deployment$' "$manifest")" -eq 2 ] || fail "$mode did not render both Deployments"
	[ "$(grep -Fxc '          args: ["operator"]' "$operator_manifest")" -eq 1 ] || fail "$mode operator args are not exactly [\"operator\"]"
	assert_absent "$operator_manifest" 'HIKYO_DB' "$mode operator pod contains database configuration"
	[ "$(grep -Fxc '        runAsNonRoot: true' "$manifest")" -eq 2 ] || fail "$mode does not harden both pod security contexts"
	[ "$(grep -Fxc '            readOnlyRootFilesystem: true' "$manifest")" -eq 2 ] || fail "$mode does not harden both container root filesystems"
done

if helm template fixture "$chart" --set database.existingSecret=fixture >/dev/null 2>&1; then
	fail 'chart accepted a server listener without trusted proxy CIDRs'
fi
if helm template fixture "$chart" --set 'network.trustedProxyCIDRs={10.42.0.0/16}' >/dev/null 2>&1; then
	fail 'chart accepted a server without database.existingSecret'
fi

printf 'Chart check: cluster-wide, namespaced, no-rollout, hardening, and refusal assertions passed\n'
