#!/bin/sh
set -eu

# Fixture: a valid chart passes, and each targeted mutation is REFUSED — proving
# the structural checker actually constrains RBAC verbs, TokenRequest scope,
# container args and hardening, not just that the chart renders.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chart="$script_dir/../../chart/hikyo"

"$script_dir/check-chart.sh" "$chart" >/dev/null

# refute CHART DESCRIPTION FILE SED-EXPR
# copies the chart, applies SED-EXPR to FILE (relative to the chart), and asserts
# check-chart.sh now fails.
refute() {
	desc=$1
	file=$2
	expr=$3
	work=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-chart-fixture.XXXXXX")
	cp -R "$chart" "$work/chart"
	sed "$expr" "$work/chart/$file" >"$work/mutated" && mv "$work/mutated" "$work/chart/$file"
	if "$script_dir/check-chart.sh" "$work/chart" >/dev/null 2>&1; then
		rm -rf "$work"
		printf 'Chart fixture: mutation accepted (%s)\n' "$desc" >&2
		exit 1
	fi
	rm -rf "$work"
	printf 'Chart fixture: refused %s\n' "$desc"
}

refute 'missing operator runAsNonRoot' \
	templates/operator-deployment.yaml \
	'/runAsNonRoot: true/d'

# Widen the Secrets verbs to include list/watch (the exact regression the exact
# verb check exists to catch).
refute 'secrets list/watch' \
	templates/_helpers.tpl \
	's/\["get", "create", "update", "patch"\]/["get", "list", "watch", "create", "update", "patch"]/'

# Change the operator container args away from the pinned [operator] multicall.
refute 'operator args tampered' \
	templates/operator-deployment.yaml \
	's/args: \["operator"\]/args: ["server"]/'

# Leak database configuration into the operator pod.
refute 'operator database env leak' \
	templates/operator-deployment.yaml \
	's/- name: HIKYO_OPERATOR_NAMESPACES/- name: HIKYO_DB\n              value: leaked\n            - name: HIKYO_OPERATOR_NAMESPACES/'

printf 'Chart fixture: valid chart accepted; RBAC/args/hardening mutations refused\n'
