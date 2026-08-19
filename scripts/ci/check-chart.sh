#!/bin/sh
set -eu

# Structured chart check: renders the operator chart across modes and asserts the
# RBAC rules, security contexts, container args and env EXACTLY, by parsing the
# rendered YAML per document (python3 + PyYAML) rather than substring-grepping —
# a substring check passes a chart whose verbs, resourceNames or env drifted.

if [ "$#" -gt 1 ]; then
	printf 'usage: %s [CHART]\n' "$0" >&2
	exit 2
fi

chart=${1:-chart/hikyo}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/hikyo-chart-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

if ! python3 -c 'import yaml' >/dev/null 2>&1; then
	printf 'Chart check: python3 with PyYAML is required\n' >&2
	exit 2
fi

fail() {
	printf 'Chart check: %s\n' "$1" >&2
	exit 1
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

render_mode cluster-wide \
	--set 'operator.designatedServiceAccounts.ns-a={sa-a,sa-shared}' \
	--set 'operator.designatedServiceAccounts.ns-b={sa-b,sa-shared}'
render_mode namespaced \
	--set 'operator.namespaces={ns-a,ns-b}' \
	--set 'operator.designatedServiceAccounts.ns-a={sa-a,sa-shared}' \
	--set 'operator.designatedServiceAccounts.ns-b={sa-b}'
render_mode no-rollouts --set operator.triggerRollouts=false

python3 - "$tmp/cluster-wide.yaml" "$tmp/namespaced.yaml" "$tmp/no-rollouts.yaml" <<'PY' || exit 1
import sys, yaml

cluster_wide, namespaced, no_rollouts = sys.argv[1], sys.argv[2], sys.argv[3]

def load(path):
    with open(path) as f:
        return [d for d in yaml.safe_load_all(f) if d]

def fail(msg):
    print(f"Chart check: {msg}", file=sys.stderr)
    sys.exit(1)

def by(docs, kind, name=None, namespace=None):
    out = []
    for d in docs:
        if d.get("kind") != kind:
            continue
        m = d.get("metadata", {})
        if name is not None and m.get("name") != name:
            continue
        if namespace is not None and m.get("namespace") != namespace:
            continue
        out.append(d)
    return out

def one(docs, kind, name=None, namespace=None):
    m = by(docs, kind, name, namespace)
    if len(m) != 1:
        fail(f"expected exactly one {kind} name={name} ns={namespace}, found {len(m)}")
    return m[0]

OP = "fixture-hikyo-operator"

# Exact rule model: normalize each rendered rule to a canonical, order-independent
# tuple, then compare the WHOLE rule set of every operator (Cluster)Role to an
# expected list per mode. A set comparison — not per-rule spot checks — is what
# catches a stray rule, a widened verb, or a dropped restriction; nothing may be
# present that is not expected, and nothing expected may be missing.
def norm(r):
    return (
        tuple(sorted(r.get("apiGroups", []))),
        tuple(sorted(r.get("resources", []))),
        tuple(sorted(r.get("verbs", []))),
        tuple(sorted(r.get("resourceNames", []))),
    )

def rule(groups, resources, verbs, names=()):
    return (tuple(sorted(groups)), tuple(sorted(resources)), tuple(sorted(verbs)), tuple(sorted(names)))

def expect_rules(rules, expected, where):
    got = sorted(norm(r) for r in rules)
    want = sorted(expected)
    if got != want:
        missing = [r for r in want if r not in got]
        extra = [r for r in got if r not in want]
        fail(f"{where}: RBAC rule set mismatch; missing={missing} extra={extra}")

# Rule building blocks (the operator's full ADR verb surface, § 0.10).
INSTANCES = rule(["hikyo.dev"], ["hikyoinstances"], ["get", "list", "watch"])
CRD = rule(["apiextensions.k8s.io"], ["customresourcedefinitions"], ["get"],
           ["hikyoinstances.hikyo.dev", "hikyosecrets.hikyo.dev"])
HIKYOSECRETS = rule(["hikyo.dev"], ["hikyosecrets"], ["get", "list", "watch", "patch"])
STATUS = rule(["hikyo.dev"], ["hikyosecrets/status"], ["update", "patch"])
FINALIZERS = rule(["hikyo.dev"], ["hikyosecrets/finalizers"], ["update"])
EVENTS = rule([""], ["events"], ["create", "patch"])
SECRETS = rule([""], ["secrets"], ["get", "create", "update", "patch"])
WORKLOAD = rule(["apps"], ["deployments", "statefulsets", "daemonsets"], ["get", "list", "watch", "patch"])
SERVICEACCOUNTS = rule([""], ["serviceaccounts"], ["get"])

# Cluster-scoped reads that always live on the ClusterRole.
CLUSTER_READS = [INSTANCES, CRD]
# Per-CR converge rules; secrets is get/create/update/patch ONLY (never list/watch).
CONVERGE = [HIKYOSECRETS, STATUS, FINALIZERS, EVENTS, SECRETS, SERVICEACCOUNTS]

def assert_rbac_inventory(docs, expected, mode):
    # Closure over WHICH RBAC objects exist, not only their rules: a brand-new
    # stray Role/ClusterRole (e.g. a rogue secrets list/watch grant under an
    # unexpected name) passes every per-role rule check because nothing looks at it.
    # Compare the full (kind, name, namespace) inventory to the expected set.
    got = set()
    for d in docs:
        if d.get("kind") in ("Role", "ClusterRole"):
            m = d.get("metadata", {})
            got.add((d["kind"], m.get("name"), m.get("namespace")))
    want = set(expected)
    if got != want:
        fail(f"{mode}: RBAC object inventory mismatch; missing={sorted(want - got)} extra={sorted(got - want)}")

def assert_leader_election(docs, mode):
    le = one(docs, "Role", f"{OP}-leader-election", "default")
    expect_rules(le["rules"], [
        rule(["coordination.k8s.io"], ["leases"], ["get", "create", "update"]),
    ], f"{mode} leader-election Role")

def assert_token_role(docs, ns, want_names):
    role = one(docs, "Role", f"{OP}-token", ns)
    rules = role["rules"]
    if len(rules) != 1:
        fail(f"token Role {ns}: expected exactly one rule, got {len(rules)}")
    r = rules[0]
    if r.get("resources") != ["serviceaccounts/token"] or r.get("verbs") != ["create"]:
        fail(f"token Role {ns}: rule = {r}")
    if sorted(r.get("resourceNames", [])) != sorted(want_names):
        fail(f"token Role {ns}: resourceNames = {r.get('resourceNames')}, want {want_names}")
    # Bound to the operator SA in the release namespace.
    rb = one(docs, "RoleBinding", f"{OP}-token", ns)
    subj = rb["subjects"][0]
    if subj["namespace"] != "default" or subj["name"] != OP:
        fail(f"token RoleBinding {ns}: subject = {subj}")

def assert_hardened(docs, mode):
    deploys = by(docs, "Deployment")
    if len(deploys) != 2:
        fail(f"{mode}: expected 2 Deployments, got {len(deploys)}")
    op = None
    for d in deploys:
        pod = d["spec"]["template"]["spec"]
        psc = pod.get("securityContext", {})
        if not psc.get("runAsNonRoot"):
            fail(f"{mode}: a pod securityContext is not runAsNonRoot")
        if psc.get("seccompProfile", {}).get("type") != "RuntimeDefault":
            fail(f"{mode}: a pod is missing seccompProfile RuntimeDefault")
        c = pod["containers"][0]
        csc = c.get("securityContext", {})
        if not csc.get("readOnlyRootFilesystem"):
            fail(f"{mode}: a container is not readOnlyRootFilesystem")
        if csc.get("allowPrivilegeEscalation") is not False:
            fail(f"{mode}: a container allows privilege escalation")
        if csc.get("capabilities", {}).get("drop") != ["ALL"]:
            fail(f"{mode}: a container does not drop ALL capabilities")
        if c["name"] == "operator":
            op = c
    if op is None:
        fail(f"{mode}: no operator container")
    if op.get("args") != ["operator"]:
        fail(f"{mode}: operator args = {op.get('args')}, want [operator]")
    assert_env_allowlist(op, mode)
    return op

# The operator container's env is an EXACT allowlist: only the operator's own
# scoping/config vars, never database or listener config. Set equality catches
# both an extra variable (leak) and a missing one (drift).
ALLOWED_ENV = {
    "HIKYO_OPERATOR_NAMESPACES",
    "HIKYO_OPERATOR_TRIGGER_ROLLOUTS",
    "HIKYO_OPERATOR_NAMESPACE",
    "POD_NAMESPACE",
}

def assert_env_allowlist(op, mode):
    names = [e["name"] for e in op.get("env", [])]
    if len(names) != len(set(names)):
        fail(f"{mode}: duplicate operator env names: {names}")
    if set(names) != ALLOWED_ENV:
        fail(f"{mode}: operator env = {sorted(names)}, want exactly {sorted(ALLOWED_ENV)}")

# ---- cluster-wide ----
# The single ClusterRole carries cluster reads + all converge rules + workload.
cw = load(cluster_wide)
assert_rbac_inventory(cw, [
    ("ClusterRole", OP, None),
    ("Role", f"{OP}-token", "ns-a"),
    ("Role", f"{OP}-token", "ns-b"),
    ("Role", f"{OP}-leader-election", "default"),
], "cluster-wide")
cr = one(cw, "ClusterRole", OP)
expect_rules(cr["rules"], CLUSTER_READS + CONVERGE + [WORKLOAD], "cluster-wide ClusterRole")
# TokenRequest is per-namespace even under cluster-wide watch.
assert_token_role(cw, "ns-a", ["sa-a", "sa-shared"])
assert_token_role(cw, "ns-b", ["sa-b", "sa-shared"])
# No stamp-root Role in cluster-wide mode (the ClusterRole covers Secrets).
if by(cw, "Role", f"{OP}-stamp-root"):
    fail("cluster-wide: unexpected stamp-root Role (ClusterRole already covers Secrets)")
assert_leader_election(cw, "cluster-wide")
assert_hardened(cw, "cluster-wide")

# ---- namespaced ----
# The ClusterRole is cluster-scoped reads ONLY; each per-namespace Role carries the
# converge rules + workload (no cluster reads, no token rule).
ns = load(namespaced)
assert_rbac_inventory(ns, [
    ("ClusterRole", OP, None),
    ("Role", OP, "ns-a"),
    ("Role", OP, "ns-b"),
    ("Role", f"{OP}-token", "ns-a"),
    ("Role", f"{OP}-token", "ns-b"),
    ("Role", f"{OP}-stamp-root", "default"),
    ("Role", f"{OP}-leader-election", "default"),
], "namespaced")
cr = one(ns, "ClusterRole", OP)
expect_rules(cr["rules"], CLUSTER_READS, "namespaced ClusterRole")
for n in ("ns-a", "ns-b"):
    role = one(ns, "Role", OP, n)
    expect_rules(role["rules"], CONVERGE + [WORKLOAD], f"namespaced Role {n}")
assert_token_role(ns, "ns-a", ["sa-a", "sa-shared"])
assert_token_role(ns, "ns-b", ["sa-b"])
# Stamp-root Role lives in the release namespace: name-restricted get/update on the
# fixed stamp-root Secret + an unrestricted create, and NOTHING else.
sr = one(ns, "Role", f"{OP}-stamp-root", "default")
expect_rules(sr["rules"], [
    rule([""], ["secrets"], ["get", "update"], ["hikyo-operator-stamp-root"]),
    rule([""], ["secrets"], ["create"]),
], "stamp-root Role")
assert_leader_election(ns, "namespaced")
op = assert_hardened(ns, "namespaced")
env = {e["name"]: e.get("value") for e in op.get("env", [])}
if env.get("HIKYO_OPERATOR_NAMESPACES") != "ns-a,ns-b":
    fail(f"operator watch env = {env.get('HIKYO_OPERATOR_NAMESPACES')}, want ns-a,ns-b")

# ---- no-rollouts ----
# triggerRollouts=false drops the workload rule ENTIRELY and nothing else changes.
nr = load(no_rollouts)
assert_rbac_inventory(nr, [
    ("ClusterRole", OP, None),
    ("Role", f"{OP}-leader-election", "default"),
], "no-rollouts")
cr = one(nr, "ClusterRole", OP)
expect_rules(cr["rules"], CLUSTER_READS + CONVERGE, "no-rollouts ClusterRole")
assert_leader_election(nr, "no-rollouts")
assert_hardened(nr, "no-rollouts")

print("Chart check: every RBAC rule set, TokenRequest scope, stamp-root grant, hardening, args and the exact env allowlist asserted")
PY

# Refusal fixtures: the server listener is invalid without both a database Secret
# and explicit trusted proxy CIDRs.
if helm template fixture "$chart" --set database.existingSecret=fixture >/dev/null 2>&1; then
	fail 'chart accepted a server listener without trusted proxy CIDRs'
fi
if helm template fixture "$chart" --set 'network.trustedProxyCIDRs={10.42.0.0/16}' >/dev/null 2>&1; then
	fail 'chart accepted a server without database.existingSecret'
fi
# A designated ServiceAccount for a namespace outside the watch set is refused.
if helm template fixture "$chart" \
	--set database.existingSecret=fixture \
	--set 'network.trustedProxyCIDRs={10.42.0.0/16}' \
	--set 'operator.namespaces={ns-a}' \
	--set 'operator.designatedServiceAccounts.ns-b={sa-b}' >/dev/null 2>&1; then
	fail 'chart accepted a TokenRequest grant for an unwatched namespace'
fi

printf 'Chart check: cluster-wide, namespaced, no-rollout, hardening, and refusal assertions passed\n'
