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

def rule_for(rules, resources, group=""):
    want = set(resources)
    for r in rules:
        if r.get("apiGroups", [""]) == [group] and set(r.get("resources", [])) == want:
            return r
    return None

def assert_secrets_rule(rules, where):
    # Secrets: exactly get/create/update/patch, never list/watch.
    r = rule_for(rules, ["secrets"])
    if r is None:
        fail(f"{where}: no secrets rule")
    if sorted(r["verbs"]) != sorted(["get", "create", "update", "patch"]):
        fail(f"{where}: secrets verbs = {r['verbs']}, want get/create/update/patch exactly")

def assert_no_secret_listwatch(rules, where):
    for r in rules:
        if "secrets" in r.get("resources", []):
            for v in r.get("verbs", []):
                if v in ("list", "watch"):
                    fail(f"{where}: secrets rule carries forbidden verb {v}")

def assert_no_token_rule(rules, where):
    for r in rules:
        if "serviceaccounts/token" in r.get("resources", []):
            fail(f"{where}: must NOT carry a serviceaccounts/token rule")

def assert_workload_rule(rules, where, present):
    r = rule_for(rules, ["deployments", "statefulsets", "daemonsets"], group="apps")
    if present and r is None:
        fail(f"{where}: missing workload rule")
    if present and sorted(r["verbs"]) != sorted(["get", "list", "watch", "patch"]):
        fail(f"{where}: workload verbs = {r['verbs']}")
    if not present and r is not None:
        fail(f"{where}: workload rule present but triggering disabled")
    # No stray apps rules either way.
    if not present:
        for r2 in rules:
            if r2.get("apiGroups") == ["apps"]:
                fail(f"{where}: an apps rule survived triggerRollouts=false")

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
    for e in op.get("env", []):
        if e["name"].startswith("HIKYO_DB"):
            fail(f"{mode}: operator env leaks database config {e['name']}")
    return op

# ---- cluster-wide ----
cw = load(cluster_wide)
cr = one(cw, "ClusterRole", OP)
assert_secrets_rule(cr["rules"], "cluster-wide ClusterRole")
assert_no_secret_listwatch(cr["rules"], "cluster-wide ClusterRole")
assert_no_token_rule(cr["rules"], "cluster-wide ClusterRole")
assert_workload_rule(cr["rules"], "cluster-wide ClusterRole", present=True)
# TokenRequest is per-namespace even under cluster-wide watch.
assert_token_role(cw, "ns-a", ["sa-a", "sa-shared"])
assert_token_role(cw, "ns-b", ["sa-b", "sa-shared"])
# No stamp-root Role in cluster-wide mode (the ClusterRole covers Secrets).
if by(cw, "Role", f"{OP}-stamp-root"):
    fail("cluster-wide: unexpected stamp-root Role (ClusterRole already covers Secrets)")
assert_hardened(cw, "cluster-wide")

# ---- namespaced ----
ns = load(namespaced)
cr = one(ns, "ClusterRole", OP)
# The namespaced ClusterRole is cluster-scoped reads ONLY — no Secrets.
if rule_for(cr["rules"], ["secrets"]) is not None:
    fail("namespaced ClusterRole must not grant Secrets")
assert_no_token_rule(cr["rules"], "namespaced ClusterRole")
for n in ("ns-a", "ns-b"):
    role = one(ns, "Role", OP, n)
    assert_secrets_rule(role["rules"], f"namespaced Role {n}")
    assert_no_secret_listwatch(role["rules"], f"namespaced Role {n}")
    assert_no_token_rule(role["rules"], f"namespaced Role {n}")
    assert_workload_rule(role["rules"], f"namespaced Role {n}", present=True)
assert_token_role(ns, "ns-a", ["sa-a", "sa-shared"])
assert_token_role(ns, "ns-b", ["sa-b"])
# Stamp-root Role lives in the release namespace, name-restricted get/update + create.
sr = one(ns, "Role", f"{OP}-stamp-root", "default")
restricted = None
create = None
for r in sr["rules"]:
    if r.get("resourceNames") == ["hikyo-operator-stamp-root"]:
        restricted = r
    elif r.get("resources") == ["secrets"] and r.get("verbs") == ["create"]:
        create = r
if restricted is None or sorted(restricted["verbs"]) != sorted(["get", "update"]):
    fail(f"stamp-root Role: name-restricted rule wrong: {restricted}")
if create is None:
    fail("stamp-root Role: missing unrestricted create rule")
op = assert_hardened(ns, "namespaced")
env = {e["name"]: e.get("value") for e in op.get("env", [])}
if env.get("HIKYO_OPERATOR_NAMESPACES") != "ns-a,ns-b":
    fail(f"operator watch env = {env.get('HIKYO_OPERATOR_NAMESPACES')}, want ns-a,ns-b")

# ---- no-rollouts ----
nr = load(no_rollouts)
cr = one(nr, "ClusterRole", OP)
assert_workload_rule(cr["rules"], "no-rollouts ClusterRole", present=False)
assert_hardened(nr, "no-rollouts")

print("Chart check: RBAC rules, TokenRequest scope, stamp-root grant, hardening, args and env asserted structurally")
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
