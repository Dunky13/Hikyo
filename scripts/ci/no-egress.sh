#!/usr/bin/env bash
# mvp-boundary O7 + ops-spec §13 / CI invariant 4: an instrumented boot+idle run
# of `hikyo server`, with NOTHING configured (no remotes, no recipients, no
# adapters, no IdPs), originates ZERO outbound connections and still boots and
# serves. strace records every connect(2); the run fails if any targets a
# non-loopback address. Loopback and AF_UNIX/AF_NETLINK connects are the local
# machinery (sqlite has none, but DNS-over-127.0.0.53 and the like are fine).
#
# Linux-only: it depends on strace and connect(2) tracing. Runs in CI, not on a
# developer's macOS box.
set -euo pipefail

command -v strace >/dev/null || { echo "no-egress: strace is required"; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"; [ -n "${pgid:-}" ] && kill -TERM "-${pgid}" 2>/dev/null || true' EXIT

bin="$work/hikyo"
go build -o "$bin" ./cmd/hikyo

port=47811
origin="http://127.0.0.1:${port}"
trace="$work/connect.log"
serverlog="$work/server.log"

export HIKYO_STATE_DIR="$work/state"
export HIKYO_DB="sqlite:$work/hikyo.db"
mkdir -p "$HIKYO_STATE_DIR"

# setsid so the whole strace+server tree shares one process group we can reap.
setsid strace -f -e trace=connect -o "$trace" \
	"$bin" server --dev --listen "127.0.0.1:${port}" >"$serverlog" 2>&1 &
child=$!
pgid="$(ps -o pgid= "$child" | tr -d ' ')"

# Boots and serves with outbound unavailable (CI invariant 4).
healthy=0
for _ in $(seq 1 60); do
	if curl -sf "${origin}/healthz" >/dev/null 2>&1; then healthy=1; break; fi
	sleep 0.5
done
if [ "$healthy" -ne 1 ]; then
	echo "no-egress: server never became healthy at ${origin}"
	sed -n '1,120p' "$serverlog" >&2
	exit 1
fi

# Idle, so a background poller or lazy dialer would have to reach out here.
sleep 3
curl -sf "${origin}/readyz" >/dev/null 2>&1 || true

kill -TERM "-${pgid}" 2>/dev/null || true
pgid=""
wait "$child" 2>/dev/null || true

# Any connect(2) to an AF_INET/AF_INET6 address that is not loopback is egress.
egress="$(grep -E 'connect\([0-9]+, \{sa_family=AF_INET6?,' "$trace" \
	| grep -vE '127\.0\.0\.[0-9]+|"::1"|::ffff:127\.' || true)"
if [ -n "$egress" ]; then
	echo "no-egress: an unconfigured boot+idle attempted outbound connections:"
	echo "$egress"
	exit 1
fi

count="$(grep -cE 'connect\([0-9]+, \{sa_family=AF_INET6?,' "$trace" || true)"
echo "no-egress: OK — booted, served, and originated 0 non-loopback connections (${count} loopback connect(2) calls seen)"
