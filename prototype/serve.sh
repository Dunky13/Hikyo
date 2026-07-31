#!/usr/bin/env bash
# Serve the prototypes hub. Binds 0.0.0.0 so LAN / Tailscale can reach it.
# ponytail: python stdlib http.server does the whole job — no deps, no framework.
set -euo pipefail
PORT="${1:-8642}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Serving $DIR on :$PORT"
echo "  local     http://localhost:$PORT/"
LAN=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)
[ -n "$LAN" ] && echo "  LAN       http://$LAN:$PORT/"
TS=$(command -v tailscale >/dev/null 2>&1 && tailscale ip -4 2>/dev/null | head -1 || true)
[ -n "$TS" ] && echo "  Tailscale http://$TS:$PORT/   (or http://$(hostname -s):$PORT/ via MagicDNS)"
echo "Ctrl-C to stop."
exec python3 -m http.server "$PORT" --bind 0.0.0.0 --directory "$DIR"
