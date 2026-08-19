# Hikyo Compose demo

This stack proves the rendered `env_file` path against a real Hikyo server and
Docker Compose. From the repository root, run `scripts/compose-demo.sh`; the
script performs the operator journey end to end:

1. Start a loopback `hikyo server --dev`, create the local administrator, and
   establish its password and TOTP factor.
2. Create the keys and values, then publish them.
3. Mint a workload service account, grant it `read` on the environment, and
   write its credential to a mode-`0600` file.
4. Materialize the Compose and Hikyo configuration in a temporary project
   directory with the same literal, normalized absolute `runtime_dir`, then run
   `hikyo context create demo --instance <url>` and `hikyo compose render`.
5. Run `docker compose up`; the container receives every target value and
   prints its exact stored bytes as base64.

Hikyo applies Go `strings.TrimSpace` to every input before storing it. The demo
therefore compares delivered bytes with `TrimSpace(input)`, not with the raw
input. Its leading- and trailing-whitespace corpus entries prove that this trim
is the only transformation; all remaining stored bytes are delivered exactly.
Declarations use `allow_empty: true`, so an empty or whitespace-only input is
stored and delivered as an empty value after trimming.

The `${NAME:?message}` forms make Compose refuse an unset or empty generated
runtime path or stamp instead of silently starting stale containers. The
`format: raw` field prevents Compose from interpreting `$`, quotes, backslashes,
or surrounding whitespace. It requires Docker Compose 2.30.0 or newer.

Rendered plaintext exists only below `runtime_dir`, never in this worktree or
durable Hikyo state. Production should use tmpfs (`RuntimeDirectory=` under
systemd or `$XDG_RUNTIME_DIR`). The demo uses a temporary path below `/tmp`, so
`hikyo compose doctor` may report `runtime_not_tmpfs` on Linux hosts where
`/tmp` is persistent; the script accepts only that named finding.

Offline delivery is disabled by default. To opt in per stack, set
`snapshot.offline_serve: true`; the encrypted snapshot expires after at most
7 days. Every offline serve prints the exact warning
`serving stale from <issued_at RFC3339>, generation <stamp>`.
