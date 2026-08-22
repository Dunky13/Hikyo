# Handoff: #256 public-address dialer

Issue: https://github.com/Hikyo-Org/Hikyo/issues/256 (parent #207; programme
#203; audit ID `BE21-A`).

## Contract

- `netpolicy.PublicDialer` owns resolver, every-answer address validation,
  allowed-CIDR exceptions, exact-address dialing, validated-address fallback,
  and per-connection policy rechecks.
- Mixed public/non-public answers fail before any socket opens. IPv4-mapped
  answers are canonicalized before CIDR checks and dialing; IPv6 answers retain
  bracketed host-port form.
- Forgejo and GitHub Actions use the shared dialer while retaining their own
  TLS minimum, request deadline, redirect refusal, and explicit no-proxy policy.
- An opaque forward proxy changes the first-hop address seen by `DialContext`.
  `PublicDialer` therefore makes no claim about the proxy's ultimate target.

SAML metadata keeps its existing proxy-aware pinned-request round tripper. That
boundary needs the complete validated address set to preserve fallback and to
send an approved IP in CONNECT; reducing it to `DialContext` would either lose
that property or incorrectly validate only the proxy hop. Issue #257 owns its
guarded fetch seam and can adopt the shared dialer for compatible direct dials
without moving redirect or response policy into `netpolicy`.

Generated outputs: none.

## Regression evidence

- Netpolicy fixtures cover mixed answers, IPv4/IPv6 exact pinning, fallback,
  allowed private CIDRs, IPv4-mapped answers, per-connection rebinding checks,
  pre-dial and successful-dial cancellation, invalid policy inputs, and
  incomplete dependency refusal.
- Adapter parity tests pin TLS 1.2 minimum, provider-specific redirect refusal,
  no opaque/ambient proxy, true private-CIDR exceptions, exact pinned addresses,
  and mixed-answer refusal before either provider opens a socket.
- Existing adapter, SAML, and isolation behavior remains green.

## Validation

```text
go test -count=1 ./internal/service/... -run SAML                16 passed
go test -count=1 ./internal/isolation/ -run SAML                  6 passed
go test -race -count=1 ./internal/netpolicy/... ./internal/adapter/...
                                                                  128 passed
go vet ./...                                                      passed
go test -count=1 ./...                         3379 passed in 58 packages
```

## Review

Two-axis review round 1 found invalid CIDRs were skipped, cancellation could
return a just-opened connection, and adapter parity evidence did not exercise
the guarded path. Those findings produced constructor-time config validation,
connection cleanup around cancellation, and deterministic provider fixtures.
Round 2 on the exact corrected snapshot returned Standards `CLEAN` and Spec
`SOUND`, with no unresolved or critical new findings.
