# Handoff: #241 root auth and session-owned browser cache

Issue: https://github.com/Hikyo-Org/Hikyo/issues/241 (parent #205; programme
#203; audit ID `FE01-B`). Base: `4522f5f5fc7f30bcd79460f3ff11cb6352ec6e07`.

## Contract

- `AuthProvider` owns the exhaustive root states: checking, anonymous,
  authenticated, and transitioning. An authenticated state's `sessionEpoch` is
  the server-issued session id; principal and non-secret session metadata stay
  in memory only.
- Root `whoami` checks are deliberately outside TanStack. There is no public
  cache: every root QueryClient entry belongs to one anonymous or authenticated
  session epoch. New ids, logout, and expiry cancel old work, clear mutations,
  and destroy every query before the new epoch renders. A same-id assurance
  refresh preserves entries and invalidates their answers.
- Login, passkey login, step-up, logout, account-security changes, membership
  changes, and hierarchy/policy changes report session transitions to the root
  owner. Operation-specific 401 responses do not cause global logout; only a
  `whoami` 401 does. Mutation completions carry a root revision guard; a stale
  completion suspends and reconciles the cookie-authoritative identity.
- Tabs publish only the constant `session-changed` event over a
  `BroadcastChannel`. Focus and the earliest server-reported idle/absolute
  expiry recheck `whoami`. No token, principal, or session id enters the
  channel, localStorage, or sessionStorage.

## Coverage

- `AuthProvider.test.tsx` pins replacement isolation against a deferred old
  result, same-epoch cache preservation, expiry-to-anonymous reset, blocking
  focus replacement, and stale-mutation reconciliation.
- `shell.spec.ts` drives two tabs through one real browser-cookie login and
  logout, proving both tabs leave the obsolete route/cache epoch.
- Post-merge validation: 253 Vitest tests, TypeScript, production build, full
  desktop browser run (135 unaffected passes plus repaired settings 20/20),
  mobile shell 16/16, and mobile settings 20/20.
- Generated outputs: none.
