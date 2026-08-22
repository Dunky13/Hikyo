# Handoff: #240 explicit SPA route policy

Parent #205, programme #203, frontend slice FE01-A.

## Contract

`web/src/app/navigation.ts` is now the single authoritative route registry.
Every entry declares both its access mode and chrome mode through a closed
discriminated union:

| Access mode | Chrome | Anonymous behavior |
|---|---|---|
| `public` | `none` | Render the route |
| `ceremony` + `establish-or-reuse` | `none` | Render login in place, preserving ceremony state |
| `ceremony` + `required` | `none` | Follow the authenticated fallback to `/login` |
| `authenticated` | `shell` | Follow the authenticated fallback to `/login` |

The registry constructor rejects duplicate ids and paths, invalid access/chrome
combinations, ceremony routes without an explicit session policy, and
chromeless routes placed in sidebar navigation. `SurfaceId`, anonymous routes,
shell routes, and signed-in chromeless routes are derived from this registry.
The old manually maintained `SurfaceId`, `CHROMELESS_IDS`, and `CHROMELESS`
lists are gone.

## Migration

- `/login` and `/workspace/callback` are public and chromeless.
- `/reauth/cli` and `/workspace/approve` are chromeless establishment
  ceremonies. They retain their state-bearing URL while login renders.
- Every other current route is authenticated and renders in the shell.
- Route URLs and component ownership are unchanged.

The browser parity checks pin anonymous authenticated-route redirects, live
session login redirects, and anonymous CLI/workspace ceremony behavior. During
the mobile run, the existing shell scroll container failed the accessibility
rule for keyboard-focusable scroll regions. Making `main#content` focusable
also gives the skip link a valid target; the isolated dark/light reproductions
and both exact CI-shaped browser projects pass with that campsite fix.

## Generated outputs

None. This slice changes handwritten TypeScript, tests, and this handoff only.

## Validation

- `pnpm --dir web exec vitest run src/app/navigation.test.ts e2e/registry.test.ts`: 22 passed.
- `pnpm --dir web run typecheck`: passed.
- `./scripts/ci/build-spa.sh --verify`: 24 files, 255 tests, typecheck, and production build passed.
- Playwright desktop with a fresh fixture: 142 passed, 1 intentional skip.
- Playwright mobile with a fresh fixture: 143 passed.

