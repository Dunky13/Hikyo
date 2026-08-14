# GitHub organization transfer handoff

Date: 2026-08-14

## Repository cutover

- Transferred `Dunky13/Hikyo` to `Hikyo-Org/Hikyo` without renaming it.
- Preserved GitHub repository ID `1316165429`, issues, pull requests,
  environments, and three active repository rulesets.
- Updated the canonical Git remote to
  `git@github.com:Hikyo-Org/Hikyo.git`.
- Replaced tracked personal-owner references with `Hikyo-Org` and changed the
  Go module path to `github.com/Hikyo-Org/hikyo`.
- Changed container and Helm coordinates to `ghcr.io/hikyo-org/hikyo` and
  `ghcr.io/hikyo-org/charts/hikyo`.
- Merged the protected-branch namespace cutover in
  [Hikyo-Org/Hikyo#127](https://github.com/Hikyo-Org/Hikyo/pull/127) as
  `33eadc5dc5b290ff5d70af269e8b7ca084fe6374`.

## Organization controls

- Organization-wide two-factor authentication is enforced.
- Default repository permission is `none`; non-owner repository, team, and
  Pages creation is disabled.
- GitHub Actions allows GitHub-owned actions plus the exact external actions
  used by Hikyo, with SHA pinning required.
- The default workflow token is read-only and cannot approve pull requests.
- GitHub's recommended code-security configuration is attached; Dependabot,
  secret scanning, and push protection remain enabled.

## Pages

- Bound the verified `hikyo.app` domain to the transferred repository.
- GitHub Pages reports `cname=hikyo.app`, HTTPS enforced, and protected-domain
  state `verified`.
- `https://hikyo.app/` returned HTTP 200 after the binding was applied.
- [Hikyo-Org/Hikyo#129](https://github.com/Hikyo-Org/Hikyo/pull/129)
  repaired the Pages artifact so `/.well-known/security.txt` is deployed and
  checked live.

## Validation

- Generated-code freshness, formatting, static analysis, docs, client, web,
  Helm, fixture, PostgreSQL, and full Go checks passed locally.
- The full Go suite passed 2,560 tests across 40 packages; Playwright passed
  104 desktop and mobile tests.
- The owner-namespace and delivery-path review found no blocking standards,
  specification, or security findings. Release and registry coordinates match
  their independent fixtures.
- GitHub Actions passed the exact GoReleaser, Cosign, Helm, CodeQL, full Go,
  PostgreSQL, and web/E2E gates before and after merge.

## Remote verification

- The Pages-repair baseline is
  `9bb4622fdb10bd46ec3fb928fddf3f08cca701d7`; main CI run `31807138041`
  and Pages run `31807138102` passed on that SHA.
- The canonical Pages site and live security policy passed, all three rulesets
  remain active, and the old personal repository URL redirects to the
  organization repository.
- No Hikyo organization container package exists yet; the next release will be
  the first publication under `ghcr.io/hikyo-org`.
