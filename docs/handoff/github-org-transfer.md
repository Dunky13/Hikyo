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
- Opened the protected-branch namespace cutover as
  [Hikyo-Org/Hikyo#127](https://github.com/Hikyo-Org/Hikyo/pull/127).

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

## Validation

- Generated-code freshness, formatting, static analysis, docs, client, web,
  Helm, fixture, PostgreSQL, and full Go checks passed locally.
- The full Go suite passed 2,560 tests across 40 packages; Playwright passed
  104 desktop and mobile tests.
- The owner-namespace and delivery-path review found no blocking standards,
  specification, or security findings. Release and registry coordinates match
  their independent fixtures.
- GoReleaser and Cosign are not installed locally, so their exact release gates
  remain delegated to GitHub Actions, the repository's source of truth.

## Remaining remote verification

- Merge the owner-namespace cutover through the protected `main` branch after
  exact-head CI passes.
- Verify the canonical Pages deployment, rulesets, package namespace, and old
  repository redirect after merge.
