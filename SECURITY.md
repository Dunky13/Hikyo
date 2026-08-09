# Security policy

Do not report vulnerabilities in public issues. Use GitHub Private Vulnerability
Reporting or, when GitHub is unavailable or inaccessible, the independently
hosted fallback address below.

## Reporting a vulnerability

1. Report privately through [GitHub Private Vulnerability Reporting](https://github.com/Dunky13/wenv/security/advisories/new).
2. If GitHub is unavailable or you cannot access it, email
   [security@developwent.io](mailto:security@developwent.io). This address is
   fallback-only so reports stay consolidated in the primary channel.
3. Include affected versions, impact, reproduction steps, and any known
   mitigations. Do not include secrets that are not needed to reproduce the
   issue.

Both channels are notification-tested quarterly. Accepting a report creates a
temporary private fix fork and grants the reporter access so remediation never
leaks through the public pull-request flow.

## Response targets

Reports are acknowledged within 7 days. Fix-release targets start when a report
is confirmed:

- critical: 14 days;
- high: 30 days; and
- medium or low: the next scheduled release.

These are targets for a solo maintainer, not guarantees. The disclosure clock
below is the reporter's backstop. Reporters are credited in the advisory unless
they opt out.

## Coordinated-disclosure embargo

The default embargo is 90 days from the report itself. The clock never waits on
acknowledgement. If acknowledgement is missed, reporters are expressly invited
to escalate through `security@developwent.io`; disclosure at the 90-day deadline
is legitimate regardless of maintainer response.

The embargo may be shortened by mutual agreement. Active exploitation
accelerates disclosure and remediation; it never extends the embargo. Extension
beyond 90 days requires mutual agreement for exceptional coordination on a
non-exploited issue and a revised hard deadline. If a reporter cannot be reached
at that deadline, the advisory is published on schedule.

The patched release is published before advisory details. Immediate mitigation
guidance, the fix, and the advisory are fast-tracked ahead of any milestone when
exploitation is active.

## Advisories and CVEs

A CVE is requested through the private GitHub advisory before publication. CVE
assignment is never release-blocking: an urgent fix may ship under its GHSA,
with the CVE added later. Duplicates use the existing CVE; a rejected request
leaves the GHSA as the canonical reference.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest patch release of the latest minor | Yes |
| All older stable releases | No |
| Prereleases | No |

The table is the concise form of the complete [support policy](./SUPPORT.md).
There are no backports or overlapping support windows.
