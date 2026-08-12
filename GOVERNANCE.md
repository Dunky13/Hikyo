# Hikyo governance

Hikyo uses an honest BDFL model. The current maintainer set has one member,
Marc Went, who is the benevolent dictator for life (BDFL). If the maintainer
set grows, the BDFL retains final decision authority.

## Roles and powers

The maintainer set jointly holds merge authority, release authority,
security-response authority, and authority to amend this document. Release
authority and signing-key custody are one responsibility and are never split.

Maintainers are invited after sustained, high-quality contributions. Acceptance
includes organization 2FA and the review duties in `CONTRIBUTING.md`. A
maintainer may leave voluntarily or be removed by the BDFL for cause, including
security negligence or a breach of project trust.

## Continuity

Twelve consecutive months without maintainer response and without a designated
successor is abandonment. In that case, the stated intent is to archive the
repository instead of implying continued maintenance. The MPL-2.0 license and
this project's pledge allow a renamed fork to continue.

When a successor is designated, `GOVERNANCE.md` names them. Succession transfers
organization and disclosure-channel ownership. Signing authority moves by
re-keying under the recovery root, or by the documented out-of-band trust
bootstrap if that recovery root is unavailable. Plaintext private keys are never
handed to a successor.

No successor is currently designated.

## Conflicts of interest

A maintainer with a personal stake in a decision, including employment, a
competing or hosted offering, or paid work on a contribution, discloses it in
the issue or pull request before deciding. With one BDFL there is no honest
recusal quorum; disclosure in the permanent record is the control.

## Amendment procedure

A locked ADR, including the OSS mechanics decision that governs this document,
may be amended only by reopening its originating ticket, running the same
adversarial cross-model review that locked it, and recording the amendment in
the ADR itself. Amendments to this governance document follow that procedure.

Repository branch and tag protections are enforced and auditable. Organization-wide
2FA enforcement remains pending until the repository is transferred from its current
personal owner to a dedicated organization. Hikyo does not claim that control is
active before the transfer is complete and verified.

## Fully-open pledge

Every capability required to run Hikyo in production is and will remain open
source; there is no `/ee` directory and there will never be one.

This includes every functional and administrative outcome: running,
configuring, backing up, restoring, upgrading, and operating Hikyo, including
everything a hosted tenant could see or do. A future hosted service may schedule
and operate released open-source artifacts through documented public
interfaces. It may not contain an exclusive capability, policy engine, API,
recovery mechanism, tenancy control, or data transformation.

The MPL-2.0 license keeps modifications to existing files open. The pledge and
this public amendment procedure govern the wider no-open-core commitment.
