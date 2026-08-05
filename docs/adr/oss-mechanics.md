# Envweave OSS project mechanics (ADR, locked 2026-08-05)

Context: the license decision ([#9](https://github.com/Dunky13/envweave/issues/9)) fixes Apache-2.0, DCO-not-CLA as a principle, and the public "no /ee" commitment as a positioning asset; the threat model ([#8](https://github.com/Dunky13/envweave/issues/8)) fixes mandatory maintainer security review for crypto/auth/adapter/delivery contributions, protected branches, and maintainer 2FA; the architecture ADR ([#22](https://github.com/Dunky13/envweave/issues/22)) fixes the supply-chain trust model (offline cosign key-pair signing the checksum manifest and image digests, pinned trust root, fail-closed installers, digest-pinned chart, full-commit-SHA-pinned toolchains and CI actions, SBOM per release); the API/CLI ADR ([#25](https://github.com/Dunky13/envweave/issues/25)) fixes that the compatibility freeze fires at the first *stable* SemVer release and that prerelease tags freeze nothing; the deployment-adapter ADR ([#28](https://github.com/Dunky13/envweave/issues/28)) and K8s ADR ([#19](https://github.com/Dunky13/envweave/issues/19)) fix the only two extension points (in-tree adapters behind the Go seam; the ESO provider path post-freeze). What those ADRs delegated here is the human machinery around them: **where the project lives, how the repository is shaped, how contributions and disclosures arrive, how releases are cut and signed by an actual person, who governs, and how a future hosted service is structurally prevented from corrupting the open-source edition.** This ADR fixes those.

Granularity note: this ADR fixes process and structure, not artifact content. The spec document set's contents → synthesis ([#27](https://github.com/Dunky13/envweave/issues/27)); what is in the first release → MVP boundary ([#26](https://github.com/Dunky13/envweave/issues/26)); CI pipeline steps and exact pinned action SHAs → implementation under #22's rules. A delegation satisfied in letter but violating an intent stated here reopens this ADR.

## Canonical home — GitHub, in an organization, no public mirror

**The canonical repository is Envweave's GitHub organization repository.** The repository currently sits in a personal namespace (`Dunky13/envweave`); **transfer into a dedicated GitHub organization is a fixed implementation step of this ADR**, because a load-bearing enforcement claim depends on it: GitHub cannot enforce collaborator 2FA on a personal repository — only an organization can require 2FA of all members. GitHub redirects the old URL after transfer, so the move is cheap now and only gets more expensive.

The owner's standing bias is self-hosted Forgejo — and it does not apply, because the bias is about *his* infrastructure and this decision is about *contributors'*. A public project lives where its contributors, issue reports, and security researchers already are. GitHub supplies, at zero build cost, three things this ADR depends on by name: Private Vulnerability Reporting (§ Disclosure), CVE assignment via GitHub-as-CNA, and the Actions runners that build (but never sign — § Ceremony) the artifacts.

**There is no public mirror — but there is a private backup, because "it's just git" understates what lives on GitHub.** A git push migrates refs; it does not migrate issues, PR discussion, releases and their assets, advisory history, PVR state, rulesets, or permissions. A scheduled job exports the repository — git refs plus the API-exportable metadata (issues, PRs, releases, repository configuration) — encrypted, to the maintainer's own infrastructure. The export is a disaster-recovery artifact, not a mirror: it is not public, not synced-to-be-browsed, and carries no contributor-facing promises. A migration runbook (where the backup restores to, what is lost) lives with it in `docs/release/`.

*Rejected: Forgejo canonical + GitHub mirror.* Dogfoods self-hosting at the cost of splitting issues, PRs, and advisories across two systems — the mirror becomes where contributors knock and nobody answers.

*Rejected: GitHub canonical + Forgejo read-only public mirror.* A sync channel with failure modes, maintained for a statement the README pledge (§ Governance) makes better in one sentence.

## Repository shape — one repo, one tag, one ceremony

**Everything ships from a single repository with a single Go module:**

```
cmd/envweave/        # multicall entry point (server/operator/migrate/client verbs, #22)
internal/            # all Go packages — nothing importable by third parties
web/                 # SPA (Vite), embedded via embed.FS at build (#22)
chart/               # Helm chart, released as an OCI artifact from the same tag
deploy/compose/      # reference Compose files (#18)
docs/                # adr/, spec/, user/, operator/, release/, research/ (§ Documentation)
prototype/           # frozen wayfinding prototypes (kept; not release material)
```

The load-bearing property is **one tag = one ceremony**: a release tag produces the binary, the image, and the chart together, and one offline signing pass (§ Ceremony) covers all of them. A separate chart repository would put the chart outside the ceremony — either it gets its own key (second custody problem) or it ships unsigned (hole in the fail-closed installer story) — and introduces version skew between chart and image that #22's digest-pinning rule exists to prevent.

**One version, everywhere, by table.** A release version `X.Y.Z` (or `X.Y.Z-rc.N`) maps normatively: git tag `vX.Y.Z` = binary's reported version = image tag = chart `version` = chart `appVersion`; the image is additionally addressed by its index digest and the chart pins that digest (#22). **No artifact of a release exists without the complete set, and no artifact is ever rebuilt under an already-used version** — a changed byte is a new patch release. Prereleases carry the `-rc.N` suffix in every position and are unsupported (§ Releases).

**Tags are immutable by ruleset.** Branch protection does not protect tags, so the repository carries a `v*` tag ruleset: creation restricted to the maintainer role, update and deletion forbidden, no bypass actors including administrators. The ceremony (§ Ceremony) additionally refuses to run for a version that has ever been used and verifies the tagged commit is reachable from `main`.

`internal/` is a statement, not a habit: Envweave is a product, not a library, and no Go API is a compatibility surface. The frozen surfaces are `/api/v1` and the CLI (#25) — nothing else. This keeps the SemVer promise (§ Releases) meaning exactly what #25 says it means, with no accidental third-party importers to break.

*Rejected: SPA in a separate repository.* Kills the `embed.FS` single-artifact property #22 fixes.

## Contribution model

**DCO, enforced fail-closed by a full-commit-SHA-pinned CI check** (#22's pinning rule — "digest-pinned" is the image vocabulary; Actions pin by commit SHA). Every commit in a PR must carry `Signed-off-by`, and an unsigned commit blocks merge — no maintainer override path, because an override path is how "mandatory" decays into "usually".

**The DCO evidence is the PR's commit history, not the merge commit.** GitHub's squash-merge message is repository-configurable, defaults to the PR body for multi-commit PRs, and is editable by the merger — so a trailer in the squashed commit on `main` is not guaranteed and is not the record. The record is the commits as submitted in the PR, which GitHub retains with the PR after squash; the CI check runs against exactly those commits, before merge. Squash merge stays the default for what it buys — linear history, one commit per change, one revert unit — with merge commits reserved for the rare series whose intermediate states are individually meaningful.

**PR flow:** fork → PR against `main`. `main` is protected by a ruleset that states its semantics rather than gesturing at "protection": PRs required (no direct pushes), named status checks required against the current head, approvals dismissed as stale on new pushes, force-push and deletion forbidden, **empty bypass list — the rules apply to administrators**. Organization-level 2FA enforcement covers every member (§ Canonical home).

**Security-sensitive paths and the honest solo-maintainer limit.** CONTRIBUTING.md names the #8 list — cryptography, authentication, deployment adapters, delivery paths — and every **contribution** touching them requires maintainer review, no exceptions; with one maintainer as the only merger, that review is structural. What a solo maintainer *cannot* have is independent review of his own changes: GitHub does not let an author approve their own PR, so a required-approval setting would deadlock every maintainer-authored change. The ADR states this honestly instead of claiming an enforcement that cannot exist: **maintainer-authored changes merge on CI green without independent human review until a second maintainer exists**, at which point required approvals turn on for the security-sensitive paths and the gap closes. The compensating control meanwhile is the project's standing practice of adversarial cross-model review for security-relevant changes — a real check, honestly not equivalent to an independent human maintainer, and not presented as one.

**Issue-first for large changes.** CONTRIBUTING.md states the rule: open an issue and get maintainer agreement before writing a large PR. A rejected large PR costs the contributor a week and the project the contributor; the issue costs an evening.

**Issue templates: bug report, feature request, blank — and deliberately no security template.** A template still opens the public issue composer, where a reporter can type the vulnerability into a public issue. Instead, `.github/ISSUE_TEMPLATE/config.yml` carries a `contact_links` entry that routes "Report a security vulnerability" directly to the private-reporting URL, so the chooser offers no public path for it.

**Dev setup is one command** (owner's standing pattern), documented in CONTRIBUTING.md and kept working by CI running it from scratch.

*Rejected: merge queue / bors.* Coordination machinery for a contributor volume the project does not have; add when merge conflicts between concurrent PRs are a weekly event.

## Security disclosure

**GitHub Private Vulnerability Reporting is the primary channel; SECURITY.md is the contract.**

- **Channel:** PVR enabled on the repository — private reports, private fix forks, no triage infrastructure to build. **One independently-hosted fallback is published beside it** (an owner lean reversed by review: PVR alone makes GitHub an availability and access single point of failure for exactly the reports that matter most): a monitored security contact address on the maintainer's own domain, listed in SECURITY.md and served at `/.well-known/security.txt`, stated explicitly as fallback-only so triage stays consolidated in PVR.
- **CVE:** requested through the GitHub advisory (GitHub is a CNA) **while the advisory is still private**. Assignment is GitHub-reviewed and can lag, so it is **never release-blocking**: an urgent fix ships with the GHSA advisory alone, and the CVE id is amended in when it arrives.
- **Embargo:** coordinated disclosure, 90-day default from acknowledged report, shortened by mutual agreement. **Active exploitation accelerates, never extends**: immediate mitigation guidance to users, fix and advisory fast-tracked ahead of any milestone. Extension beyond 90 days happens only by mutual agreement for exceptional coordination needs on a *non-exploited* issue, with a revised hard deadline; a reporter who cannot be reached at deadline gets the advisory published on schedule.
- **Response contract in SECURITY.md:** acknowledgement within 7 days; the supported-versions table (§ Releases); reporters credited in the advisory unless they opt out.
- **Publication order:** patched release first, then advisory details. The fail-closed installer story (#22) means users who update get the fix before the details are public.

## Releases — SemVer, milestone-driven, latest minor only

**Versioning is SemVer, and `1.0.0` is a load-bearing tag:** it is the first stable release, and per #25 it *is* the API and CLI compatibility freeze. Everything before it is `0.x` — prerelease tags freeze nothing, breaking changes are free, and the version number says so honestly. `1.0.0` is cut when, and only when, the MVP acceptance criteria (#26) pass; the version is a gate, not a date.

**Cadence is milestone-driven, not calendar-driven.** After 1.0: patch releases on demand (security fixes fast-tracked — § Disclosure), minor releases when accumulated features justify a ceremony. A solo maintainer who promises a monthly train will miss one, and a broken release promise costs more trust than no promise.

**The support policy is executable, not a slogan.** Supported: **the latest patch release of the latest minor of the latest major — one version.** Security fixes land there and only there. The previous minor is end-of-life the day a new minor ships — stated in the release notes that ship it, not discovered later. Prereleases are never supported. A consequence stated plainly: an urgent security fix may require a feature-bearing minor upgrade to receive, because there are no backport branches; the upgrade path (single binary, goose roll-forward migrations per #22) is deliberately kept cheap enough that this is a reasonable ask. Response commitment is the § Disclosure contract — acknowledgement and fast-tracked fixes — not an unbounded "always" from a project with one maintainer; the continuity limit is governed in § Governance.

LTS is a named future decision with a trigger: a maintainer team large enough to fund backports, not before.

*Rejected: latest-two-minors.* Doubles the backport surface for a v1 user base that does not yet exist.

## Signing — custody, ceremony, rotation, compromise

#22 fixes the trust model: offline cosign key-pair, pinned trust root, fail-closed installers. This ADR fixes the humans and, where review found the envelope short, extends it — **two declared refinements to #22**: the chart digest joins the signed set, and the trust root grows a recovery key.

**What is signed — the chart is inside the envelope.** The signing pass covers the **release manifest**: source commit, binary checksums, image index digest, **chart digest**, and SBOM hashes, bound together in one signed document, plus cosign signatures on the image and chart OCI digests themselves. An unsigned chart would be the hole in the fail-closed story — a replaced chart swaps the image digest it pins and every workload it templates. Official install paths verify the chart signature before Helm processes it.

**Custody.** The cosign key-pair is generated on the maintainer's workstation with the network interface disabled for the generation and every subsequent decryption — "offline key" is a statement about *when plaintext exists*, not a consecrated machine. The private key is stored age-encrypted on **two USB sticks in separate physical locations**; the passphrase lives in the maintainer's password manager. Decryption happens to memory-backed storage only (tmpfs), never a disk path that backup, snapshotting, or indexing can see; the signing scratch directory is excluded from all three by the runbook, and swap on the signing workstation is encrypted. **CI never holds, sees, or uses the signing key** — a CI secret is exfiltratable by anyone who can run a workflow, which is exactly the contributor population.

**A second key exists: the recovery root.** Same custody scheme, separate passphrase, stored on separate media from the primary, **used for exactly one thing**: signing trust-metadata updates — rotation statements and revocations. Verifiers pin both public keys from day one. This is what makes compromise recovery *reachable* (below) instead of aspirational.

**Drills and loss.** Once a year, and before each first-use-after-storage-change, the runbook exercises restore-decrypt-sign-verify from each USB copy. The runbook also fixes the loss procedures: lost key or lost passphrase → the recovery root signs a rotation to a fresh primary; lost recovery root while the primary is healthy → primary signs a statement introducing a new recovery root; both lost → the out-of-band path below, honestly a new-trust-bootstrap event. Maintainer incapacity is § Governance.

**Ceremony** (runbook at `docs/release/signing.md`, executed per release):

1. CI builds the tagged artifacts and publishes checksums and digests as a draft. The ceremony refuses to start unless the tag is a never-before-used version reachable from `main`.
2. The maintainer pulls the artifacts and recomputes hashes locally. **This is a consistency check, not independent validation**: it proves the manifest matches the artifacts, not that the pipeline was honest — a compromised pipeline produces malicious artifacts with matching hashes. That residual is #8's accepted compromised-CI risk, restated here rather than laundered into a verification claim. Reproducible-builds verification (rebuild from the tagged commit in a pinned environment, compare byte-for-byte) is the named upgrade that would close it; it is not claimed for v1.
3. The maintainer decrypts the key (network off, tmpfs), signs the release manifest and the image and chart digests, re-encrypts, and verifies cleanup. Plaintext exists only for this step.
4. Signatures are uploaded; the maintainer verifies the *published* artifacts — registry digests and release assets as the world sees them — match the signed manifest before flipping the release public.

**Rotation binds keys to release ranges — no ambiguous window.** A routine re-key publishes a trust-metadata update signed by the *old* primary: old key's validity **ends at a named cutoff release**, new key's begins at its activation release. The old public key is retained by verifiers for releases at or below the cutoff — historical verification — and accepted for nothing newer, so the "transition window" in which two keys can sign new releases does not exist. Trust metadata carries a monotonic version; verifiers refuse metadata older than the highest seen.

**Compromise is the recovery root's moment, and the limit is stated honestly.** A compromised primary gets a revocation signed by the **recovery root** — not by anything the compromised key endorses — published through the repository, release notes, and advisory (§ Disclosure). Verifiers that pin the recovery root refuse the revoked key from the moment they see the metadata. What no design can do is push that knowledge into an installer that never fetches trust metadata: **an existing verifier that has not received the update continues to trust the revoked key until its user acts.** The advisory therefore always carries the manual re-pin instruction, and the fail-closed property means a verifier that *has* updated refuses everything signed by the revoked key. If both primary and recovery root are compromised together, trust re-bootstraps out-of-band; the runbook says so rather than pretending the chain survives every failure.

*Rejected: hardware token (YubiKey).* Stronger at rest, but a single physical token is a single point of failure for the release pipeline, and cosign+PIV adds ceremony friction a solo maintainer will be tempted to script away. Named upgrade once there are two maintainers to hold two tokens.

*Rejected: threshold/split custody.* No second custodian exists; a threshold scheme among one person is theatre.

## Governance — honest BDFL, with continuity

**GOVERNANCE.md states the truth: a single maintainer holds decision authority.** No committee language, no foundation cosplay — governance documents that describe a structure the project does not have are a species of the silent fallback the code standards forbid. The document fixes, concretely:

- **Roles and powers.** The maintainer set holds, jointly: merge authority, release authority (which *is* signing-key custody — the two are never split), security-response authority, and GOVERNANCE.md amendment authority. While the set has one member, that member is the BDFL and ties don't exist; if it grows, the BDFL retains final say and the document says so plainly.
- **Maintainership** is by invitation after sustained quality contributions; acceptance includes the security obligations (#8: org 2FA, review duties on the sensitive paths). **Removal**: voluntary resignation, or by the BDFL for cause (security negligence, trust violation) — stated now, while it is hypothetical, because writing a removal rule during a dispute is how projects die.
- **Continuity.** Twelve months of maintainer non-responsiveness with no designated successor is the named abandonment condition; the stated intent — recorded so it is *someone's* to execute — is that the repository be archived rather than left implying maintenance, and that the pledge and license permit any fork to continue under a different name (§ Trademark). A designated successor, when one exists, is named in GOVERNANCE.md and receives custody per the § Signing loss procedures.
- **Amending locked decisions.** A locked ADR (this one included) is amended only by reopening its ticket, running the same adversarial cross-model review that locked it, and recording the amendment in the ADR itself — the wayfinding rule, made permanent governance.
- **Repository enforcement**: the § Contribution ruleset semantics and organization 2FA are stated as *enforced, auditable settings*, not aspirations.

**Trademark: a separate one-page policy (`TRADEMARK.md`), not a governance paragraph.** It names the mark's owner (the maintainer, personally, until a legal entity exists), and draws the line precisely: nominative use is always fine ("works with Envweave", "fork of Envweave"); unmodified redistribution and compatibility statements are fine; **what requires permission is offering a hosted or packaged service under the Envweave name or confusingly-similar branding** — the point is preventing confusion about what is official, and forks are free to thrive renamed. Apache-2.0's code freedoms are unaffected and the policy says so.

**The no-/ee pledge is published twice, deliberately.** The full text lives in GOVERNANCE.md; a short named section in the README carries the one-sentence version — *every capability required to run Envweave in production is and will remain open source; there is no /ee directory and there will never be one* — with a link to the full text. The README is where evaluators decide whether to invest an afternoon; a pledge they cannot see from there is positioning value left on the table (#9 fixed the pledge as exactly that asset).

## Documentation — markdown in-repo now, site at 1.0

```
docs/adr/        # locked ADRs (exists)
docs/spec/       # the #27 handoff set
docs/user/       # concepts, environment-matrix UI, CLI usage
docs/operator/   # install (Compose, K8s), backup/restore, hardening, runbooks (#32)
docs/release/    # signing ceremony + custody runbooks, release checklist, backup/migration runbook
docs/research/   # wayfinding research summaries (exists)
```

Documentation is **markdown in the repository, reviewed through the same PR flow as code**. GitHub's rendering is sufficient while the audience is contributors and early adopters. A generated documentation site (Starlight or mkdocs-material on GitHub Pages) is **deferred with an explicit trigger: it ships with 1.0**, when there are users to read it — building a site during spec churn is polish applied before the surface stops moving.

*Rejected: wiki.* Divorced from PR review; drifts from the code it describes with no diff to catch it.

## Plugin system — no, and the presumption is confirmed

**v1 ships no plugin or extension system, and this is now a recorded decision, not a presumption.** #28 already fixes the principle — *pluggable means interface-neutral, never runtime-loaded* — and a plugin system would reverse a locked ADR. The extension points are exactly the two the upstream ADRs name:

1. **New deployment adapters land in-tree**, as contributions through the Go seam (#28), under mandatory security review (#8). An adapter is trusted server code; the review requirement is the trust boundary.
2. **The ESO provider path** (#19), post-API-freeze, as the named Kubernetes extension route.

**Revisit trigger:** multiple concrete third-party adapter demands that cannot reasonably land in-tree (licensing conflicts, proprietary provider SDKs, maintainer bandwidth). Until that trigger fires, "we should have a plugin API" is speculation, and the answer is the seam.

## Hosted-service coexistence — the self-hoster test

The map's scope guard: a hosted offering is out of scope, but must not be *precluded*. This ADR fixes the coexistence rule, and fixes it as a **decidable test**, because "operations, never features" alone is not one — backups and upgrades *are* capabilities, and a proprietary control plane around the same binary could produce hosted-only outcomes without touching core:

> **The self-hoster test:** every functional and administrative outcome — running, configuring, backing up, restoring, upgrading, and operating Envweave, including everything a hosted tenant can see or do — must be achievable by a self-hoster using only released open-source artifacts and documented public interfaces. Hosted-side code may *schedule and operate* those public interfaces; it may never contain an exclusive capability, policy engine, API, recovery mechanism, tenancy control, or data transformation.

The mechanisms by which open-core arrives anyway, each closed by name:

- **No cloud-only feature flags in core.** A flag whose enabled branch only the hosted service exercises is /ee with extra steps.
- **No CLA, ever — and the claim is stated at its true width.** DCO means contributors keep their copyright, so the maintainer cannot unilaterally relicense *contributed* work — the specific lever a relicense-style pivot needs. What DCO does **not** do is legally prevent open-core: Apache-2.0 permits proprietary derivatives, and nothing stops new proprietary code beside old open code. The pledge's real enforcement is **governance, not law**: the no-/ee commitment plus the self-hoster test, amendable only through the § Governance locked-decision procedure — a public, deliberate, reviewable act, not a quiet drift. Structurally *hindered* and publicly *staked*, not legally impossible; the ADR says which.
- **Multi-tenancy is already core** (map principle: multi-tenant single installation), so a hosted service needs no fork to be a service.

Nothing here builds the hosted service or commits to one; it fixes the constraint any future one must satisfy.

## What this ADR binds

- **#26 (MVP boundary):** `1.0.0` is gated on its acceptance criteria; the plugin-system confirmation recorded here feeds its presumptively-out list.
- **#27 (synthesis):** the license & governance document in the handoff set synthesizes #9 + this ADR; the spec set lands under `docs/spec/`.
- **#22 (architecture), two declared refinements:** the chart digest and SBOM hashes join the signed release manifest; the pinned trust root becomes primary + recovery keys. Both extend #22's envelope without weakening any claim it makes.
- **Implementation:** organization transfer, rulesets (branch + tag), PVR enablement, security.txt, DCO check, issue-template `config.yml`, CONTRIBUTING.md, GOVERNANCE.md, SECURITY.md, TRADEMARK.md, the backup/migration job, and `docs/release/signing.md` are all implementation artifacts of this ADR, buildable without further decisions.
