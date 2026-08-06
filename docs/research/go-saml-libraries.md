# Go SAML Service Provider libraries — landscape research

**Date:** 2026-08-06
**Context:** Envweave 1.0 promotes SAML SP support. The human-auth ADR mandates composed single-purpose *proven* libraries ("known library means proven, not conveniently shaped"). Named attack class: XML signature wrapping (XSW). This document is research input for the build-vs-scope-reduce decision; it ranks options and deliberately makes no decision.
**Method:** Primary sources only — GitHub repos/API (release dates, commit history, contributor stats, go.mod of consuming products), GitHub Security Advisories, library source code (validation paths read directly), the Dec 2020 Mattermost coordinated disclosure, and Russell Haering's March 2026 SAML vulnerability research report.

---

## 1. Executive summary

- The entire Go SAML SP ecosystem rests on **one foundation**: `beevik/etree` (non-validating XML parser) + `russellhaering/goxmldsig` (XML-DSIG + C14N). There is no hardened alternative parser in use; nobody moved to libxml2 bindings.
- Go's `encoding/xml` **round-trip instability (CVE-2020-29509/29510/29511) was never fixed in the stdlib**. The Go team treats round-trip stability as out of scope. The ecosystem mitigation is `mattermost/xml-roundtrip-validator` (reject any document that mutates across a parse/serialize cycle) plus single-parse architectures on etree. Both major libraries adopted this — it is a mitigation, not a foundation fix, and it is still the state of the art in 2026.
- **Both major libraries have critical signature-bypass CVE history**, and gosaml2 shipped security fixes as recently as **March 2026** (unsigned LogoutRequest acceptance; CBC padding panic) and **August 2026** (unsigned LogoutResponse acceptance; XML token-flood cap). The v0.11.0 release notes admit assertion signatures inside a signed Response envelope "were skipped entirely, which could allow XML wrapping attacks" — an XSW-class fix landing in year 10 of the library's life.
- **Every serious Go product that ships SAML forks its library**: Grafana → `grafana/saml` (fork of crewjam), Teleport → `gravitational/saml` (fork of crewjam) + upstream gosaml2, Mattermost → `mattermost/gosaml2`. This is the ecosystem's revealed preference: upstream alone is not trusted at face value; vendors pin, patch, and self-audit.
- A meaningful set of respected Go products **refuse in-process SAML entirely** and tell users to bridge via an IdP broker: Pomerium, MinIO, oauth2-proxy (all OIDC-only), Gitea/Forgejo (no SAML shipped), Argo CD (embeds Dex as its bridge). This posture is normal and accepted in the self-hosted/k8s ecosystem.
- **Honest verdict up front:** by Envweave's "proven" standard, no Go SAML SP library qualifies unconditionally. crewjam/saml has the strongest *default* validation posture but a bus factor of 1 and slow cadence; gosaml2 has the most active 2026 security maintenance but a permissive-by-default API whose validation gaps are the integrator's problem. Both are viable only with a hardened wrapper, pinned versions, and independent review — or the ticket returns the scope-reduction (bridge) proposal.

---

## 2. Threat-model background

### 2.1 XML signature wrapping (XSW)

The named attack class. Attacker takes a validly signed assertion/response and relocates or duplicates elements so the signature check passes over one element while the application consumes another (unsigned or attacker-controlled) element. Root causes in practice: validating "a" signature instead of *the* signature covering the consumed element; processing multiple `<Assertion>` elements when only one was verified; Reference URI/ID mismatch between verification and extraction.

Concrete Go instances:
- **CVE-2022-41912** (crewjam/saml, critical): responses containing multiple `Assertion` elements bypassed authentication; fixed v0.4.9.
- **gosaml2 v0.11.0 (2026-03-18)**: assertion signatures within a signed Response envelope were previously "skipped entirely, which could allow XML wrapping attacks" — now verified when present. Related issue [#219](https://github.com/russellhaering/gosaml2/issues/219) ("Assertions signature is not verified when the response is signed", opened 2025-05-29) **is still open** as of 2026-08-06.

### 2.2 Dec 2020: Go encoding/xml round-trip instability (Mattermost joint disclosure)

Three stdlib CVEs — **CVE-2020-29509** (attribute instability), **CVE-2020-29510** (directive instability), **CVE-2020-29511** (element instability) — established that malformed XML *mutates* across a decode/encode cycle in Go's `encoding/xml`. Any SAML implementation that verified a signature on one serialization and extracted claims from another could be fed a document that is validly signed under one reading and attacker-controlled under the other.

Coordinated patches: Dex 2.27.0, crewjam/saml 0.4.3, gosaml2 0.6.0 (gosaml2's instance tracked as CVE-2020-29509 in GHSA-xhqq-x44f-9fgg, critical).

What each did about it, and the 2026 status:
- **The stdlib was never fixed.** The Go team declined to guarantee round-trip stability in `encoding/xml`; the semantics remain unstable by design.
- **Mattermost open-sourced `github.com/mattermost/xml-roundtrip-validator` (xrv)**: reject any input whose round-trip is unstable, before any SAML processing.
- **crewjam/saml** validates all XML input with xrv since v0.4.3 (it still parses with both `encoding/xml` and etree internally, so xrv is load-bearing).
- **gosaml2** depends on xrv (in go.mod today) and parses/validates on etree via goxmldsig — single-parse discipline plus round-trip rejection.
- **Verdict on the foundation:** the unstable stdlib parser is a *contained* problem, not a solved one. Containment depends on every input path going through xrv and no re-serialization between verification and extraction. That invariant is enforced by convention inside each library, not by types.

### 2.3 March 2026: Haering's systematic review

Russell Haering (gosaml2/goxmldsig author) published a research report ([gist, 2026-03-12](https://gist.github.com/russellhaering/f1a824c978b5083ea862a9eac6ecd096)) cataloguing 9 SAML attack classes across 60+ CVEs (XSW, round-trip, comment injection/canonicalization, multiple-assertion injection, signature bypass, replay, DoS, namespace differentials, open redirect/RelayState). The March 2026 gosaml2/goxmldsig releases (v0.11.0/v1.6.0), the two March 2026 GHSAs, and oss-fuzz integration all landed alongside it — i.e., the maintainer ran an adversarial pass over his own library ten years in and found real bugs. Credit for honesty; also evidence of how much was latent.

### 2.4 Other relevant classes in Go

- **Entity expansion / billion laughs:** largely N/A — Go's `encoding/xml` and etree do not process DTDs/custom entities. The actual DoS vectors were **deflate decompression bombs** on the Redirect binding (CVE-2023-28119 crewjam, fixed 0.4.13; CVE-2023-26483 gosaml2, fixed 0.9.0) and **XML token floods** (gosaml2 v0.12.0, 2026-08-05, adds `MaximumXMLTokens`, default 50,000).
- **Comment-in-NameID** (the 2018 Duo class, `user@corp.com<!---->.evil.com`): no published Go CVE. crewjam extracts text via `encoding/xml` chardata concatenation (immune to first-text-segment truncation); gosaml2 extracts via etree. Haering's report covers the class (verification/extraction divergence over comments); treat as reviewed-but-not-formally-proven in the Go libs.
- **Weak algorithms:** `goxmldsig` **still accepts RSA-SHA1 and ECDSA-SHA1 signatures on verification** (verified in `sign.go`/`xml_constants.go` on main, 2026-08): `signatureMethodsByIdentifier` includes the SHA-1 methods with no default rejection and no built-in allowlist knob. Rejecting SHA-1 is the integrator's job in both libraries.

---

## 3. Library-by-library

### 3.1 crewjam/saml (`github.com/crewjam/saml`)

**What it is:** the most widely used Go SAML library; SP *and* IdP implementations, HTTP middleware, metadata, Redirect/POST/Artifact bindings, encrypted assertions, partial SLO.

**Maintenance (as of 2026-08-06):**
- Tags `v0.5.0`/`v0.5.1` cut on commits dated 2025-04-12/14 (no GitHub releases at all — tags only, no release notes; the v0.5 bump is the golang-jwt v5 migration and cleanups).
- Last substantive commit on `main`: 2025-05-09. Repo `pushed_at` 2026-01-29 (branch activity). **84 open issues.** 1.1k stars.
- Contributor concentration: `crewjam` (Ross Kinder) 211 commits, next non-bot contributor 8. **Bus factor: 1.**
- Notable: an XML namespace-handling fix (#580, "Improper namespace application in elementToBytes") was **reverted** on 2025-04-14 — namespace serialization is still delicate territory.

**CVE/advisory history (complete for the GitHub Advisory DB):**

| ID | Severity | Class | Fixed |
|---|---|---|---|
| CVE-2020-27846 / GHSA-4hq8-gmxx-h6w9 | Critical | Signature verification bypass via XML round-trip instability (Dec 2020 joint disclosure); fix = xrv validation of all input | v0.4.3 |
| CVE-2022-41912 / GHSA-j2jp-wvqg-wc2g | Critical | Auth bypass via multiple `Assertion` elements (XSW-class) | v0.4.9 |
| CVE-2023-28119 / GHSA-5mqj-xc49-246p | High | DoS via deflate decompression bomb | v0.4.13 |
| CVE-2023-45683 / GHSA-267v-3v32-g6q5 | High | XSS via missing Binding syntax validation (SP-rendered HTTP responses) | v0.4.14 |

**Default validation posture (read from `service_provider.go`, main):** the strongest of the Go libraries — validation failures are hard errors.
- Signature: required on the Response **or** on each Assertion (unsigned envelope ⇒ every assertion must be signed); pluggable `SignatureVerifier`.
- `Destination`: must equal the URL the response was received at or the configured ACS URL (spec §3.4.5.2); may be omitted only on unsigned responses.
- `InResponseTo`: must match a tracked outstanding request ID (cookie-based `RequestTracker`, one-time use) — **unless** `AllowIDPInitiated` is set. **`AllowIDPInitiated` defaults to false**: IdP-initiated SSO is refused out of the box.
- Freshness: `IssueInstant` within `MaxIssueDelay` (90s default) on response and assertion; `NotBefore`/`NotOnOrAfter` with `MaxClockSkew` (180s default).
- Audience: enforced against the SP EntityID (`ValidateAudienceRestriction` overridable).
- Encrypted assertions: supported.
- **Gaps the integrator owns:** no assertion-ID replay cache (single use is enforced indirectly via one-time InResponseTo tracking — adequate only while `AllowIDPInitiated` stays false); SHA-1 signatures accepted on verification (goxmldsig); SLO support is partial and less exercised.

### 3.2 russellhaering/gosaml2 (`github.com/russellhaering/gosaml2`) + goxmldsig

**What it is:** SP-only SAML 2.0 implementation on etree + goxmldsig; POST binding response consumption, Redirect AuthnRequest generation, encrypted assertions, SLO decode/validate.

**Maintenance (as of 2026-08-06):**
- **The most active Go SAML project in 2026.** Releases: v0.9.0/v0.9.1 (Mar 2023), v0.10.0 (2025-03-20), **v0.11.0 (2026-03-18, security)**, **v0.12.0 (2026-08-05, security hardening — yesterday relative to this research)**. goxmldsig in lockstep: v1.5.0 (2025-03-20), v1.6.0 (2026-03-18), v1.6.1 (2026-08-04).
- oss-fuzz integration added in v0.11.0. Go 1.25 minimum.
- Contributor concentration: `russellhaering` 142 commits, next 23. **Bus factor: ~1** (though demonstrably engaged in 2026).
- 65 open issues, including open security-relevant issue #219 (see §2.1).

**CVE/advisory history (complete):**

| ID | Severity | Class | Fixed |
|---|---|---|---|
| CVE-2020-15216 / GHSA-5684-g483-2249 | Critical | Signature validation bypass — a valid signed response could be modified and still pass (via goxmldsig; found by jupenur) | v0.5.0 |
| CVE-2020-29509 / GHSA-xhqq-x44f-9fgg | Critical | Auth bypass via encoding/xml round-trip mutation (Dec 2020 joint disclosure) | v0.6.0 |
| CVE-2020-7731 / GHSA-prjq-f4q3-fvfr | High | Nil-pointer crash on malformed XML signatures | patched |
| CVE-2023-26483 / GHSA-6gc3-crp7-25w5 | Moderate | DoS via deflate decompression bomb | v0.9.0 |
| GHSA-pcgw-qcv5-h8ch (no CVE yet) | High (7.5) | **Unsigned `LogoutRequest` accepted even with signature validation enabled** — forged logout for any user (`ErrMissingSignature` fell through to processing the raw document root) | v0.11.0 (2026-03-18) |
| GHSA-hwqm-qvj9-4jr2 (no CVE yet) | High | CBC padding panic — unauthenticated process crash via crafted ciphertext | v0.11.0 (2026-03-18) |

goxmldsig's own advisory: CVE-2020-7711 (nil-deref crash on malformed signatures, High).

Additionally fixed without advisories: v0.11.0 verified assertion signatures inside signed envelopes (XSW-class, §2.1) and replaced `panic()` calls with errors; v0.12.0 rejects unsigned `LogoutResponse` and caps XML token counts.

**Default validation posture (read from `validate.go`, `retrieve_assertion.go`, `saml.go`, main):** *permissive by design* — this is the library's biggest liability for a security-critical integrator.
- **The WarningInfo footgun:** `RetrieveAssertionInfo` returns **success** with a `WarningInfo` struct the caller must inspect. **Audience mismatch (`NotInAudience`), Conditions time-window violations (`InvalidTime`), and `OneTimeUse` are warnings, not errors.** An integrator who checks only `err != nil` accepts assertions for other services and expired assertions. This is documented behavior, not a bug — and a recurring real-world integration failure.
- `Destination`: checked **only if present** — a response omitting `Destination` passes, signed or not (crewjam is stricter here).
- `InResponseTo`: **not validated at all**; no request-ID tracking exists. Consequently IdP-initiated and replayed-response flows are implicitly accepted unless the integrator builds tracking.
- No replay cache.
- Hard errors it does enforce: issuer (only if `IdentityProviderIssuer` configured), status = Success, SubjectConfirmation method = bearer, `SubjectConfirmationData.Recipient` == ACS URL, `SubjectConfirmationData.NotOnOrAfter` with `ClockSkew`.
- Signature: response-or-assertion signed required (with the 2026 fixes above); `SkipSignatureValidation` escape hatch exists.
- SHA-1 accepted on verification; no algorithm allowlist option.

### 3.3 russellhaering/goxmldsig — the foundation everything stands on

- XML-DSIG signing/verification over **etree**; implements the full C14N family in pure Go: Exclusive C14N 1.0 ± comments (with PrefixList), Canonical XML 1.0 (REC) ± comments, Canonical XML 1.1 ± comments (verified in `canonicalize.go`/`validate.go`). Canonicalization algorithm is taken from the signature's declared `CanonicalizationMethod` — there is no built-in pin to exclusive-C14N; a strict SP should reject non-exclusive methods itself.
- Used by **everyone**: crewjam/saml, gosaml2, Dex's SAML connector, zitadel/saml, Grafana, Mattermost, Teleport, HashiCorp cap. It is the single point of failure of the Go SAML ecosystem.
- CVE history: CVE-2020-7711 (nil-deref, High); CVE-2020-15216's root cause lived here too.
- SHA-1 verification accepted (see §2.4). Self-described as implementing "the subset of relevant standards needed" for SAML 2.0.
- Maintenance mirrors gosaml2 (same maintainer, lockstep releases, Aug 2026 current).
- **libxml2 / hardened-parser question:** answered — no Go SAML library uses libxml2 bindings (cgo) or any validating parser. etree (beevik, general-purpose, non-validating) + xrv + single-parse discipline is the 2026 state of the art. The foundation problem (§2.2) is contained, not solved.

### 3.4 HashiCorp cap/saml (`github.com/hashicorp/cap/saml`)

- HashiCorp's SP-only SAML package, built **on gosaml2 v0.11.0 + goxmldsig v1.6.0** (crewjam v0.4.14 used for metadata types) — go.mod verified. It exists precisely because raw gosaml2 defaults are insufficient: it wraps it with policy options (`ValidateResponseSignature()` / `ValidateAssertionSignature()`), follows the Kantara interoperable SAML deployment profile, Web Browser SSO profile only, HTTP-POST + HTTP-Redirect bindings.
- **No SLO at all** (verified: no logout code in the package) — deliberate subset.
- Backing: HashiCorp identity team; underpins Vault's SAML auth method (the consuming `vault-plugin-auth-saml` repo is not public — Vault Enterprise). MPL-2.0.
- Assessment: the best public example of the "hardened wrapper over gosaml2" pattern, and prior art for the exact subset Envweave would need. Still inherits the gosaml2/goxmldsig foundation and its March/August 2026 fix cadence (cap pinned v0.11.0 as of this research, i.e. without the v0.12.0 hardening).

### 3.5 zitadel/saml

- **IdP-side implementation, not an SP** ("A SAML 2.0 server (IdP) implementation written for Go"). Backed by ZITADEL, active (v0.4.1 Oct 2025, pushed Jul 2026), uses goxmldsig + amdonov/xmlsig. No response encryption, no artifact binding. **Not a candidate for Envweave's SP role** — listed to close the question.

### 3.6 RobotsAndPencils/go-saml

- **Archived 2023-11-15. Dead.** CVE-2023-48703 (High: trusts cryptographic keys embedded in the document — a textbook signature-validation sin) and CVE-2020-36563 (SHA-1 signatures). Disqualified; listed for completeness.

### 3.7 The vendor forks (what production actually runs)

| Fork | Of | Status | Why it exists |
|---|---|---|---|
| `grafana/saml` | crewjam/saml (v0.4.15 base) | Active — last commit 2026-07-24 ("Tweak IdP-initiated flows") | Grafana Enterprise SAML; upstream cadence too slow, they patch and dependency-bump themselves |
| `gravitational/saml` (`v0.4.15-teleport.2`) | crewjam/saml | Pinned via go.mod replace in Teleport | Teleport carries its own patches on top of v0.4.15; also uses upstream gosaml2 v0.11.0 |
| `mattermost/gosaml2` | russellhaering/gosaml2 | Active — 2026-03-24 CBC fix ported, configurable deflate-bomb protection, AES-GCM support | Mattermost controls its own security patch latency (they ran the 2020 disclosure) |

The pattern is unambiguous: **at production scale, nobody consumes these libraries un-forked and un-audited.**

---

## 4. Default-validation matrix

What each library enforces by default (hard error) vs leaves to the integrator. "⚠" = returned as warning or silently skipped.

| Check | crewjam/saml | gosaml2 | cap/saml (wrapper) |
|---|---|---|---|
| Signature required (response or per-assertion) | ✅ | ✅ (post-2026 fixes) | ✅ policy-driven |
| Assertion sigs inside signed envelope verified | ✅ | ✅ since v0.11.0 (issue #219 still open) | inherits gosaml2 |
| Audience restriction | ✅ hard error | ⚠ `WarningInfo.NotInAudience` | ✅ |
| Destination | ✅ (must match; omitted only if unsigned) | ⚠ only checked if present | inherits |
| Recipient (SubjectConfirmationData) | ✅ | ✅ | ✅ |
| InResponseTo | ✅ tracked, one-time, required unless IdP-initiated enabled | ❌ not validated | integrator |
| NotBefore/NotOnOrAfter + skew | ✅ (180s skew) | ⚠ Conditions violations → `WarningInfo.InvalidTime`; SubjectConfirmationData bound is hard | ✅ |
| Response freshness (IssueInstant) | ✅ 90s | ❌ | — |
| Replay cache (assertion IDs) | ❌ (indirect via one-time InResponseTo) | ❌ | ❌ |
| IdP-initiated SSO refusable | ✅ refused by default | ❌ implicitly accepted (no InResponseTo check) | configurable |
| Reject RSA-SHA1 | ❌ | ❌ | ❌ (goxmldsig accepts) |
| Pin exclusive C14N | ❌ (honors declared method) | ❌ | ❌ |
| Decompression bomb cap | ✅ since 0.4.13 | ✅ since 0.9.0 + token cap in 0.12.0 | inherits |
| Round-trip (xrv) validation | ✅ | ✅ | inherits |
| Encrypted assertions | ✅ | ✅ (CBC panic fixed v0.11.0) | ✅ |

Integrator burden regardless of library: replay cache, SHA-1 rejection, C14N pinning, metadata refresh safety (fetch over TLS, signature/pinning of IdP metadata, no auto-trust of new keys), RelayState open-redirect protection.

---

## 5. Who ships what (production users, 2025/2026)

| Product | SAML SP library | Notes |
|---|---|---|
| Grafana | `grafana/saml` fork of crewjam + goxmldsig v1.6.0 | Enterprise-only feature; OSS users bridge via Keycloak/Dex |
| Mattermost | `mattermost/gosaml2` fork v0.10.0 + goxmldsig v1.6.0 | Ran the 2020 disclosure; maintains xrv |
| Teleport | `gravitational/saml` fork (crewjam v0.4.15 base) + gosaml2 v0.11.0 | Both stacks in-tree |
| Vault (SAML auth method, Enterprise) | `hashicorp/cap/saml` → gosaml2 v0.11.0 | Closed-source plugin over public wrapper |
| Sourcegraph | crewjam v0.4.14 + gosaml2 v0.9.1 (public snapshot; stale versions) | Both stacks |
| Dex | goxmldsig directly (own connector logic) | Connector unmaintained, deprecation candidate |
| Pomerium | **none** | OIDC-only by design |
| Gitea / Forgejo | **none shipped** | SAML PR long-open, never merged |
| MinIO | **none** | OIDC + AD/LDAP only; docs point at Keycloak/Dex |
| oauth2-proxy | **none** | OIDC-only |
| Boundary | **none** | OIDC/LDAP/password |

No serious Go product was found consuming an unpatched upstream at current versions with default settings. The two live upstreams are effectively single-maintainer projects whose largest consumers maintain private/public forks.

---

## 6. The alternative: no in-process SAML (IdP-bridge posture)

Delegate SAML to a broker the customer already runs (or deploys alongside), so Envweave speaks only OIDC:

- **Keycloak** — mature SAML↔OIDC brokering (Java; the most battle-tested SAML implementation available to self-hosters). The standard recommendation for Grafana OSS, MinIO, oauth2-proxy users needing SAML.
- **ZITADEL, Authentik** — actively maintained self-hostable brokers with SAML federation; fit Envweave's self-hosting audience.
- **Dex** — the canonical embed (Argo CD ships it for exactly this purpose), **but its SAML connector is unmaintained and a deprecation candidate; Dex's own docs steer users to OIDC/LDAP**. Dex is prior art for the *pattern*, not a recommendable SAML bridge in 2026.

Prior art for refusing native SAML: Pomerium, MinIO, oauth2-proxy, Boundary, Gitea/Forgejo (§5). Reception: fully normalized in the self-hosted/k8s world — the friction is not technical but commercial (the enterprise "SAML support" checkbox). Argo CD's Dex-embed shows a middle road: ship a bridge as a deployment detail rather than linking SAML into the trusted process. For a secrets manager specifically, keeping XML parsing and signature validation out of the trusted process entirely is a defensible security argument, not a cop-out — the March/August 2026 fix stream demonstrates the attack surface is still yielding bugs.

Cost: one more container for customers whose IdP can't emit OIDC directly; SAML-attribute → OIDC-claim mapping is broker config the docs must own; "SAML supported via bridge" needs honest framing in sales/README.

---

## 7. Protocol subset needed for SP-only

If built in-process, the defensible 1.0 subset is:

- **SP-initiated Web Browser SSO only**: HTTP-Redirect binding for outgoing AuthnRequest, HTTP-POST binding for incoming Response. This is what cap/saml ships and what virtually every IdP (Okta, Entra, Google, Keycloak) supports.
- **SP metadata endpoint** (static XML: EntityID, ACS URL, WantAssertionsSigned=true, signing cert).
- **IdP metadata ingest**: manual upload/pinned URL; treat metadata as trust-root configuration (admin action), not auto-refreshed background fetch.
- **Refuse IdP-initiated SSO** (crewjam default; must be built for gosaml2).
- **Skip SLO.** Commonly skipped (cap/saml omits it entirely); it is where gosaml2's 2026 vulnerabilities lived (unsigned LogoutRequest/LogoutResponse); its security value for a session-cookie SP is marginal — local logout suffices.
- **Skip artifact binding** (crewjam has it; almost never required).
- **Require signing; treat encrypted assertions as optional-accept** (support exists in both libs, but decryption paths produced the CBC panic bugs — if accepted, pin to GCM where the IdP allows).
- **Reject SHA-1 signature/digest algorithms and non-exclusive canonicalization** in the wrapper, since no library does it for you.

---

## 8. Verdicts (per option, no decision)

**Ranking for Envweave's standard — "proven, not conveniently shaped", XSW as the named threat:**

### Option A — crewjam/saml, pinned fork, hardened config — *best in-process option*
- **For:** strongest secure-by-default validation of any Go lib (hard errors on Destination, InResponseTo, audience, freshness; IdP-initiated refused by default); xrv since 2020; complete advisory history with credible fixes; the library Grafana and Teleport chose to fork rather than abandon.
- **Against:** bus factor 1; no formal releases (bare tags); last substantive commit May 2025; 84 open issues; a namespace-handling fix reverted in 2025; SHA-1 accepted; no replay cache; the fork-first behavior of its biggest users is itself the verdict on consuming upstream directly.
- **Honest posture:** viable **only** as a pinned fork (Envweave-owned or tracking grafana/saml), with a wrapper adding SHA-1 rejection + C14N pinning + replay cache, and an adversarial review of the response-parsing path before 1.0.

### Option B — gosaml2 + goxmldsig behind a cap/saml-style strict wrapper — *most active, most footguns*
- **For:** only Go SAML project with 2026 security releases, fuzzing, and a maintainer who published a 60-CVE adversarial self-review; Mattermost/Teleport/Vault sit on it; cap/saml is a public blueprint for the hardened wrapper.
- **Against:** permissive-by-default API is disqualifying without a wrapper (audience/time violations are *warnings*; Destination optional; InResponseTo unvalidated; IdP-initiated implicitly accepted); XSW-class and unsigned-SLO fixes landing in **2026** show validation logic was still wrong ten years in; issue #219 still open; bus factor ~1.
- **Honest posture:** use only via hashicorp/cap/saml or an equivalent Envweave wrapper that turns every warning into an error and adds InResponseTo tracking + replay cache. Raw gosaml2 fails Envweave's bar outright.

### Option C — hashicorp/cap/saml directly
- **For:** HashiCorp-backed hardened wrapper, deployment-profile-driven, Vault-adjacent pedigree, exactly the SP-only/no-SLO subset Envweave needs.
- **Against:** thin public track record outside Vault; inherits the entire gosaml2/goxmldsig risk surface (and lagged on v0.12.0 hardening at research time); signature policy is options-driven — misconfiguration is still possible; MPL-2.0 to note.
- **Honest posture:** the strongest "composed single-purpose library" story on paper; still transitively rests on a single-maintainer DSIG core.

### Option D — no in-process SAML: OIDC-only + documented IdP-bridge (scope reduction)
- **For:** removes XML parsing, DSIG, and canonicalization from a secrets manager's trusted process entirely; the only option with no unproven dependency; strong prior art (Pomerium, MinIO, oauth2-proxy, Boundary, Gitea; Argo CD's embedded-bridge variant); aligns with the ADR's rejection of conveniently-shaped dependencies.
- **Against:** enterprise-checkbox friction; pushes a Keycloak/ZITADEL/Authentik deployment onto customers; Dex — the lightest embed — has an unmaintained SAML connector, so the bridge recommendation must name heavier brokers.
- **Honest posture:** the only option that is unambiguously *proven* by Envweave's standard.

### Disqualified
- **zitadel/saml** — IdP-side, not an SP.
- **RobotsAndPencils/go-saml** — archived, CVE-2023-48703 (trusts embedded keys).
- **Dex-as-library or Dex SAML connector** — unmaintained, deprecation candidate, docs call SAML unsafe.

### Landscape verdict
By the human-auth ADR's definition of *proven*, **no Go SAML SP library qualifies unconditionally in 2026.** The ecosystem is two single-maintainer projects on one shared DSIG core, with critical-severity validation bypasses fixed as recently as March 2026 and an XSW-adjacent issue still open; every at-scale consumer forks and self-audits. In-process SAML is *achievable* (Options A–C, each with a mandatory hardening wrapper and review budget), but it cannot be honestly represented as composing a proven library — it is adopting a liability and managing it. The scope-reduction path (Option D) is the only one that meets the standard as written; whether the enterprise checkbox justifies carrying Options A–C's residual risk is the decision this document deliberately does not make.

---

## Sources

- GitHub Advisory Database queries for `crewjam` and `gosaml2` (advisory IDs inline above)
- [GHSA-pcgw-qcv5-h8ch — unsigned LogoutRequest](https://github.com/russellhaering/gosaml2/security/advisories/GHSA-pcgw-qcv5-h8ch); [GHSA-hwqm-qvj9-4jr2 — CBC padding panic](https://github.com/advisories/GHSA-hwqm-qvj9-4jr2); [GHSA-5684-g483-2249 — CVE-2020-15216](https://github.com/russellhaering/gosaml2/security/advisories/GHSA-5684-g483-2249); [GHSA-xhqq-x44f-9fgg — CVE-2020-29509](https://github.com/russellhaering/gosaml2/security/advisories/GHSA-xhqq-x44f-9fgg); [GHSA-4hq8-gmxx-h6w9 — crewjam XML processing](https://github.com/crewjam/saml/security/advisories/GHSA-4hq8-gmxx-h6w9); [GHSA-j2jp-wvqg-wc2g — CVE-2022-41912](https://github.com/advisories/GHSA-j2jp-wvqg-wc2g)
- [Mattermost coordinated disclosure: Go XML round-trip vulnerabilities (Dec 2020)](https://mattermost.com/blog/coordinated-disclosure-go-xml-vulnerabilities/)
- [Russell Haering, "Comprehensive SAML Security Vulnerability Research Report" (2026-03-12)](https://gist.github.com/russellhaering/f1a824c978b5083ea862a9eac6ecd096)
- GitHub API: repo/tag/release/commit/contributor data for crewjam/saml, russellhaering/gosaml2, russellhaering/goxmldsig, zitadel/saml, RobotsAndPencils/go-saml, grafana/saml, mattermost/gosaml2 (retrieved 2026-08-06)
- Source reads (main branches, 2026-08-06): `gosaml2/validate.go`, `retrieve_assertion.go`, `saml.go`, `decode_response.go`, `go.mod`; `goxmldsig/validate.go`, `canonicalize.go`, `sign.go`, `xml_constants.go`; `crewjam/saml/service_provider.go`
- go.mod of grafana/grafana, mattermost/mattermost, gravitational/teleport, sourcegraph/sourcegraph-public-snapshot, dexidp/dex, hashicorp/cap/saml, pomerium/pomerium, go-gitea/gitea
- [gosaml2 v0.11.0](https://github.com/russellhaering/gosaml2/releases/tag/v0.11.0) and [v0.12.0](https://github.com/russellhaering/gosaml2/releases/tag/v0.12.0) release notes; [gosaml2 issue #219](https://github.com/russellhaering/gosaml2/issues/219)
- [hashicorp/cap/saml README](https://github.com/hashicorp/cap/tree/main/saml); Argo CD user-management docs (Dex bridge); Dex documentation on SAML connector status; MinIO external-IAM docs (OIDC-only)
