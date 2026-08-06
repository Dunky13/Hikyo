# GitHub REST API facts for the Actions deployment adapter

Date: 2026-08-06. Scope: verified facts (official GitHub docs only, URL per fact) needed by the Envweave GitHub Actions adapter design — Actions secrets/variables CRUD at repo/org/environment scope, limits, fine-grained PAT gating, rate limits, environments, GHES. Anything the docs do not settle is in the final "Ambiguities / unverified" section, not silently interpolated.

All endpoint facts from the versioned REST reference (`apiVersion=2022-11-28`): [secrets](https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28), [variables](https://docs.github.com/en/rest/actions/variables?apiVersion=2022-11-28), [deployment environments](https://docs.github.com/en/rest/deployments/environments?apiVersion=2022-11-28).

## 1. Actions secrets API

Write model is **client-side sealed-box encryption**: fetch the scope's public key, encrypt with libsodium, PUT ciphertext + `key_id`. Values are never readable back — list/get responses carry only `name`, `created_at`, `updated_at` (+ `visibility`/`selected_repositories_url` at org scope). ([secrets API](https://docs.github.com/en/rest/actions/secrets?apiVersion=2022-11-28))

| Operation | Repo | Org | Environment | Status |
|---|---|---|---|---|
| List | `GET /repos/{owner}/{repo}/actions/secrets` | `GET /orgs/{org}/actions/secrets` | `GET /repos/{owner}/{repo}/environments/{environment_name}/secrets` | 200 |
| Get (metadata only) | `.../actions/secrets/{secret_name}` | same shape | same shape | 200 |
| Public key | `GET .../actions/secrets/public-key` | `GET /orgs/{org}/actions/secrets/public-key` | `GET .../environments/{environment_name}/secrets/public-key` | 200; fields `key_id`, `key` (Base64) |
| Create/update | `PUT .../actions/secrets/{secret_name}` | same shape | same shape | **201 created / 204 updated** |
| Delete | `DELETE .../actions/secrets/{secret_name}` | same shape | same shape | 204 |

- **PUT body**: `encrypted_value` + `key_id`, both required (org adds required `visibility`, optional `selected_repository_ids`). The 201-vs-204 split is the free created/updated oracle for secrets.
- **Encryption**: libsodium sealed box — the official guide's examples use `crypto_box_seal` (Node.js) / `SealedBox` (Python/C#/Ruby) against the Base64-decoded public key ([Encrypting secrets for the REST API](https://docs.github.com/en/rest/guides/encrypting-secrets-for-the-rest-api?apiVersion=2022-11-28)).
- **Stale `key_id`**: no documented error/status anywhere (endpoint docs and encryption guide both silent). See Ambiguities.
- **Org visibility**: enum `all` | `private` | `selected`. With `selected`, access is limited to `selected_repository_ids`; membership managed via `GET/PUT /orgs/{org}/actions/secrets/{secret_name}/repositories` (PUT replaces the whole set, 204) and `PUT/DELETE .../repositories/{repository_id}` (204; **409 when the secret's visibility is not `selected`**).
- **Environment path shape**: **repo-name-based** — `/repos/{owner}/{repo}/environments/{environment_name}/...`. No `/repositories/{repository_id}/...` variant in the current docs (older docs used the repository-id shape; the current reference does not). `environment_name` must be URL-encoded ("any slashes in the name must be replaced with `%2F`").
- **Environment pre-existence**: the secrets endpoints only take an existing environment name; the API to create one is `PUT /repos/{owner}/{repo}/environments/{environment_name}` — "Create or update an environment", returns 200, 422 on invalid name or conflicting `deployment_branch_policy` flags ([environments API](https://docs.github.com/en/rest/deployments/environments?apiVersion=2022-11-28)). So the adapter can idempotently ensure-then-write, but environment creation needs a different permission than secret writes (§4).

## 2. Actions variables API

Symmetric to secrets minus encryption — and **values ARE readable back**: get/list response schemas include `value` (required, string, plaintext) at all three scopes. ([variables API](https://docs.github.com/en/rest/actions/variables?apiVersion=2022-11-28))

| Operation | Repo | Org | Environment | Status |
|---|---|---|---|---|
| Create | `POST /repos/{owner}/{repo}/actions/variables` | `POST /orgs/{org}/actions/variables` | `POST .../environments/{environment_name}/variables` | 201 |
| Update | `PATCH .../actions/variables/{name}` | same shape | same shape | 204 |
| Get/List | `GET .../actions/variables[/{name}]` | same shape | same shape | 200, includes `value` |
| Delete | `DELETE .../actions/variables/{name}` | same shape | same shape | 204 |

- **Create-on-existing (the conflict oracle)**: the REST docs document only 201 for POST — no conflict status is listed. **Observed behavior is 409 "Variable already exists"**, corroborated by GitHub's own `gh` CLI, which POSTs and on 409 falls back to PATCH with the code comment "Server will return a 409 if variable already exists" ([cli/cli `pkg/cmd/variable/set/http.go`](https://github.com/cli/cli/blob/trunk/pkg/cmd/variable/set/http.go)); same 409 reported against the environment-variables endpoint in [terraform-provider-github discussion #2328](https://github.com/integrations/terraform-provider-github/discussions/2328). Usable as a create-that-fails-on-existing oracle (never reads values), but the status code is *not contractually documented* — treat any 4xx on POST-create as "exists or invalid" and branch on the message defensively. See Ambiguities.
- **PATCH on a missing variable**: behavior undocumented (no 404 listed). See Ambiguities.
- **Env path shape**: repo-name-based, same `/repos/{owner}/{repo}/environments/{environment_name}/variables` pattern, same URL-encoding note.
- **Org visibility**: same `all`/`private`/`selected` enum + `selected_repository_ids` + `/repositories` sub-endpoints as secrets.
- **Name grammar & case** ([variables reference](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)): alphanumeric (`[a-z]`, `[A-Z]`, `[0-9]`) or underscore only; must not start with a number; must not start with `GITHUB_`; "case insensitive when referenced. GitHub stores secret names as uppercase" — i.e. `foo` and `FOO` collide.
- **Limits** (same reference): 48 KB per variable; **500 per repository**, **1,000 per organization**, **100 per environment**; combined org+repo variables available to one workflow run capped at **256 KB**.

## 3. Secrets limits

All from the [secrets reference](https://docs.github.com/en/actions/reference/secrets-reference):

| Limit | Value |
|---|---|
| Max secret size | 48 KB ("Secrets are limited to 48 KB in size"); larger payloads = documented workaround of storing an encrypted file in the repo and the passphrase as a secret ([using secrets guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)) |
| Count | 1,000 org secrets / 100 repo secrets / 100 environment secrets |
| Workflow visibility of org secrets | only "the first 100 organization secrets (sorted alphabetically)" when >100 exist |
| Name grammar | identical to variables: `[A-Za-z0-9_]`, no leading digit, no `GITHUB_` prefix, case-insensitive (stored uppercase) |
| Precedence | environment > repository > organization for same-named secrets |

## 4. Fine-grained PATs

Permission → endpoint mapping from [Permissions required for fine-grained PATs](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28):

| Endpoints | Permission (fine-grained) |
|---|---|
| `/repos/.../actions/secrets/*` (incl. public-key) | Repository **"Secrets"** — read for GET, write for PUT/DELETE |
| `/repos/.../actions/variables/*` | Repository **"Variables"** — read/write |
| `/repos/.../environments/{name}/secrets/*` AND `.../variables/*` | Repository **"Environments"** — read/write. NOT covered by Secrets/Variables permissions |
| `PUT/DELETE /repos/.../environments/{name}` (create/delete environment) | Repository **"Administration"** (write); GET environments is readable via Actions read |
| `/orgs/{org}/actions/secrets/*` | Organization **"Secrets"** — read/write (incl. `/repositories` sub-endpoints) |
| `/orgs/{org}/actions/variables/*` | Organization **"Variables"** — read/write |

Adapter consequence: a token that writes repo + environment secrets/vars needs **Secrets (write) + Variables (write) + Environments (write)**; auto-creating environments additionally needs **Administration (write)** — a much broader grant, so "environment must pre-exist" is a reasonable adapter stance to keep token scope minimal.

- **Org endpoints do work with fine-grained PATs** (org permission categories exist for them), but the token's resource owner must be that org, orgs may require approval ("your token will be marked as `pending` until it is reviewed by an organization administrator"), and a fine-grained PAT cannot "access multiple organizations at once" ([managing PATs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)). Other documented fine-grained gaps (Packages, Checks API, outside-collaborator repos) don't touch these endpoints.
- **Expiry**: fine-grained PAT lifetime is 1–366 days **or `none`** — "Infinite lifetimes are allowed but may be blocked by a maximum lifetime policy set by your organization or enterprise owner" (same page). So the adapter must expect both never-expiring tokens and org-mandated short lifetimes. Classic PATs: expiration optional; GitHub auto-deletes tokens unused for a year; org owners can restrict classic PAT access entirely.
- **Prefixes are contractual**: classic `ghp_`, fine-grained `github_pat_` (also `gho_`/`ghu_`/`ghs_`/`ghr_` for OAuth/App tokens) — documented in [GitHub's token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github). The adapter can distinguish token kinds client-side by prefix.

## 5. Rate limits

From [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28):

| Limit | Value |
|---|---|
| Primary, PAT-authenticated | **5,000 req/h** (15,000/h for OAuth/GitHub Apps owned by Enterprise Cloud orgs — not PATs) |
| Secondary: concurrency | max **100 concurrent requests** |
| Secondary: points | **900 points/min** per REST endpoint group; GET/HEAD/OPTIONS = 1 pt, POST/PATCH/PUT/DELETE = **5 pts** → mutation ceiling ≈ 180/min |
| Secondary: content creation | **80 content-generating requests/min, 500/h** |
| Secondary: CPU | 90 s CPU per 60 s real time |
| On limit | **403 or 429**; `retry-after` (seconds) when present wins; else if `x-ratelimit-remaining: 0`, wait until `x-ratelimit-reset` (UTC epoch seconds); else wait ≥1 min, then exponential backoff with a retry cap |

Mutation-burst best practice is explicit ([best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api?apiVersion=2022-11-28)): "make requests serially instead of concurrently" and "If you are making a large number of `POST`, `PATCH`, `PUT`, or `DELETE` requests, wait at least one second between each request." A sync pushing N secrets should therefore write serially at ≤1 req/s, honoring `retry-after` — no parallel PUT fan-out.

## 6. Environments

- **Plan availability** ([managing environments](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment), [environments API](https://docs.github.com/en/rest/deployments/environments?apiVersion=2022-11-28)): public repos — all plans ("Environments, environment secrets, and deployment protection rules are available in public repositories for all current GitHub plans"). Private repos — **GitHub Pro (user) / Team (org) or Enterprise required; Free gets none** ("Users with GitHub Free plans can only configure environments for public repositories"). Converting public→private on Free: "any configured protection rules or environment secrets will be ignored, and you will not be able to configure any environments." Some protection rules (e.g. wait timers, required reviewers on private repos) are Enterprise-gated on top of that. The adapter must expect environment endpoints to fail on Free-plan private repos and degrade to repo-level secrets.
- **Pre-existence**: environment secret/variable endpoints address an environment by name; creation is a separate API (`PUT /repos/{owner}/{repo}/environments/{environment_name}`, §1) behind Administration permission. Workflows referencing an unknown environment auto-create it, but "only repository admins can configure the environment."
- **Protection rules gate deployments, not secret writes**: "A job that references an environment must follow any protection rules for the environment before running or accessing the environment's secrets" — rules sit between *jobs* and secret *use*. Nothing in the environments or secrets docs applies protection rules to the REST write path; writing an environment secret via API needs only the Environments permission, no reviewer approval. (Docs state this only from the deployment side; see Ambiguities for the strictness caveat.)

## 7. GHES vs github.com (brief)

- Base URL: `http(s)://HOSTNAME/api/v3` instead of `https://api.github.com` ([GHES REST quickstart](https://docs.github.com/en/enterprise-server@3.17/rest/quickstart)); same endpoint paths after the prefix.
- Actions secrets and variables endpoints exist in current GHES REST docs (e.g. [GHES 3.13 variables](https://docs.github.com/en/enterprise-server@3.13/rest/actions/variables)) — no path differences for the endpoints in §1–§2. Variables require a GHES version that ships them (present throughout the currently supported 3.x line).
- Rate limits are **admin-configured** via the Management Console, so github.com's 5,000/h and secondary-limit numbers do not transfer ([GHES rate limit config](https://docs.github.com/en/enterprise-server@3.17/admin/configuring-settings/configuring-user-applications-for-your-enterprise/configuring-rate-limits)); the adapter should key off response headers, not hardcoded quotas.

## Ambiguities / unverified

1. **Variable POST-on-existing → 409 is undocumented.** The REST reference lists only 201 for the create endpoints. The 409 "Variable already exists" behavior is confirmed only by GitHub's `gh` CLI source (which relies on it) and user reports — GitHub could change it without a docs-visible break. If the design leans on it as a conflict oracle, pin the assumption with an integration test and treat unexpected 4xx as "possibly exists".
2. **Stale/wrong `key_id` on secret PUT**: no documented status code or error shape anywhere (REST reference and encryption guide both silent). Presumably a 4xx; the adapter should re-fetch the public key and retry once on any 4xx from a secret PUT, but the exact contract is unverified.
3. **PATCH on a nonexistent variable**: no documented error status (404 assumed, unverified).
4. **Secret PUT rejecting invalid names / oversize values**: no status codes documented for name-grammar or 48 KB violations on the API path (the grammar/limits are documented for the product, not as API error contracts).
5. **Protection rules vs. API secret writes**: the docs describe protection rules purely as deployment/job gates and document no restriction on REST secret writes — but they never affirmatively state "API writes bypass protection rules." Confirmed by omission only.
6. **Environment endpoints on Free-plan private repos**: the failure mode (status code) when calling environment secrets endpoints on an unsupported plan is not documented.
7. **GHES rate-limit defaults**: the GHES admin page documents configurability ("Enter limits ... or accept the prefilled default limits") but not whether API rate limiting is enabled out of the box.
8. **Historic repository-id-based environment paths**: the current API version documents only `/repos/{owner}/{repo}/environments/...`; older API versions used `/repositories/{repository_id}/environments/...`. Any statement about when the switch happened is not in the current docs — only the current shape is verified.
