-- +goose Up
-- Multi-instance: the directory tier and the workspace tier (#71,
-- multi-instance ADR). Roll-forward only: no Down section by policy.
--
-- The ADR's architecture in one sentence: an instance holds named REMOTE
-- entries and renders a directory of the instances they name, fetched
-- server-to-server under a metadata-scoped credential; and a browser may
-- operate a remote's data DIRECTLY, as the human, under a session the REMOTE
-- issues. No server ever proxies, stores or sees another instance's secret
-- values, which is why there is no table here that could hold one.
--
-- Sides. Four of these tables belong to the VIEWING side (it holds remotes
-- and their snapshots) and three to the SERVING side (it mints connections,
-- allowlists origins and issues workspace sessions). Every instance may be
-- both — the relationship is per-direction and symmetric, and there is
-- deliberately no "main" flag anywhere in this schema. An instance that has
-- no rows in `remotes` shows no directory and performs zero outbound
-- connections; the air-gap posture is unchanged by construction.
--
-- Classes. `instance_identity` and `remotes`/`remote_snapshots` are
-- `class=instance`: instance-scope configuration and foreign structure at
-- rest, read only through proofs evaluated on `instance-directory`. The other
-- three are `class=authn` for the reason 00005 and 00014 both state —
-- resolving WHO a caller is cannot itself run under a proof, because the
-- proof is what the answer produces. An instance-connection credential and a
-- workspace handoff both resolve at the same chokepoint as authorize(), and
-- the origin allowlist is consulted at handoff issuance, which is
-- pre-authentication.
--
-- hikyo:table instance_identity class=instance chain=-
-- hikyo:table remotes class=instance chain=-
-- hikyo:table remote_snapshots class=instance chain=-
-- hikyo:table instance_connections class=authn chain=-
-- hikyo:table workspace_origins class=authn chain=-
-- hikyo:table workspace_handoffs class=authn chain=-
-- hikyo:table sessions_rebuilt class=authn chain=-

-- The instance's own identity: a server-generated opaque id, minted HERE
-- because migration is init, and preserved by backup/restore for the reason
-- the ADR gives — a restored instance IS the instance.
--
-- It is returned ONLY in the authenticated directory listing, never pre-auth:
-- the meta endpoint's closed allowlist (version, API revision, protocol
-- capabilities) does not carry it and must not grow to. That is what makes
-- self-connection detectable at the authenticated fetch rather than guessable
-- from outside, and it is why a URL that later comes to resolve to this
-- instance fails loud at fetch time instead of rendering the instance as its
-- own remote.
--
-- Single row, like `credential_policy` and `auth_instance_state`, for the
-- same reason: there is exactly one instance, and a table that could hold two
-- would need a rule about which one wins.
CREATE TABLE instance_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    identity TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

-- Minted by the migration rather than by a boot mint site. Boot's system
-- proof set is closed by invariant 11 and growing it would reopen the
-- tenant-isolation ADR for a value that has exactly one correct moment to
-- come into existence: the moment the schema does.
INSERT INTO instance_identity (id, identity, created_at)
VALUES (
    1,
    'ins_' || lower(hex(randomblob(16))),
    strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')
);

-- A connection entry: this instance's named pointer at another one. Git's
-- mental model is the intended reading, and `remote` is the CLI noun.
--
-- URL AND PIN ARE IMMUTABLE. There is deliberately no UPDATE statement
-- anywhere naming either column, and no `remote edit` verb: re-pointing a
-- stored credential at a different host is the credential-redirect attack the
-- API/CLI ADR closed for CI contexts — whoever can edit the URL of an entry
-- holding a valid credential redirects that credential to an attacker's
-- validly-certificated server. Re-pointing is remove + add, which re-runs the
-- full ceremony including the human fingerprint confirmation. `name` is the
-- one mutable field.
--
-- `spki_pin` is base64(sha256(SubjectPublicKeyInfo)) — the HPKP construction
-- the CLI's local trust store already uses, over the public key rather than
-- the certificate, so an ordinary certificate renewal does not break a pin.
-- It is verified on EVERY connection before any request is written.
--
-- `credential_sealed` is WRITE-ONLY after storage: sealed under the instance
-- keyring, never re-displayable through any surface, and leaving the process
-- only inside TLS to the pinned remote. It is a BLOB and not a bearer
-- verifier because this side must PRESENT the value, not recognise it — the
-- recognising half lives in `instance_connections` on the serving instance.
CREATE TABLE remotes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    spki_pin TEXT NOT NULL,
    credential_sealed BLOB NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

-- The last-known snapshot, one row per entry, destroyed with it.
--
-- Two clocks, deliberately separate. `last_attempt_at`/`last_outcome` record
-- what happened on the most recent fetch; `observed_at` and the listing
-- columns record the most recent SUCCESS. That split is the whole point of
-- the freshness model: an unreachable remote serves its last-known listing
-- MARKED STALE WITH ITS AGE ("unreachable 2h — last known state shown"),
-- never silently as current, and a credential rejection is a distinct loud
-- state from unreachability because the operator's fix differs.
--
-- The listing columns are nullable together or not at all — an entry that has
-- never succeeded has no listing, and a zero-count "listing" would be a claim
-- about a fetch that never returned. The CHECK makes the pairing total over
-- ALL SIX success columns, not three of them: a row carrying a listing but a
-- NULL version or a NULL count decodes to "" and 0, which reads as a peer that
-- said it runs no version and holds no organisations. That is a fabricated
-- claim about a fetch, and the CHECK is where it is refused.
--
-- The second CHECK ties `last_outcome = 'ok'` to the presence of a listing in
-- ONE direction only. A success must have observed something; a FAILURE may
-- still carry the last successful listing, because preserving it is exactly
-- what "unreachable 2h — last known state shown" is made of. The converse
-- refusal — a failure path writing the outcome 'ok' over a stale listing — is
-- enforced in Go at RecordFetchFailure, where the caller and its intent are
-- visible.
--
-- This is foreign structure at rest: instance-scope rows holding identity,
-- names and counts, and NOTHING VALUE-BEARING — there is nothing value-
-- bearing for it to hold, because the credential that produced it may read
-- nothing else. It is not encrypted beyond the database's own posture, and
-- pretending it were secret material would misstate the boundary.
CREATE TABLE remote_snapshots (
    remote_id TEXT PRIMARY KEY REFERENCES remotes (id) ON DELETE CASCADE,
    last_attempt_at TEXT NOT NULL,
    last_outcome TEXT NOT NULL CHECK (
        last_outcome IN (
            'ok', 'unreachable', 'credential-rejected', 'pin-mismatch',
            'redirect-refused', 'identity-conflict', 'self-connected'
        )
    ),
    observed_at TEXT,
    instance_identity TEXT,
    version TEXT,
    org_count INTEGER,
    project_count INTEGER,
    listing TEXT,
    CHECK (
        (
            observed_at IS NULL AND instance_identity IS NULL AND version IS NULL
            AND org_count IS NULL AND project_count IS NULL AND listing IS NULL
        )
        OR (
            observed_at IS NOT NULL AND instance_identity IS NOT NULL AND version IS NOT NULL
            AND org_count IS NOT NULL AND project_count IS NOT NULL AND listing IS NOT NULL
        )
    ),
    CHECK (last_outcome <> 'ok' OR observed_at IS NOT NULL)
);

-- The serving side's instance connection: the machine principal that
-- represents "some other installation may read my directory listing", TOGETHER
-- WITH its one credential.
--
-- Principal and credential are ONE ROW because the ADR makes them one unit:
-- `remote-credential create` mints both with a stable immutable id, there is
-- one credential per principal EVER, and `revoke` kills the credential and
-- retires the principal with it. Two tables would have admitted an orphan
-- principal and a re-armed revoked one, both of which the lifecycle exists to
-- prevent. Rotation is a new create, never a second row here.
--
-- It is beside, not inside, the service-account taxonomy: instance-owned,
-- mintable only under `instance-config`, with none of #17's project-ownership
-- or subtree-confinement rules applying. That is why it is not a
-- `service_accounts` row — that table's kind CHECK admits only workload and
-- automation, and its composite FK demands a project this principal has not
-- got.
--
-- Confinement is DOUBLE and neither half lives here. The grant API caps the
-- principal at exactly `instance-directory` (domain.machineAllowlists); the
-- artifact-eligibility matrix caps the CREDENTIAL to the directory-serve
-- operation alone (internal/authz/eligibility.go). Capability confinement
-- alone would not confine the credential: a future operation whose formula
-- accepted `instance-directory` would widen every existing token without any
-- grant changing.
--
-- `label` names the intended peer for the audit trail. It is descriptive, not
-- enforced — the serving instance cannot verify who holds the token, and does
-- not pretend to.
CREATE TABLE instance_connections (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE REFERENCES principals (id),
    label TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('hikyo-token')),
    verifier BLOB UNIQUE,
    prefix_hint TEXT NOT NULL,
    lifetime TEXT NOT NULL CHECK (lifetime IN ('finite', 'indefinite')),
    expires_at TEXT,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    CHECK (
        (lifetime = 'finite' AND expires_at IS NOT NULL)
        OR (lifetime = 'indefinite' AND expires_at IS NULL)
    ),
    CHECK (kind <> 'hikyo-token' OR verifier IS NOT NULL)
);

-- The origin allowlist: a remote's explicit consent list of exact UI origins
-- whose browsers may perform the handoff and call its API cross-origin.
--
-- EXACT origins. No wildcards, no subdomain matching — the primary key is the
-- origin string itself, so an inexact entry is unrepresentable rather than
-- merely discouraged.
--
-- It names UI ORIGINS, not instances, deliberately: what is being trusted is
-- precisely the code served at that origin, which is the true trust statement
-- and the thing an admin must be able to point at when auditing why
-- cross-origin access exists.
--
-- What it gates, precisely: handoff issuance (the redirect_uri authority and
-- the transaction's origin binding) and browser readability (CORS echoes only
-- a matching origin, without credentials mode). It is NOT bearer
-- authorization — CORS controls what a browser may read, not what a token may
-- do. The server-side half is what carries the rest: workspace session rows
-- are bound to their requesting origin, and deleting a row here atomically
-- revokes every session bound to it, which is what makes de-allowlisting a
-- real kill switch rather than a headers change.
CREATE TABLE workspace_origins (
    origin TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

-- The handoff transaction: short-lived, single-use, server-side, on the
-- issuing (remote) instance. The human-auth ADR's own transaction pattern,
-- carried to the browser edition of the RFC 8252 shape — the front channel
-- carries code and state ONLY, never the artifact.
--
-- Every transaction binds state, the exact callback URI, the requesting
-- origin, the PKCE challenge (S256), the purpose, and the target human once
-- authenticated.
--
-- A STEP-UP transaction binds three more things, and the bindings are what
-- stop an elevated consent being replayed: the initiating workspace session
-- id, the exact operation being elevated, and — where the operation is
-- key-scoped, per the locked ceremony content the remote's own UI uses — the
-- environment and the enumerated key set. An ESTABLISHMENT transaction binds
-- none of them: purpose alone licenses issuance, and there is no prior
-- session to name.
--
-- `state_verifier` and `code_verifier` are stored as verifiers, not values,
-- for the same reason every other bearer in this schema is: both cross a
-- redirect. `code_verifier` is NULL until approval, because a transaction
-- that has not been approved has issued no code.
--
-- `consumed_at` is the single-use mechanism, set in the same transaction that
-- reads the row. Expiry is in minutes.
CREATE TABLE workspace_handoffs (
    id TEXT PRIMARY KEY,
    state_verifier BLOB NOT NULL UNIQUE,
    code_verifier BLOB UNIQUE,
    origin TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('establishment', 'step-up')),
    session_id TEXT,
    operation TEXT,
    env_id TEXT,
    key_set TEXT,
    principal_id TEXT REFERENCES principals (id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    CHECK (
        (purpose = 'establishment' AND session_id IS NULL AND operation IS NULL)
        OR (purpose = 'step-up' AND session_id IS NOT NULL AND operation IS NOT NULL)
    )
);

CREATE INDEX workspace_handoffs_expiry ON workspace_handoffs (expires_at);

-- The workspace session is a SESSION ROW, not a new artifact class with a
-- parallel lifecycle. The ADR is explicit: it is a server-side session row on
-- the issuing instance "in every locked mechanical respect" — opaque bearer,
-- fast-hash verifier, artifact type, idle and absolute clocks, assurance
-- record, generation binding — differing from a browser session only in
-- TRANSPORT (an Authorization header, never a cookie) and in two added bound
-- fields.
--
-- Reusing the row type is therefore not a shortcut, it is the requirement:
-- explicit revocation, grant-change and generation invalidation, credential
-- epoch, account disablement and restore inertness all apply to a workspace
-- session because they apply to `sessions`, and a parallel table would have
-- had to re-implement every one of them and would drift from the original the
-- first time one changed.
--
-- sqlite cannot alter a CHECK constraint in place, so the table is rebuilt to
-- widen `artifact` and to add the two bound fields. The rebuild is why this
-- statement block exists at all; nothing else about the table changes.
--
-- POSTGRES REBUILDS IT TOO, identically, and could have got away with three
-- ALTERs. It does not, because the cross-engine directive-parity lint requires
-- every `hikyo:table` directive to exist on both engines: a temporary table on
-- one side only is a build failure. Paying twenty lines of postgres DDL to
-- keep one schema account rather than two is the cheaper of the two costs.
--
-- IN-FLIGHT REAUTHENTICATION WINDOWS DO NOT SURVIVE THIS MIGRATION. `reauth_windows`
-- carries an ON DELETE CASCADE reference to `sessions`, so the drop would take
-- its rows anyway; the DELETE below makes that explicit on both engines rather
-- than leaving it as an incidental cascade that only one dialect performs.
-- A reauthentication window lives for minutes and the human retries; a migration is a
-- deploy. Nothing else references `sessions`.
--
-- `requesting_origin` is NULL for cli and browser sessions and NOT NULL for a
-- workspace session — the CHECK ties it to the artifact type, so an
-- origin-bound session cannot exist without an origin and a same-origin
-- session cannot acquire one. That column is what makes origin removal an
-- atomic kill switch: one statement over one indexed column.
--
-- `handoff_id` records the transaction that issued it, the correlating key
-- the audit events carry.
--
-- The rebuilt table restates the SHAPE `sessions` HAS REACHED BY 00018 — which
-- is the 00014 shape, because 00015-00018 do not touch this table — and not
-- the shape 00005 declared: `csrf_verifier` (00006), `provider_id` (00007) and
-- `saml_provider_id` plus the singular-provenance CHECK (00010) are all part
-- of the table now and would be silently dropped by a rebuild that copied only
-- the original columns. Restating them is a ONE-TIME, FROZEN cost — migrations
-- are append-only and immutable, so a later migration altering `sessions`
-- alters the post-00019 table normally and never returns here.
CREATE TABLE sessions_rebuilt (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    verifier BLOB NOT NULL UNIQUE,
    artifact TEXT NOT NULL CHECK (artifact IN ('cli', 'browser', 'workspace')),
    session_generation INTEGER NOT NULL,
    credential_epoch INTEGER NOT NULL,
    auth_method TEXT NOT NULL,
    factors TEXT NOT NULL,
    authenticated_at TEXT NOT NULL,
    ceremony_id TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    csrf_verifier BLOB,
    provider_id TEXT REFERENCES oidc_providers (id) ON DELETE CASCADE,
    saml_provider_id TEXT REFERENCES saml_providers (id) ON DELETE CASCADE,
    requesting_origin TEXT,
    handoff_id TEXT,
    CHECK (provider_id IS NULL OR saml_provider_id IS NULL),
    CHECK (
        (artifact = 'workspace' AND requesting_origin IS NOT NULL AND handoff_id IS NOT NULL)
        OR (artifact <> 'workspace' AND requesting_origin IS NULL AND handoff_id IS NULL)
    )
);

INSERT INTO sessions_rebuilt (
    id, principal_id, verifier, artifact, session_generation, credential_epoch,
    auth_method, factors, authenticated_at, ceremony_id, created_at,
    last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent,
    csrf_verifier, provider_id, saml_provider_id, requesting_origin, handoff_id
)
SELECT
    id, principal_id, verifier, artifact, session_generation, credential_epoch,
    auth_method, factors, authenticated_at, ceremony_id, created_at,
    last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent,
    csrf_verifier, provider_id, saml_provider_id, NULL, NULL
FROM sessions;

DELETE FROM reauth_windows;

DROP TABLE sessions;

ALTER TABLE sessions_rebuilt RENAME TO sessions;

CREATE INDEX sessions_principal_idx ON sessions (principal_id);

CREATE INDEX sessions_origin_idx ON sessions (requesting_origin);
