-- +goose Up
-- OIDC federation and the conditional-fetch cursor (#62, machine-identities
-- ADR § Federation, § Federated bindings expire, § JWKS, § Restore; revision
-- ADR § Revision identity). Roll-forward only: no Down section by policy.
--
-- Three additions and one table rebuild.
--
-- WHY THE BINDING IS A ROW OF machine_credentials RATHER THAN A SIBLING
-- TABLE. The ADR puts a federated binding under the SAME lifetime rules as a
-- bearer credential -- the same instance ceiling, the same default-off
-- `allow_indefinite`, the same "renewal is a mint", the same credential epoch,
-- the same revocation surface -- so a sibling table would have had to carry a
-- second copy of `lifetime`, `expires_at`, `credential_epoch` and
-- `revoked_at`, and every clamp, enumeration and epoch query would have needed
-- a twin. It would also have made the liveness-aware uniqueness the
-- replacement rule needs unrepresentable: a binding is IMMUTABLE, so changing
-- one is revoke-plus-insert in a single transaction, which means the
-- `(issuer, subject)` pair must be unique only among LIVE rows, and a partial
-- unique index cannot span two tables. Both facts point the same way, so the
-- discriminator 00014 left for exactly this arrival is what carries it.
--
-- The accepted consequence, stated rather than discovered later: bindings
-- share `max_live_credentials` with bearer tokens, and a lifetime tightening
-- enumerates both kinds together. That is what the ADR asks for.
--
-- hikyo:table federation_issuers class=authn chain=-
-- hikyo:table pin_generations class=authn chain=-

-- An instance-scoped issuer configuration, under `instance-config`. It is
-- NEVER org- or project-scoped: #16 fixed this exact argument for human
-- providers, because an org-scoped issuer would let an org admin add a
-- provider and mint identities authenticating into the instance.
--
-- `issuer` is stored and compared BYTE-EXACT, with no canonicalization step.
-- OpenID Connect defines `iss` as case-sensitive, so any normalization that
-- folds case, resolves a URL or strips a trailing slash can merge two distinct
-- external issuers into one -- and the uniqueness constraint would enforce the
-- merge rather than catch it.
--
-- `issuer_type` is a closed set because the CI-binding rules are per type: a
-- Forgejo or GitHub Actions binding MUST pin `event_name` (§ Binding), and a
-- Kubernetes one has no such claim. It is declared here rather than inferred
-- from the issuer URL, because inferring it would make a rename of the
-- deployment change the security rules that apply to it.
--
-- `jwks_mode` picks discovery or the per-issuer STATIC JWKS the ADR offers as
-- a configured alternative for air-gapped installations. Static is not the
-- default and never becomes one: "a static-only installation breaks silently
-- on the day someone rotates the issuer's keys", so choosing it is a typed
-- operator act.
--
-- `refused_audiences` is the load-bearing column, and it is a list rather than
-- a flag because the value differs per platform and is not derivable: the
-- Kubernetes API-server default audience is whatever that cluster was
-- configured with, and Forgejo's Actions audience defaults to
-- `<instance>/<repository owner>` -- shared across every repository that owner
-- has, so accepting it makes any workflow in any of their repositories satisfy
-- the binding. Newline-joined, because audit.Schema and this schema both keep
-- lists as one delimited string rather than adding a JSON column whose shape
-- nothing validates.
CREATE TABLE federation_issuers (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL UNIQUE,
    issuer_type TEXT NOT NULL CHECK (issuer_type IN ('kubernetes', 'forgejo', 'github-actions')),
    jwks_mode TEXT NOT NULL CHECK (jwks_mode IN ('discovery', 'static')),
    static_jwks TEXT,
    refused_audiences TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT,
    updated_by TEXT,
    CHECK ((jwks_mode = 'static') = (static_jwks IS NOT NULL))
);

-- The pin generation the conditional cursor is bound to (§ Authentication,
-- authorization and the fetch path: "pin creation, reassignment or release"
-- invalidates a cursor). Pins themselves are #52's; this is the counter the
-- cursor already has to cover, because a cursor that omitted it would keep
-- answering "current" across a pin change on the day pins arrive.
--
-- An ABSENT row reads as generation 0. That is not a silent fallback: zero is
-- the truthful "this principal has never had a pin in this environment", and
-- materialising a row per (principal, environment) pair before any pin exists
-- would be a write on a read path.
CREATE TABLE pin_generations (
    principal_id TEXT NOT NULL REFERENCES principals (id),
    environment_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    PRIMARY KEY (principal_id, environment_id)
);

-- The machine_credentials rebuild. sqlite can neither widen a CHECK nor add a
-- NOT NULL column without a default, so the documented table rebuild (00006,
-- 00009) is the only route to either. Both are needed here: `kind` gains
-- `oidc-federation`, and `prefix_hint` becomes nullable because a federation
-- binding has no minted value to keep a hint of.
--
-- The five new columns are the binding, and every one is NULL for a bearer
-- credential:
--
--   issuer_id        the configured issuer this binding trusts.
--   subject          the `sub` it names, matched BYTE-FOR-BYTE. No wildcards,
--                    no namespace patterns, no path prefixes, no case folding.
--                    A pattern rule such as "any ServiceAccount in namespace
--                    prod" hands a Hikyo principal to anyone holding `create
--                    serviceaccount` in that namespace.
--   audience         the `aud` it accepts. MANDATORY, and the issuer's default
--                    audience is refused (see refused_audiences above).
--   required_claims  a JSON object of claim -> required value, EVERY one of
--                    which validation requires. The subject alone is not a
--                    sufficient statement of which workload this is, and on CI
--                    issuers it is actively misleading.
--   reactivated_at   the restore predicate's instant (§ Restore). When set,
--                    the binding refuses any token whose `iat` is not
--                    STRICTLY GREATER than this plus the maximum accepted
--                    positive clock skew. It is PERMANENT for the life of the
--                    binding, not a quarantine window that expires: once a
--                    window lifts, a pre-restore token whose `iat` was skewed
--                    into the future is admitted by ordinary validation, which
--                    is the exact artifact the predicate exists to exclude.
--
-- The three CHECKs make each kind's shape total, so a federation row carrying
-- a bearer verifier -- or a bearer row carrying a subject -- is
-- unrepresentable rather than merely unwritten.
CREATE TABLE machine_credentials_new (
    id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id),
    kind TEXT NOT NULL CHECK (kind IN ('hikyo-token', 'oidc-federation')),
    verifier BLOB UNIQUE,
    prefix_hint TEXT,
    lifetime TEXT NOT NULL CHECK (lifetime IN ('finite', 'indefinite')),
    expires_at TEXT,
    credential_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    issuer_id TEXT REFERENCES federation_issuers (id),
    subject TEXT,
    audience TEXT,
    required_claims TEXT,
    reactivated_at TEXT,
    CHECK (
        (lifetime = 'finite' AND expires_at IS NOT NULL)
        OR (lifetime = 'indefinite' AND expires_at IS NULL)
    ),
    CHECK (
        kind <> 'hikyo-token'
        OR (
            verifier IS NOT NULL AND prefix_hint IS NOT NULL
            AND issuer_id IS NULL AND subject IS NULL AND audience IS NULL
            AND required_claims IS NULL AND reactivated_at IS NULL
        )
    ),
    CHECK (
        kind <> 'oidc-federation'
        OR (
            verifier IS NULL AND prefix_hint IS NULL
            AND issuer_id IS NOT NULL AND subject IS NOT NULL
            AND audience IS NOT NULL AND required_claims IS NOT NULL
        )
    )
);

INSERT INTO machine_credentials_new (
    id, service_account_id, kind, verifier, prefix_hint, lifetime, expires_at,
    credential_epoch, created_at, created_by, revoked_at, last_used_at,
    issuer_id, subject, audience, required_claims, reactivated_at
)
SELECT id, service_account_id, kind, verifier, prefix_hint, lifetime, expires_at,
       credential_epoch, created_at, created_by, revoked_at, last_used_at,
       NULL, NULL, NULL, NULL, NULL
FROM machine_credentials;

DROP TABLE machine_credentials;

ALTER TABLE machine_credentials_new RENAME TO machine_credentials;

CREATE INDEX machine_credentials_account ON machine_credentials (service_account_id);

-- LIVENESS-AWARE uniqueness, and the partial predicate is the whole point.
-- The binding key is `(issuer, subject)` and a binding is IMMUTABLE, so a
-- stricter re-pin is a replacement mint: the old row stays as a revoked
-- historical record while the new one takes the pair. A total unique index
-- would refuse that transaction; dropping uniqueness altogether would let two
-- live bindings claim one external identity, and the authentication read would
-- have to pick one.
CREATE UNIQUE INDEX machine_credentials_binding
    ON machine_credentials (issuer_id, subject)
    WHERE revoked_at IS NULL;
