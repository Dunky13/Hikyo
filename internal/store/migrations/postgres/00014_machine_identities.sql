-- +goose Up
-- Machine identities: service accounts and their credentials (#61,
-- machine-identities ADR). Roll-forward only: no Down section by policy.
--
-- STRUCTURALLY IDENTICAL to the sqlite dialect, which carries the reasoning
-- for every table, column and CHECK here. Restating it in both files is how
-- the two accounts of the same schema drift apart; this file states only what
-- differs, which is the type vocabulary (TIMESTAMPTZ, BYTEA, BIGINT, BOOLEAN).
--
-- hikyo:table service_accounts class=authn chain=-
-- hikyo:table machine_credentials class=authn chain=-
-- hikyo:table credential_policy class=authn chain=-

-- The service account. `kind` is declared at creation and IMMUTABLE.
CREATE TABLE service_accounts (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL UNIQUE REFERENCES principals (id),
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('workload', 'automation')),
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY (org_id, project_id) REFERENCES projects (org_id, id),
    UNIQUE (org_id, project_id, name)
);

CREATE INDEX service_accounts_project ON service_accounts (org_id, project_id);

-- One authenticator. `kind` is the credential-kind discriminator;
-- `lifetime`/`expires_at` are the ADR's typed lifetime, paired by CHECK.
CREATE TABLE machine_credentials (
    id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id),
    kind TEXT NOT NULL CHECK (kind IN ('hikyo-token')),
    verifier BYTEA UNIQUE,
    prefix_hint TEXT NOT NULL,
    lifetime TEXT NOT NULL CHECK (lifetime IN ('finite', 'indefinite')),
    expires_at TIMESTAMPTZ,
    credential_epoch BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CHECK (
        (lifetime = 'finite' AND expires_at IS NOT NULL)
        OR (lifetime = 'indefinite' AND expires_at IS NULL)
    ),
    CHECK (kind <> 'hikyo-token' OR verifier IS NOT NULL)
);

CREATE INDEX machine_credentials_account ON machine_credentials (service_account_id);

-- The instance credential policy, seeded with the defaults #61 chose.
-- The three values and their reasoning are in the sqlite dialect.
CREATE TABLE credential_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    max_finite_lifetime_seconds BIGINT NOT NULL CHECK (max_finite_lifetime_seconds > 0),
    allow_indefinite BOOLEAN NOT NULL,
    max_live_credentials BIGINT NOT NULL CHECK (max_live_credentials > 0),
    updated_at TIMESTAMPTZ,
    updated_by TEXT
);

INSERT INTO credential_policy (
    id, max_finite_lifetime_seconds, allow_indefinite, max_live_credentials, updated_at, updated_by
) VALUES (1, 7776000, FALSE, 5, NULL, NULL);
