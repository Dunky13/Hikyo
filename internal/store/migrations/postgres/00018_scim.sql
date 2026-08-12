-- +goose Up
-- SCIM provisioning (#73, scim-provisioning ADR). Structurally identical to
-- the sqlite dialect; see that file for the reasoning behind every column and
-- every scope class. Roll-forward only: no Down section.
--
-- hikyo:table scim_bindings class=org chain=org_id
-- hikyo:table scim_mappings class=org chain=org_id
-- hikyo:table scim_users class=org chain=org_id
-- hikyo:table scim_groups class=org chain=org_id
-- hikyo:table scim_group_members class=org chain=org_id
-- hikyo:table scim_attention class=org chain=org_id
-- hikyo:table scim_credentials class=authn chain=-

CREATE TABLE scim_bindings (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    provider_kind TEXT NOT NULL CHECK (provider_kind IN ('oidc', 'saml')),
    provider_id TEXT NOT NULL,
    provider_slug TEXT NOT NULL,
    provider_issuer TEXT NOT NULL,
    subject_source TEXT NOT NULL,
    nameid_format TEXT NOT NULL DEFAULT '',
    nameid_qualifier TEXT NOT NULL DEFAULT '',
    nameid_qualifier_present BOOLEAN NOT NULL DEFAULT FALSE,
    nameid_sp_qualifier TEXT NOT NULL DEFAULT '',
    nameid_sp_qualifier_present BOOLEAN NOT NULL DEFAULT FALSE,
    connection_principal_id TEXT NOT NULL REFERENCES principals (id),
    last_contact_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (org_id, provider_kind, provider_id),
    UNIQUE (org_id, id)
);

CREATE INDEX scim_bindings_org ON scim_bindings (org_id);

CREATE TABLE scim_mappings (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    template TEXT NOT NULL,
    scope_project_id TEXT NOT NULL DEFAULT '',
    scope_env_id TEXT NOT NULL DEFAULT '',
    inert BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (binding_id, group_id, template, scope_project_id, scope_env_id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_mappings_binding ON scim_mappings (binding_id);
CREATE INDEX scim_mappings_group ON scim_mappings (binding_id, group_id);

CREATE TABLE scim_users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    user_name TEXT NOT NULL,
    user_name_lower TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    attributes TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (binding_id, user_name_lower),
    UNIQUE (binding_id, subject),
    UNIQUE (binding_id, id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_users_binding ON scim_users (binding_id);
CREATE INDEX scim_users_account ON scim_users (binding_id, account_id);

CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    display_name_lower TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (binding_id, id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_groups_binding ON scim_groups (binding_id);

CREATE TABLE scim_group_members (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (group_id, user_id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id),
    -- The membership's group AND user must belong to the SAME binding the
    -- membership does. Two composite foreign keys make that structural: a
    -- reference pairing one binding's group with another's user cannot be
    -- written at all, rather than being refused by a check somebody might
    -- forget to run.
    FOREIGN KEY (binding_id, group_id) REFERENCES scim_groups (binding_id, id),
    FOREIGN KEY (binding_id, user_id) REFERENCES scim_users (binding_id, id)
);

CREATE INDEX scim_group_members_group ON scim_group_members (group_id);
CREATE INDEX scim_group_members_user ON scim_group_members (user_id);

CREATE TABLE scim_attention (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'provider_unavailable', 'lockout_retention', 'manual_grants_remain',
            'inert_mapping', 'stale', 'post_restore'
        )
    ),
    subject_ref TEXT NOT NULL DEFAULT '',
    cause TEXT NOT NULL DEFAULT '',
    entered_at TIMESTAMPTZ NOT NULL,
    UNIQUE (binding_id, state, subject_ref),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_attention_binding ON scim_attention (binding_id);

CREATE TABLE scim_credentials (
    id TEXT PRIMARY KEY,
    -- `org_id` is denormalised onto the credential ON PURPOSE. The row is
    -- class=authn because a SCIM request presents it BEFORE any proof exists,
    -- so the pre-auth verifier lookup cannot carry a tenant predicate. Every
    -- ADMINISTRATIVE read and write, though, runs after `manage-members(org)`
    -- has been proved, and binds this column from that proof — so a credential
    -- id from another org matches no row rather than being caught by a Go
    -- check somebody could remove.
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    verifier BYTEA NOT NULL UNIQUE,
    credential_epoch BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_credentials_binding ON scim_credentials (binding_id);
