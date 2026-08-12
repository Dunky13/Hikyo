-- +goose Up
-- SCIM provisioning (#73, scim-provisioning ADR). Roll-forward only: no Down
-- section.
--
-- hikyo:table scim_bindings class=org chain=org_id
-- hikyo:table scim_mappings class=org chain=org_id
-- hikyo:table scim_users class=org chain=org_id
-- hikyo:table scim_groups class=org chain=org_id
-- hikyo:table scim_group_members class=org chain=org_id
-- hikyo:table scim_attention class=org chain=org_id
-- hikyo:table scim_credentials class=authn chain=-
--
-- Scope classes, stated because the split is load-bearing. Everything the
-- binding OWNS is org tenant data reached through the proof-carrying
-- repository surface (ADR §7: "authorize() mints an operation- and
-- transaction-bound proof, and the store boundary rejects anything else"), so
-- those tables carry `org_id` as their chain column and every statement
-- touching them binds it from the verified proof. `scim_credentials` is the
-- one exception and is class=authn for the same reason `sessions` is: it is
-- resolved BEFORE any operation is authorized — the credential is what
-- authenticates the request that then mints the proof — so it rides the
-- enumerated authentication-resolution surface, exactly as OIDC/SAML provider
-- storage does after its own instance gate.

-- The per-org binding (ADR §1). One IdP provisioning app per org; the binding
-- IS the tenant boundary. `UNIQUE (org_id, provider_kind, provider_slug)`
-- is the ADR's "at most one binding per (org, provider)" — the concurrent
-- create race resolves to one row and the loser fails closed with the named
-- conflict rather than being reconciled in application code.
--
-- The provider reference is READ-ONLY (§1): creating a binding grants no
-- authority over the provider. `provider_issuer` is a frozen copy of the
-- issuer the referenced provider carried at binding creation, because the
-- derived subject must equal byte-exactly what the login path computes and
-- an issuer that moved under the binding is a rebinding hazard, not a
-- silently-followed rename.
--
-- `subject_source` is the SCIM attribute path carrying identity material,
-- declared IMMUTABLY at creation (§5.1). `userName` is refused as a value in
-- Go, by name, because core SCIM defines it `caseExact: false` and
-- server-unique, which contradicts byte-exact identity material.
--
-- The four `nameid_*` columns are the SAML NameID profile (§5.1): the Format
-- URI plus the fixed qualifier values, presence-byte-encoded exactly as the
-- login path does. Presence is its OWN column because an absent qualifier and
-- an empty-string qualifier are different inputs to the injective encoder, and
-- collapsing them would make two distinct SAML subjects collide.
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
    nameid_qualifier_present INTEGER NOT NULL DEFAULT 0 CHECK (nameid_qualifier_present IN (0, 1)),
    nameid_sp_qualifier TEXT NOT NULL DEFAULT '',
    nameid_sp_qualifier_present INTEGER NOT NULL DEFAULT 0 CHECK (nameid_sp_qualifier_present IN (0, 1)),
    connection_principal_id TEXT NOT NULL REFERENCES principals (id),
    last_contact_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, provider_kind, provider_id),
    UNIQUE (org_id, id)
);

CREATE INDEX scim_bindings_org ON scim_bindings (org_id);

-- The mapping table (ADR §3): a row is `(IdP group -> role template @ scope)`.
-- Multiple rows per group are allowed and a user in several mapped groups gets
-- the additive union — the grant model's only combining rule.
--
-- `group_id` is the SERVER-MINTED SCIM group id, never displayName (§3), so an
-- IdP-side rename follows the id and orphans nothing. The FK is deliberately
-- ABSENT: a mapping row survives the deletion of the group it names, flipping
-- to `inert` with an attention state (§5.4's Group DELETE row) rather than
-- vanishing — a row the database tidied away is a row the human never got to
-- decide about.
--
-- The scope columns are '' rather than NULL for the same reason
-- `grant_origins.subject` is NOT NULL: UNIQUE treats NULLs as distinct on
-- sqlite and (pre-15) on postgres, so a nullable scope column would make the
-- uniqueness key mean different things on the two engines.
CREATE TABLE scim_mappings (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    template TEXT NOT NULL,
    scope_project_id TEXT NOT NULL DEFAULT '',
    scope_env_id TEXT NOT NULL DEFAULT '',
    inert INTEGER NOT NULL DEFAULT 0 CHECK (inert IN (0, 1)),
    created_at TEXT NOT NULL,
    UNIQUE (binding_id, group_id, template, scope_project_id, scope_env_id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_mappings_binding ON scim_mappings (binding_id);
CREATE INDEX scim_mappings_group ON scim_mappings (binding_id, group_id);

-- Provisioned users (ADR §5). The row is the binding's DIRECTORY entry; the
-- account and its identity link are instance-level and survive deprovision and
-- DELETE (§5.3) — hence `account_id` referencing `accounts`, and no cascade
-- anywhere near it.
--
-- `subject` is the DERIVED subject, write-once per resource (§5.1). It is
-- stored so a subject-changing PUT/PATCH can be refused by comparing rather
-- than by re-deriving-and-hoping, and it is unique per binding so an IdP
-- cannot point two SCIM resources at one identity.
--
-- `user_name_lower` exists because RFC 7643 defines `userName` as
-- `caseExact: false`: the filter `userName eq "..."` must compare
-- case-insensitively, and a LOWER() in the predicate would defeat the index
-- and the predicate analyzer at once. `external_id` compares byte-exact and
-- therefore has no folded twin.
CREATE TABLE scim_users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id),
    user_name TEXT NOT NULL,
    user_name_lower TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    attributes TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (binding_id, user_name_lower),
    UNIQUE (binding_id, subject),
    UNIQUE (binding_id, id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_users_binding ON scim_users (binding_id);
CREATE INDEX scim_users_account ON scim_users (binding_id, account_id);

-- Provisioned groups (ADR §6). Binding-scoped, with a server-minted id.
--
-- displayName is deliberately NOT unique. RFC 7643 does not make it unique,
-- real directories hold same-named groups in different organisational units,
-- and the ADR's closed uniqueness mapping names only duplicate `userName` and
-- a subject-source collision. Okta's and Entra's `displayName eq` discovery
-- probe is an ordinary filter: a ListResponse carrying two matches is the
-- correct answer to a directory that has two.
CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    display_name_lower TEXT NOT NULL,
    external_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (binding_id, id),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_groups_binding ON scim_groups (binding_id);

-- Group membership (ADR §6). Members are references to THIS binding's
-- provisioned users; a reference resolving to no such user is refused by name,
-- which the FK makes structural rather than hopeful. Nested groups are refused
-- in Go with `invalidValue`, so there is deliberately no group-member column
-- to accidentally start writing.
CREATE TABLE scim_group_members (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES orgs (id),
    binding_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
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

-- Attention states (ADR §9). STORED, not derived: each state is audited on
-- entry AND on exit, and a view computed at read time cannot emit a
-- transition. `subject_ref` distinguishes per-object instances of the same
-- state (which user's manual grants remain, which mapping row went inert) and
-- is '' for binding-wide states.
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
    entered_at TEXT NOT NULL,
    UNIQUE (binding_id, state, subject_ref),
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_attention_binding ON scim_attention (binding_id);

-- The provisioning connection's credentials (ADR §7). Everything inherits
-- unchanged from the locked machine-credential mechanics: >=256-bit CSPRNG
-- body behind the `hik_<v>_scim_` grammar, unsalted SHA-256 verifier under a
-- UNIQUE index, several live credentials at once with identical authority
-- (overlap rotation), a lifetime ceiling with an `allow_indefinite` instance
-- opt-in, revocation biting at the next request, and the credential epoch
-- carried so a restored verifier is permanently dead.
--
-- The verifier is unsalted on purpose and that is not a shortcut: the artifact
-- carries >=256 bits of entropy, so brute force is infeasible and
-- authentication stays a single indexed read. A salt would buy nothing and
-- cost the index.
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
    verifier BLOB NOT NULL UNIQUE,
    credential_epoch INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT,
    FOREIGN KEY (org_id, binding_id) REFERENCES scim_bindings (org_id, id)
);

CREATE INDEX scim_credentials_binding ON scim_credentials (binding_id);
