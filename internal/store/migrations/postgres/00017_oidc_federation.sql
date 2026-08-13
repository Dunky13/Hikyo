-- +goose Up
-- OIDC federation and the conditional-fetch cursor (#62). Roll-forward only:
-- no Down section by policy.
--
-- STRUCTURALLY IDENTICAL to the sqlite dialect, which carries the reasoning for
-- every table, column and CHECK -- including why a federated binding is a row
-- of machine_credentials rather than a sibling table. Restating it in both
-- files is how the two accounts of the same schema drift apart; this file
-- states only what differs.
--
-- What differs: the type vocabulary (TIMESTAMPTZ, BYTEA, BIGINT), and that
-- postgres reaches the widened CHECK and the nullable column by ALTER rather
-- than the table rebuild sqlite needs. The two engines therefore end at the
-- same shape by different routes, which is the same split 00009 already made
-- for `environments.display_order`.
--
-- hikyo:table federation_issuers class=authn chain=-
-- hikyo:table pin_generations class=authn chain=-

CREATE TABLE federation_issuers (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL UNIQUE,
    issuer_type TEXT NOT NULL CHECK (issuer_type IN ('kubernetes', 'forgejo', 'github-actions')),
    jwks_mode TEXT NOT NULL CHECK (jwks_mode IN ('discovery', 'static')),
    static_jwks TEXT,
    refused_audiences TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ,
    updated_by TEXT,
    CHECK ((jwks_mode = 'static') = (static_jwks IS NOT NULL))
);

CREATE TABLE pin_generations (
    principal_id TEXT NOT NULL REFERENCES principals (id),
    environment_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    PRIMARY KEY (principal_id, environment_id)
);

-- The credential-kind discriminator gains the kind 00014 deliberately left
-- out. The constraint is dropped by its generated name, which postgres derives
-- deterministically from `<table>_<column>_check` for a single-column inline
-- CHECK -- the same name 00014's DDL produced.
ALTER TABLE machine_credentials DROP CONSTRAINT machine_credentials_kind_check;

ALTER TABLE machine_credentials
    ADD CONSTRAINT machine_credentials_kind_check
    CHECK (kind IN ('hikyo-token', 'oidc-federation'));

-- A federation binding has no minted value, so it has no prefix hint. The
-- shape CHECKs below make the pairing total in the other direction.
ALTER TABLE machine_credentials ALTER COLUMN prefix_hint DROP NOT NULL;

ALTER TABLE machine_credentials ADD COLUMN issuer_id TEXT REFERENCES federation_issuers (id);
ALTER TABLE machine_credentials ADD COLUMN subject TEXT;
ALTER TABLE machine_credentials ADD COLUMN audience TEXT;
ALTER TABLE machine_credentials ADD COLUMN required_claims TEXT;
ALTER TABLE machine_credentials ADD COLUMN reactivated_at TIMESTAMPTZ;

-- 00014's anonymous `kind <> 'hikyo-token' OR verifier IS NOT NULL` is LEFT IN
-- PLACE, deliberately. The bearer-shape constraint below implies it strictly, so
-- it is redundant rather than wrong -- and dropping it would mean naming a
-- constraint postgres generated positionally (`machine_credentials_check1`),
-- which is a guess about DDL ordering, not a fact about the schema. A redundant
-- CHECK costs one predicate on insert; a wrong guess costs a migration that
-- either fails on someone else's database or silently leaves the constraint it
-- claimed to remove.
ALTER TABLE machine_credentials
    ADD CONSTRAINT machine_credentials_bearer_shape
    CHECK (
        kind <> 'hikyo-token'
        OR (
            verifier IS NOT NULL AND prefix_hint IS NOT NULL
            AND issuer_id IS NULL AND subject IS NULL AND audience IS NULL
            AND required_claims IS NULL AND reactivated_at IS NULL
        )
    );

ALTER TABLE machine_credentials
    ADD CONSTRAINT machine_credentials_binding_shape
    CHECK (
        kind <> 'oidc-federation'
        OR (
            verifier IS NULL AND prefix_hint IS NULL
            AND issuer_id IS NOT NULL AND subject IS NOT NULL
            AND audience IS NOT NULL AND required_claims IS NOT NULL
        )
    );

-- LIVENESS-AWARE uniqueness: a binding is immutable, so a stricter re-pin is
-- revoke-plus-insert in one transaction and the pair must be unique only among
-- live rows. See the sqlite dialect for the full reasoning.
CREATE UNIQUE INDEX machine_credentials_binding
    ON machine_credentials (issuer_id, subject)
    WHERE revoked_at IS NULL;
