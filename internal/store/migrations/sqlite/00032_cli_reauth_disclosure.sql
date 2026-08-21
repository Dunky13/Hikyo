-- +goose Up
-- The CLI reauthentication handoff carries DISCLOSURE purposes as well as the
-- adapter purpose (api-cli-surface ADR, Login and reauth transports: WebAuthn
-- reauth for a 0-window or protected environment goes through browser handoff
-- to the same purpose-bound, enumerated-key-set ceremony the UI uses). The
-- handoff records the purpose and the key set the ceremony must bind, and the
-- operation CHECK admits the disclosure operations. sqlite cannot alter a
-- CHECK, so the table is recreated and its rows carried across.
CREATE TABLE cli_reauth_handoffs_new (
    id TEXT PRIMARY KEY,
    state_verifier BLOB NOT NULL UNIQUE,
    code_verifier BLOB UNIQUE,
    session_id TEXT NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals (id),
    purpose TEXT NOT NULL DEFAULT 'adapter' CHECK (purpose IN ('adapter', 'reveal', 'copy')),
    operation TEXT NOT NULL CHECK (operation IN ('adapter.configure','adapter.credential-set','adapter.adopt','adapter.sync','value.reveal','value.copy-source')),
    environment_set TEXT NOT NULL,
    key_set TEXT NOT NULL DEFAULT '',
    pkce_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    approved_windows TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(approved_windows)),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    CHECK ((purpose = 'adapter' AND key_set = '') OR (purpose <> 'adapter' AND key_set <> ''))
);

INSERT INTO cli_reauth_handoffs_new
    (id, state_verifier, code_verifier, session_id, principal_id, operation, environment_set, pkce_challenge, redirect_uri, approved_windows, created_at, expires_at, consumed_at)
SELECT id, state_verifier, code_verifier, session_id, principal_id, operation, environment_set, pkce_challenge, redirect_uri, approved_windows, created_at, expires_at, consumed_at
FROM cli_reauth_handoffs;

DROP TABLE cli_reauth_handoffs;

ALTER TABLE cli_reauth_handoffs_new RENAME TO cli_reauth_handoffs;
