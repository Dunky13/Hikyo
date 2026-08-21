-- +goose Up
-- CLI reauthentication handoffs carry disclosure purposes (see the sqlite
-- migration). Roll-forward only.
ALTER TABLE cli_reauth_handoffs DROP CONSTRAINT cli_reauth_handoffs_operation_check;
ALTER TABLE cli_reauth_handoffs ADD CONSTRAINT cli_reauth_handoffs_operation_check
    CHECK (operation IN ('adapter.configure','adapter.credential-set','adapter.adopt','adapter.sync','value.reveal','value.copy-source'));
ALTER TABLE cli_reauth_handoffs ADD COLUMN purpose TEXT NOT NULL DEFAULT 'adapter'
    CHECK (purpose IN ('adapter', 'reveal', 'copy'));
ALTER TABLE cli_reauth_handoffs ADD COLUMN key_set TEXT NOT NULL DEFAULT '';
ALTER TABLE cli_reauth_handoffs ADD CONSTRAINT cli_reauth_handoffs_key_set_check
    CHECK ((purpose = 'adapter' AND key_set = '') OR (purpose <> 'adapter' AND key_set <> ''));
