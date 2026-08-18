-- +goose Up
-- GitHub Actions is the second compiled-in deployment adapter (#66).
-- hikyo:table adapter_configure_fences class=environment chain=org_id,project_id
ALTER TABLE adapters DROP CONSTRAINT adapters_provider_check;
ALTER TABLE adapters ADD CONSTRAINT adapters_provider_check
    CHECK (provider IN ('forgejo', 'github-actions'));
ALTER TABLE adapters ADD COLUMN credential_expires_at TIMESTAMPTZ;

ALTER TABLE adapter_targets
    ADD COLUMN destination_environment TEXT NOT NULL DEFAULT '',
    ADD COLUMN repository_id BIGINT NOT NULL DEFAULT 0 CHECK (repository_id >= 0),
    ADD COLUMN visibility TEXT NOT NULL DEFAULT '' CHECK (visibility IN ('', 'all', 'private', 'selected')),
    ADD COLUMN selected_repository_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN warnings JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE adapter_targets DROP CONSTRAINT adapter_targets_destination_kind_check;
ALTER TABLE adapter_targets ADD CONSTRAINT adapter_targets_destination_kind_check
    CHECK (destination_kind IN ('repository', 'organization', 'environment'));

ALTER TABLE adapter_route_move_targets
    ADD COLUMN destination_environment TEXT NOT NULL DEFAULT '',
    ADD COLUMN repository_id BIGINT NOT NULL DEFAULT 0 CHECK (repository_id >= 0),
    ADD COLUMN visibility TEXT NOT NULL DEFAULT '' CHECK (visibility IN ('', 'all', 'private', 'selected')),
    ADD COLUMN selected_repository_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE adapter_route_move_targets DROP CONSTRAINT adapter_route_move_targets_destination_kind_check;
ALTER TABLE adapter_route_move_targets ADD CONSTRAINT adapter_route_move_targets_destination_kind_check
    CHECK (destination_kind IN ('repository', 'organization', 'environment'));
ALTER TABLE adapter_route_move_claims ADD COLUMN destination_environment TEXT NOT NULL DEFAULT '';
ALTER TABLE adapter_route_move_claims DROP CONSTRAINT adapter_route_move_claims_destination_kind_check;
ALTER TABLE adapter_route_move_claims ADD CONSTRAINT adapter_route_move_claims_destination_kind_check
    CHECK (destination_kind IN ('repository', 'organization', 'environment'));
DO $$
DECLARE legacy_unique TEXT;
BEGIN
    SELECT conname INTO legacy_unique
    FROM pg_constraint
    WHERE conrelid = 'adapter_route_move_claims'::regclass
      AND contype = 'u'
      AND pg_get_constraintdef(oid) LIKE '%provider_origin%'
      AND pg_get_constraintdef(oid) NOT LIKE '%destination_environment%';
    IF legacy_unique IS NOT NULL THEN
        EXECUTE format('ALTER TABLE adapter_route_move_claims DROP CONSTRAINT %I', legacy_unique);
    END IF;
END $$;
ALTER TABLE adapter_route_move_claims ADD CONSTRAINT adapter_route_move_claims_provider_destination_name_unique
    UNIQUE (provider_origin, destination_kind, destination_owner, destination_name, destination_environment, surface, normalized_name);

ALTER TABLE adapter_ledger
    ADD COLUMN destination_kind TEXT NOT NULL DEFAULT 'repository' CHECK (destination_kind IN ('repository', 'organization', 'environment')),
    ADD COLUMN repository_id BIGINT NOT NULL DEFAULT 0 CHECK (repository_id >= 0),
    ADD COLUMN missing BOOLEAN NOT NULL DEFAULT FALSE;
DROP INDEX adapter_ledger_active_provider_name;
CREATE UNIQUE INDEX adapter_ledger_active_provider_name
    ON adapter_ledger (provider_origin, destination_kind, repository_id, destination_id, surface, normalized_name)
    WHERE state <> 'released';
ALTER TABLE adapter_conflicts ADD COLUMN repository_id BIGINT NOT NULL DEFAULT 0 CHECK (repository_id >= 0);

CREATE TABLE adapter_configure_fences (
    target_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    environment_id TEXT NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind = 'environment'),
    destination_owner TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    destination_environment TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation = 1),
    effect_id TEXT NOT NULL UNIQUE,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('leased', 'succeeded', 'failed')),
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    FOREIGN KEY (org_id, project_id, environment_id) REFERENCES environments (org_id, project_id, id)
);
