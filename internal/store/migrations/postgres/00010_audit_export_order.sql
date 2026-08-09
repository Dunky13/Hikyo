-- +goose Up
-- Gap-free audit export ordering (#84). `seq` remains the immutable public
-- event identifier and allocation order. `commit_seq` is database-owned
-- export metadata, assigned by a deferred trigger immediately before commit.
--
-- The global advisory lock is the serialization point: while one transaction
-- is finalizing audit positions on either trail, the next cannot allocate
-- commit_seq. One key avoids opposite-order deadlocks when a transaction
-- carries events for both trails. The lock is held through commit, so visible
-- per-trail commit_seq order is commit order.
-- Postgres inserts also stamp recorded_at from clock_timestamp(); exports
-- capture that same server clock before their INTENT write, giving unbounded
-- exports a fixed terminating snapshot without application-clock skew.
-- Sequence gaps remain possible after rollback; gaplessness means exports do
-- not omit committed rows, not that position numbers are contiguous.

ALTER TABLE audit_tenant_events ADD COLUMN commit_seq BIGINT;
ALTER TABLE audit_instance_events ADD COLUMN commit_seq BIGINT;

CREATE SEQUENCE audit_tenant_commit_seq AS BIGINT;
CREATE SEQUENCE audit_instance_commit_seq AS BIGINT;

-- Rows committed before this migration have no concurrency ambiguity left;
-- preserve their existing order, then continue above the largest position.
UPDATE audit_tenant_events SET commit_seq = seq;
UPDATE audit_instance_events SET commit_seq = seq;

SELECT setval(
    'audit_tenant_commit_seq',
    COALESCE(MAX(commit_seq), 1),
    MAX(commit_seq) IS NOT NULL
) FROM audit_tenant_events;
SELECT setval(
    'audit_instance_commit_seq',
    COALESCE(MAX(commit_seq), 1),
    MAX(commit_seq) IS NOT NULL
) FROM audit_instance_events;

ALTER TABLE audit_tenant_events
    ADD CONSTRAINT audit_tenant_events_commit_seq_unique UNIQUE (commit_seq);
ALTER TABLE audit_instance_events
    ADD CONSTRAINT audit_instance_events_commit_seq_unique UNIQUE (commit_seq);

-- +goose StatementBegin
CREATE FUNCTION assign_audit_tenant_commit_seq() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    -- 0x57454E56 = "WENV"; 84 names this appender's issue/lock class.
    PERFORM pg_advisory_xact_lock(1464159830, 84);
    UPDATE audit_tenant_events
    SET commit_seq = nextval('audit_tenant_commit_seq')
    WHERE seq = NEW.seq AND commit_seq IS NULL;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION assign_audit_instance_commit_seq() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(1464159830, 84);
    UPDATE audit_instance_events
    SET commit_seq = nextval('audit_instance_commit_seq')
    WHERE seq = NEW.seq AND commit_seq IS NULL;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER audit_tenant_assign_commit_seq
AFTER INSERT ON audit_tenant_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assign_audit_tenant_commit_seq();

CREATE CONSTRAINT TRIGGER audit_instance_assign_commit_seq
AFTER INSERT ON audit_instance_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assign_audit_instance_commit_seq();
