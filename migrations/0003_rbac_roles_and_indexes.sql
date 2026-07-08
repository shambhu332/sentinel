-- Migration 0003 — RBAC role expansion + supporting indexes.
--
-- Phase 1.3:
--   * Extend app_user.role CHECK constraint to include the prompt's
--     new `analyst` role while preserving the legacy `member` value
--     (which becomes a synonym at the app layer).
--   * Add btree(tenant_id, role) index so RBAC lookups are cheap.
--   * Add btree(api_key.tenant_id, kid) for rotation queries.
--   * Track the current active count per user so we can enforce
--     "max 2 API keys per user" without a full scan on every rotation.

BEGIN;

-- ============================================================
-- Extend the role check.
-- Drop the constraint (name auto-generated from CHECK — look it up)
-- then reinstall with the wider set.
-- ============================================================
DO $$
DECLARE
    cname TEXT;
BEGIN
    SELECT conname INTO cname
    FROM pg_constraint
    WHERE conrelid = 'app_user'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%role%';
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE app_user DROP CONSTRAINT %I', cname);
    END IF;
END $$;

ALTER TABLE app_user
    ADD CONSTRAINT app_user_role_check
    CHECK (role IN ('owner', 'admin', 'analyst', 'member', 'viewer'));

-- ============================================================
-- Indexes to make RBAC + rotation queries cheap.
-- ============================================================
CREATE INDEX IF NOT EXISTS app_user_tenant_role_idx
    ON app_user (tenant_id, role);

CREATE INDEX IF NOT EXISTS api_key_user_active_idx
    ON api_key (user_id) WHERE expires_at IS NULL OR expires_at > now();

-- ============================================================
-- Trigger: enforce max 2 active keys per user (Phase 1.3 spec).
-- ============================================================
CREATE OR REPLACE FUNCTION enforce_api_key_limit() RETURNS trigger AS $$
DECLARE
    active_count INT;
BEGIN
    SELECT count(*) INTO active_count
    FROM api_key
    WHERE user_id = NEW.user_id
      AND (expires_at IS NULL OR expires_at > now());
    IF active_count > 2 THEN
        RAISE EXCEPTION
            'user % already has 2 active API keys; rotate or revoke first',
            NEW.user_id
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS api_key_limit_trg ON api_key;
CREATE TRIGGER api_key_limit_trg
    AFTER INSERT ON api_key
    FOR EACH ROW EXECUTE FUNCTION enforce_api_key_limit();

COMMIT;
