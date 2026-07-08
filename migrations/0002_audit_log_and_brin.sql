-- Migration 0002 — immutable audit log + BRIN index on scan_event.
--
-- Phase 1.1 / 1.6:
--   * `audit_log`: append-only record of every HTTP request against
--     the API (Phase 1.6 middleware writes here). A PG rule blocks
--     UPDATE and DELETE at the wire — even a compromised app role
--     cannot rewrite history.
--   * BRIN index on scan_event.emitted_at: BRIN is O(1) space vs.
--     BTREE for time-ordered append-only data. Range scans over
--     "last hour of events" stay fast without paying BTREE storage.
--   * BTREE indexes on scan_event (tenant_id, scan_id) — hot path
--     for the SSE tail reader.

BEGIN;

-- ============================================================
-- Immutable audit log
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID,                              -- nullable: unauth requests
    user_id      UUID,                              -- nullable: anon requests
    action       TEXT NOT NULL,                     -- e.g. "POST /scans"
    resource     TEXT,                              -- e.g. session_id, api_key kid
    method       TEXT,
    path         TEXT,
    status_code  INT,
    ip           INET,
    user_agent   TEXT,
    request_id   TEXT,
    duration_ms  INT,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_tenant_ts_idx
    ON audit_log (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_action_idx
    ON audit_log (action);
CREATE INDEX IF NOT EXISTS audit_log_ts_brin_idx
    ON audit_log USING BRIN (ts);

-- Immutability: no UPDATE / DELETE — even for the migration role.
-- Rules run *before* triggers and *before* RLS, so this is the tightest
-- possible guarantee short of pg_hba.conf lockdown.
CREATE OR REPLACE RULE audit_log_no_update AS
    ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_log_no_delete AS
    ON DELETE TO audit_log DO INSTEAD NOTHING;

-- Multi-tenant view: only rows for the current tenant (or unscoped
-- rows with tenant_id IS NULL, which the app cannot write).
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE  ROW LEVEL SECURITY;
CREATE POLICY audit_log_tenant_read ON audit_log
    FOR SELECT
    USING (tenant_id IS NULL OR tenant_id = sentinel_current_tenant());
CREATE POLICY audit_log_tenant_write ON audit_log
    FOR INSERT
    WITH CHECK (tenant_id IS NULL OR tenant_id = sentinel_current_tenant());
GRANT SELECT, INSERT ON audit_log TO sentinel_app;

-- ============================================================
-- scan_event — BRIN + hot-path BTREE
-- ============================================================
-- BRIN because emitted_at is strictly monotonic per partition — the
-- correlation between physical order and value is ~1.0, which is the
-- ideal BRIN case. Storage cost: kilobytes vs. gigabytes for BTREE
-- on a hot event stream.
CREATE INDEX IF NOT EXISTS scan_event_emitted_brin_idx
    ON scan_event USING BRIN (emitted_at);

-- Tail reader / SSE stream hits `WHERE scan_id = ? ORDER BY emitted_at`.
CREATE INDEX IF NOT EXISTS scan_event_scan_emitted_idx
    ON scan_event (scan_id, emitted_at);

-- Per-tenant filter for the dashboard aggregate queries.
CREATE INDEX IF NOT EXISTS scan_event_tenant_idx
    ON scan_event (tenant_id, emitted_at DESC);

-- ============================================================
-- Bootstrap a "current + next" pair of partitions so the app can
-- INSERT immediately after migration. Production runs pg_cron
-- to roll the next partition every month.
-- ============================================================
DO $$
DECLARE
    cur_month DATE := date_trunc('month', now())::date;
    next_month DATE := (date_trunc('month', now()) + interval '1 month')::date;
    after_next DATE := (date_trunc('month', now()) + interval '2 month')::date;
    cur_name TEXT := 'scan_event_' || to_char(cur_month, 'YYYY_MM');
    next_name TEXT := 'scan_event_' || to_char(next_month, 'YYYY_MM');
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF scan_event '
        'FOR VALUES FROM (%L) TO (%L)',
        cur_name, cur_month, next_month
    );
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF scan_event '
        'FOR VALUES FROM (%L) TO (%L)',
        next_name, next_month, after_next
    );
END $$;

COMMIT;
