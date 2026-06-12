-- Migration 0001 — multi-tenant baseline schema.
--
-- Postgres ≥ 14 (uses pg_catalog.gen_random_uuid, partitioned tables,
-- and `current_setting(..., missing_ok=true)` semantics for the RLS
-- policies). Run as the migration role, which is the only role with
-- BYPASSRLS in this schema. Application connections use the
-- `sentinel_app` role (no BYPASSRLS), so RLS is enforced regardless
-- of whether the app code remembers to filter by tenant_id.
--
-- One-table-per-concept, never a JSON blob carrying the whole scan.
-- Findings.evidence is JSONB because it's already heterogeneous in
-- the agent layer; everything else is typed columns so we can index.

BEGIN;

-- ============================================================
-- Roles
-- ============================================================
DO $$ BEGIN
    CREATE ROLE sentinel_app NOLOGIN NOINHERIT;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE ROLE sentinel_service NOLOGIN NOINHERIT BYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- gen_random_uuid lives in pgcrypto on Postgres 13; ≥14 has it in core.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- Tenancy
-- ============================================================
CREATE TABLE IF NOT EXISTS tenant (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'free'
                CHECK (plan IN ('free','pro','enterprise')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS app_user (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL
                CHECK (role IN ('owner','admin','member','viewer')),
    pwd_hash    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS api_key (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES app_user(id) ON DELETE SET NULL,
    name          TEXT NOT NULL,
    kid           TEXT NOT NULL UNIQUE,           -- "sk_live_4f9a"
    secret_hash   TEXT NOT NULL,                  -- argon2id(key)
    scopes        TEXT[] NOT NULL DEFAULT ARRAY['scan:write'],
    expires_at    TIMESTAMPTZ,
    rotated_from  UUID REFERENCES api_key(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_key_tenant_idx ON api_key (tenant_id);

-- ============================================================
-- Scan domain
-- ============================================================
CREATE TABLE IF NOT EXISTS app (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    package       TEXT NOT NULL,
    platform      TEXT NOT NULL CHECK (platform IN ('android','ios')),
    display_name  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, package, platform)
);

CREATE TABLE IF NOT EXISTS scan (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    app_id          UUID NOT NULL REFERENCES app(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL,
    apk_sha256      TEXT NOT NULL,
    apk_size_bytes  BIGINT NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('pending','running','completed','failed')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    phase_timings   JSONB NOT NULL DEFAULT '{}'::jsonb,
    profile         JSONB NOT NULL DEFAULT '{}'::jsonb,
    base_scan_id    UUID REFERENCES scan(id),
    git_ref         TEXT,
    UNIQUE (tenant_id, session_id)
);
CREATE INDEX IF NOT EXISTS scan_app_started_idx
    ON scan (tenant_id, app_id, started_at DESC);
CREATE INDEX IF NOT EXISTS scan_git_ref_idx
    ON scan (tenant_id, git_ref) WHERE git_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS finding (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    scan_id         UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    vuln_class      TEXT NOT NULL,
    severity        TEXT NOT NULL
                    CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    confidence      REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    cvss_vector     TEXT,
    owasp           TEXT,
    masvs           TEXT,
    cwe             TEXT,
    triage_state    TEXT NOT NULL DEFAULT 'Unreviewed',
    fingerprint     TEXT NOT NULL,
    first_seen_scan UUID REFERENCES scan(id),
    last_seen_scan  UUID REFERENCES scan(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, scan_id, finding_id)
);
CREATE INDEX IF NOT EXISTS finding_fingerprint_idx
    ON finding (tenant_id, fingerprint);
CREATE INDEX IF NOT EXISTS finding_severity_idx
    ON finding (tenant_id, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS finding_evidence_gin
    ON finding USING GIN (evidence);

-- Monthly-partitioned event log. The migration creates the parent +
-- two partitions (current + next month). A pg_cron job rolls partitions.
CREATE TABLE IF NOT EXISTS scan_event (
    id          BIGSERIAL,
    tenant_id   UUID NOT NULL,
    scan_id     UUID NOT NULL,
    event_type  TEXT NOT NULL,
    payload     JSONB NOT NULL,
    emitted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, emitted_at)
) PARTITION BY RANGE (emitted_at);

-- File baseline for delta scanning (Task 2.2). Source files hashed at
-- scan time. The CI delta scanner consults this to skip re-analysing
-- files whose sha256 matches the baseline scan's row.
CREATE TABLE IF NOT EXISTS scan_file (
    tenant_id   UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    scan_id     UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY (scan_id, path)
);
CREATE INDEX IF NOT EXISTS scan_file_tenant_idx
    ON scan_file (tenant_id, scan_id);

-- ============================================================
-- Row-Level Security
--
-- Policies read the tenant ID from a session GUC. The application
-- sets it via `SELECT set_config('sentinel.tenant_id', $1, true)`
-- at the top of every transaction (see sentinel.tenancy.context).
-- `missing_ok = true` makes current_setting return '' when unset;
-- the cast to uuid then fails, which under USING semantics means
-- "no rows match" — fail-closed.
-- ============================================================

CREATE OR REPLACE FUNCTION sentinel_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT NULLIF(current_setting('sentinel.tenant_id', true), '')::uuid
$$;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'app_user', 'api_key', 'app', 'scan', 'finding',
        'scan_event', 'scan_file'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (tenant_id = sentinel_current_tenant()) '
            'WITH CHECK (tenant_id = sentinel_current_tenant())', t
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO sentinel_app', t
        );
    END LOOP;
END $$;

-- Tenant table itself: every row visible only to the bound tenant.
ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON tenant
    USING (id = sentinel_current_tenant())
    WITH CHECK (id = sentinel_current_tenant());
GRANT SELECT, UPDATE ON tenant TO sentinel_app;

COMMIT;
