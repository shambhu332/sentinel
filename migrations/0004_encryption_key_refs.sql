-- Migration 0004: tenant encryption key references (Phase 1.4)
--
-- Tracks *references* to per-tenant encryption keys.  Key material never
-- enters the database — only opaque key_id strings that map to keys held
-- in an HSM / KMS / secret store.  The baseline HKDF-derived DEKs require
-- no DB row; this table exists for future customer-managed key (CMK)
-- rotation workflows.
--
-- Idempotent: uses IF NOT EXISTS throughout.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_encryption_keys (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     UUID        NOT NULL,
    key_id        TEXT        NOT NULL,          -- opaque reference (KMS ARN, etc.)
    key_version   INT         NOT NULL DEFAULT 1,
    algorithm     TEXT        NOT NULL DEFAULT 'AES-256-GCM',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at    TIMESTAMPTZ,
    active        BOOLEAN     NOT NULL DEFAULT TRUE,

    CONSTRAINT uq_tenant_active_key UNIQUE (tenant_id, active)
        DEFERRABLE INITIALLY DEFERRED
);

-- Fast lookup: "give me the active key for tenant X"
CREATE INDEX IF NOT EXISTS idx_enc_keys_tenant_active
    ON tenant_encryption_keys (tenant_id)
    WHERE active = TRUE;

-- Audit: history of all keys (including rotated) for a tenant
CREATE INDEX IF NOT EXISTS idx_enc_keys_tenant_all
    ON tenant_encryption_keys (tenant_id, created_at DESC);

COMMENT ON TABLE tenant_encryption_keys IS
    'Key references for per-tenant APK encryption. '
    'Key material is never stored here — only KMS/HSM identifiers.';

COMMIT;
