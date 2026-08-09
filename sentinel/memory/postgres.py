"""PostgresMemory — canonical T1 backend for SENTINEL.

Phase 1.1 of the production-hardening plan makes Postgres the default
Tier-1 store. It backs:

    * events        → `scan_event` (monthly-partitioned, BRIN on emitted_at)
    * findings      → `finding`
    * audit_log     → `audit_log` (immutable — PG RULEs block UPDATE/DELETE)

The T2 (semantic) and T3 (graph) tiers stay in Qdrant / Neo4j and are
implemented alongside in `sentinel.memory.production`. Callers should
compose the tiers, not require them from a single class.

Design notes:

* **asyncpg pool** — one shared pool per process, sized from settings.
* **Tenant isolation via RLS** — every transaction opens with
    `SELECT set_config('sentinel.tenant_id', $1, true)`
  which activates the tenant_isolation policies defined in migration
  0001. The application role has no BYPASSRLS, so a bug in Python
  code cannot leak cross-tenant rows.
* **No ORM.** Every query is a hand-written parametrised SQL string.
  ORMs hide the RLS `set_config` and the partition pruning we depend
  on. Postgres error surface is small enough to type once.
* **Finding envelope stays canonical.** We persist the Pydantic
  `Finding` as JSONB in `finding.evidence` alongside the typed columns
  used for indexes. Read path validates the JSONB back through the
  Pydantic model so downstream code never sees a hand-shaped dict.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from sentinel.core.finding import Finding, Severity
from sentinel.memory.interface import MemoryError, MemoryInterface

logger = logging.getLogger(__name__)


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _dsn_from_env() -> str:
    """Read Postgres DSN from env with a sensible local default."""
    return (
        os.getenv("SENTINEL_POSTGRES_URL")
        or os.getenv("POSTGRES_URL")
        or "postgresql://sentinel_service:sentineldev@localhost:5432/sentinel"
    )


class PostgresMemory(MemoryInterface):
    """Postgres-backed Tier-1 memory (events + findings + audit log).

    Tier 2/3 raise `NotImplementedError`; compose with
    `QdrantMemory` / `Neo4jMemory` (Phase 1.2) when full stack is
    required. This keeps the file small and its responsibilities
    single-purpose.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        tenant_id: str | None = None,
        min_pool_size: int = 2,
        max_pool_size: int = 10,
        statement_timeout_ms: int = 30_000,
    ) -> None:
        self._dsn = dsn or _dsn_from_env()
        self._tenant_id = tenant_id
        self._min_pool_size = min_pool_size
        self._max_pool_size = max_pool_size
        self._statement_timeout_ms = statement_timeout_ms
        self._pool: Any = None

    # ---------- Lifecycle ----------

    async def connect(self) -> None:
        try:
            import asyncpg  # type: ignore[import-untyped]
        except ImportError as e:  # pragma: no cover
            raise MemoryError(
                "asyncpg not installed. Run: poetry install"
            ) from e

        try:
            self._pool = await asyncpg.create_pool(
                dsn=self._dsn,
                min_size=self._min_pool_size,
                max_size=self._max_pool_size,
                command_timeout=self._statement_timeout_ms / 1000.0,
                server_settings={
                    "application_name": "sentinel",
                    "statement_timeout": str(self._statement_timeout_ms),
                },
            )
        except Exception as e:
            raise MemoryError(
                f"Failed to open Postgres pool at {self._safe_dsn()}: {e}"
            ) from e

        try:
            async with self._pool.acquire() as conn:
                await conn.execute("SELECT 1")
        except Exception as e:
            raise MemoryError(f"Postgres ping failed: {e}") from e

        logger.info("PostgresMemory: connected to %s", self._safe_dsn())

    async def close(self) -> None:
        if self._pool is not None:
            try:
                await self._pool.close()
            except Exception:
                logger.exception("Postgres pool close failed")
            self._pool = None

    # ---------- Tier 1: Events ----------

    async def publish_event(
        self,
        session_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        self._require_pool()
        scan_id, tenant_id = await self._resolve_scan(session_id)
        payload_json = json.dumps(payload, default=str)
        async with self._acquire_tenant_conn(tenant_id) as conn:
            await conn.execute(
                """
                INSERT INTO scan_event (tenant_id, scan_id, event_type, payload, emitted_at)
                VALUES ($1, $2, $3, $4::jsonb, now())
                """,
                tenant_id, scan_id, event_type, payload_json,
            )

    async def poll_events(
        self,
        session_id: str,
        since: datetime | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, Any]]:
        self._require_pool()
        scan_id, tenant_id = await self._resolve_scan(session_id)

        conditions = ["scan_id = $1"]
        params: list[Any] = [scan_id]
        if since is not None:
            params.append(since.astimezone(timezone.utc))
            conditions.append(f"emitted_at > ${len(params)}")
        if event_type is not None:
            params.append(event_type)
            conditions.append(f"event_type = ${len(params)}")

        sql = (
            "SELECT id, event_type, emitted_at, payload FROM scan_event "
            "WHERE " + " AND ".join(conditions) + " ORDER BY emitted_at ASC"
        )
        async with self._acquire_tenant_conn(tenant_id) as conn:
            rows = await conn.fetch(sql, *params)

        out: list[dict[str, Any]] = []
        for row in rows:
            payload_raw = row["payload"]
            if isinstance(payload_raw, str):
                try:
                    payload = json.loads(payload_raw)
                except json.JSONDecodeError:
                    payload = {"_raw": payload_raw}
            else:
                payload = payload_raw
            out.append({
                "id": str(row["id"]),
                "event_type": row["event_type"],
                "ts": row["emitted_at"].isoformat(),
                "payload": payload,
            })
        return out

    # ---------- Tier 1: Findings ----------

    async def save_finding(self, finding: Finding) -> None:
        self._require_pool()
        scan_id, tenant_id = await self._resolve_scan(finding.session_id)
        envelope = finding.model_dump_json()
        async with self._acquire_tenant_conn(tenant_id) as conn:
            triage_val: Any = getattr(finding, "triage_state", None)
            triage_str = (
                triage_val.value if hasattr(triage_val, "value")
                else (str(triage_val) if triage_val else "Unreviewed")
            )
            sev_val: Any = finding.severity
            sev_str = sev_val.value if isinstance(sev_val, Severity) else str(sev_val)
            await conn.execute(
                """
                INSERT INTO finding (
                    tenant_id, scan_id, finding_id, agent_id, vuln_class,
                    severity, confidence, evidence, cvss_vector, owasp,
                    masvs, cwe, triage_state, fingerprint, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10,
                        $11, $12, $13, $14, now())
                ON CONFLICT (tenant_id, scan_id, finding_id)
                DO UPDATE SET
                    evidence     = EXCLUDED.evidence,
                    severity     = EXCLUDED.severity,
                    confidence   = EXCLUDED.confidence,
                    triage_state = EXCLUDED.triage_state
                """,
                tenant_id,
                scan_id,
                finding.finding_id,
                finding.agent_id,
                finding.vuln_class,
                sev_str,
                float(finding.confidence),
                envelope,
                finding.cvss_vector,
                finding.owasp,
                finding.masvs,
                None,  # cwe is not on the base Finding model
                triage_str,
                self._fingerprint(finding),
            )

    async def get_findings(
        self,
        session_id: str,
        min_severity: str | None = None,
    ) -> list[Finding]:
        self._require_pool()
        scan_id, tenant_id = await self._resolve_scan(session_id)
        async with self._acquire_tenant_conn(tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT evidence::text AS body, severity
                FROM finding
                WHERE scan_id = $1
                ORDER BY created_at ASC
                """,
                scan_id,
            )
        floor = _SEVERITY_RANK.get(Severity(min_severity)) if min_severity else None
        out: list[Finding] = []
        for row in rows:
            body = row["body"]
            if not body:
                continue
            try:
                f = Finding.model_validate_json(body)
            except Exception:
                logger.warning("Skipping unparseable finding body in scan %s", scan_id)
                continue
            if floor is not None and _SEVERITY_RANK[f.severity] < floor:
                continue
            out.append(f)
        return out

    async def get_finding(
        self,
        session_id: str,
        finding_id: str,
    ) -> Finding | None:
        self._require_pool()
        scan_id, tenant_id = await self._resolve_scan(session_id)
        async with self._acquire_tenant_conn(tenant_id) as conn:
            row = await conn.fetchrow(
                """
                SELECT evidence::text AS body
                FROM finding
                WHERE scan_id = $1 AND finding_id = $2
                """,
                scan_id, finding_id,
            )
        if row is None or not row["body"]:
            return None
        try:
            return Finding.model_validate_json(row["body"])
        except Exception:
            return None

    # ---------- Audit log (Phase 1.6) ----------

    async def write_audit(
        self,
        *,
        action: str,
        method: str | None = None,
        path: str | None = None,
        status_code: int | None = None,
        resource: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        duration_ms: int | None = None,
        tenant_id: str | None = None,
        user_id: str | None = None,
    ) -> None:
        """Immutable audit-log write.

        The `audit_log` table has PG RULEs blocking UPDATE and DELETE
        (migration 0002). Even a compromised app role cannot rewrite
        history — the strongest guarantee short of streaming to
        append-only external storage.
        """
        self._require_pool()
        # Audit inserts may happen for unauthenticated requests where
        # we have no tenant — allowed by the migration's NULL policy.
        tid = tenant_id or self._tenant_id
        async with self._pool.acquire() as conn:
            if tid is not None:
                await conn.execute(
                    "SELECT set_config('sentinel.tenant_id', $1, true)", tid,
                )
            await conn.execute(
                """
                INSERT INTO audit_log (
                    tenant_id, user_id, action, resource,
                    method, path, status_code, ip, user_agent,
                    request_id, duration_ms, ts
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11, now())
                """,
                tid, user_id, action, resource,
                method, path, status_code, ip, user_agent,
                request_id, duration_ms,
            )

    # ---------- Tier 2 / Tier 3 — graceful degradation ----------
    # pgvector / Qdrant and Neo4j wiring is not yet implemented. Return
    # empty results and log so callers never crash; they just get nothing.

    async def add_embedding(
        self, session_id: str, finding_id: str, text: str, metadata: dict[str, Any],
    ) -> None:
        logger.warning(
            "[memory] PostgresMemory is Tier-1 only — embedding for %s skipped. "
            "Enable pgvector or Qdrant for semantic search.",
            finding_id,
        )

    async def search_similar(
        self, query_text: str, session_id: str | None = None, limit: int = 10,
    ) -> list[dict[str, Any]]:
        logger.warning(
            "[memory] PostgresMemory is Tier-1 only — similarity search returning empty."
        )
        return []

    async def add_graph_node(
        self, session_id: str, node_id: str, node_type: str, attrs: dict[str, Any],
    ) -> None:
        logger.warning(
            "[memory] PostgresMemory is Tier-1 only — graph node %s skipped.", node_id,
        )

    async def add_graph_edge(
        self, session_id: str, src: str, dst: str, edge_type: str, attrs: dict[str, Any],
    ) -> None:
        logger.warning(
            "[memory] PostgresMemory is Tier-1 only — graph edge %s→%s skipped.", src, dst,
        )

    async def find_paths(
        self, session_id: str, src: str, dst: str, max_length: int = 5,
    ) -> list[list[str]]:
        logger.warning(
            "[memory] PostgresMemory is Tier-1 only — path search %s→%s returning empty.",
            src, dst,
        )
        return []

    # ---------- Health ----------

    async def health_check(self) -> dict[str, bool]:
        if self._pool is None:
            return {"tier1": False, "tier2": False, "tier3": False}
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("SELECT 1")
            tier1 = True
        except Exception:
            tier1 = False
        return {"tier1": tier1, "tier2": False, "tier3": False}

    # ---------- Helpers ----------

    def _require_pool(self) -> None:
        if self._pool is None:
            raise MemoryError(
                "PostgresMemory not connected. Call await memory.connect() first."
            )

    def _safe_dsn(self) -> str:
        # Strip password for logs.
        try:
            head, _, tail = self._dsn.partition("://")
            if "@" not in tail:
                return self._dsn
            userinfo, host = tail.split("@", 1)
            if ":" in userinfo:
                user, _ = userinfo.split(":", 1)
                userinfo = f"{user}:***"
            return f"{head}://{userinfo}@{host}"
        except Exception:
            return "postgres://***"

    def _acquire_tenant_conn(self, tenant_id: str | None) -> "_AcquireTenant":
        """Acquire a pool connection and pin its RLS tenant GUC."""
        return _AcquireTenant(self._pool, tenant_id or self._tenant_id)

    async def _resolve_scan(self, session_id: str) -> tuple[str, str]:
        """Look up (scan_id, tenant_id) from session_id.

        Callers pass the human-facing `session_id` string; the DB uses
        UUID PKs. If the row doesn't exist yet (first event), the
        caller is expected to have created it via the scans route.
        For test / bootstrap flows we auto-insert a row into `tenant`,
        `app`, and `scan` — but only if a tenant_id was explicitly
        supplied at construction time (avoids silent tenant creation
        in production).
        """
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, tenant_id FROM scan WHERE session_id = $1",
                session_id,
            )
        if row is not None:
            return str(row["id"]), str(row["tenant_id"])

        if self._tenant_id is None:
            raise MemoryError(
                f"session_id {session_id!r} not found and no tenant configured; "
                "the API layer must POST /scans before publishing events."
            )
        # Bootstrap path — used by tests + local dev.
        return await self._bootstrap_scan(session_id, self._tenant_id)

    async def _bootstrap_scan(self, session_id: str, tenant_id: str) -> tuple[str, str]:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            # Ensure tenant exists.
            await conn.execute(
                """
                INSERT INTO tenant (id, slug, name)
                VALUES ($1, $2, $2)
                ON CONFLICT (id) DO NOTHING
                """,
                tenant_id, f"tenant-{tenant_id[:8]}",
            )
            # Ensure a stub app.
            app_row = await conn.fetchrow(
                """
                INSERT INTO app (tenant_id, package, platform, display_name)
                VALUES ($1, 'unknown.package', 'android', 'bootstrap')
                ON CONFLICT (tenant_id, package, platform) DO UPDATE
                    SET display_name = EXCLUDED.display_name
                RETURNING id
                """,
                tenant_id,
            )
            app_id = app_row["id"]
            # Insert scan row.
            scan_row = await conn.fetchrow(
                """
                INSERT INTO scan (
                    tenant_id, app_id, session_id, apk_sha256,
                    apk_size_bytes, status
                )
                VALUES ($1, $2, $3, '', 0, 'running')
                ON CONFLICT (tenant_id, session_id) DO UPDATE
                    SET status = scan.status
                RETURNING id
                """,
                tenant_id, app_id, session_id,
            )
        return str(scan_row["id"]), tenant_id

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        """Stable dedup fingerprint — agent + vuln_class + recommendation prefix.

        Real fingerprint logic lives in `sentinel.core.dedup`; this is a
        fallback for when that path isn't populated (e.g. legacy findings).
        """
        return f"{finding.agent_id}:{finding.vuln_class}:{finding.recommendation[:80]}"


class _AcquireTenant:
    """Context manager that pins the tenant GUC on the acquired connection."""

    def __init__(self, pool: Any, tenant_id: str | None) -> None:
        self._pool = pool
        self._tenant = tenant_id
        self._acq_cm: Any = None
        self._conn: Any = None

    async def __aenter__(self) -> Any:
        self._acq_cm = self._pool.acquire()
        self._conn = await self._acq_cm.__aenter__()
        if self._tenant is not None:
            await self._conn.execute(
                "SELECT set_config('sentinel.tenant_id', $1, true)",
                self._tenant,
            )
        return self._conn

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        return await self._acq_cm.__aexit__(exc_type, exc, tb)
