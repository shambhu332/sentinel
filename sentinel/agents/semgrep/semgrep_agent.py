"""SG_001 — Semgrep AST-pattern Agent.

Wraps the `semgrep` CLI to provide rule-based AST analysis as a
complement to the existing regex-based agents (C_007, A_004, etc.).
Rules live as one YAML per file under
`sentinel/agents/semgrep/rules/` so contributors can add coverage
without touching Python.

Detection flow:
1. Confirm the semgrep binary is on PATH (returns no findings + a
   warning if absent — pipeline keeps running).
2. Invoke `semgrep --config <rules_dir> --json --quiet
   --metrics=off <source_dir>` against the decompiled Java tree.
3. Parse the JSON, map each semgrep result onto a SENTINEL Finding
   using the rule's `metadata.sentinel_*` fields.

Every failure mode (missing binary, timeout, malformed JSON, missing
rules dir) is caught and downgraded to a logged warning + empty
findings — the agent never crashes the pipeline.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# Maps the metadata.sentinel_severity string (rule-authored) to the
# canonical Severity enum the rest of SENTINEL uses. Falls back via
# _severity_from_semgrep when missing.
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
}

# Fallback when a rule omits sentinel_severity: use semgrep's own
# severity (ERROR/WARNING/INFO) as a coarse signal.
_SEMGREP_SEVERITY_FALLBACK: dict[str, Severity] = {
    "ERROR":   Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO":    Severity.LOW,
}

# Defaults for fields that should never be missing.
_DEFAULT_VULN_CLASS = "Pattern Match"
_DEFAULT_CONFIDENCE = 0.65

# Cap total subprocess wall-time. Semgrep on a large decompiled tree
# can run for several minutes; capping prevents a runaway scan from
# blocking the whole phase. Findings produced before the timeout are
# lost (semgrep emits them only at the end) — that's the trade-off.
_SUBPROCESS_TIMEOUT_SECONDS = 300


class SemgrepAgent(BaseAgent):
    """SG_001: AST pattern-based static analysis via Semgrep."""

    AGENT_ID = "SG_001"
    VULN_CLASS = "Pattern Match"
    PHASE = "static"

    # Path to the bundled rules directory. Resolved at class-load
    # time so test code can monkeypatch the attribute on the instance.
    RULES_DIR: Path = (
        Path(__file__).resolve().parent / "rules"
    )

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            self._log.info("No decompiled source — skipping")
            return False
        if not self.RULES_DIR.exists():
            self._log.warning(
                "Semgrep rules directory missing at %s — skipping",
                self.RULES_DIR,
            )
            return False
        return True

    async def analyze(self) -> list[Finding]:
        if shutil.which("semgrep") is None:
            self._log.warning(
                "semgrep binary not on PATH — install via "
                "`poetry add semgrep` or `pip install semgrep`. "
                "Returning zero findings; pipeline continues.",
            )
            return []

        ctx = self._context
        source_dir = ctx.decompiled_dir
        assert source_dir is not None  # is_applicable guards this

        raw = self._run_semgrep(source_dir)
        if raw is None:
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            self._log.warning(
                "Semgrep output was not valid JSON (%s); first 200 chars: %r",
                e, raw[:200],
            )
            return []

        results = data.get("results", []) or []
        if not results:
            self._log.info("Semgrep produced 0 results")
            return []

        package = (ctx.manifest or {}).get("package", "?")
        findings: list[Finding] = []
        for r in results:
            try:
                findings.append(self._result_to_finding(r, source_dir, package))
            except Exception as e:  # noqa: BLE001
                # One bad result should never sink the rest. Log + drop.
                self._log.warning(
                    "Skipping malformed semgrep result %r: %s",
                    r.get("check_id", "?"), e,
                )

        self._log.info("Semgrep produced %d finding(s)", len(findings))
        return findings

    # ---------- Internals ----------

    def _run_semgrep(self, source_dir: Path) -> str | None:
        """Run `semgrep` and return raw stdout or None on failure."""
        cmd = [
            "semgrep",
            "--config", str(self.RULES_DIR),
            "--json",
            "--quiet",
            "--metrics=off",
            "--no-git-ignore",
            str(source_dir),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            # Binary disappeared between which() and run() — extremely
            # rare but handle it explicitly to keep the surface clean.
            self._log.warning("semgrep binary missing at exec time")
            return None
        except subprocess.TimeoutExpired:
            self._log.warning(
                "semgrep timed out after %ds against %s — returning no findings",
                _SUBPROCESS_TIMEOUT_SECONDS, source_dir,
            )
            return None
        except Exception as e:  # noqa: BLE001
            self._log.warning("semgrep subprocess failed: %s", e)
            return None

        # Semgrep exit codes:
        #   0 = no findings
        #   1 = findings present (still a successful run)
        #   >1 = error
        if proc.returncode not in (0, 1):
            self._log.warning(
                "semgrep exited %d: %s",
                proc.returncode, (proc.stderr or "")[:500],
            )
            return None
        return proc.stdout or ""

    def _result_to_finding(
        self,
        result: dict[str, Any],
        source_dir: Path,
        package: str,
    ) -> Finding:
        """Translate one semgrep result into a SENTINEL Finding."""
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}

        check_id = str(result.get("check_id", "unknown"))
        # Semgrep's check_id is namespaced (e.g.
        # `rules.webview-javascript-interface-exposure.webview-...`);
        # users care about the final segment.
        short_id = check_id.rsplit(".", 1)[-1]

        vuln_class = (
            metadata.get("sentinel_vuln_class")
            or _DEFAULT_VULN_CLASS
        )

        severity = self._severity_for(metadata, result)
        confidence = self._confidence_for(metadata)

        path_str = str(result.get("path", ""))
        try:
            rel_path = str(Path(path_str).relative_to(source_dir))
        except (ValueError, TypeError):
            rel_path = path_str

        start = result.get("start", {}) or {}
        line = int(start.get("line", 0) or 0)

        matched_lines = str(extra.get("lines", ""))[:1000]

        evidence: dict[str, Any] = {
            "title": f"{short_id}: {vuln_class}",
            "package": package,
            "file": rel_path,
            "line": line,
            "matched_lines": matched_lines,
            "semgrep_rule_id": short_id,
            "semgrep_check_id": check_id,
            "owasp_masvs": str(metadata.get("owasp_masvs", "")),
            "cwe": str(metadata.get("cwe", "")),
            "vector": (
                f"Semgrep matched rule '{short_id}' at {rel_path}:{line}. "
                "The matched code shows the pattern statically; runtime "
                "exploitability depends on reachability and input "
                "control. See the rule's `message` for the specific "
                "weakness."
            ),
            "message": str(extra.get("message", ""))[:1000],
        }

        # Optional MASVS/OWASP top-level fields when the rule provides them
        masvs = metadata.get("owasp_masvs")
        recommendation = self._build_recommendation(short_id, vuln_class)

        kwargs: dict[str, Any] = {
            "vuln_class": vuln_class,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": recommendation,
        }
        if masvs and isinstance(masvs, str) and len(masvs) <= 20:
            kwargs["masvs"] = masvs
        return self._make_finding(**kwargs)

    @staticmethod
    def _severity_for(
        metadata: dict[str, Any],
        result: dict[str, Any],
    ) -> Severity:
        sentinel_sev = str(metadata.get("sentinel_severity", "")).upper()
        if sentinel_sev in _SEVERITY_MAP:
            return _SEVERITY_MAP[sentinel_sev]
        # Fall back to semgrep's own severity (ERROR/WARNING/INFO)
        semgrep_sev = str(
            (result.get("extra", {}) or {}).get("severity", ""),
        ).upper()
        return _SEMGREP_SEVERITY_FALLBACK.get(semgrep_sev, Severity.MEDIUM)

    @staticmethod
    def _confidence_for(metadata: dict[str, Any]) -> float:
        raw = metadata.get("sentinel_confidence", _DEFAULT_CONFIDENCE)
        try:
            val = float(raw)
        except (TypeError, ValueError):
            return _DEFAULT_CONFIDENCE
        # Clamp into Finding's allowed range
        return max(0.0, min(1.0, val))

    @staticmethod
    def _build_recommendation(rule_id: str, vuln_class: str) -> str:
        """Per-rule remediation text. Defaults to a generic message."""
        per_rule: dict[str, str] = {
            "webview-javascript-interface-exposure": (
                "Only call addJavascriptInterface for WebViews that load "
                "trusted, fully controlled content. If the WebView ever "
                "loads remote URLs, ads, or deep-linked pages, remove the "
                "interface or restrict the exposed methods with "
                "@JavascriptInterface and minSdkVersion >= 17."
            ),
            "webview-allow-file-access": (
                "Set setAllowFileAccess(false) unless the WebView "
                "specifically needs to load file:// URLs. Combined with "
                "JS, file access enables local-file exfiltration."
            ),
            "webview-universal-file-access": (
                "Set setAllowUniversalAccessFromFileURLs(false). The "
                "permissive form lets local HTML XHR any origin and "
                "exfiltrate the response."
            ),
            "webview-javascript-enabled": (
                "Disable JS unless the WebView genuinely needs it. If "
                "enabled, audit the WebView's loaded URLs and any "
                "addJavascriptInterface calls."
            ),
            "crypto-des": (
                "Replace DES with AES-256/GCM. DES's 56-bit key space is "
                "brute-forceable in hours on modern hardware."
            ),
            "crypto-ecb-mode": (
                "Switch to AES/GCM/NoPadding (authenticated) or "
                "AES/CBC/PKCS5Padding with a random IV per encryption. "
                "ECB mode leaks plaintext patterns."
            ),
            "crypto-md5": (
                "Replace MD5 with SHA-256 or SHA-3 for any security "
                "purpose (passwords, signatures, integrity). Practical "
                "collisions have existed since 2008."
            ),
            "crypto-sha1": (
                "Replace SHA-1 with SHA-256 or SHA-3. SHA-1 collisions "
                "are practical (SHAttered, 2017) and NIST has deprecated "
                "SHA-1 for digital signatures since 2011."
            ),
            "crypto-insecure-random": (
                "Use java.security.SecureRandom for any security-sensitive "
                "randomness (tokens, IVs, session IDs). java.util.Random "
                "is a non-cryptographic PRNG."
            ),
            "tls-hostname-verifier-allow-all": (
                "Remove the ALLOW_ALL hostname verifier. Use the platform "
                "default verifier or a strict pinning verifier. Accepting "
                "any hostname defeats TLS entirely."
            ),
            "tls-trust-all-certs": (
                "Remove the trust-all X509TrustManager. Use the system "
                "default TrustManagerFactory; pin certificates via "
                "NetworkSecurityConfig if higher assurance is needed."
            ),
            "tls-cleartext-http-url": (
                "Replace http:// with https://. If a cleartext "
                "destination is genuinely required, restrict it via "
                "NetworkSecurityConfig per-domain rather than enabling "
                "cleartext globally."
            ),
            "storage-mode-world-readable": (
                "Drop MODE_WORLD_READABLE — use MODE_PRIVATE. If sharing "
                "data with other apps is intentional, use a "
                "ContentProvider with FileProvider URIs and grantUri "
                "permissions."
            ),
            "storage-mode-world-writeable": (
                "Drop MODE_WORLD_WRITEABLE — use MODE_PRIVATE. World-"
                "writeable files allow other apps to tamper with this "
                "app's state."
            ),
            "storage-external-storage": (
                "Avoid external storage for anything sensitive. Use "
                "Context.getFilesDir() (app-private internal storage) or "
                "encrypted storage via EncryptedFile/EncryptedSharedPrefs."
            ),
            "sql-raw-query-concatenation": (
                "Use parameterised queries: rawQuery(sql, selectionArgs) "
                "or SQLiteDatabase.query()/insert() with bind args. "
                "String concatenation enables SQL injection."
            ),
            "command-exec-concatenation": (
                "Pass commands as String[] (argv) and never concatenate "
                "untrusted input. Better: avoid Runtime.exec entirely; "
                "use the platform API for the operation you actually need."
            ),
            "pending-intent-mutable": (
                "Add PendingIntent.FLAG_IMMUTABLE to the flags argument. "
                "On Android 12+ this is mandatory for security; older "
                "versions ignore the flag harmlessly."
            ),
        }
        return per_rule.get(
            rule_id,
            f"Review the matched {vuln_class} pattern and remediate per "
            f"the rule's `message`. Consult OWASP MASVS for guidance.",
        )
