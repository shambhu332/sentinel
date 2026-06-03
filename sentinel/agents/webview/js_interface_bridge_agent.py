"""C_008 — JavaScript Interface Bridge Method Auditor.

Where C_004 detects the *call site* (``webView.addJavascriptInterface(obj, "name")``)
and SG_001's ``webview-javascript-interface-exposure`` rule confirms it via
pattern match, **neither agent looks at the bridge class itself** — i.e.
the Java object that gets handed to JavaScript. That object's
``@JavascriptInterface``-annotated methods are the actual attack surface.
This agent fills that gap by classifying every annotated method by what
it lets attacker-controlled JavaScript do under the app's UID.

Why this matters
================
The Android contract is that ``@JavascriptInterface`` methods on the
bridge object are callable from JavaScript loaded into the WebView.
If the WebView ever loads remote content (or remote content can be
injected via cleartext / open-redirect / postMessage to an attacker
origin), each annotated method becomes an attacker-callable function.
Real payouts:

* **JavascriptInterface → Runtime.exec** — JS-to-RCE in the app's UID
  ($5k–25k at Slack, Lyft, Microsoft, multiple banking apps)
* **JS-callable arbitrary file write / delete** ($1k–10k)
* **JS-callable reflection on a String arg** (``Class.forName(name)``
  → ``getMethod(...).invoke``) — also RCE in practice ($1k–10k)
* **Device-identifier read / SharedPreferences token read** — PII /
  session-token exfiltration ($500–2k)

Detection
=========
We parse each decompiled ``.java`` file with tree-sitter-java, walk all
class bodies, and for every method whose modifiers include
``@JavascriptInterface``, classify the method body by what it exposes:

CRITICAL (RCE primitive)
    ``Runtime.getRuntime().exec(`` / ``ProcessBuilder(`` / ``loadClass(``
HIGH (filesystem write / reflection / Intent dispatch)
    ``openFileOutput`` / ``FileOutputStream(`` / ``delete()`` /
    ``Class.forName(`` / ``getMethod(`` /
    ``startActivity(`` / ``sendBroadcast(`` / ``startService(``
MEDIUM (filesystem read / identifier exfil / sensitive prefs)
    ``FileInputStream(`` / ``openFileInput`` /
    ``getDeviceId`` / ``getImei`` / ``getAndroidId`` / ``getAccounts(`` /
    ``SharedPreferences`` ``getString(`` of a sensitive-keyword key
LOW (bridge exists at all — informational)
    Annotated method with none of the above. Still recorded because
    bridge presence is a precondition for every escalation chain
    above and exporting *any* surface to remote JS is a documented
    risk (Android docs explicitly warn against it).

Precision ceiling
-----------------
Pure intra-procedural body-scan. We deliberately do *not*:

* Follow taint from the method parameter through helpers
  (``exec(sanitise(input))``). That is the job of TAINT_001.
* Verify whether the WebView the bridge is attached to *actually*
  loads remote content. C_004 / SG_001 already inspect call-sites
  and ``loadUrl`` patterns; correlation belongs in COR_001.

The result is intentionally call-site-agnostic: a bridge method that
calls ``Runtime.exec`` is **always** worth flagging, because every
``addJavascriptInterface`` call elsewhere in the app weaponises it.

Non-goals
---------
The classifier does not infer parameter taint. A bridge method that
``exec()``s a literal hardcoded string is still flagged HIGH/CRITICAL:
that's a deliberate, conservative bias since the *call to* ``exec``
is the dangerous capability and JS can swap the literal later via
build-time string obfuscation defeats.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

try:
    import tree_sitter_java as _ts_java
    from tree_sitter import Language, Parser
    _HAS_TS = True
except ImportError:  # pragma: no cover — declared in pyproject.toml
    _HAS_TS = False
    _ts_java = None  # type: ignore[assignment]
    Language = Parser = None  # type: ignore[assignment,misc]


# ---------- Severity classification patterns ----------
#
# Substring tests over the (whitespace-collapsed) method body. We are
# intentionally permissive about receiver text since decompiled JADX
# output rewrites receivers freely.

_CRITICAL_PATTERNS: tuple[str, ...] = (
    "Runtime.getRuntime().exec",
    "ProcessBuilder(",
    ".loadClass(",
)

_HIGH_PATTERNS: tuple[str, ...] = (
    # Filesystem write / delete
    "openFileOutput(",
    "FileOutputStream(",
    "FileWriter(",
    ".delete()",
    # Reflection on (potentially attacker-controlled) name
    "Class.forName(",
    ".getMethod(",
    ".getDeclaredMethod(",
    # Intent dispatch — composes with P_010's threat model
    "startActivity(",
    "startActivities(",
    "sendBroadcast(",
    "startService(",
    "startForegroundService(",
)

_MEDIUM_PATTERNS: tuple[str, ...] = (
    # Filesystem read
    "FileInputStream(",
    "openFileInput(",
    # Device identifiers (PII)
    "getDeviceId(",
    "getImei(",
    "getAndroidId(",
    "Settings.Secure.ANDROID_ID",
    "getAccounts(",
    "getSubscriberId(",
    "getSimSerialNumber(",
)

# SharedPreferences read with a sensitive-looking key bumps the
# finding to MEDIUM. The key list mirrors TAINT_001's
# SENSITIVE_KEY_HINTS so chained finding correlation is consistent.
_SENSITIVE_KEY_RE = re.compile(
    r'getString\s*\(\s*"[^"]*('
    r'token|auth|password|passwd|pwd|secret|api[_-]?key|session|jwt|cookie|'
    r'oauth|refresh|access[_-]?key|credential'
    r')[^"]*"',
    re.IGNORECASE,
)

# Per-scan caps mirror the other AST agents.
_MAX_FILES = 1500
_MAX_FINDINGS_PER_SCAN = 100
_PARSE_BYTE_LIMIT = 2_000_000


@dataclass(frozen=True)
class _BridgeMethod:
    """One ``@JavascriptInterface``-annotated method."""
    file: Path
    class_name: str
    method_name: str
    line: int
    body_text: str
    severity: Severity
    category: str
    trigger: str  # The pattern that triggered the tier — for evidence


class JavaScriptInterfaceBridgeAgent(BaseAgent):
    """C_008: bridge-side audit of ``@JavascriptInterface`` methods."""

    AGENT_ID = "C_008"
    VULN_CLASS = "JavaScript Interface Bridge"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if not _HAS_TS:
            self._log.warning(
                "[C_008] tree-sitter-java unavailable — skipping. "
                "Install via `poetry add tree-sitter tree-sitter-java`.",
            )
            return False
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            self._log.info("[C_008] no decompiled directory — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        root = self._effective_root(self._context.decompiled_dir)
        if root is None:
            return []

        parser = _get_parser()
        bridges: list[_BridgeMethod] = []
        scanned = 0

        for java_file in self._iter_java_files(root):
            if scanned >= _MAX_FILES:
                self._log.info(
                    "[C_008] reached file cap (%d); skipping remainder",
                    _MAX_FILES,
                )
                break
            scanned += 1
            try:
                src = java_file.read_bytes()
            except OSError:
                continue
            if len(src) == 0 or len(src) > _PARSE_BYTE_LIMIT:
                continue
            # Cheap pre-filter: skip files that don't mention the
            # annotation at all. tree-sitter is fast but the parse
            # for an unrelated 100kB class is still wasted work.
            if b"JavascriptInterface" not in src:
                continue
            try:
                tree = parser.parse(src)
            except Exception as e:  # noqa: BLE001
                self._log.debug("[C_008] parse failed for %s: %s",
                                java_file, e)
                continue
            for bm in _scan_tree(tree.root_node, src, java_file):
                bridges.append(bm)
                if len(bridges) >= _MAX_FINDINGS_PER_SCAN:
                    break
            if len(bridges) >= _MAX_FINDINGS_PER_SCAN:
                break

        if not bridges:
            self._log.info("[C_008] no @JavascriptInterface methods detected")
            return []

        # One Finding per annotated method. Dedupe by
        # (file, class, method) so an over-eager AST walk can't
        # double-fire on the same source location.
        seen: set[tuple[str, str, str]] = set()
        findings: list[Finding] = []
        for bm in bridges:
            key = (str(bm.file), bm.class_name, bm.method_name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._bridge_to_finding(bm, root))

        self._log.info(
            "[C_008] %d JS-interface bridge findings from %d files",
            len(findings), scanned,
        )
        return findings

    # ---------- Helpers ----------

    @staticmethod
    def _effective_root(decompiled_dir: Path | None) -> Path | None:
        if decompiled_dir is None:
            return None
        sources = decompiled_dir / "sources"
        if sources.exists() and sources.is_dir():
            return sources
        return decompiled_dir

    @staticmethod
    def _iter_java_files(root: Path) -> Iterable[Path]:
        for p in root.rglob("*.java"):
            if p.is_file():
                yield p

    def _bridge_to_finding(self, bm: _BridgeMethod, root: Path) -> Finding:
        try:
            rel = bm.file.relative_to(root)
        except ValueError:
            rel = bm.file
        confidence = _confidence_for_severity(bm.severity)
        evidence = {
            "title": (
                f"@JavascriptInterface method exposes {bm.category} "
                f"to remote JS"
            ),
            "file": str(rel),
            "class": bm.class_name,
            "method": bm.method_name,
            "line": bm.line,
            "category": bm.category,
            "trigger": bm.trigger,
        }
        rec = (
            f"In {rel}:{bm.line} the method "
            f"{bm.class_name}.{bm.method_name}() is annotated "
            f"@JavascriptInterface, which makes it callable from any "
            f"JavaScript loaded into a WebView that uses this bridge. "
            f"The method body invokes a {bm.category} primitive "
            f"({bm.trigger}), giving remote JS the same capability "
            "under the app's UID. Fix: (1) remove the @JavascriptInterface "
            "annotation from any method that does not need to be "
            "JS-callable; (2) for methods that must remain exposed, "
            "validate every argument against a strict allow-list before "
            "use and never pass a JS-supplied string to Runtime.exec, "
            "reflection, or filesystem APIs; (3) ensure the WebView is "
            "only ever loaded with controlled, signed, in-app content "
            "(WebViewAssetLoader) — never remote URLs that an attacker "
            "could control via MITM, open redirect, or postMessage."
        )
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=bm.severity,
            confidence=confidence,
            evidence=evidence,
            owasp="M7",
            masvs="MSTG-PLATFORM-7",
            recommendation=rec,
        )


def _confidence_for_severity(s: Severity) -> float:
    """Confidence scales inversely with detection ambiguity.

    The patterns are intentionally substring-anchored, so a CRITICAL
    hit (``Runtime.exec``) is essentially certain when the method
    is annotated. LOW hits are flagged on annotation alone and carry
    intentionally lower confidence to keep noise down.
    """
    return {
        Severity.CRITICAL: 0.92,
        Severity.HIGH: 0.85,
        Severity.MEDIUM: 0.75,
        Severity.LOW: 0.50,
    }[s]


# ---------- tree-sitter glue ----------

_PARSER: Parser | None = None


def _get_parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        if not _HAS_TS:
            raise RuntimeError("tree-sitter-java not installed")
        lang = Language(_ts_java.language())
        _PARSER = Parser(lang)
    return _PARSER


def _text(node: Any, src: bytes) -> str:
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _line(node: Any) -> int:
    return node.start_point[0] + 1 if node is not None else 0


def _walk(node: Any):
    yield node
    for c in node.children:
        yield from _walk(c)


def _class_name_of(method_node: Any, src: bytes) -> str:
    """Return the enclosing class' simple name, or '<unknown>'."""
    n = method_node.parent
    while n is not None:
        if n.type in {"class_declaration", "interface_declaration",
                      "enum_declaration", "record_declaration"}:
            name = n.child_by_field_name("name")
            return _text(name, src) if name is not None else "<unknown>"
        n = n.parent
    return "<unknown>"


def _method_has_jsi_annotation(method_node: Any, src: bytes) -> bool:
    """True when ``@JavascriptInterface`` (any qualifier prefix) is
    among the method's modifiers.
    """
    for child in method_node.children:
        if child.type == "modifiers":
            for ann in child.children:
                if ann.type in {"annotation", "marker_annotation"}:
                    name = ann.child_by_field_name("name")
                    text = _text(name, src) if name is not None else _text(ann, src)
                    if text.endswith("JavascriptInterface"):
                        return True
    return False


def _method_body_text(method_node: Any, src: bytes) -> str:
    body = None
    for c in method_node.children:
        if c.type == "block":
            body = c
            break
    return _text(body, src) if body is not None else ""


def _classify(body: str) -> tuple[Severity, str, str] | None:
    """Return ``(severity, category, trigger)`` for the worst tier hit,
    or ``None`` if nothing matched (caller will record it as LOW).
    """
    for pat in _CRITICAL_PATTERNS:
        if pat in body:
            return Severity.CRITICAL, "command-execution / class-loading", pat
    for pat in _HIGH_PATTERNS:
        if pat in body:
            if pat in {"openFileOutput(", "FileOutputStream(", "FileWriter(",
                      ".delete()"}:
                cat = "filesystem-write"
            elif pat in {"Class.forName(", ".getMethod(",
                        ".getDeclaredMethod("}:
                cat = "reflection"
            else:
                cat = "intent-dispatch"
            return Severity.HIGH, cat, pat
    for pat in _MEDIUM_PATTERNS:
        if pat in body:
            if pat in {"FileInputStream(", "openFileInput("}:
                cat = "filesystem-read"
            else:
                cat = "device-identifier"
            return Severity.MEDIUM, cat, pat
    m = _SENSITIVE_KEY_RE.search(body)
    if m is not None:
        return Severity.MEDIUM, "sensitive-preferences-read", m.group(0)[:80]
    return None


def _scan_tree(root: Any, src: bytes, file_path: Path) -> list[_BridgeMethod]:
    out: list[_BridgeMethod] = []
    for n in _walk(root):
        if n.type != "method_declaration":
            continue
        if not _method_has_jsi_annotation(n, src):
            continue
        name_node = n.child_by_field_name("name")
        method_name = _text(name_node, src) if name_node is not None else "<anon>"
        cls = _class_name_of(n, src)
        body = _method_body_text(n, src)
        classified = _classify(body)
        if classified is None:
            sev, cat, trigger = (
                Severity.LOW, "bridge-exposure", "@JavascriptInterface",
            )
        else:
            sev, cat, trigger = classified
        out.append(_BridgeMethod(
            file=file_path,
            class_name=cls,
            method_name=method_name,
            line=_line(n),
            body_text=body,
            severity=sev,
            category=cat,
            trigger=trigger,
        ))
    return out


__all__: Iterable[str] = ["JavaScriptInterfaceBridgeAgent"]
