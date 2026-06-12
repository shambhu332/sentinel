"""UI_001 — Activity-graph auth-bypass detector.

Builds a NetworkX DiGraph of activity transitions inferred from
`startActivity(new Intent(this, Foo.class))` and `Intent#setClass`
calls in decompiled Java. Then runs simple-path search from the
LAUNCHER activity to a set of "sensitive sink" activities (admin
panels, payment screens, transfer screens) and flags any path that
does not pass through an "auth gate" (login, OTP, biometric).

Why this beats single-file regex: a screen named `AdminPanelActivity`
might be exported=false (so not reachable directly), but if the
launcher → home → settings → admin chain has no auth check anywhere,
a runtime exploit can drive the app into that state without ever
entering credentials.

Tradeoffs:
  * String-class-name extraction is heuristic — `Class.forName(...)`
    targets are not resolved here (that's REFL_001's job).
  * "Auth gate" detection is keyword-based on activity names and
    `checkCallingOrSelfPermission` references inside the activity.
    A custom-named auth activity may be missed; that's a false
    negative, not a false positive.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)

# Keywords identifying sensitive sink activities (case-insensitive substr)
_SINK_KEYWORDS = (
    "admin", "payment", "transfer", "withdraw", "checkout",
    "settings", "kyc", "wallet", "vault", "balance",
)

# Keywords identifying auth gate activities
_AUTH_KEYWORDS = (
    "login", "signin", "auth", "otp", "biometric", "passcode",
    "pin", "fingerprint", "unlock", "lock",
)

# startActivity(new Intent(this, X.class))
# Captures the class name in `X.class`.
_INTENT_CLASS_RE = re.compile(
    r"new\s+Intent\s*\(\s*[^,]+,\s*([\w.$]+)\.class\s*\)"
)
# `intent.setClass(this, X.class)`
_SETCLASS_RE = re.compile(
    r"\.\s*setClass(?:Name)?\s*\(\s*[^,]+,\s*([\w.$]+)\.class\s*\)"
)

_MAX_FILES = 2500
_MAX_PATHS = 5
_MAX_PATH_LEN = 6


class ActivityGraphAgent(BaseAgent):
    """UI_001: NetworkX-based auth-bypass-path detector."""

    AGENT_ID = "UI_001"
    VULN_CLASS = "Activity Auth-Bypass Path"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        return bool(
            ctx.decompiled_dir
            and ctx.decompiled_dir.exists()
            and ctx.manifest
        )

    async def analyze(self) -> list[Finding]:
        try:
            import networkx as nx
        except ImportError:
            logger.debug("networkx not installed — UI_001 disabled")
            return []

        ctx = self._context
        root = ctx.decompiled_dir
        assert root is not None

        launcher = self._launcher_activity_name()
        if not launcher:
            return []

        # 1) Build the graph: nodes = activity class names, edges =
        # observed startActivity transitions.
        graph = nx.DiGraph()
        activity_files: dict[str, Path] = self._index_activity_files(root)
        for activity, src_path in activity_files.items():
            graph.add_node(activity)
            try:
                text = src_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for tgt in self._extract_transitions(text, activity):
                graph.add_edge(activity, tgt)

        if launcher not in graph:
            return []

        # 2) Sinks = activities whose simple-name matches a sensitive keyword.
        sinks = [
            n for n in graph.nodes
            if any(k in n.lower() for k in _SINK_KEYWORDS)
        ]
        if not sinks:
            return []

        # 3) Auth-gated nodes — activities that look like auth screens
        # OR have permission-check / token-check tokens in their source.
        auth_nodes = self._detect_auth_nodes(activity_files)

        # 4) Find simple paths launcher → sink that visit ZERO auth nodes.
        findings: list[Finding] = []
        for sink in sinks:
            try:
                paths = nx.all_simple_paths(
                    graph, source=launcher, target=sink, cutoff=_MAX_PATH_LEN,
                )
            except nx.NetworkXNoPath:
                continue
            unguarded: list[list[str]] = []
            for p in paths:
                if any(node in auth_nodes for node in p):
                    continue
                unguarded.append(p)
                if len(unguarded) >= _MAX_PATHS:
                    break
            if not unguarded:
                continue
            findings.append(self._make_finding(
                vuln_class=self.VULN_CLASS,
                severity=Severity.HIGH,
                confidence=0.65,
                recommendation=(
                    "An activity-transition path exists from the LAUNCHER "
                    "to a sensitive sink without passing through any "
                    "recognised auth screen or permission check. Verify "
                    "that the sink enforces auth at onCreate (call "
                    "checkCallingOrSelfPermission or a session-token "
                    "guard) — relying on UI flow alone is insufficient."
                ),
                evidence={
                    "launcher": launcher,
                    "sink": sink,
                    "paths": unguarded[:_MAX_PATHS],
                    "path_count": len(unguarded),
                    "graph_size": graph.number_of_nodes(),
                },
            ))
        return findings

    # ---------- helpers ----------

    def _launcher_activity_name(self) -> str | None:
        for act in (self._context.manifest or {}).get("activities", []):
            if not isinstance(act, dict):
                continue
            filters = act.get("intent_filters") or []
            if not isinstance(filters, list):
                continue
            for f in filters:
                if not isinstance(f, dict):
                    continue
                cats = f.get("categories") or []
                if "android.intent.category.LAUNCHER" in cats:
                    name = act.get("name", "")
                    if name:
                        return name.split(".")[-1]
        return None

    def _index_activity_files(self, root: Path) -> dict[str, Path]:
        """Map simple-name -> Java source path for every activity-like file.

        Heuristic: any .java file whose contents reference
        `extends Activity`, `extends AppCompatActivity`, or
        `extends FragmentActivity`.
        """
        out: dict[str, Path] = {}
        scanned = 0
        for path in root.rglob("*.java"):
            scanned += 1
            if scanned > _MAX_FILES:
                break
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                continue
            if "extends Activity" not in head and \
               "extends AppCompatActivity" not in head and \
               "extends FragmentActivity" not in head:
                continue
            out[path.stem] = path
        return out

    @staticmethod
    def _extract_transitions(text: str, source_activity: str) -> list[str]:
        targets: set[str] = set()
        for pat in (_INTENT_CLASS_RE, _SETCLASS_RE):
            for m in pat.finditer(text):
                cls = m.group(1).split(".")[-1]
                if cls != source_activity:
                    targets.add(cls)
        return sorted(targets)

    @staticmethod
    def _detect_auth_nodes(activity_files: dict[str, Path]) -> set[str]:
        out: set[str] = set()
        for name, path in activity_files.items():
            lower = name.lower()
            if any(k in lower for k in _AUTH_KEYWORDS):
                out.add(name)
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Any explicit permission/token check counts as a gate.
            if any(t in text for t in (
                "checkCallingOrSelfPermission",
                "enforceCallingOrSelfPermission",
                "isUserAuthenticated",
                "isLoggedIn",
                "validateSession",
                "BiometricPrompt",
                "FingerprintManager",
            )):
                out.add(name)
        return out


__all__ = ["ActivityGraphAgent"]
