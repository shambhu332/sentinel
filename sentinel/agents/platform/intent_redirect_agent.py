"""P_010 — Intent Redirect Agent (CWE-926).

Detects the "Intent Redirect" pattern: the app reads an Intent object
(or its components) from an untrusted external source — typically a
``getXxxExtra`` call on the inbound ``Intent`` — and then dispatches
that attacker-controlled Intent through ``startActivity``,
``startService``, ``sendBroadcast`` etc. without sanitising it.

Why this matters: the app's own UID is used to dispatch the
attacker's Intent. That lets an external caller indirectly invoke
exported-with-signature components, internal Activities that were
never meant to be reachable from outside, or system components with
permissions the attacker's UID does not hold. It is the canonical
"confused deputy" on Android (CWE-926). Real bounties at Meta,
Slack, Lyft, Microsoft, etc. have paid in the $1k–$10k range.

Detection
=========
We parse each decompiled ``.java`` file with tree-sitter-java and,
for every method body:

1. Build a list of *tainted* local variables — locals whose value at
   declaration time comes from one of:

   * ``getIntent().getParcelableExtra(…)``  (returns Intent)
   * ``getIntent().getParcelable(…)``       (returns Bundle/Parcelable)
   * ``intent.getParcelableExtra(…)`` where ``intent`` is itself an
     Intent-typed parameter / field reference (best-effort match)
   * ``getIntent().getBundleExtra(…).getParcelable(…)``  (chained)

2. Within the same method, walk forward and look for an *unsanitised*
   dispatch — one of these sink methods called with a tainted variable
   as its (first) argument:

   ``startActivity, startActivities, startActivityForResult,
   startActivityIfNeeded, startService, startForegroundService,
   bindService, sendBroadcast, sendBroadcastAsUser, sendOrderedBroadcast,
   sendStickyBroadcast, startIntentSender``.

3. A sink call is *sanitised* when, between the tainted assignment and
   the dispatch, one of these methods was invoked on the same variable:

   ``setComponent, setPackage, setClassName, setClass, setComponentName,
   setSelector``.

   These force the receiver Component or Package, which prevents
   re-routing to a different (privileged) target — the canonical fix
   recommended by Android's own
   `setPackage <https://developer.android.com/guide/components/intents-filters>`__
   guidance.

Precision ceiling
-----------------
This is a pure intra-procedural AST analysis. We deliberately do *not*:

* Follow assignments through helper methods (Intent → wrap() → dispatch).
  That is what TAINT_001 is for and a future hook is described in
  ``docs/INTENT_FLOW.md``.
* Track the Intent's component graph through arbitrary builder chains.
  We accept that a builder API can hide the sanitiser and flag the
  case as MEDIUM (confidence 0.65) rather than HIGH.

The result: we expect a low false-positive rate on the obvious
single-method anti-pattern and *deliberately under-call* on cases we
cannot resolve without inter-procedural data flow. The companion doc
quantifies this and shows when to escalate to TAINT_001.

Non-goals
---------
``PendingIntent`` mutability (CWE-927) is already covered by
``SG_001``'s ``pending-intent-mutable.yaml`` Semgrep rule. We do not
duplicate it here — the rule is precise enough on a single line and
re-emitting the finding here would inflate the report.
"""
from __future__ import annotations

import logging
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


# Methods on inbound Intents that return an attacker-controlled
# Parcelable/Bundle/Intent — every call site is a taint source.
_INTENT_EXTRA_GETTERS = {
    "getParcelableExtra",
    "getParcelableArrayExtra",
    "getParcelableArrayListExtra",
    "getBundleExtra",
    "getSerializableExtra",
}

# Bundle/Parcelable getters that re-extract an Intent we then dispatch.
_BUNDLE_GETTERS = {
    "getParcelable",
    "getParcelableArrayList",
}

# Receiver text patterns we accept as "an inbound Intent". Best-effort —
# the goal is to catch the common decompiled forms without forcing a
# full type analysis (which JADX output rarely surfaces cleanly).
_INTENT_RECEIVER_HINTS = (
    "getIntent()",
    "intent",
    "this.intent",
    "mIntent",
    "getActivity().getIntent()",
)

# Sinks that dispatch an Intent. We anchor on the *first* argument
# being the suspected Intent variable; that matches every signature
# in `android.content.Context` for these calls.
_DISPATCH_SINKS = {
    "startActivity",
    "startActivities",
    "startActivityForResult",
    "startActivityIfNeeded",
    "startService",
    "startForegroundService",
    "bindService",
    "sendBroadcast",
    "sendBroadcastAsUser",
    "sendOrderedBroadcast",
    "sendOrderedBroadcastAsUser",
    "sendStickyBroadcast",
    "sendStickyOrderedBroadcast",
    "startIntentSender",
    "startIntentSenderForResult",
}

# Methods on an Intent that lock down its target component. If any of
# these is called on the tainted variable before the dispatch, the
# Intent can no longer be redirected to a different target.
_COMPONENT_SANITIZERS = {
    "setComponent",
    "setPackage",
    "setClassName",
    "setClass",
    "setComponentName",
    "setSelector",
}

# Per-scan caps. The AST walk is cheap but bookkeeping for every file
# in a decompiled APK is not — we mirror TAINT_001's defensive caps.
_MAX_FILES = 1500
_MAX_FINDINGS_PER_SCAN = 100
_PARSE_BYTE_LIMIT = 2_000_000  # ~2 MB per file — skip generated giants


@dataclass(frozen=True)
class _SourceHit:
    """One ``Intent extra → local`` taint introduction."""
    var_name: str
    line: int
    code: str
    via_bundle: bool


@dataclass(frozen=True)
class _Hit:
    """A confirmed unsanitised dispatch."""
    file: Path
    var_name: str
    source_line: int
    source_code: str
    sink_method: str
    sink_line: int
    sink_code: str
    via_bundle: bool       # True when the chain went getBundleExtra → getParcelable
    receiver_hint: str     # Receiver text on the sink (for context)


class IntentRedirectAgent(BaseAgent):
    """P_010: AST-based Intent Redirect (CWE-926) detector."""

    AGENT_ID = "P_010"
    VULN_CLASS = "Intent Redirect"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if not _HAS_TS:
            self._log.warning(
                "[P_010] tree-sitter-java unavailable — skipping. "
                "Install via `poetry add tree-sitter tree-sitter-java`.",
            )
            return False
        if ctx.decompiled_dir is None or not ctx.decompiled_dir.exists():
            self._log.info("[P_010] no decompiled directory — skipping")
            return False
        return True

    async def analyze(self) -> list[Finding]:
        root = self._effective_root(self._context.decompiled_dir)
        if root is None:
            return []

        parser = _get_parser()
        hits: list[_Hit] = []
        scanned = 0
        for java_file in self._iter_java_files(root):
            if scanned >= _MAX_FILES:
                self._log.info(
                    "[P_010] reached file cap (%d); skipping remainder",
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
            try:
                tree = parser.parse(src)
            except Exception as e:  # noqa: BLE001
                self._log.debug("[P_010] parse failed for %s: %s",
                                java_file, e)
                continue
            for hit in _scan_tree(tree.root_node, src, java_file):
                hits.append(hit)
                if len(hits) >= _MAX_FINDINGS_PER_SCAN:
                    break
            if len(hits) >= _MAX_FINDINGS_PER_SCAN:
                break

        if not hits:
            self._log.info("[P_010] no Intent Redirect patterns detected")
            return []

        # Dedupe hits with identical (file, sink_line, sink_method) — the
        # same dispatch may be reached by multiple aliases of the tainted
        # variable in pathological decompiled output.
        seen: set[tuple[str, int, str]] = set()
        findings: list[Finding] = []
        for hit in hits:
            key = (str(hit.file), hit.sink_line, hit.sink_method)
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._hit_to_finding(hit, root))

        self._log.info(
            "[P_010] %d Intent Redirect findings from %d files",
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

    def _hit_to_finding(self, hit: _Hit, root: Path) -> Finding:
        try:
            rel = hit.file.relative_to(root)
        except ValueError:
            rel = hit.file
        chain = "Intent extra" + (
            " (via Bundle)" if hit.via_bundle else ""
        )
        severity, confidence = _classify(hit)
        evidence = {
            "title": f"Intent Redirect via {hit.sink_method}",
            "file": str(rel),
            "source_line": hit.source_line,
            "source_code": hit.source_code,
            "sink_line": hit.sink_line,
            "sink_method": hit.sink_method,
            "sink_code": hit.sink_code,
            "variable": hit.var_name,
            "taint_chain": chain,
            "receiver": hit.receiver_hint,
            "cwe": "CWE-926",
        }
        rec = (
            f"At {rel}:{hit.sink_line} the application dispatches an Intent "
            f"({hit.var_name}) read from an external caller via "
            f"{rel}:{hit.source_line}. An attacker who controls the inbound "
            "Intent can substitute an arbitrary inner Intent and cause this "
            "method to invoke a target chosen by the attacker, under this "
            "app's UID and permissions (CWE-926: Inclusion of Functionality "
            "from Untrusted Control Sphere). Fix: before dispatching, pin "
            "the component with setComponent()/setClassName(), or pin the "
            "package with setPackage(\"com.your.app\"). For Intents that "
            "must remain implicit, validate the resolved ComponentName "
            "against an allowlist (PackageManager.resolveActivity) before "
            "dispatch and reject anything outside it."
        )
        return self._make_finding(
            vuln_class=self.VULN_CLASS,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            owasp="M1",
            masvs="MSTG-PLATFORM-3",
            recommendation=rec,
        )


def _classify(hit: _Hit) -> tuple[Severity, float]:
    """Tier the severity and confidence based on what the AST showed.

    HIGH/0.85 — straight extra → dispatch with no observed wrapping
    MEDIUM/0.70 — chain went through a Bundle (less obvious to readers,
                  still exploitable but slightly more fragile to changes
                  in the decompiled output)
    """
    if hit.via_bundle:
        return Severity.MEDIUM, 0.70
    return Severity.HIGH, 0.85


# ---------- Module-level tree-sitter glue (kept here to avoid coupling
#            to TAINT_001 internals).

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


def _line_text(src: bytes, line_no: int) -> str:
    if line_no <= 0:
        return ""
    try:
        text = src.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover
        return ""
    lines = text.splitlines()
    if 0 <= line_no - 1 < len(lines):
        return lines[line_no - 1].strip()[:200]
    return ""


def _walk(node: Any):
    yield node
    for c in node.children:
        yield from _walk(c)


def _invocation_parts(call: Any, src: bytes) -> tuple[str, str, list[Any]]:
    """Return ``(receiver_text, method_name, positional_args)``."""
    name_node = call.child_by_field_name("name")
    obj_node = call.child_by_field_name("object")
    args_node = call.child_by_field_name("arguments")
    method = _text(name_node, src) if name_node is not None else ""
    receiver = _text(obj_node, src) if obj_node is not None else ""
    args: list[Any] = []
    if args_node is not None:
        for c in args_node.children:
            if c.type in {"(", ")", ","}:
                continue
            args.append(c)
    return receiver, method, args


def _receiver_is_intent(receiver: str) -> bool:
    """Best-effort check: does this receiver expression read from an
    inbound Intent? We accept ``getIntent()``, bare ``intent`` /
    ``mIntent``, and field forms — JADX names parameters consistently
    enough that this is reliable in practice.
    """
    if not receiver:
        return False
    rs = receiver.strip()
    if rs in _INTENT_RECEIVER_HINTS:
        return True
    # `getIntent()` may appear inside a parenthesised cast: "(Intent) getIntent()"
    if "getIntent()" in rs:
        return True
    # Bare param name lowercase variants
    if rs.lower() in {"intent", "mintent"}:
        return True
    return False


def _is_intent_extra_source(call: Any, src: bytes) -> tuple[bool, bool]:
    """Return ``(is_source, via_bundle)``.

    ``is_source`` — this call's return value is attacker-controlled.
    ``via_bundle`` — the call shape was ``getBundleExtra(...).getParcelable(...)``
    (or similar): a one-extra-deep chain that still yields an Intent.
    """
    receiver, method, _args = _invocation_parts(call, src)

    if method in _INTENT_EXTRA_GETTERS and _receiver_is_intent(receiver):
        return True, False

    # Chained form: foo.getBundleExtra("x").getParcelable("y")
    # The outer call's receiver is itself a method_invocation whose
    # method is in _INTENT_EXTRA_GETTERS and whose receiver is an Intent.
    if method in _BUNDLE_GETTERS:
        obj = call.child_by_field_name("object")
        if obj is not None and obj.type == "method_invocation":
            inner_recv, inner_name, _ = _invocation_parts(obj, src)
            if (inner_name in _INTENT_EXTRA_GETTERS
                    and _receiver_is_intent(inner_recv)):
                return True, True
    return False, False


def _identifier_text(node: Any, src: bytes) -> str | None:
    """If ``node`` is an identifier (or a parenthesised one), return
    its text; otherwise None.
    """
    if node is None:
        return None
    n = node
    # Strip casts like ((Intent) inner) → inner
    while n.type in {"parenthesized_expression", "cast_expression"}:
        # cast_expression children: ( type ) value
        value = n.child_by_field_name("value")
        if value is not None:
            n = value
            continue
        # Fallback: pick the last identifier child
        idents = [c for c in n.children if c.type == "identifier"]
        if not idents:
            return None
        n = idents[-1]
    if n.type == "identifier":
        return _text(n, src)
    return None


def _scan_method(
    method_node: Any,
    src: bytes,
    file_path: Path,
) -> list[_Hit]:
    """Scan a single method body for source→sink redirect patterns."""
    body = None
    for c in method_node.children:
        if c.type == "block":
            body = c
            break
    if body is None:
        return []

    # 1. Collect tainted variables in this method (intra-procedural).
    tainted: dict[str, _SourceHit] = {}
    # 2. Track sanitiser application per variable (var → True if seen).
    sanitised: set[str] = set()
    # 3. Record dispatches in order so we can interleave correctly.
    hits: list[_Hit] = []

    for n in _walk(body):
        # ---- Source: local_variable_declaration with an init from extras
        if n.type == "local_variable_declaration":
            for decl in n.children:
                if decl.type != "variable_declarator":
                    continue
                name_node = decl.child_by_field_name("name")
                value_node = decl.child_by_field_name("value")
                if name_node is None or value_node is None:
                    continue
                vname = _text(name_node, src)
                # Peel off casts: (Intent) foo.getParcelableExtra("k")
                call = _unwrap_to_invocation(value_node)
                if call is None:
                    continue
                is_src, via_bundle = _is_intent_extra_source(call, src)
                if not is_src:
                    continue
                tainted[vname] = _SourceHit(
                    var_name=vname,
                    line=_line(n),
                    code=_line_text(src, _line(n)),
                    via_bundle=via_bundle,
                )
            continue

        # ---- Source: plain assignment to an already-declared var
        if n.type == "assignment_expression":
            lhs = n.child_by_field_name("left")
            rhs = n.child_by_field_name("right")
            if lhs is None or rhs is None:
                continue
            lhs_name = _identifier_text(lhs, src)
            if lhs_name is None:
                continue
            call = _unwrap_to_invocation(rhs)
            if call is not None:
                is_src, via_bundle = _is_intent_extra_source(call, src)
                if is_src:
                    tainted[lhs_name] = _SourceHit(
                        var_name=lhs_name,
                        line=_line(n),
                        code=_line_text(src, _line(n)),
                        via_bundle=via_bundle,
                    )
                    # Reassignment also clears any prior sanitiser state.
                    sanitised.discard(lhs_name)
                    continue
            # Re-assignment from a non-extras source: clear taint.
            if lhs_name in tainted:
                tainted.pop(lhs_name, None)
                sanitised.discard(lhs_name)
            continue

        # ---- Sink + sanitiser detection: method invocations
        if n.type != "method_invocation":
            continue
        receiver, method, args = _invocation_parts(n, src)

        # Sanitiser: setComponent / setPackage / setClassName on a tainted var
        if method in _COMPONENT_SANITIZERS:
            rcv_name = _identifier_text_from_receiver(n, src)
            if rcv_name in tainted:
                sanitised.add(rcv_name)
            continue

        # Sink: dispatch with first arg being a tainted variable
        if method in _DISPATCH_SINKS and args:
            arg_name = _identifier_text(args[0], src)
            if arg_name and arg_name in tainted and arg_name not in sanitised:
                src_hit = tainted[arg_name]
                line = _line(n)
                hits.append(_Hit(
                    file=file_path,
                    var_name=arg_name,
                    source_line=src_hit.line,
                    source_code=src_hit.code,
                    sink_method=method,
                    sink_line=line,
                    sink_code=_line_text(src, line),
                    via_bundle=src_hit.via_bundle,
                    receiver_hint=receiver,
                ))

    return hits


def _unwrap_to_invocation(node: Any) -> Any | None:
    """Drill through casts/parens and return the underlying
    ``method_invocation`` node, or None.
    """
    n = node
    while n is not None and n.type in {
        "parenthesized_expression", "cast_expression",
    }:
        value = n.child_by_field_name("value")
        n = value if value is not None else (
            n.children[-1] if n.children else None
        )
    if n is not None and n.type == "method_invocation":
        return n
    return None


def _identifier_text_from_receiver(call: Any, src: bytes) -> str | None:
    """For a method_invocation, return the identifier text of its
    receiver (the object the call is made on), peeling casts/parens.
    """
    obj = call.child_by_field_name("object")
    if obj is None:
        return None
    return _identifier_text(obj, src)


def _scan_tree(root: Any, src: bytes, file_path: Path) -> list[_Hit]:
    out: list[_Hit] = []
    for n in _walk(root):
        if n.type in {"method_declaration", "constructor_declaration"}:
            out.extend(_scan_method(n, src, file_path))
    return out


__all__: Iterable[str] = ["IntentRedirectAgent"]
