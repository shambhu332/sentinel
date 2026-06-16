"""TAINT_001 — lightweight tree-sitter-based data-flow tracer.

Why custom and not FlowDroid? FlowDroid is a Soot-based research tool;
integrating it means shipping a JVM, parsing IFDS results, and accepting
several minutes of analysis per APK. For SENTINEL's use case (decompiled
Java from JADX, post-deobfuscation) a smaller analyzer wins: faster,
deterministic, and we keep the algorithm transparent — easy to explain
in code review and easy to extend with new source/sink/sanitizer
patterns. We accept the recall trade-off (no reflection, no field
sensitivity) in exchange for explainability and speed.

Algorithm at a glance
=====================

For each Java source file in the decompiled tree we

1. parse it with tree-sitter-java,
2. enumerate the declared methods (class + method name),
3. build per-method def-use maps (variable name → list of nodes that
   could be its current value at any point — assignments, the
   initialiser, or the formal parameter itself),
4. for every ``method_invocation`` that matches a SINK pattern from
   :mod:`taint_config`, take each tracked argument and run a backward
   slice through the def-use chain until we land on
   * a SOURCE pattern         → tainted, depth 0 (record flow),
   * a SANITIZER pattern       → flow terminates as clean,
   * a literal                 → benign,
   * a method *parameter*      → inter-procedural hop (see below),
   * any unrecognised callable → benign (conservative — we'd rather
                                 miss a flow than ship FPs).

The IPA pass walks at most ``MAX_IPA_DEPTH`` (default 3) call-graph
hops away. For each parameter it finds the callers of the enclosing
method (across the indexed project) and recurses on the argument those
callers passed at the same positional index.

Confidence:

  ====  =================================
  hops  confidence
  ====  =================================
   0    0.9 (sink and source in one method)
   1    0.8
   2    0.7
   3    0.6 (capped — won't go deeper)
  ====  =================================

Sanitizers
----------

When the backward slice walks *through* a sanitizer call whose
``applies_to_classes`` covers the candidate sink's ``vuln_class``, the
flow is marked SANITIZED and discarded (no Finding emitted). This is
the single most important false-positive cutter — every direct
``Integer.parseInt`` between source and SQL sink kills the report.

Scope of analysis
-----------------

* Intra-procedural: complete within a method body.
* Inter-procedural: across method boundaries within the indexed
  decompiled tree (one tree per scan). No cross-DEX, no reflection,
  no virtual-call resolution beyond name match.
* Sensitive to local variables and method parameters. Not sensitive
  to instance fields, static fields, arrays, or collections — these
  would require points-to analysis we deliberately did not build.

Performance
-----------

Two budgets bound work:

* ``per_file_timeout_s``: cumulative analysis time inside one file.
  Checked at each method boundary; on overrun we log + skip the rest
  of the file. Parsing itself is microseconds — the slow part is the
  backward slice on pathological methods.
* ``MAX_FILES``: the analyser caps the number of files it walks. The
  default (1500) is comfortably above any APK we've seen post-JADX
  for application code (vendored libraries are usually excluded).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tree_sitter_java as _ts_java
    from tree_sitter import Language, Node, Parser
    _HAS_TS = True
except ImportError:  # pragma: no cover — declared in pyproject.toml
    _HAS_TS = False
    _ts_java = None  # type: ignore[assignment]
    Language = Parser = Node = None  # type: ignore[assignment,misc]

from sentinel.agents.taint.taint_config import (
    SANITIZERS,
    SINKS,
    SOURCES,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
    confidence_for_depth,
    key_looks_sensitive,
)

logger = logging.getLogger(__name__)


# ---------- Constants ----------

#: Maximum inter-procedural hops the analyser will follow. The spec
#: pins this to 3; raising it costs analysis time non-linearly.
MAX_IPA_DEPTH = 3

#: Hard cap on the number of decompiled .java files to analyse per
#: scan. Mostly defensive — JADX output for a typical APK contains
#: 200-500 application-code .java files; the rest are vendored
#: dependencies we let other agents handle.
MAX_FILES = 1500

#: Default per-file analysis time budget in seconds.
DEFAULT_PER_FILE_TIMEOUT_S = 8.0

#: Hop "kind" tags used in trace records.
_HOP_SOURCE = "source"
_HOP_SINK = "sink"
_HOP_VAR = "variable"
_HOP_CALL = "call"


# ---------- Data classes ----------

@dataclass
class TraceHop:
    """One step in a taint flow — file:line plus the code excerpt."""
    file: str
    line: int
    code: str
    kind: str        # source | sink | variable | call
    label: str = ""  # human-readable annotation (e.g. source name)
    # Zero-based byte offsets within the line for the offending node.
    # Both default to 0 when the upstream constructor didn't pass them
    # (older callers / tests). The frontend treats start==end as "whole
    # line" and falls back to highlighting the full row.
    start_col: int = 0
    end_col: int = 0


@dataclass
class TaintFlow:
    """A complete source → sink path that survived sanitiser check."""
    source: TraceHop
    sink: TraceHop
    hops: list[TraceHop] = field(default_factory=list)
    vuln_class: str = ""
    sink_spec: SinkSpec | None = None
    source_spec: SourceSpec | None = None
    depth: int = 0
    sanitized: bool = False

    @property
    def confidence(self) -> float:
        return confidence_for_depth(self.depth)


@dataclass
class _MethodInfo:
    """Indexed view of a single Java method."""
    qualified_name: str          # "ClassName.methodName"
    simple_name: str
    class_name: str
    file: Path
    source_bytes: bytes
    node: Any                    # tree_sitter.Node (method_declaration)
    body_node: Any | None        # the `block` child, or None for abstract
    param_names: list[str] = field(default_factory=list)
    # variable name → list of expression nodes that are possible
    # current values at any program point in this method.
    def_use: dict[str, list[Any]] = field(default_factory=dict)


# ---------- Parser singleton ----------

_PARSER_CACHE: Parser | None = None


def _get_parser() -> Parser:
    global _PARSER_CACHE
    if _PARSER_CACHE is None:
        if not _HAS_TS:
            raise RuntimeError(
                "tree-sitter-java not installed — install via "
                "`poetry add tree-sitter-java`",
            )
        lang = Language(_ts_java.language())
        _PARSER_CACHE = Parser(lang)
    return _PARSER_CACHE


# ---------- Small AST helpers ----------

def _text(node: Any, src: bytes) -> str:
    """Decode the byte slice for a node."""
    if node is None:
        return ""
    return src[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace",
    )


def _line(node: Any) -> int:
    """1-based line number of a node."""
    return node.start_point[0] + 1 if node is not None else 0


def _cols(node: Any) -> tuple[int, int]:
    """(start_col, end_col) zero-based within the start line.

    When the node spans multiple lines, end_col is clamped to the end
    of the start line so the frontend highlights to end-of-line
    instead of jumping into wrong territory.
    """
    if node is None:
        return (0, 0)
    start_row, start_col = node.start_point
    end_row, end_col = node.end_point
    if end_row != start_row:
        return (start_col, max(start_col, start_col + 80))
    return (start_col, end_col)


def _line_text(src: bytes, line_no: int) -> str:
    """Return the (trimmed) source line ``line_no`` (1-based)."""
    if line_no <= 0:
        return ""
    try:
        text = src.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover — decode("replace") never raises
        return ""
    lines = text.splitlines()
    if 0 <= line_no - 1 < len(lines):
        return lines[line_no - 1].strip()[:200]
    return ""


def _walk(node: Any):
    """Pre-order traversal generator."""
    yield node
    for c in node.children:
        yield from _walk(c)


def _children_of_type(node: Any, type_name: str) -> list[Any]:
    return [c for c in node.children if c.type == type_name]


def _first_of_type(node: Any, type_name: str) -> Any | None:
    for c in node.children:
        if c.type == type_name:
            return c
    return None


# ---------- Method-invocation decomposition ----------

def _invocation_parts(call: Any, src: bytes) -> tuple[str, str, list[Any]]:
    """Return ``(receiver_text, method_name, positional_args)``.

    ``receiver_text`` is the raw decoded source of the object/receiver
    expression (empty string for a bare ``foo()``). ``positional_args``
    is the list of argument expression nodes from the call's
    ``argument_list``, with commas/parens excluded.
    """
    name_node = call.child_by_field_name("name")
    obj_node = call.child_by_field_name("object")
    args_node = call.child_by_field_name("arguments")

    method_name = _text(name_node, src) if name_node is not None else ""
    receiver_text = _text(obj_node, src) if obj_node is not None else ""

    positional: list[Any] = []
    if args_node is not None:
        for c in args_node.children:
            # Skip punctuation and trivia. The non-trivial children
            # are the actual argument expressions.
            if c.type in {"(", ")", ","}:
                continue
            positional.append(c)
    return receiver_text, method_name, positional


def _match_source(call: Any, src: bytes) -> SourceSpec | None:
    receiver, name, _ = _invocation_parts(call, src)
    for spec in SOURCES:
        if spec.method_name != name:
            continue
        if spec.receiver_hint and spec.receiver_hint not in receiver:
            continue
        return spec
    return None


def _match_sink(call: Any, src: bytes) -> SinkSpec | None:
    receiver, name, _ = _invocation_parts(call, src)
    for spec in SINKS:
        if spec.method_name != name:
            continue
        if spec.receiver_hint and spec.receiver_hint not in receiver:
            continue
        return spec
    return None


def _match_sanitizer(
    call: Any, src: bytes, vuln_class: str,
) -> SanitizerSpec | None:
    receiver, name, _ = _invocation_parts(call, src)
    for spec in SANITIZERS:
        if spec.method_name != name:
            continue
        if spec.receiver_hint and spec.receiver_hint not in receiver:
            continue
        # Empty `applies_to_classes` ⇒ universal sanitizer.
        if spec.applies_to_classes and vuln_class not in spec.applies_to_classes:
            continue
        return spec
    return None


# ---------- Per-method index ----------

def _collect_methods(root: Any, src: bytes, file_path: Path) -> list[_MethodInfo]:
    """Walk the AST and produce a ``_MethodInfo`` for each method body."""
    results: list[_MethodInfo] = []
    # Find every method_declaration; record the enclosing class name so
    # method references stay disambiguated when an APK has many
    # MainActivity-equivalent classes across packages.
    class_stack: list[str] = []

    def visit(n: Any) -> None:
        opened_class = False
        if n.type in {"class_declaration", "interface_declaration",
                      "enum_declaration"}:
            ident = n.child_by_field_name("name")
            class_stack.append(_text(ident, src) if ident is not None
                               else "<anon>")
            opened_class = True
        if n.type == "method_declaration" or n.type == "constructor_declaration":
            mname_node = n.child_by_field_name("name")
            mname = _text(mname_node, src) if mname_node is not None else "<?>"
            cls = class_stack[-1] if class_stack else "<top>"
            body = _first_of_type(n, "block")
            params = _collect_param_names(n, src)
            info = _MethodInfo(
                qualified_name=f"{cls}.{mname}",
                simple_name=mname,
                class_name=cls,
                file=file_path,
                source_bytes=src,
                node=n,
                body_node=body,
                param_names=params,
            )
            info.def_use = _build_def_use(info)
            results.append(info)
        for c in n.children:
            visit(c)
        if opened_class:
            class_stack.pop()

    visit(root)
    return results


def _collect_param_names(method_node: Any, src: bytes) -> list[str]:
    params_node = _first_of_type(method_node, "formal_parameters")
    if params_node is None:
        return []
    out: list[str] = []
    for c in params_node.children:
        if c.type == "formal_parameter":
            ident = c.child_by_field_name("name")
            if ident is None:
                # Older grammars don't expose a `name` field — fall back
                # to the last identifier child.
                idents = [k for k in c.children if k.type == "identifier"]
                ident = idents[-1] if idents else None
            if ident is not None:
                out.append(_text(ident, src))
        elif c.type == "spread_parameter":
            # Vararg `String... args` — record the trailing identifier.
            idents = [k for k in c.children if k.type == "identifier"]
            if idents:
                out.append(_text(idents[-1], src))
    return out


def _build_def_use(info: _MethodInfo) -> dict[str, list[Any]]:
    """For each local variable, list every expression that could be its value.

    We walk the body and record:

    * ``local_variable_declaration`` initialisers (``String x = expr;``)
    * ``assignment_expression`` right-hand sides (``x = expr;``)

    Each formal parameter starts with itself as its sole "definition"
    — that placeholder is what triggers IPA when a slice resolves to a
    parameter name.
    """
    duse: dict[str, list[Any]] = {}
    body = info.body_node
    if body is None:
        return duse

    # Seed parameters so a backward slice that hits a parameter name
    # gets a stable handle.
    for p in info.param_names:
        duse.setdefault(p, [])

    for n in _walk(body):
        if n.type == "local_variable_declaration":
            for decl in _children_of_type(n, "variable_declarator"):
                name_node = decl.child_by_field_name("name")
                value_node = decl.child_by_field_name("value")
                if name_node is not None:
                    var = _text(name_node, info.source_bytes)
                    duse.setdefault(var, [])
                    if value_node is not None:
                        duse[var].append(value_node)
        elif n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                var = _text(left, info.source_bytes)
                duse.setdefault(var, []).append(right)
    return duse


# ---------- Project index ----------

class ProjectIndex:
    """All methods in the project, indexed for IPA lookups.

    Method lookups key on the simple (unqualified) name — that's all
    tree-sitter gives us cheaply for a backward analysis. To stop two
    classes with a same-named method confusing the caller graph, we
    also store each call site's receiver text and filter at query time:

    * receiver is empty / ``this`` → call resolves to the caller's own
      class; only callers whose ``class_name`` matches the callee class
      are returned;
    * receiver looks like a class name and matches the callee class →
      returned;
    * receiver is anything else (an instance variable, a chained call,
      …) → we don't have type info, so we permissively include the
      caller. Better recall here than a missed flow.
    """

    def __init__(self) -> None:
        self.methods: list[_MethodInfo] = []
        # callee simple name → list of (caller_method, call_node, receiver_text)
        self._callers_of: dict[str, list[tuple[_MethodInfo, Any, str]]] = {}
        # simple method name → defining _MethodInfo(s)
        self._by_simple_name: dict[str, list[_MethodInfo]] = {}

    def add_file(self, path: Path, src: bytes) -> None:
        try:
            tree = _get_parser().parse(src)
        except Exception as e:  # pragma: no cover — tree-sitter is robust
            logger.warning("[TAINT_001] parse failed for %s: %s", path, e)
            return
        for mi in _collect_methods(tree.root_node, src, path):
            self.methods.append(mi)
            self._by_simple_name.setdefault(mi.simple_name, []).append(mi)

    def freeze(self) -> None:
        """Build the reverse call-graph after every file is loaded."""
        for caller in self.methods:
            if caller.body_node is None:
                continue
            for n in _walk(caller.body_node):
                if n.type != "method_invocation":
                    continue
                receiver, name, _ = _invocation_parts(n, caller.source_bytes)
                if not name:
                    continue
                self._callers_of.setdefault(name, []).append(
                    (caller, n, receiver),
                )

    def callers_of(
        self, simple_name: str, callee_class: str,
    ) -> list[tuple[_MethodInfo, Any]]:
        raw = self._callers_of.get(simple_name, [])
        out: list[tuple[_MethodInfo, Any]] = []
        for caller, call_node, receiver in raw:
            recv = (receiver or "").strip()
            if not recv or recv == "this":
                if caller.class_name == callee_class:
                    out.append((caller, call_node))
            elif recv == callee_class:
                out.append((caller, call_node))
            else:
                # Receiver is an unfamiliar expression — permissive.
                out.append((caller, call_node))
        return out


# ---------- Backward-slice engine ----------

@dataclass
class _SliceResult:
    """Outcome of analysing one expression for taint.

    ``tainted`` is the headline answer. If true, ``source_spec`` and
    ``source_hop`` describe where the taint originated, and ``hops``
    enumerates every intermediate variable/call we walked to get there
    (most-recent-first; we reverse before producing the user-facing
    trace).
    """
    tainted: bool = False
    sanitized: bool = False
    via_param_idx: int | None = None
    via_param_method: _MethodInfo | None = None
    source_spec: SourceSpec | None = None
    source_hop: TraceHop | None = None
    hops: list[TraceHop] = field(default_factory=list)


class _Tracer:
    def __init__(
        self,
        index: ProjectIndex,
        per_file_timeout_s: float,
        max_ipa_depth: int = MAX_IPA_DEPTH,
    ) -> None:
        self.index = index
        self.per_file_timeout_s = per_file_timeout_s
        self.max_ipa_depth = max_ipa_depth

    # ---------- Top-level entry per file ----------

    def trace_file(self, file_path: Path) -> list[TaintFlow]:
        """Run taint analysis for one decompiled file's methods."""
        flows: list[TaintFlow] = []
        per_file_methods = [m for m in self.index.methods if m.file == file_path]
        deadline = time.monotonic() + self.per_file_timeout_s
        for method in per_file_methods:
            if time.monotonic() > deadline:
                logger.warning(
                    "[TAINT_001] per-file timeout (%.1fs) exceeded — "
                    "skipping remaining methods in %s",
                    self.per_file_timeout_s, file_path,
                )
                break
            flows.extend(self._analyze_method(method))
        return flows

    # ---------- One method ----------

    def _analyze_method(self, method: _MethodInfo) -> list[TaintFlow]:
        if method.body_node is None:
            return []
        flows: list[TaintFlow] = []
        src = method.source_bytes
        for call in _walk(method.body_node):
            if call.type != "method_invocation":
                continue
            sink_spec = _match_sink(call, src)
            if sink_spec is None:
                continue

            _, _, positional = _invocation_parts(call, src)
            # Sensitive-key check for SharedPreferences puts. Skip the
            # whole sink unless the literal key matches a known
            # credential hint.
            if sink_spec.key_arg_must_be_sensitive:
                if sink_spec.key_arg_index >= len(positional):
                    continue
                key_node = positional[sink_spec.key_arg_index]
                if key_node.type != "string_literal":
                    # Dynamic key — can't decide statically; skip to
                    # avoid false positives on locale or theme prefs.
                    continue
                if not key_looks_sensitive(_text(key_node, src)):
                    continue

            for arg_idx in sink_spec.arg_indices:
                if arg_idx >= len(positional):
                    continue
                arg_expr = positional[arg_idx]
                result = self._slice_expr(
                    expr=arg_expr,
                    method=method,
                    vuln_class=sink_spec.vuln_class,
                    depth=0,
                    visited=set(),
                )
                if result.sanitized or not result.tainted:
                    continue
                if result.source_hop is None:
                    continue

                _sc, _ec = _cols(call)
                sink_hop = TraceHop(
                    file=str(method.file),
                    line=_line(call),
                    code=_line_text(src, _line(call)),
                    kind=_HOP_SINK,
                    label=sink_spec.method_name,
                    start_col=_sc,
                    end_col=_ec,
                )
                # Trace was built source-first as we recursed back; the
                # caller side ends up at index 0, so the natural read
                # order is source → … → sink. No reverse needed.
                flows.append(TaintFlow(
                    source=result.source_hop,
                    sink=sink_hop,
                    hops=list(result.hops),
                    vuln_class=sink_spec.vuln_class,
                    sink_spec=sink_spec,
                    source_spec=result.source_spec,
                    depth=max(
                        sum(1 for h in result.hops if h.kind == _HOP_CALL),
                        0,
                    ),
                    sanitized=False,
                ))
        return flows

    # ---------- Backward slice on one expression ----------

    def _slice_expr(
        self,
        expr: Any,
        method: _MethodInfo,
        vuln_class: str,
        depth: int,
        visited: set[tuple[str, str]],
    ) -> _SliceResult:
        """Resolve ``expr`` to a SOURCE, BENIGN, or PARAMETER outcome.

        ``visited`` carries ``(method_qname, var_name)`` pairs so a
        cyclic chain ``x = y; y = x;`` terminates instead of recursing
        forever. ``depth`` is the IPA hop count — incremented only when
        we follow a parameter into a caller.
        """
        if expr.type in {
            "string_literal", "decimal_integer_literal",
            "hex_integer_literal", "decimal_floating_point_literal",
            "boolean_literal", "null_literal", "character_literal",
            "octal_integer_literal", "binary_integer_literal",
        }:
            return _SliceResult(tainted=False)

        if expr.type == "parenthesized_expression":
            for c in expr.children:
                if c.type not in {"(", ")"}:
                    return self._slice_expr(c, method, vuln_class, depth, visited)
            return _SliceResult()

        if expr.type == "cast_expression":
            inner = expr.child_by_field_name("value")
            if inner is not None:
                return self._slice_expr(inner, method, vuln_class, depth, visited)
            return _SliceResult()

        if expr.type == "unary_expression":
            inner = expr.child_by_field_name("operand")
            if inner is not None:
                return self._slice_expr(inner, method, vuln_class, depth, visited)
            return _SliceResult()

        if expr.type == "binary_expression":
            return self._slice_binary(expr, method, vuln_class, depth, visited)

        if expr.type == "identifier":
            return self._slice_identifier(
                expr, method, vuln_class, depth, visited,
            )

        if expr.type == "method_invocation":
            return self._slice_invocation(
                expr, method, vuln_class, depth, visited,
            )

        if expr.type == "object_creation_expression":
            # `new File(tainted)` — treat like a call: any tainted ctor
            # argument propagates. We don't model the constructed object
            # as tainted on its own.
            for c in expr.children:
                if c.type == "argument_list":
                    for ac in c.children:
                        if ac.type in {"(", ")", ","}:
                            continue
                        r = self._slice_expr(
                            ac, method, vuln_class, depth, visited,
                        )
                        if r.sanitized:
                            return r
                        if r.tainted:
                            return r
            return _SliceResult()

        if expr.type == "field_access":
            # Not field-sensitive — be honest and treat field reads as
            # unknown rather than guessing.
            return _SliceResult()

        # Anything else (ternary, lambda, array_access, …) is treated
        # as unknown / benign. Documented as a limitation.
        return _SliceResult()

    # ---- helpers per expression type ---------------------------------

    def _slice_binary(
        self,
        expr: Any,
        method: _MethodInfo,
        vuln_class: str,
        depth: int,
        visited: set[tuple[str, str]],
    ) -> _SliceResult:
        left = expr.child_by_field_name("left")
        right = expr.child_by_field_name("right")
        for side in (left, right):
            if side is None:
                continue
            r = self._slice_expr(side, method, vuln_class, depth, visited)
            if r.sanitized:
                return r
            if r.tainted:
                return r
        return _SliceResult()

    def _slice_identifier(
        self,
        ident: Any,
        method: _MethodInfo,
        vuln_class: str,
        depth: int,
        visited: set[tuple[str, str]],
    ) -> _SliceResult:
        src = method.source_bytes
        name = _text(ident, src)

        key = (method.qualified_name, name)
        if key in visited:
            return _SliceResult()
        visited = visited | {key}

        defs = method.def_use.get(name)

        # Parameter with no in-method redefinition → trigger IPA.
        if defs is not None and not defs and name in method.param_names:
            return self._follow_parameter(
                name, method, vuln_class, depth, visited,
            )

        if defs:
            for d in defs:
                r = self._slice_expr(d, method, vuln_class, depth, visited)
                if r.sanitized:
                    return r
                if r.tainted:
                    _sc, _ec = _cols(ident)
                    hop = TraceHop(
                        file=str(method.file),
                        line=_line(ident),
                        code=_line_text(src, _line(ident)),
                        kind=_HOP_VAR,
                        label=name,
                        start_col=_sc,
                        end_col=_ec,
                    )
                    return _SliceResult(
                        tainted=True,
                        source_spec=r.source_spec,
                        source_hop=r.source_hop,
                        hops=r.hops + [hop],
                    )
            # All definitions checked, none tainted.
            return _SliceResult()

        # Unknown identifier (field reference, captured local, etc).
        return _SliceResult()

    def _slice_invocation(
        self,
        call: Any,
        method: _MethodInfo,
        vuln_class: str,
        depth: int,
        visited: set[tuple[str, str]],
    ) -> _SliceResult:
        src = method.source_bytes

        # 1. Sanitizer first — it short-circuits everything downstream.
        san = _match_sanitizer(call, src, vuln_class)
        if san is not None:
            # We still need to know whether the *input* would have been
            # tainted, so that we can mark the result as sanitized and
            # decline to emit. We don't recurse — sanitizer is a hard
            # terminator.
            return _SliceResult(sanitized=True)

        # 2. Source — terminates the chain with TAINTED.
        srcspec = _match_source(call, src)
        if srcspec is not None:
            _sc, _ec = _cols(call)
            hop = TraceHop(
                file=str(method.file),
                line=_line(call),
                code=_line_text(src, _line(call)),
                kind=_HOP_SOURCE,
                label=srcspec.label,
                start_col=_sc,
                end_col=_ec,
            )
            return _SliceResult(
                tainted=True,
                source_spec=srcspec,
                source_hop=hop,
                hops=[],
            )

        # 3. Unknown call: propagate taint from any tainted argument.
        # Conservative on purpose — we don't mark *any* call result as
        # taint-laundering. This is the pure-function assumption: if the
        # output depends on a tainted input we propagate, otherwise we
        # treat it as clean.
        _, _, positional = _invocation_parts(call, src)
        for arg in positional:
            r = self._slice_expr(arg, method, vuln_class, depth, visited)
            if r.sanitized:
                return r
            if r.tainted:
                return r
        return _SliceResult()

    # ---------- IPA: follow a parameter to its callers ----------

    def _follow_parameter(
        self,
        param_name: str,
        method: _MethodInfo,
        vuln_class: str,
        depth: int,
        visited: set[tuple[str, str]],
    ) -> _SliceResult:
        if depth >= self.max_ipa_depth:
            return _SliceResult()
        try:
            param_idx = method.param_names.index(param_name)
        except ValueError:
            return _SliceResult()

        callers = self.index.callers_of(
            method.simple_name, method.class_name,
        )
        if not callers:
            return _SliceResult()

        for caller, call_node in callers:
            _, _, positional = _invocation_parts(
                call_node, caller.source_bytes,
            )
            if param_idx >= len(positional):
                continue
            arg_at_caller = positional[param_idx]
            sub = self._slice_expr(
                expr=arg_at_caller,
                method=caller,
                vuln_class=vuln_class,
                depth=depth + 1,
                visited=visited,
            )
            if sub.sanitized:
                return sub
            if sub.tainted:
                _sc, _ec = _cols(call_node)
                call_hop = TraceHop(
                    file=str(caller.file),
                    line=_line(call_node),
                    code=_line_text(
                        caller.source_bytes, _line(call_node),
                    ),
                    kind=_HOP_CALL,
                    label=(
                        f"{caller.qualified_name} → "
                        f"{method.qualified_name} (arg #{param_idx})"
                    ),
                    start_col=_sc,
                    end_col=_ec,
                )
                return _SliceResult(
                    tainted=True,
                    source_spec=sub.source_spec,
                    source_hop=sub.source_hop,
                    hops=sub.hops + [call_hop],
                )
        return _SliceResult()


# ---------- Public entry point ----------

def analyse_tree(
    root_dir: Path,
    per_file_timeout_s: float = DEFAULT_PER_FILE_TIMEOUT_S,
    max_files: int = MAX_FILES,
    max_ipa_depth: int = MAX_IPA_DEPTH,
) -> list[TaintFlow]:
    """Walk ``root_dir`` for ``*.java`` files and return every taint flow.

    Intended to be called once per scan from :class:`TaintAgent`.
    """
    if not _HAS_TS:
        logger.warning(
            "[TAINT_001] tree-sitter-java unavailable — taint analysis "
            "disabled for this scan",
        )
        return []

    index = ProjectIndex()
    walked = 0
    for path in sorted(root_dir.rglob("*.java")):
        if walked >= max_files:
            logger.info(
                "[TAINT_001] reached MAX_FILES (%d); stopping discovery",
                max_files,
            )
            break
        try:
            src = path.read_bytes()
        except OSError as e:
            logger.debug("[TAINT_001] cannot read %s: %s", path, e)
            continue
        index.add_file(path, src)
        walked += 1
    if walked == 0:
        return []
    index.freeze()

    tracer = _Tracer(
        index=index,
        per_file_timeout_s=per_file_timeout_s,
        max_ipa_depth=max_ipa_depth,
    )

    # Trace each file. We iterate over distinct file paths from the
    # index so a file that contained zero methods (rare) is skipped.
    seen: set[Path] = set()
    all_flows: list[TaintFlow] = []
    for m in index.methods:
        if m.file in seen:
            continue
        seen.add(m.file)
        all_flows.extend(tracer.trace_file(m.file))
    return all_flows


__all__ = [
    "analyse_tree",
    "TaintFlow", "TraceHop",
    "ProjectIndex",
    "MAX_IPA_DEPTH", "MAX_FILES", "DEFAULT_PER_FILE_TIMEOUT_S",
]
