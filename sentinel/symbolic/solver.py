"""z3 wrapper used by D_052 Symbolic Intent Explorer.

Three things this module owns:

  * `SymbolDecl`        — declarative binding of a Java-side variable
                          to a z3 symbol + the extras-key it maps to
                          when we decode the witness
  * `encode_guard`      — parses a Java guard string ("var == 5",
                          'role.equals("admin")', "isAdmin",
                          "code > 0 && role.equals(\"x\")") into a z3
                          expression. Returns None when nothing in the
                          guard matches a declared symbol (caller
                          treats that as "unknown — assume satisfiable").
  * `solve_constraints` — runs z3.Solver against a guard list and
                          returns a SolverResult carrying the
                          witness assignment per extras-key.

Why pull this out of d052 into its own module:
  * D_072 JNI Shadow Executor needs the same constraint-decode
    plumbing for symbolic offsets into native buffers.
  * Future Frida hooks (symbolic_intent.ts) receive the SolverResult
    serialised — keeping the model assembly here keeps the agent
    code small.

Fails open: when z3-solver is not installed (the `symbolic` extra is
not active) every entrypoint returns a SolverResult with sat=False
and reason="z3-solver missing". Agents check the flag and degrade.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Recognised guard shapes — kept here as the single source of truth.
_STR_EQ_RE = re.compile(
    r'(\w+)\s*(?:==|\.equals\s*\(\s*)\s*"([^"]+)"',
)
_INT_CMP_RE = re.compile(
    r'(\w+)\s*(==|>=|<=|>|<|!=)\s*(-?\d+)',
)
_BOOL_RE = re.compile(
    r"\bif\s*\(\s*(!?)(\w+)\s*\)",
)
# Top-level `&&` split — naive but robust enough for the shape we care
# about; we do not handle parenthesised disjunction (z3 still gets the
# conjunction of every clause we DO recognise).
_AND_SPLIT_RE = re.compile(r"\s+&&\s+")


@dataclass(frozen=True)
class SymbolDecl:
    """One Java-side variable -> (z3 sort, extras-key)."""

    name: str                  # local Java variable name in the guard
    kind: str                  # "bool" | "int" | "string"
    extras_key: str            # the key under getXXXExtra("key", ...)
    default: Any = None        # default value the Java code passed in


@dataclass
class SolverResult:
    """Output of solve_constraints."""

    sat: bool
    witness: dict[str, Any] = field(default_factory=dict)
    encoded_constraints: list[str] = field(default_factory=list)
    skipped_guards: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sat": self.sat,
            "witness": self.witness,
            "encoded_constraints": self.encoded_constraints,
            "skipped_guards": self.skipped_guards,
            "reason": self.reason,
        }


def _z3_available() -> bool:
    try:
        import z3  # noqa: F401
        return True
    except ImportError:
        return False


def encode_guard(
    guard: str,
    symbols: dict[str, Any],
):
    """Translate a single Java guard string into a z3 expression.

    Supports `&&`-joined clauses. Each clause matches one of three
    families — string equality, int comparison, bare boolean. Returns
    None when no clause is encodable, or the resulting z3 expression
    (And(...) when multiple clauses match).
    """
    if not _z3_available():
        return None
    from z3 import And, Not, StringVal

    parts: list[Any] = []
    for clause in _AND_SPLIT_RE.split(guard):
        clause = clause.strip()
        if not clause:
            continue

        # 1) String equality (covers .equals + ==)
        m = _STR_EQ_RE.search(clause)
        if m and m.group(1) in symbols:
            parts.append(symbols[m.group(1)] == StringVal(m.group(2)))
            continue

        # 2) Integer comparison
        m = _INT_CMP_RE.search(clause)
        if m and m.group(1) in symbols:
            sym = symbols[m.group(1)]
            op = m.group(2)
            n = int(m.group(3))
            mapping = {
                "==": sym == n, "!=": sym != n,
                ">":  sym > n,  ">=": sym >= n,
                "<":  sym < n,  "<=": sym <= n,
            }
            parts.append(mapping[op])
            continue

        # 3) Bare boolean: `var` or `!var`
        m = _BOOL_RE.search(f"if({clause})")
        if m and m.group(2) in symbols:
            sym = symbols[m.group(2)]
            parts.append(Not(sym) if m.group(1) == "!" else sym)
            continue

    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return And(*parts)


def solve_constraints(
    decls: list[SymbolDecl],
    guards: list[str],
) -> SolverResult:
    """Solve the conjunction of every encodable guard.

    The result is the assignment a runtime caller (Frida hook) can use
    to construct an Intent that satisfies every guard simultaneously.
    Decls drive both z3 sort selection and the witness decoding.
    """
    if not _z3_available():
        return SolverResult(
            sat=False, reason="z3-solver missing — install with 'symbolic' extra",
        )

    from z3 import Bool, Int, Solver, String
    from z3 import sat as z3_sat

    symbols: dict[str, Any] = {}
    for d in decls:
        if d.kind == "bool":
            symbols[d.name] = Bool(d.name)
        elif d.kind == "int":
            symbols[d.name] = Int(d.name)
        else:
            symbols[d.name] = String(d.name)

    solver = Solver()
    encoded: list[str] = []
    skipped: list[str] = []
    for g in guards:
        expr = encode_guard(g, symbols)
        if expr is None:
            skipped.append(g)
            continue
        solver.add(expr)
        encoded.append(str(expr))

    if solver.check() != z3_sat:
        return SolverResult(
            sat=False,
            encoded_constraints=encoded,
            skipped_guards=skipped,
            reason="unsat",
        )

    model = solver.model()
    witness: dict[str, Any] = {}
    for d in decls:
        sym = symbols[d.name]
        val = model[sym]
        if val is None:
            # z3 didn't constrain this variable — keep the default the
            # Java code uses so the runtime Intent is still well-formed.
            if d.default is not None:
                witness[d.extras_key] = d.default
            continue
        if d.kind == "bool":
            witness[d.extras_key] = bool(val)
        elif d.kind == "int":
            witness[d.extras_key] = val.as_long()
        else:
            raw = val.as_string() if hasattr(val, "as_string") else str(val)
            witness[d.extras_key] = raw.strip('"')

    return SolverResult(
        sat=True,
        witness=witness,
        encoded_constraints=encoded,
        skipped_guards=skipped,
        reason="sat",
    )


__all__ = [
    "SolverResult",
    "SymbolDecl",
    "encode_guard",
    "solve_constraints",
]
