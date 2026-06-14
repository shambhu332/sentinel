"""Unit tests for sentinel.symbolic.solver — the z3 wrapper used by
D_052 (Symbolic Intent) and D_072 (JNI Shadow Executor).
"""
from __future__ import annotations

import pytest

from sentinel.symbolic import SolverResult, SymbolDecl, solve_constraints


def test_bool_guard_solved():
    decls = [SymbolDecl("isPremium", "bool", "isPremium", default=False)]
    r = solve_constraints(decls, ["isPremium"])
    assert r.sat is True
    assert r.witness == {"isPremium": True}


def test_negated_bool_guard_solved():
    decls = [SymbolDecl("debugOn", "bool", "debugOn", default=True)]
    r = solve_constraints(decls, ["!debugOn"])
    assert r.sat is True
    assert r.witness == {"debugOn": False}


def test_string_equality_via_equals():
    decls = [SymbolDecl("role", "string", "role")]
    r = solve_constraints(decls, ['role.equals("admin")'])
    assert r.sat is True
    assert r.witness == {"role": "admin"}


def test_string_equality_via_double_equals():
    decls = [SymbolDecl("code", "string", "code")]
    r = solve_constraints(decls, ['code == "OPEN_SESAME"'])
    assert r.sat is True
    assert r.witness == {"code": "OPEN_SESAME"}


def test_int_comparison_ge():
    decls = [SymbolDecl("level", "int", "debug_level", default=0)]
    r = solve_constraints(decls, ["level >= 5"])
    assert r.sat is True
    assert r.witness["debug_level"] >= 5


def test_conjunction_string_and_int():
    decls = [
        SymbolDecl("role", "string", "role"),
        SymbolDecl("level", "int", "level"),
    ]
    r = solve_constraints(decls, ['role.equals("admin") && level >= 7'])
    assert r.sat is True
    assert r.witness["role"] == "admin"
    assert r.witness["level"] >= 7


def test_unsat_when_contradicting_int_clauses():
    decls = [SymbolDecl("x", "int", "x", default=0)]
    r = solve_constraints(decls, ["x > 5", "x < 0"])
    assert r.sat is False
    assert r.reason == "unsat"


def test_unsat_when_contradicting_string_clauses():
    decls = [SymbolDecl("role", "string", "role")]
    r = solve_constraints(decls, ['role.equals("admin")',
                                   'role.equals("user")'])
    assert r.sat is False


def test_unmodelable_guard_is_skipped_not_unsat():
    # If we can't encode the guard, the solver treats it as no
    # constraint — the rest of the formula still gets solved.
    decls = [SymbolDecl("ready", "bool", "ready")]
    r = solve_constraints(decls, ["someCallThatWeCantParse()", "ready"])
    assert r.sat is True
    assert r.witness == {"ready": True}
    assert "someCallThatWeCantParse()" in r.skipped_guards


def test_default_preserved_when_z3_doesnt_constrain_variable():
    # A variable that doesn't appear in any guard takes its default.
    decls = [
        SymbolDecl("ready", "bool", "ready"),
        SymbolDecl("locale", "string", "locale", default="en"),
    ]
    r = solve_constraints(decls, ["ready"])
    assert r.sat is True
    assert r.witness["ready"] is True
    assert r.witness.get("locale") == "en"


def test_encoded_constraints_recorded():
    decls = [SymbolDecl("isPremium", "bool", "isPremium")]
    r = solve_constraints(decls, ["isPremium"])
    assert len(r.encoded_constraints) == 1
    # z3 stringifies a plain Bool sym as its name
    assert "isPremium" in r.encoded_constraints[0]


def test_no_z3_installed_returns_sat_false_with_reason(monkeypatch):
    import sys
    # Pretend z3 isn't installed by hiding it from the import path
    monkeypatch.setitem(sys.modules, "z3", None)
    decls = [SymbolDecl("isPremium", "bool", "isPremium")]
    r = solve_constraints(decls, ["isPremium"])
    assert r.sat is False
    assert "z3-solver missing" in r.reason


def test_solver_result_dict_shape():
    r = SolverResult(sat=True, witness={"a": 1})
    d = r.to_dict()
    assert d["sat"] is True
    assert d["witness"] == {"a": 1}
    assert d["encoded_constraints"] == []
    assert d["skipped_guards"] == []
