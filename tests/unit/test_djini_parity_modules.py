"""Unit tests for the djini-parity build-out modules.

Covers (one module per section):

* sentinel/exploit/poc_studio.py
* sentinel/reports/cvss.py
* sentinel/reports/sarif.py
* sentinel/reports/siem.py
* sentinel/agents/api_security/openapi_inferrer.py
* sentinel/fuzz/harness_gen.py
* sentinel/devices/pool.py
* sentinel/planner/planner.py

The tests are deliberately small + deterministic — no Frida, no
mitmproxy, no AFL++ toolchain. Each one exercises one contract that
breaks silently if a future commit touches the wrong piece.
"""
from __future__ import annotations

import asyncio
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from sentinel.core.finding import Finding, Severity

# ----------------------------- helpers ------------------------------------


def _mk_finding(
    agent_id: str = "D_072",
    severity: Severity = Severity.HIGH,
    evidence: dict[str, Any] | None = None,
    vuln_class: str = "JNI Native RCE",
    recommendation: str = "Patch the export",
) -> Finding:
    return Finding(
        session_id="test-session-1234",
        agent_id=agent_id,
        vuln_class=vuln_class,
        severity=severity,
        confidence=0.85,
        recommendation=recommendation,
        evidence=evidence or {"file": "app/MainActivity.java", "line": 42},
    )


# ----------------------------- poc_studio ---------------------------------


def test_poc_studio_eligibility_routing():
    from sentinel.exploit.poc_studio import _pick_format, studio_can_handle

    frida_finding = _mk_finding(evidence={
        "dynamic_target": True,
        "frida_payload": {"probes": ["%n%n%n"]},
        "frida_method": "jnishadow",
    })
    assert studio_can_handle(frida_finding)
    assert _pick_format(frida_finding) == "frida_python"

    http_finding = _mk_finding(
        agent_id="N_006",
        evidence={"url": "https://api.example.com/users/42"},
    )
    assert studio_can_handle(http_finding)
    assert _pick_format(http_finding) == "shell_curl"

    xss_finding = _mk_finding(
        agent_id="D_086",
        evidence={"html_payload": "<script>alert(1)</script>"},
    )
    assert studio_can_handle(xss_finding)
    assert _pick_format(xss_finding) == "html_xss"

    not_eligible = _mk_finding(evidence={"file": "x.java", "line": 1})
    assert not studio_can_handle(not_eligible)


def test_poc_studio_emit_for_scan_writes_index(tmp_path: Path):
    from sentinel.exploit.poc_studio import emit_for_scan

    findings = [
        _mk_finding(evidence={
            "dynamic_target": True,
            "frida_payload": {"probes": [{"kind": "canary", "value": "AAAA"}]},
            "frida_method": "jnishadow",
        }),
        _mk_finding(
            agent_id="N_006", vuln_class="API Key Leak",
            evidence={"url": "https://api.example.com/login"},
        ),
        _mk_finding(
            agent_id="D_086", vuln_class="Intent XSS",
            evidence={"html_payload": "<script>1</script>"},
        ),
    ]
    out = tmp_path / "poc"
    arts = emit_for_scan(findings, out, target_package="com.x.app", allow_live=False)
    assert len(arts) == 3
    assert all(a.path.exists() for a in arts)
    assert (out / "index.json").exists()
    index = json.loads((out / "index.json").read_text())
    assert {row["format"] for row in index} == {"frida_python", "shell_curl", "html_xss"}
    # No live PoC: every artifact must be non-runnable.
    assert all(row["is_runnable"] is False for row in index)


def test_poc_studio_live_mode_marks_runnable(tmp_path: Path):
    from sentinel.exploit.poc_studio import emit_for_scan

    findings = [_mk_finding(evidence={
        "dynamic_target": True,
        "frida_payload": {"probes": []},
    })]
    arts = emit_for_scan(findings, tmp_path, allow_live=True)
    assert len(arts) == 1
    assert arts[0].is_runnable
    assert "--i-am-authorized" in arts[0].path.read_text()


# ----------------------------- cvss ----------------------------------------


def test_cvss_vector_for_known_agent():
    from sentinel.reports.cvss import severity_from_score, vector_for_finding

    finding = _mk_finding(agent_id="D_072", severity=Severity.CRITICAL)
    vec, score = vector_for_finding(finding)
    assert vec.startswith("CVSS:3.1/")
    assert score > 0
    assert severity_from_score(score) in ("High", "Critical")


def test_cvss_stamp_idempotent():
    from sentinel.reports.cvss import stamp

    finding = _mk_finding()
    stamp(finding)
    assert finding.cvss_vector and finding.cvss_vector.startswith("CVSS:3.1/")
    assert finding.evidence.get("cvss_v3_score") is not None

    # Second stamp must NOT overwrite an existing vector.
    original = finding.cvss_vector
    stamp(finding)
    assert finding.cvss_vector == original


def test_cvss_severity_bands():
    from sentinel.reports.cvss import severity_from_score
    assert severity_from_score(0.0) == "None"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(4.0) == "Medium"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(9.5) == "Critical"


# ----------------------------- sarif ---------------------------------------


def test_sarif_log_shape():
    from sentinel.reports.sarif import render_sarif

    findings = [
        _mk_finding(agent_id="D_072", severity=Severity.CRITICAL),
        _mk_finding(agent_id="N_002", severity=Severity.MEDIUM,
                    vuln_class="Cleartext Traffic"),
    ]
    doc = render_sarif(findings, session_id="abc12345")
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "SENTINEL"
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"D_072", "N_002"}
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["fingerprints"]["sentinel/v1"]
    assert results[0]["level"] in ("error", "warning", "note")


def test_sarif_includes_cvss_when_stamped():
    from sentinel.reports.cvss import stamp
    from sentinel.reports.sarif import render_sarif

    f = _mk_finding()
    stamp(f)
    doc = render_sarif([f], session_id="abc12345")
    result_props = doc["runs"][0]["results"][0]["properties"]
    assert "security-severity" in result_props


# ----------------------------- siem ----------------------------------------


def test_siem_bundle_contains_three_formats(tmp_path: Path):
    from sentinel.reports.siem import build_bundle

    findings = [_mk_finding(agent_id="D_072"), _mk_finding(agent_id="N_002")]
    blob = build_bundle(findings, session_id="abc12345")
    assert len(blob) > 0

    import io
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        names = set(zf.namelist())
    assert "README.md" in names
    assert "manifest.json" in names
    assert "elastic/rules.ndjson" in names
    assert "falco/sentinel_rules.yaml" in names
    assert any(n.startswith("splunk/") and n.endswith(".spl") for n in names)


def test_siem_dedups_by_agent_id():
    import io

    from sentinel.reports.siem import build_bundle

    # Two findings, same agent — must yield one rule.
    findings = [_mk_finding(agent_id="D_072"), _mk_finding(agent_id="D_072")]
    blob = build_bundle(findings, "s1234567")
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["rule_count"] == 1
    assert manifest["finding_count"] == 2


# ----------------------------- OpenAPI inferrer ----------------------------


class _Flow:
    """Minimal duck-typed CapturedFlow stand-in."""
    def __init__(self, method, host, path, headers=None):
        self.method = method
        self.host = host
        self.path = path
        self.url = f"https://{host}{path}"
        self.request_headers = headers or {}


def test_openapi_templatize_groups_by_id_segment():
    from sentinel.agents.api_security.openapi_inferrer import _templatize_path

    assert _templatize_path("/users/42/orders") == "/users/{id}/orders"
    assert _templatize_path("/u/a1b2c3d4e5f6a7b8c9d0/profile") == "/u/{id}/profile"
    assert _templatize_path("/static") == "/static"
    assert _templatize_path("/") == "/"


def test_openapi_inferrer_flags_unauthed_mutating_endpoint(tmp_path: Path, monkeypatch):
    """The inferrer flags POST /users with zero observed auth across calls."""
    from sentinel.agents.api_security.openapi_inferrer import OpenAPIInferrerAgent

    capture = type("Capture", (), {"flows": [
        _Flow("POST", "api.example.com", "/users/42", headers={}),
        _Flow("POST", "api.example.com", "/users/9001", headers={}),
        _Flow("POST", "api.example.com", "/users/123", headers={}),
    ]})()

    class FakeCtx:
        sources = {"mitmproxy": capture}
        manifest = {}
        decompiled_dir = None

    class FakeMemory:
        async def add_finding(self, *a, **k): return None

    agent = OpenAPIInferrerAgent.__new__(OpenAPIInferrerAgent)
    agent._context = FakeCtx()
    agent._memory = FakeMemory()
    # Stub _make_finding so we don't drag in BaseAgent's full plumbing.
    def _make_finding(**kw):
        return Finding(
            session_id="test-session-1234",
            agent_id="API_001",
            vuln_class=kw["vuln_class"], severity=kw["severity"],
            confidence=kw["confidence"], recommendation=kw["recommendation"],
            evidence=kw["evidence"],
        )
    agent._make_finding = _make_finding

    findings = asyncio.run(agent.analyze())
    # One inventory + at least one endpoint finding.
    assert any(f.evidence.get("kind") == "api_inventory" for f in findings)
    endpoint_findings = [f for f in findings if f.evidence.get("kind") == "endpoint"]
    assert endpoint_findings, "expected an endpoint finding for the unauthed POST"
    assert endpoint_findings[0].evidence["auth_consistency"] == "never"
    assert endpoint_findings[0].severity == Severity.HIGH


# ----------------------------- fuzz harness_gen ----------------------------


def test_fuzz_signature_parses_jni_name():
    from sentinel.fuzz import parse_jni_signature

    sig = parse_jni_signature(
        symbol="Java_com_x_NativeLib_decrypt",
        params_str="String, int",
        return_type="jstring",
        source_lib="libnative.so",
    )
    assert sig.symbol == "Java_com_x_NativeLib_decrypt"
    assert sig.return_type == "jstring"
    assert sig.arg_types == ("jstring", "jint")
    assert sig.source_lib == "libnative.so"


def test_fuzz_generate_for_apk_writes_harnesses(tmp_path: Path):
    from sentinel.fuzz import generate_for_apk

    native_info = {"exports": [
        {"symbol": "Java_com_x_Native_doIt",
         "lib": "libfoo.so", "params": "jstring", "return_type": "void"},
        {"symbol": "SomeNonJniExport"},   # should be skipped
        {"symbol": "Java_com_x_Native_other",
         "lib": "libfoo.so", "params": "jint, jstring", "return_type": "jint"},
    ]}
    sigs = generate_for_apk(native_info, tmp_path)
    assert len(sigs) == 2
    assert (tmp_path / "Java_com_x_Native_doIt_harness.c").exists()
    assert (tmp_path / "jni_stub" / "jni_stub.h").exists()
    assert (tmp_path / "Makefile").exists()
    assert (tmp_path / "run.sh").exists()


# ----------------------------- DeviceManager -------------------------------


def test_device_manager_parses_adb_output(monkeypatch):
    from sentinel.devices.pool import DeviceManager, _parse_devices_output

    parsed = _parse_devices_output(
        "List of devices attached\n"
        "emulator-5554\tdevice\n"
        "ABCDEF1234\tdevice\n"
        "OFFLINE_ID\toffline\n"
    )
    assert {d.serial for d in parsed} == {"emulator-5554", "ABCDEF1234", "OFFLINE_ID"}
    by_serial = {d.serial: d for d in parsed}
    assert by_serial["emulator-5554"].is_emulator is True
    assert by_serial["OFFLINE_ID"].state == "offline"


def test_device_manager_lease_round_robins(monkeypatch):
    """Two consecutive leases over a two-device pool produce both serials."""
    import sentinel.devices.pool as pool_mod
    from sentinel.devices.pool import DeviceInfo, DeviceManager

    fake_devices = [
        DeviceInfo(serial="emulator-5554", state="device", is_emulator=True),
        DeviceInfo(serial="emulator-5556", state="device", is_emulator=True),
    ]

    def fake_parse(_txt: str): return fake_devices
    monkeypatch.setattr(pool_mod, "_parse_devices_output", fake_parse)
    monkeypatch.setattr(pool_mod, "_run_adb", lambda *a, **k: "")
    monkeypatch.setattr(pool_mod, "_enrich", lambda d: None)

    mgr = DeviceManager()

    async def two_leases():
        async with mgr.lease() as d1:
            first = d1.serial
        async with mgr.lease() as d2:
            second = d2.serial
        return first, second

    a, b = asyncio.run(two_leases())
    assert {a, b} == {"emulator-5554", "emulator-5556"}


# ----------------------------- planner -------------------------------------


def test_planner_heuristic_picks_highest_priority():
    from sentinel.planner.planner import (
        AdaptivePlanner,
        AgentTool,
        _priority_of,
    )

    tools = [
        AgentTool(agent_id="A_001", name="X", phase="Phase 2",
                  category="auth", severity_hint="varies", cls=type("A", (), {})),
        AgentTool(agent_id="D_072", name="JniShadow", phase="Phase 2",
                  category="dynamic", severity_hint="varies", cls=type("D", (), {})),
        AgentTool(agent_id="N_002", name="Cleartext", phase="Phase 2",
                  category="network", severity_hint="varies", cls=type("N", (), {})),
    ]
    planner = AdaptivePlanner(tools=tools, router=None)

    async def run_decide():
        return await planner.decide(findings_so_far=[])

    decision = asyncio.run(run_decide())
    # D_072 has the lowest priority index — must come out first.
    assert decision.next_tool == "D_072"
    assert _priority_of("D_072") < _priority_of("A_001")


def test_planner_stops_when_no_remaining():
    from sentinel.planner.planner import AdaptivePlanner, AgentTool

    tool = AgentTool(agent_id="D_072", name="X", phase="Phase 2",
                     category="dynamic", severity_hint="varies", cls=type("D", (), {}))
    planner = AdaptivePlanner(tools=[tool], router=None)
    asyncio.run(planner.decide([]))
    planner.mark_done("D_072")
    second = asyncio.run(planner.decide([]))
    assert second.next_tool is None
