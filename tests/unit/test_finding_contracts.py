"""Regression tests for finding transport contracts."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from sentinel.api.scan_runner import ScanJob, ScanRegistry, _build_full_roster
from sentinel.core.finding import Finding, Severity
from sentinel.core.scan_context import ScanContext


def _finding() -> Finding:
    return Finding(
        session_id="test-session-1234",
        agent_id="N_002",
        vuln_class="Cleartext Traffic",
        severity=Severity.HIGH,
        confidence=0.9,
        recommendation="Use HTTPS for all traffic.",
        evidence={
            "url": "http://api.example.com/login",
            "_triage": {"outcome": "verified"},
        },
        screenshots=["evidence/before.png"],
        code_snippet={
            "file": "app/src/main/java/MainActivity.java",
            "line": 42,
            "content": "loadUrl(\"http://api.example.com/login\")",
        },
        context_factors={
            "exposure": "Network-reachable",
            "controls": "None",
            "impact": "Credential disclosure",
            "likelihood": "High",
        },
        financial_impact_score=1250.0,
        compliance_tags=["MASVS-NETWORK"],
        poc="curl http://api.example.com/login",
        severity_rationale="HIGH because…",
        verification_status="Code-level only",
        source_tags=["Cleartext Traffic", "Hardcoded URL"],
        reproduction_commands=[
            "mitmdump -p 8080",
            "adb shell settings put global http_proxy 192.168.1.10:8080",
        ],
        observed_result="The request to api.example.com is visible in plaintext.",
        code_snippets=[
            {
                "label": "Hardcoded URL",
                "file": "app/src/main/java/MainActivity.java",
                "line": 42,
                "content": "loadUrl(\"http://api.example.com/login\")",
            },
        ],
    )


def test_finding_model_accepts_new_djini_fields():
    f = _finding()
    assert f.severity_rationale.startswith("HIGH")
    assert f.verification_status == "Code-level only"
    assert "Cleartext Traffic" in f.source_tags
    assert len(f.reproduction_commands) == 2
    assert f.observed_result.startswith("The request")
    assert f.code_snippets and f.code_snippets[0]["line"] == 42


def test_finding_screenshots_accepts_dict_entries():
    f = Finding(
        session_id="test-session-1234",
        agent_id="N_002",
        vuln_class="Cleartext Traffic",
        severity=Severity.MEDIUM,
        confidence=0.7,
        recommendation="x",
        screenshots=[
            "evidence/legacy_string.png",
            {
                "path": "evidence/after_resume_123.webp",
                "caption": "Home screen after deep-link redirect",
                "step_index": 1,
                "label": "after_resume",
            },
        ],
    )
    assert len(f.screenshots) == 2
    assert isinstance(f.screenshots[0], str)
    assert f.screenshots[1]["step_index"] == 1


def test_finding_rejects_malformed_screenshot_entry():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Finding(
            session_id="test-session-1234",
            agent_id="N_002",
            vuln_class="x",
            severity=Severity.LOW,
            confidence=0.5,
            recommendation="x",
            screenshots=[{"caption": "no path key here"}],  # missing 'path'
        )


def test_scan_job_finding_dict_preserves_detail_fields(tmp_path: Path):
    job = ScanJob(
        session_id="test-session-1234",
        apk_path=tmp_path / "app.apk",
        apk_filename="app.apk",
        options={},
    )
    job.findings = [_finding()]

    [row] = job.finding_dicts()

    assert row["severity"] == "high"
    assert row["severity_label"] == "High"
    assert row["triage"] == "verified"
    assert "_triage" not in row["evidence"]
    assert row["screenshots"] == ["evidence/before.png"]
    assert row["code_snippet"]["line"] == 42
    assert row["context_factors"]["exposure"] == "Network-reachable"
    assert row["financial_impact_score"] == 1250.0
    assert row["compliance_tags"] == ["MASVS-NETWORK"]
    assert row["poc"].startswith("curl ")


def test_report_loader_rehydrates_findings_with_session_id(
    tmp_path: Path,
    monkeypatch,
):
    from sentinel.api.routes import reports

    session_id = "test-session-1234"
    report_dir = tmp_path / session_id / "reports"
    report_dir.mkdir(parents=True)
    payload = {
        "session_id": session_id,
        "findings": [
            {
                **_finding().model_dump(mode="json"),
                "finding_id": _finding().finding_id,
                "rag_mapping": {},
                "rag_passage_ids": [],
                "triage_explanation": "ok",
            },
        ],
    }
    (report_dir / f"VAPT_Report_{session_id}.json").write_text(
        json.dumps(payload),
    )

    settings = type("Settings", (), {"workspace": str(tmp_path)})()
    monkeypatch.setattr(reports, "get_settings", lambda: settings)

    [finding] = reports._load_findings_for_session(session_id)

    assert finding.session_id == session_id
    assert finding.severity is Severity.HIGH
    assert finding.screenshots == ["evidence/before.png"]
    assert finding.code_snippet and finding.code_snippet["line"] == 42
    assert finding.context_factors


def test_dynamic_roster_only_adds_frida_agents_when_frida_enabled():
    static_ids = {cls.AGENT_ID for cls in _build_full_roster(False, False)}
    dynamic_ids = {cls.AGENT_ID for cls in _build_full_roster(True, False)}
    frida_ids = {cls.AGENT_ID for cls in _build_full_roster(True, True)}

    assert "N_003" in dynamic_ids
    assert "A_003" not in dynamic_ids
    assert "D_001" not in dynamic_ids
    assert "D_075" in frida_ids
    assert "D_001" in frida_ids
    assert static_ids < dynamic_ids < frida_ids


def test_fast_roster_is_smaller_high_signal_subset():
    standard_ids = {
        cls.AGENT_ID for cls in _build_full_roster(False, False)
    }
    fast_ids = {
        cls.AGENT_ID
        for cls in _build_full_roster(False, False, scan_profile="fast")
    }

    assert fast_ids < standard_ids
    assert len(fast_ids) < len(standard_ids) // 2
    for required in {"META_002", "A_001", "A_004", "N_001", "N_002", "P_015"}:
        assert required in fast_ids


def test_p015_handles_string_only_activity_manifest(tmp_path: Path):
    from sentinel.agents.platform.p015_deep_link_mapper import DeepLinkMapperAgent

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id="test-session-1234",
        apk_path=apk,
        workspace=tmp_path / "workspace",
    )
    ctx.manifest = {
        "package": "com.example.app",
        "activities": ["com.example.MainActivity"],
    }

    agent = DeepLinkMapperAgent(ctx, memory=object())  # type: ignore[arg-type]

    assert asyncio.run(agent.is_applicable()) is False
    assert asyncio.run(agent.analyze()) == []


def test_p015_emits_new_djini_fields(tmp_path: Path):
    """P_015 must populate severity_rationale, verification_status,
    source_tags, dynamic_target, and code_snippets
    on every emitted finding so the new FindingDetailView has data to
    render. Runtime proof fields stay empty until the ADB truth engine
    executes the dynamic target."""
    from sentinel.agents.platform.p015_deep_link_mapper import DeepLinkMapperAgent

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id="test-session-1234",
        apk_path=apk,
        workspace=tmp_path / "workspace",
    )
    ctx.manifest = {
        "package": "com.example.app",
        "activities": ["com.example.LoginActivity"],
        "deep_links": [{
            "activity": "com.example.LoginActivity",
            "actions": "android.intent.action.VIEW",
            "categories": "android.intent.category.BROWSABLE",
            "auto_verify": False,
            "data_elements": [{
                "scheme": "https",
                "host": "example.com",
                "pathPrefix": "/oauth/callback",
            }],
        }],
    }

    agent = DeepLinkMapperAgent(ctx, memory=object())  # type: ignore[arg-type]
    findings = asyncio.run(agent.analyze())

    assert findings, "P_015 should fire on this manifest"
    for f in findings:
        assert f.verification_status == "Code-level only"
        assert "Deep Link / URL Scheme" in f.source_tags
        assert f.severity_rationale and len(f.severity_rationale) > 40
        assert f.dynamic_target
        assert f.dynamic_target["type"] == "deep_link"
        assert f.dynamic_target["scheme"] == "https"
        assert f.reproduction_commands == []
        assert f.observed_result is None
        assert f.code_snippets and f.code_snippets[0]["file"] == "AndroidManifest.xml"
        assert "<intent-filter" in f.code_snippets[0]["content"]

    # The auth-redirect path should also pick up the dedicated tag.
    auth_finding = next(
        (f for f in findings if f.evidence.get("auth_path_detected")),
        None,
    )
    assert auth_finding is not None
    assert "Auth Redirect Surface" in auth_finding.source_tags


def test_p015_uses_manifest_deep_links(tmp_path: Path):
    from sentinel.agents.platform.p015_deep_link_mapper import DeepLinkMapperAgent

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id="test-session-1234",
        apk_path=apk,
        workspace=tmp_path / "workspace",
    )
    ctx.manifest = {
        "package": "com.example.app",
        "activities": ["com.example.LinkActivity"],
        "deep_links": [{
            "activity": "com.example.LinkActivity",
            "actions": "android.intent.action.VIEW",
            "categories": "android.intent.category.BROWSABLE",
            "auto_verify": False,
            "data_elements": [{
                "scheme": "https",
                "host": "example.com",
                "pathPrefix": "/",
            }],
        }],
    }

    agent = DeepLinkMapperAgent(ctx, memory=object())  # type: ignore[arg-type]
    findings = asyncio.run(agent.analyze())

    assert findings
    assert {f.evidence["issue"] for f in findings} >= {
        "missing_auto_verify",
        "unguarded_action_view",
        "overly_broad_path",
    }
    assert all(f.dynamic_target for f in findings)
    assert all(f.reproduction_commands == [] for f in findings)


def test_n002_emits_new_djini_fields(tmp_path: Path):
    """N_002 must populate the new fields whether the trigger is the
    manifest opt-in, hardcoded URLs, or both."""
    from sentinel.agents.network.cleartext_traffic_agent import CleartextTrafficAgent

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    workspace = tmp_path / "workspace"
    decompiled = workspace / "decompiled"
    src = decompiled / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "Api.java").write_text(
        'public class Api {\n'
        '    String base = "http://api.example.com/v1/login";\n'
        '}\n',
        encoding="utf-8",
    )

    ctx = ScanContext(
        session_id="test-session-1234",
        apk_path=apk,
        workspace=workspace,
    )
    ctx.manifest = {
        "package": "com.example.app",
        "uses_cleartext_traffic": True,
    }
    ctx.decompiled_dir = decompiled

    agent = CleartextTrafficAgent(ctx, memory=object())  # type: ignore[arg-type]
    findings = asyncio.run(agent.analyze())

    assert len(findings) == 1
    f = findings[0]
    assert f.verification_status == "Code-level only"
    assert "Cleartext Traffic" in f.source_tags
    assert "Manifest Flag" in f.source_tags
    assert "Hardcoded URL" in f.source_tags
    assert f.severity_rationale and "manifest" in f.severity_rationale.lower()
    assert f.reproduction_commands
    assert any("mitmdump" in c for c in f.reproduction_commands)
    assert any("http_proxy" in c for c in f.reproduction_commands)
    assert f.observed_result and len(f.observed_result) > 20
    # Two snippets: the actual hit + the synthesised manifest opt-in.
    assert f.code_snippets and len(f.code_snippets) == 2
    labels = {s.get("label") for s in f.code_snippets}
    assert labels == {"Hardcoded URL", "Manifest opt-in"}
    # The legacy code_snippet field must still be populated for back-compat.
    assert f.code_snippet and f.code_snippet["file"].endswith("Api.java")


def test_stg007_emits_new_djini_fields(tmp_path: Path):
    """STG_007 must populate the new fields on both code paths —
    over-broad XML mapping AND exported FileProvider in manifest."""
    from sentinel.agents.shared_prefs.stg007_insecure_file_provider import (
        InsecureFileProviderAgent,
    )

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    workspace = tmp_path / "workspace"
    resources = workspace / "resources"
    xml_dir = resources / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "file_paths.xml").write_text(
        "<paths xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
        "  <root-path name=\"all\" path=\"/\" />\n"
        "  <files-path name=\"any\" path=\".\" />\n"
        "</paths>\n",
        encoding="utf-8",
    )

    ctx = ScanContext(
        session_id="test-session-1234",
        apk_path=apk,
        workspace=workspace,
    )
    ctx.manifest = {
        "package": "com.example.app",
        "exported_components": [{
            "type": "provider",
            "name": "androidx.core.content.FileProvider",
            "authority": "com.example.app.fileprovider",
            "permission": None,
        }],
    }
    ctx.resources_dir = resources

    agent = InsecureFileProviderAgent(ctx, memory=object())  # type: ignore[arg-type]
    findings = asyncio.run(agent.analyze())

    # 2 path-mapping findings + 1 exported-provider finding
    assert len(findings) >= 3

    path_findings = [f for f in findings if f.vuln_class.startswith("Insecure FileProvider")]
    export_findings = [f for f in findings if f.vuln_class == "Exported FileProvider"]
    assert path_findings and export_findings

    for f in path_findings:
        assert f.verification_status == "Code-level only"
        assert "FileProvider Misconfiguration" in f.source_tags
        assert f.severity_rationale and "mapping" in f.severity_rationale.lower()
        assert f.reproduction_commands
        assert any("apktool d target.apk" in c for c in f.reproduction_commands)
        assert any("getUriForFile" in c for c in f.reproduction_commands)
        assert not any("content://" in c for c in f.reproduction_commands)
        assert f.observed_result and f.observed_result.startswith("Static proof only")
        assert "not dynamically verified" in f.observed_result
        assert "image_cache/secret.bin" not in f.observed_result
        assert f.code_snippets and f.code_snippets[0]["file"].endswith("file_paths.xml")
        # Legacy singular snippet must still be populated for back-compat.
        assert f.code_snippet and f.code_snippet["content"]

    root_path = next((f for f in path_findings if f.evidence.get("tag") == "root-path"), None)
    assert root_path is not None
    assert "Device-Root Exposure" in root_path.source_tags

    [exp] = export_findings
    assert exp.severity is Severity.CRITICAL
    assert exp.verification_status == "Code-level only"
    assert "Exported Component" in exp.source_tags
    assert any("dumpsys package" in c for c in exp.reproduction_commands)
    assert exp.observed_result.startswith("Static proof only")
    assert exp.code_snippets and exp.code_snippets[0]["file"] == "AndroidManifest.xml"
    assert "android:exported=\"true\"" in exp.code_snippets[0]["content"]


def test_n005_emits_new_djini_fields(tmp_path: Path):
    """N_005 must populate the new fields on every emitted finding —
    bypass (HIGH), survived (INFO positive), and no-pinning-observed
    (INFO inconclusive) — so the runtime-verified bucket has narrative
    rationale to render."""
    from types import SimpleNamespace

    from sentinel.agents.dynamic.cert_pinning_bypass_agent import (
        CertPinningBypassAgent,
    )

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")

    def _run(events: list[SimpleNamespace]) -> list[Finding]:
        ctx = ScanContext(
            session_id="test-session-1234",
            apk_path=apk,
            workspace=tmp_path / "workspace",
        )
        ctx.manifest = {"package": "com.example.app"}
        ctx.sources = {"frida": SimpleNamespace(events=events)}
        agent = CertPinningBypassAgent(ctx, memory=object())  # type: ignore[arg-type]
        return asyncio.run(agent.analyze())

    bypass_evt = SimpleNamespace(
        kind="tls.bypass",
        payload={
            "library": "okhttp.CertificatePinner",
            "method": "check",
            "host": "api.example.com",
        },
        timestamp=0,
    )
    survived_evt = SimpleNamespace(
        kind="tls.bypass_failed",
        payload={"library": "TrustKit", "error": "overload mismatch"},
        timestamp=0,
    )
    hooks_summary = SimpleNamespace(
        kind="tls.hooks_summary",
        payload={
            "attempted": ["okhttp.CertificatePinner", "TrustKit"],
            "succeeded": ["okhttp.CertificatePinner"],
            "failed": ["TrustKit"],
        },
        timestamp=0,
    )

    bypass, survived = _run([bypass_evt, survived_evt, hooks_summary])

    assert bypass.severity is Severity.HIGH
    assert bypass.verification_status == "Runtime-verified via Frida"
    assert "Certificate Pinning" in bypass.source_tags
    assert "Pinning Bypassed" in bypass.source_tags
    assert "OkHttp Pinning" in bypass.source_tags
    assert bypass.severity_rationale and "okhttp" in bypass.severity_rationale.lower()
    assert bypass.observed_result and "api.example.com" in bypass.observed_result
    assert bypass.reproduction_commands
    assert any("frida" in c.lower() for c in bypass.reproduction_commands)
    assert any("mitmdump" in c for c in bypass.reproduction_commands)
    assert bypass.code_snippets and bypass.code_snippets[0]["file"].endswith(".js")

    assert survived.severity is Severity.INFO
    assert survived.verification_status == "Runtime-observed via Frida"
    assert "Pinning Resisted" in survived.source_tags
    assert "TrustKit Pinning" in survived.source_tags
    assert survived.severity_rationale and "INFO" in survived.severity_rationale
    assert survived.observed_result and "TrustKit" in survived.observed_result

    # No-pinning-observed path: only the hooks_summary event, no bypasses.
    no_pin_summary = SimpleNamespace(
        kind="tls.hooks_summary",
        payload={
            "attempted": ["okhttp.CertificatePinner", "TrustKit"],
            "succeeded": [],
            "failed": [],
        },
        timestamp=0,
    )
    # Need at least one tls.* event so analyze() doesn't early-exit.
    placeholder = SimpleNamespace(kind="tls.hooks_installed",
                                  payload={"libraries": []}, timestamp=0)
    [observed] = _run([placeholder, no_pin_summary])
    assert observed.severity is Severity.INFO
    assert observed.verification_status == "Runtime-observed via Frida"
    assert "Inconclusive" in observed.source_tags
    assert observed.code_snippets[0]["file"].endswith(".js")


def test_sarif_exporter_surfaces_new_djini_fields():
    """The SARIF exporter must lift the new Djini fields into
    result.properties so GitHub Code Scanning / SARIF aggregators
    show the same narrative the SENTINEL UI does."""
    from sentinel.reports.sarif import render_sarif

    f = _finding()
    doc = render_sarif([f], session_id="test-session-1234")
    [run] = doc["runs"]
    [result] = run["results"]

    props = result["properties"]
    assert props["severity_rationale"].startswith("HIGH")
    assert props["verification_status"] == "Code-level only"
    assert "Cleartext Traffic" in props["source_tags"]
    assert any("mitmdump" in c for c in props["reproduction_commands"])
    assert props["observed_result"].startswith("The request")
    assert props["code_snippets"][0]["file"].endswith(".java")

    # Region pulled from code_snippet.line, not the evidence dict.
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42
    assert "snippet" in region

    # Message text prefers observed_result over recommendation.
    assert result["message"]["text"].startswith("The request")

    # Rule tags inherit source_tags as slug-cased entries.
    [rule] = run["tool"]["driver"]["rules"]
    assert "cleartext-traffic" in rule["properties"]["tags"]

    # partialFingerprints helps deduplicate across runs.
    assert "sentinel/agent+vuln+file" in result["partialFingerprints"]


def test_triager_lifts_verdict_onto_finding_fields():
    """LLMTriager must populate severity_rationale + verification_status
    on the Finding itself (not just evidence._triage) so the bucket
    classifier can route the finding to AI-Powered AppSec."""
    from sentinel.triage.models import TriageOutcome, TriageResult, TriageVerdict
    from sentinel.triage.triager import LLMTriager

    f = _finding()
    # Reset the agent's defaults so we can prove the triager overrode them.
    f.severity_rationale = None
    f.verification_status = "Code-level only"

    verified = TriageResult(
        outcome=TriageOutcome.VERIFIED,
        verdict=TriageVerdict(
            is_real_bug=True,
            confidence=0.92,
            explanation="The hardcoded URL is reachable at startup and "
                        "transmits the session cookie in cleartext.",
        ),
        llm_provider="groq",
        duration_ms=1100,
    )
    LLMTriager._apply_triage_to_finding(f, verified)
    assert f.verification_status == "Verified by LLM triage"
    assert f.severity_rationale.startswith("The hardcoded URL")

    # Uncertain triage should still flip out of "Code-level only".
    g = _finding()
    g.verification_status = "Code-level only"
    uncertain = TriageResult(
        outcome=TriageOutcome.UNCERTAIN,
        verdict=TriageVerdict(
            is_real_bug=True,
            confidence=0.4,
            explanation="The endpoint may or may not handle real "
                        "credentials — need a runtime check to confirm.",
        ),
    )
    LLMTriager._apply_triage_to_finding(g, uncertain)
    assert g.verification_status.startswith("LLM triage uncertain")
    assert "runtime check" in g.severity_rationale

    # Filtered findings should NOT have verification_status touched,
    # but should record the FP reason in evidence._filter_reason.
    h = _finding()
    h.verification_status = "Code-level only"
    filtered = TriageResult(
        outcome=TriageOutcome.FILTERED,
        verdict=TriageVerdict(
            is_real_bug=False,
            confidence=0.85,
            explanation="The URL is only used in a debug-only code path "
                        "guarded by BuildConfig.DEBUG.",
            false_positive_reason="Debug-only code path",
        ),
    )
    LLMTriager._apply_triage_to_finding(h, filtered)
    assert h.verification_status == "Code-level only"
    assert h.evidence["_filter_reason"] == "Debug-only code path"


def test_pipeline_contract_new_fields_survive_every_hop(tmp_path: Path):
    """End-to-end contract test for the new Djini-style fields.

    Path under test:
      STG_007.analyze()
        → ScanJob.findings
        → ScanJob.finding_dicts()        (the API row shape)
        → R_001._classify_section(...)   (report bucket assignment)
        → frontend findingBucket()       (mirror — must agree with backend)

    Every hop must preserve severity_rationale, verification_status,
    source_tags, reproduction_commands, observed_result, code_snippets,
    and the screenshot dict shape.
    """
    from sentinel.agents.shared_prefs.stg007_insecure_file_provider import (
        InsecureFileProviderAgent,
    )

    # ----- Hop 1: agent emits findings -----
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    workspace = tmp_path / "workspace"
    xml_dir = workspace / "resources" / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "file_paths.xml").write_text(
        "<paths xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
        "  <root-path name=\"all\" path=\"/\" />\n"
        "</paths>\n",
        encoding="utf-8",
    )
    ctx = ScanContext(
        session_id="pipeline-test-1",
        apk_path=apk,
        workspace=workspace,
    )
    ctx.manifest = {
        "package": "com.example.app",
        "exported_components": [],
    }
    ctx.resources_dir = workspace / "resources"

    agent = InsecureFileProviderAgent(ctx, memory=object())  # type: ignore[arg-type]
    findings = asyncio.run(agent.analyze())
    assert len(findings) == 1
    f = findings[0]

    # Attach a screenshot in the new dict shape so we prove that hop too.
    f.screenshots = [{
        "path": "evidence/before_traversal.webp",
        "caption": "App home before traversal attempt",
        "step_index": 0,
        "label": "before_traversal",
    }]
    # Pretend the LLM triager verified this finding.
    from sentinel.triage.models import TriageOutcome, TriageResult, TriageVerdict
    from sentinel.triage.triager import LLMTriager
    LLMTriager._attach_result(f, TriageResult(
        outcome=TriageOutcome.VERIFIED,
        verdict=TriageVerdict(
            is_real_bug=True,
            confidence=0.95,
            explanation="root-path mapping confirmed; runtime exploitability "
                        "requires a reachable grant flow.",
        ),
    ))
    LLMTriager._apply_triage_to_finding(
        f, LLMTriager._get_result(f),
    )

    # ----- Hop 2: wrap in ScanJob, call finding_dicts() -----
    job = ScanJob(
        session_id="pipeline-test-1",
        apk_path=apk,
        apk_filename="app.apk",
        options={},
    )
    job.findings = [f]
    [row] = job.finding_dicts()

    assert row["severity_rationale"].startswith("root-path mapping")
    assert row["verification_status"] == "Verified by LLM triage"
    assert "FileProvider Misconfiguration" in row["source_tags"]
    assert any("apktool d target.apk" in c for c in row["reproduction_commands"])
    assert not any("content://" in c for c in row["reproduction_commands"])
    assert row["observed_result"].startswith("Static proof only")
    assert "not dynamically verified" in row["observed_result"]
    assert row["code_snippets"] and row["code_snippets"][0]["file"].endswith("file_paths.xml")
    assert isinstance(row["screenshots"][0], dict)
    assert row["screenshots"][0]["caption"] == "App home before traversal attempt"
    assert row["triage"] == "verified"
    assert "_triage" not in row["evidence"]      # cleaned for the API

    # ----- Hop 3: R_001 bucket classification -----
    from sentinel.agents.reporting.r001_report_agent import ReportGeneratorAgent

    class _StubSection:
        def __init__(self, finding):
            self.finding = finding
            self.rag_mapping = {}
            self.rag_passage_ids = []
            self.triage_explanation = None

    bucket = ReportGeneratorAgent._classify_section(_StubSection(f))
    assert bucket == "ai_powered", (
        "LLM-verified finding must land in the AI-Powered bucket"
    )

    # A second finding without any triage / rationale should stay static.
    sast_only = _finding()
    sast_only.severity_rationale = None
    sast_only.verification_status = "Code-level only"
    sast_only.evidence = {k: v for k, v in sast_only.evidence.items() if k != "_triage"}
    assert ReportGeneratorAgent._classify_section(
        _StubSection(sast_only),
    ) == "static_tool"

    # ----- Hop 4: frontend findingBucket() predicate (mirrored) -----
    def frontend_bucket(d: dict) -> str:
        ev = d.get("evidence") or {}
        if d.get("severity_rationale"):
            return "ai_powered"
        if d.get("verification_status") and d["verification_status"] != "Code-level only":
            return "ai_powered"
        verify = ev.get("_verify")
        if isinstance(verify, dict) and verify.get("outcome"):
            return "ai_powered"
        if ev.get("_swarm"):
            return "ai_powered"
        if ev.get("dynamic_target"):
            return "ai_powered"
        if d.get("llm_rationale") or ev.get("llm_rationale"):
            return "ai_powered"
        return "static_tool"

    assert frontend_bucket(row) == "ai_powered", (
        "Frontend bucket must agree with backend for the verified row"
    )
    # And the pure-static finding must also agree once round-tripped
    # through finding_dicts(), proving the predicate is consistent
    # across both buckets.
    static_job = ScanJob(
        session_id="pipeline-test-1",
        apk_path=apk,
        apk_filename="app.apk",
        options={},
    )
    static_job.findings = [sast_only]
    [static_row] = static_job.finding_dicts()
    assert frontend_bucket(static_row) == "static_tool"


def test_scan_registry_restores_persisted_state(tmp_path: Path):
    registry = ScanRegistry(workspace=tmp_path)
    job = ScanJob(
        session_id="test-session-1234",
        apk_path=tmp_path / "uploads" / "app.apk",
        apk_filename="app.apk",
        options={"dynamic": True},
    )
    job.status = "completed"
    job.phase = "done"
    job.findings = [_finding()]
    job.tool_health = {"dynamic": {"status": "completed"}}
    job.manifest = {"package": "com.example.app"}

    asyncio.run(registry.add(job))

    restored = ScanRegistry(workspace=tmp_path).get("test-session-1234")

    assert restored is not None
    assert restored.status == "completed"
    assert restored.options == {"dynamic": True}
    assert restored.tool_health["dynamic"]["status"] == "completed"
    assert restored.manifest["package"] == "com.example.app"
    assert len(restored.findings) == 1
    assert restored.findings[0].screenshots == ["evidence/before.png"]


def test_scan_registry_restores_legacy_report_json(tmp_path: Path):
    session_id = "legacy-session-123"
    reports_dir = tmp_path / session_id / "reports"
    reports_dir.mkdir(parents=True)
    report = {
        "package": "com.legacy.app",
        "version": "1.2.3",
        "session_id": session_id,
        "apk_sha256": "abc123",
        "apk_size_bytes": 456,
        "generated_at": "2026-06-16T12:00:00+00:00",
        "findings": [_finding().model_copy(
            update={"session_id": session_id},
        ).model_dump(mode="json")],
    }
    (reports_dir / f"VAPT_Report_{session_id}.json").write_text(
        json.dumps(report),
    )

    restored = ScanRegistry(workspace=tmp_path).get(session_id)

    assert restored is not None
    assert restored.status == "completed"
    assert restored.apk_sha256 == "abc123"
    assert restored.apk_size_bytes == 456
    assert restored.manifest["package"] == "com.legacy.app"
    assert restored.manifest["version_name"] == "1.2.3"
    assert len(restored.findings) == 1
