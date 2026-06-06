"""Unit tests for N_008 InsecureTrustManagerAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.network import InsecureTrustManagerAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _make_ctx(tmp_path, *, decompiled: bool = True):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    apk = tmp_path / "fake.apk"
    apk.write_bytes(b"PK\x03\x04")
    ctx = ScanContext(
        session_id=generate_session_id(),
        apk_path=apk,
        workspace=ws,
        scope=BountyScope(),
    )
    if decompiled:
        d = ws / "decompiled"
        d.mkdir(exist_ok=True)
        ctx.decompiled_dir = d
    ctx.manifest = {"package": "com.x"}
    return ctx


def _plant(decompiled_dir, fqcn: str, body: str) -> None:
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


# ---------- is_applicable ----------


@pytest.mark.asyncio
async def test_not_applicable_without_decompiled(memory, tmp_path):
    ctx = _make_ctx(tmp_path, decompiled=False)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


# ---------- empty-body trust methods ----------


_TRUST_ALL = """
package com.x;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
class TrustAll implements X509TrustManager {
  public void checkClientTrusted(X509Certificate[] chain, String authType) {}
  public void checkServerTrusted(X509Certificate[] chain, String authType) {}
  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
"""

_TRUST_ALL_RETURN_ONLY = """
package com.x;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
class TrustAllReturn implements X509TrustManager {
  public void checkClientTrusted(X509Certificate[] chain, String authType) { return; }
  public void checkServerTrusted(X509Certificate[] chain, String authType) { return; }
  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
"""

_REAL_TRUST_MANAGER = """
package com.x;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.X509TrustManager;
class PinnedTrust implements X509TrustManager {
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    if (chain == null || chain.length == 0) {
      throw new CertificateException("empty chain");
    }
  }
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    if (chain == null) throw new CertificateException("no chain");
  }
  public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}
"""


@pytest.mark.asyncio
async def test_empty_check_methods_flagged_critical(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.TrustAll", _TRUST_ALL)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.agent_id == "N_008"
    assert f.severity == Severity.CRITICAL
    assert f.vuln_class == "Insecure TrustManager"
    assert "checkClientTrusted" in f.evidence["empty_methods"]
    assert "checkServerTrusted" in f.evidence["empty_methods"]


@pytest.mark.asyncio
async def test_return_only_body_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.TrustAllReturn", _TRUST_ALL_RETURN_ONLY)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_real_trust_manager_not_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.PinnedTrust", _REAL_TRUST_MANAGER)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- permissive HostnameVerifier ----------


_HV_RETURN_TRUE = """
package com.x;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
class HV implements HostnameVerifier {
  public boolean verify(String hostname, SSLSession session) { return true; }
}
"""

_HV_REAL = """
package com.x;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.HttpsURLConnection;
class HV implements HostnameVerifier {
  public boolean verify(String hostname, SSLSession session) {
    return HttpsURLConnection.getDefaultHostnameVerifier()
        .verify(hostname, session);
  }
}
"""


@pytest.mark.asyncio
async def test_return_true_hostname_verifier_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.HV", _HV_RETURN_TRUE)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].vuln_class == "Permissive HostnameVerifier"


@pytest.mark.asyncio
async def test_real_hostname_verifier_not_flagged(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.HV", _HV_REAL)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


# ---------- trust-all factory hint boosts confidence ----------


_TRUST_ALL_FACTORY = """
package com.x;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
class SSLPwn {
  TrustManager[] build() {
    return new TrustManager[] { new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] chain, String authType) {}
      public void checkServerTrusted(X509Certificate[] chain, String authType) {}
      public X509Certificate[] getAcceptedIssuers() { return null; }
    }};
  }
}
"""


@pytest.mark.asyncio
async def test_trust_all_factory_bumps_confidence(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.SSLPwn", _TRUST_ALL_FACTORY)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].confidence == 0.90
    assert findings[0].evidence["trust_all_factory"] is True


# ---------- both vectors emit independently ----------


_COMBINED = """
package com.x;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
class Both {
  public void checkServerTrusted(X509Certificate[] chain, String authType) {}
  public void checkClientTrusted(X509Certificate[] chain, String authType) {}
  public boolean verify(String hostname, SSLSession session) { return true; }
}
"""


@pytest.mark.asyncio
async def test_combined_emits_two_findings(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.Both", _COMBINED)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 2
    classes = sorted(f.vuln_class for f in findings)
    assert classes == ["Insecure TrustManager", "Permissive HostnameVerifier"]


# ---------- Finding-schema compliance ----------


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _make_ctx(tmp_path)
    _plant(ctx.decompiled_dir, "com.x.TrustAll", _TRUST_ALL)
    agent = InsecureTrustManagerAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Communication"
    assert f.masvs == "MSTG-NETWORK-3"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
