"""Unit tests for N_012 DnsLeakAgent."""
from __future__ import annotations

import pytest

from sentinel.agents.network import DnsLeakAgent
from sentinel.core.finding import BountyScope, Severity
from sentinel.core.scan_context import ScanContext, generate_session_id
from sentinel.memory import LightweightMemory


@pytest.fixture
async def memory(tmp_path):
    mem = LightweightMemory(data_dir=tmp_path / "data")
    await mem.connect()
    yield mem
    await mem.close()


def _ctx(tmp_path, *, decompiled=True, with_resources=True):
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
    if with_resources:
        res = ws / "resources"
        (res / "res" / "xml").mkdir(parents=True, exist_ok=True)
        ctx.resources_dir = res
    ctx.manifest = {"package": "com.x"}
    return ctx


def _plant_java(decompiled_dir, fqcn, body):
    parts = fqcn.split(".")
    f = decompiled_dir.joinpath(*parts).with_suffix(".java")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)


def _plant_xml(ctx, name, content):
    f = ctx.resources_dir / "res" / "xml" / name
    f.write_text(content)


@pytest.mark.asyncio
async def test_not_applicable_when_both_absent(memory, tmp_path):
    ctx = _ctx(tmp_path, decompiled=False, with_resources=False)
    agent = DnsLeakAgent(context=ctx, memory=memory)
    assert await agent.is_applicable() is False


@pytest.mark.asyncio
async def test_doh_false_in_nsc_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_xml(ctx, "network_security_config.xml", """<?xml version="1.0"?>
<network-security-config>
  <base-config dnsOverHttps="false" />
</network-security-config>
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.vuln_class == "DNS Leak via NetworkSecurityConfig"


@pytest.mark.asyncio
async def test_set_private_dns_off_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_java(ctx.decompiled_dir, "com.x.Net", """
class Net {
  void wire(android.net.ConnectivityManager cm) {
    cm.setPrivateDnsMode("off");
  }
}
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_class == "DNS Leak via Private-DNS Opt-Out"


@pytest.mark.asyncio
async def test_raw_udp_53_socket_is_high(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_java(ctx.decompiled_dir, "com.x.Raw", """
import java.net.*;
class Raw {
  void wire() throws Exception {
    DatagramSocket s = new DatagramSocket(53);
  }
}
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].vuln_class == "DNS Leak via Raw UDP/53 Socket"


@pytest.mark.asyncio
async def test_hardcoded_resolver_is_medium(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_java(ctx.decompiled_dir, "com.x.Pin", """
class Pin {
  String resolver() { return "1.1.1.1"; }
}
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_safe_app_no_findings(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_java(ctx.decompiled_dir, "com.x.Safe", """
import java.net.*;
class Safe {
  void resolve() throws Exception {
    InetAddress.getByName("api.example.com");
  }
}
""")
    _plant_xml(ctx, "network_security_config.xml", """<?xml version="1.0"?>
<network-security-config>
  <base-config />
</network-security-config>
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    assert await agent.analyze() == []


@pytest.mark.asyncio
async def test_optout_suppresses_hardcoded_resolver_duplicate(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_java(ctx.decompiled_dir, "com.x.Both", """
import android.net.*;
class Both {
  String r() { return "8.8.8.8"; }
  void off(ConnectivityManager cm) { cm.setPrivateDnsMode("off"); }
}
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    findings = await agent.analyze()
    # opt-out HIGH fires; the hardcoded resolver branch is suppressed
    # because it would double-flag the same file.
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_finding_schema_compliance(memory, tmp_path):
    ctx = _ctx(tmp_path)
    _plant_xml(ctx, "nsc.xml", """<?xml version="1.0"?>
<network-security-config>
  <base-config dnsOverHttps="false" />
</network-security-config>
""")
    agent = DnsLeakAgent(context=ctx, memory=memory)
    f = (await agent.analyze())[0]
    assert f.owasp == "M3: Insecure Communication"
    assert f.masvs == "MSTG-NETWORK-1"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert f.recommendation
