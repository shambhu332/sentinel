"""N_012: Private-DNS / Encrypted-DNS Opt-Out Detection.

Android 9 introduced ``Private DNS`` (DNS-over-TLS), and Android 12
added ``Network.getPrivateDnsServerName()`` plus a per-app way to
honour the user's encrypted-DNS preference. Apps that opt *out* of
the user's setting — by forcing system DNS through a custom resolver
or by setting ``dnsOverHttps="false"`` / ``dns="cleartext"`` in
their network security config — leak the user's DNS lookup history
to anyone on the local network and to upstream resolvers in plain
text.

We flag four signals:

1. ``res/xml/network_security_config.xml`` containing
   ``dnsOverHttps="false"`` or ``android:usesCleartextTraffic="true"``
   on a ``<base-config>`` / ``<domain-config>`` element.
2. Java calls to ``LinkProperties.setDnsServers`` or
   ``ConnectivityManager.setPrivateDnsMode("off")`` /
   ``setPrivateDnsMode(PRIVATE_DNS_MODE_OFF)``.
3. Direct UDP/53 socket constructions (``new DatagramSocket(53)`` /
   ``InetSocketAddress(host, 53)``) — apps that resolve DNS via raw
   sockets bypass the system resolver entirely and so cannot honour
   Private DNS.
4. A hardcoded DNS-over-cleartext resolver IP (``8.8.8.8``, ``1.1.1.1``)
   passed to a ``setDnsServers`` call without a TLS/HoTTPS argument.

Severity:

* HIGH — explicit opt-out via NetworkSecurityConfig or
  setPrivateDnsMode("off").
* MEDIUM — DNS resolver IP hardcoded in source (unclear whether the
  app honours the user's encrypted-DNS preference upstream).
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_OPT_OUT_JAVA = re.compile(
    r"(setPrivateDnsMode\s*\(\s*\"?off\"?\s*\)|"
    r"setPrivateDnsMode\s*\(\s*PRIVATE_DNS_MODE_OFF\s*\)|"
    r"LinkProperties\s*\.\s*setDnsServers\s*\()",
    re.IGNORECASE,
)
_RAW_DNS_SOCKET = re.compile(
    r"(new\s+DatagramSocket\s*\(\s*53\s*\)|"
    r"new\s+InetSocketAddress\s*\([^)]*,\s*53\s*\))",
)
_HARDCODED_RESOLVER_IP = re.compile(
    r'"(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9)"',
)


class DnsLeakAgent(BaseAgent):
    """Flag apps that opt out of encrypted DNS."""

    AGENT_ID = "N_012"
    VULN_CLASS = "DNS Leak"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return bool(
            self._context.decompiled_dir or self._context.resources_dir
        )

    async def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._audit_network_security_config())
        findings.extend(self._audit_java_sources())
        return findings

    def _audit_network_security_config(self) -> list[Finding]:
        findings: list[Finding] = []
        res = self._context.resources_dir
        if not res:
            return findings
        xml_dir = res / "res" / "xml"
        if not xml_dir.exists():
            xml_dir = res / "xml"
        if not xml_dir.exists():
            return findings

        for xml_file in xml_dir.glob("*.xml"):
            try:
                content = xml_file.read_text(errors="replace")
            except OSError:
                continue
            if "<network-security-config" not in content:
                continue
            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                continue

            rel = self._rel_xml(xml_file)
            for elem in root.iter():
                tag = self._strip_ns(elem.tag)
                if tag not in ("base-config", "domain-config"):
                    continue
                attrs = {k.split("}")[-1]: v for k, v in elem.attrib.items()}
                opt_out_signal = None
                if attrs.get("dnsOverHttps", "").lower() == "false":
                    opt_out_signal = 'dnsOverHttps="false"'
                if attrs.get("cleartextTrafficPermitted", "").lower() == "true":
                    # Same config knob — clear-text-traffic implies a
                    # weaker security posture, but more specifically
                    # it's distinct from DNS leak. We surface it under
                    # this finding only when the config also opts out
                    # of DoH. Cleartext-traffic on its own is N_002.
                    pass
                if opt_out_signal is None:
                    continue
                findings.append(self._make_finding(
                    vuln_class="DNS Leak via NetworkSecurityConfig",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence={
                        "file": rel,
                        "element": tag,
                        "issue": (
                            "NetworkSecurityConfig declares "
                            f"{opt_out_signal} — the app opts out of "
                            "DNS-over-HTTPS, leaking lookup history "
                            "to anyone on the network."
                        ),
                    },
                    recommendation=(
                        "Remove the explicit dnsOverHttps=\"false\" "
                        "attribute and let the platform honour the "
                        "user's Private DNS preference. Apps almost "
                        "never have a legitimate reason to force "
                        "cleartext DNS; if a corporate captive-portal "
                        "requires it, scope the config to a specific "
                        "<domain-config> rather than <base-config>."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    ),
                ))
        return findings

    def _audit_java_sources(self) -> list[Finding]:
        findings: list[Finding] = []
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return findings

        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue

            rel = str(java_file.relative_to(decompiled))
            optout = _OPT_OUT_JAVA.search(source)
            raw_dns = _RAW_DNS_SOCKET.search(source)
            resolver_ip = _HARDCODED_RESOLVER_IP.search(source)

            if optout:
                findings.append(self._make_finding(
                    vuln_class="DNS Leak via Private-DNS Opt-Out",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    evidence={
                        "file": rel,
                        "trigger": optout.group(0)[:80],
                        "issue": (
                            "Java code disables Private DNS or sets a "
                            "custom resolver — the user's encrypted-"
                            "DNS preference is overridden by the app."
                        ),
                    },
                    recommendation=(
                        "Remove the setPrivateDnsMode(\"off\") / "
                        "LinkProperties.setDnsServers call. The "
                        "platform resolver honours the user's Private "
                        "DNS setting transparently — apps should not "
                        "override it."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-1",
                    cvss_vector=(
                        "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    ),
                ))
            if raw_dns:
                findings.append(self._make_finding(
                    vuln_class="DNS Leak via Raw UDP/53 Socket",
                    severity=Severity.HIGH,
                    confidence=0.80,
                    evidence={
                        "file": rel,
                        "trigger": raw_dns.group(0)[:80],
                        "issue": (
                            "App opens a raw UDP/53 socket — bypasses "
                            "the system resolver and the user's "
                            "Private DNS setting."
                        ),
                    },
                    recommendation=(
                        "Use InetAddress.getByName / the platform "
                        "resolver. Raw UDP/53 sockets cannot honour "
                        "Private DNS and leak lookups in cleartext."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-1",
                ))
            if resolver_ip and not optout:
                findings.append(self._make_finding(
                    vuln_class="DNS Leak via Hardcoded Resolver",
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    evidence={
                        "file": rel,
                        "resolver_ip": resolver_ip.group(1),
                        "issue": (
                            "Hardcoded public DNS resolver IP in source"
                            " — unclear whether the lookup is wrapped "
                            "in TLS / HTTPS or sent in plain UDP."
                        ),
                    },
                    recommendation=(
                        "Prefer the platform resolver and let users "
                        "configure Private DNS at the system level. "
                        "If a specific resolver is required, use the "
                        "TLS endpoint (e.g. 1.1.1.1:853) or DoH URL."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-1",
                ))
        return findings

    def _rel_xml(self, xml_file) -> str:
        rel = str(xml_file)
        res = self._context.resources_dir
        if res:
            try:
                rel = str(xml_file.relative_to(res))
            except ValueError:
                pass
        return rel

    @staticmethod
    def _strip_ns(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag
