"""N_008: Insecure TrustManager / HostnameVerifier Detection.

Detects two classic TLS-disabling patterns in decompiled Java:

1. ``X509TrustManager`` (or ``TrustManager``) implementations whose
   ``checkServerTrusted`` / ``checkClientTrusted`` body is empty (or
   contains only a return). The certificate-chain validation is
   effectively skipped — the app accepts any cert, enabling trivial
   MITM regardless of N_001's cert-pinning verdict.

2. ``HostnameVerifier`` implementations whose ``verify`` method
   unconditionally returns ``true``. Equivalent break: a valid cert
   for ``evil.example.com`` is accepted as if it were issued for the
   target host.

Both bugs are common in code paths that started life as "let me test
against a self-signed staging server" and got shipped. They're orders
of magnitude more impactful than missing pinning because they undo the
default platform TLS guarantees, not just the app-layer addition.

Detection is regex over decompiled source — we deliberately don't
require a fully parsed Java AST here. The patterns are tight enough
that the FP rate on production code is near zero (a real
``checkServerTrusted`` body always contains a CertificateException
throw or a cert-chain inspection).
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

# checkServerTrusted / checkClientTrusted with an empty body. The body
# is empty if it only contains whitespace or a bare ``return;``.
_EMPTY_TRUST_METHOD = re.compile(
    r"public\s+void\s+(checkServerTrusted|checkClientTrusted)\s*"
    r"\(\s*X509Certificate\s*\[\s*\]\s*\w+\s*,\s*String\s+\w+\s*\)"
    r"(?:\s+throws\s+[A-Za-z0-9_.,\s]+)?"
    r"\s*\{\s*(?:return\s*;)?\s*\}",
)

# verify(String, SSLSession) that returns true with no other branches.
_PERMISSIVE_HOSTNAME_VERIFIER = re.compile(
    r"public\s+boolean\s+verify\s*\(\s*String\s+\w+\s*,\s*"
    r"SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;\s*\}",
)

# Trust-all factory pattern: anonymous TrustManager array with both
# methods empty — fingerprints the canonical SSLContext.init() trust-all
# snippet seen in many "test-cert workaround" StackOverflow answers.
_TRUST_ALL_ARRAY_HINT = re.compile(
    r"new\s+TrustManager\s*\[\s*\]\s*\{\s*new\s+X509TrustManager\s*\(\s*\)",
)


class InsecureTrustManagerAgent(BaseAgent):
    """Detect TLS-bypassing TrustManager / HostnameVerifier implementations."""

    AGENT_ID = "N_008"
    VULN_CLASS = "Insecure TLS Validation"
    PHASE = "Phase 2"

    async def is_applicable(self) -> bool:
        return self._context.decompiled_dir is not None

    async def analyze(self) -> list[Finding]:
        decompiled = self._context.decompiled_dir
        if not decompiled:
            return []

        findings: list[Finding] = []
        for java_file in decompiled.rglob("*.java"):
            try:
                source = java_file.read_text(errors="replace")
            except OSError:
                continue

            rel = str(java_file.relative_to(decompiled))

            empty_methods = sorted({
                m.group(1) for m in _EMPTY_TRUST_METHOD.finditer(source)
            })
            if empty_methods:
                trust_all = bool(_TRUST_ALL_ARRAY_HINT.search(source))
                findings.append(self._make_finding(
                    vuln_class="Insecure TrustManager",
                    severity=Severity.CRITICAL,
                    confidence=0.90 if trust_all else 0.85,
                    evidence={
                        "file": rel,
                        "empty_methods": empty_methods,
                        "trust_all_factory": trust_all,
                        "issue": (
                            "X509TrustManager method body is empty — every "
                            "certificate chain is accepted without validation"
                        ),
                    },
                    recommendation=(
                        "Remove the custom TrustManager and rely on the "
                        "platform default. If a private CA is genuinely "
                        "required, ship its certificate in the app and "
                        "validate the chain against it explicitly rather "
                        "than disabling validation. For staging-only "
                        "trust-all paths, guard them with BuildConfig.DEBUG "
                        "checks and assert they are stripped from release "
                        "builds via R8 / ProGuard rules."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-3",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ))

            if _PERMISSIVE_HOSTNAME_VERIFIER.search(source):
                findings.append(self._make_finding(
                    vuln_class="Permissive HostnameVerifier",
                    severity=Severity.CRITICAL,
                    confidence=0.90,
                    evidence={
                        "file": rel,
                        "issue": (
                            "HostnameVerifier.verify() unconditionally "
                            "returns true — host-cert binding skipped"
                        ),
                    },
                    recommendation=(
                        "Delete the custom HostnameVerifier and let "
                        "HttpsURLConnection / OkHttp use the default "
                        "verifier. The platform implementation correctly "
                        "compares the SSL session hostname against the "
                        "certificate's Subject Alt Names. Returning true "
                        "unconditionally allows any valid cert from any "
                        "domain to impersonate the target."
                    ),
                    owasp="M3: Insecure Communication",
                    masvs="MSTG-NETWORK-3",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                ))

        return findings
