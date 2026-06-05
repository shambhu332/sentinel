"""RN_001 — React Native bundle auditor.

Detects React Native ship artifacts and, when the JS bundle is plain
text (i.e. NOT compiled to Hermes bytecode), scans it for the small
set of issues that RN apps trip over most often in practice:

* secrets baked into the bundle (AWS / Google / Firebase patterns),
* ``AsyncStorage.setItem(...)`` with credential-shaped keys,
* cleartext ``fetch('http://...')`` / ``XMLHttpRequest`` to ``http:``,
* ``WebView`` with ``originWhitelist={['*']}`` taking a dynamic URI,
* ``dangerouslySetInnerHTML`` (DOM injection sink in WebView contents).

**The Hermes case is the headline limitation.** As of RN 0.70+ Hermes
is on by default. The shipped bundle is then a Hermes-bytecode blob —
the JS source is gone and a regex scan over the binary produces
nothing but garbage findings. When we recognise the Hermes magic
``0xC61FBC03`` at the bundle head we emit one INFO finding
documenting the limitation and stop. The honest "we can't see this"
matters more than a fake positive.

Future work (out of scope here): a Hermes-disassembler integration
would let us recover function bodies as JS and then re-run this
agent's regexes. ``hermes-dec`` and ``hbctool`` are the obvious
candidates; both ship as Node CLIs which means a JVM-style dependency
hit similar to FlowDroid. Left for a later sprint.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path

from sentinel.agents.base.base_agent import BaseAgent
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


# ---------- Detection ----------

# Hermes magic. The first 4 bytes of a Hermes-compiled bundle are
# 0xC61FBC03 little-endian → b"\x03\xBC\x1F\xC6". Documented at
# https://github.com/facebook/hermes/blob/main/include/hermes/BCGen/
# HBC/BytecodeFileFormat.h (`MAGIC = 0x1F1903C103BC1FC6` truncated to
# 32 bits → matches the on-disk leading 4 bytes).
_HERMES_MAGIC = b"\x03\xBC\x1F\xC6"

# Filenames we look for under apktool's resources_dir/assets/.
_RN_BUNDLE_NAME = "index.android.bundle"

# Native libs that confirm RN is present even when the bundle has
# been moved or renamed. Their presence alone doesn't constitute a
# finding — they just gate the agent's applicability.
_RN_NATIVE_LIB_HINTS = (
    "libreactnativejni.so",
    "libhermes.so",
    "libreact_nativemodule_core.so",
)


# ---------- Regex tables (plain-JS bundles only) ----------

# Sensitive-key hints reused for AsyncStorage scans. Kept narrow on
# purpose — a casual `pref_dark_mode` getItem is not a finding.
_SENSITIVE_KEY_RE = re.compile(
    r"""(?ix)
    (?:token|jwt|password|passwd|secret|auth|session|
       credential|apikey|api[_-]?key|refresh|private)
    """,
)

# AsyncStorage / SecureStore / EncryptedStorage writes. The capture
# group is the key string literal; matched against the sensitive-key
# regex below to filter benign storage writes.
_ASYNC_STORAGE_WRITE_RE = re.compile(
    r"""
    \b(?:AsyncStorage|EncryptedStorage|SecureStore)\.
    (?:setItem|setItemAsync|setStringAsync)\(
    \s*['"]([^'"]{1,160})['"]
    """,
    re.VERBOSE,
)

# fetch('http://...') and XMLHttpRequest .open('GET','http://...').
# We exclude localhost and 10.0.2.2 (Android emulator default host)
# because dev builds often carry those and they aren't shipped to
# users via a release bundle in practice.
_CLEARTEXT_URL_RE = re.compile(
    r"""['"]
        (http://
           (?!(?:localhost|127\.0\.0\.1|10\.0\.2\.2)(?:[:/]|['"]))
           [^\s'"]{3,260}
        )
    ['"]""",
    re.VERBOSE,
)

# Hardcoded-secret patterns. Each tuple: (label, pattern, severity,
# confidence). Patterns are intentionally narrow — most "looks like an
# API key" regexes false-positive on minified JS that's full of
# random-looking identifiers.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes | str], Severity, float], ...] = (
    ("AWS Access Key ID",      re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     Severity.HIGH, 0.95),
    ("Google API Key",         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     Severity.HIGH, 0.90),
    ("Firebase Web API Key",   re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     Severity.MEDIUM, 0.70),
    ("Slack Token",            re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     Severity.HIGH, 0.95),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
     Severity.HIGH, 0.95),
    ("Generic Bearer Token (long base64)",
     re.compile(r"\b[Bb]earer\s+[A-Za-z0-9_\-]{40,}\b"),
     Severity.MEDIUM, 0.55),
)

# WebView <WebView source={{uri: someVariable}} ...> with originWhitelist=['*'].
# Two-step: presence of either pattern is interesting; both together is the
# strongest signal. Match the components separately so JSX line breaks
# don't defeat us.
_WEBVIEW_DYNAMIC_URI_RE = re.compile(
    r"<WebView\b[^>]*\bsource\s*=\s*\{\{\s*uri\s*:\s*[A-Za-z_$][\w$.]*",
    re.MULTILINE,
)
_WEBVIEW_WILD_ORIGIN_RE = re.compile(
    r"originWhitelist\s*=\s*\{?\s*\[\s*['\"]\*['\"]\s*\]",
)

# JSX `dangerouslySetInnerHTML={{ __html: x }}`. Same hazard as web
# DOM XSS when the HTML body is computed from untrusted input.
_DANGEROUSLY_SET_INNER_HTML_RE = re.compile(
    r"\bdangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:",
)


# ---------- Vuln-class constants (referenced by tests) ----------

VC_HERMES_LIMIT  = "HERMES_BYTECODE_LIMITATION"
VC_INSEC_STORAGE = "INSECURE_STORAGE"
VC_CLEARTEXT     = "CLEARTEXT_TRAFFIC"
VC_SECRET        = "HARDCODED_SECRET"
VC_WV_XSS        = "WEBVIEW_XSS"
VC_DANGEROUS_HTML = "DANGEROUS_SET_INNER_HTML"


# ---------- Bundle-size cap ----------

# Cap how much of the bundle we regex-scan. Minified RN bundles for
# small apps run 1-2 MB; large ones reach 8-15 MB. 16 MiB comfortably
# covers production bundles without giving a malicious or pathological
# bundle a way to stall the scan.
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024

# Findings cap per category. Mirrors the NL_001 convention.
_MAX_HITS_PER_CATEGORY = 50


# ---------- Agent ----------

class ReactNativeAgent(BaseAgent):
    """RN_001: detect RN packaging and audit the JS bundle (plain only)."""

    AGENT_ID = "RN_001"
    VULN_CLASS = "RN_BUNDLE_AUDIT"
    PHASE = "Phase 2"
    CATEGORY = "CROSS_PLATFORM"

    async def is_applicable(self) -> bool:
        ctx = self._context
        if ctx.resources_dir is None:
            self._log.info(
                "[RN_001] resources_dir not set — apktool likely failed; "
                "RN bundle inaccessible",
            )
            return False
        if self._find_bundle() is None and not self._has_rn_native_lib():
            return False
        return True

    async def analyze(self) -> list[Finding]:
        ctx = self._context
        bundle = self._find_bundle()
        if bundle is None:
            # RN native libs are present but no bundle was extracted —
            # apktool occasionally drops assets/. Note and bail.
            self._log.info(
                "[RN_001] RN native libs present but no "
                "%s extracted; nothing to audit",
                _RN_BUNDLE_NAME,
            )
            return [self._make_finding(
                vuln_class="RN_BUNDLE_MISSING",
                severity=Severity.INFO,
                confidence=0.6,
                evidence={
                    "title": "React Native detected but bundle not extracted",
                    "resources_dir": str(ctx.resources_dir),
                    "rn_native_libs_present": True,
                },
                recommendation=(
                    "apktool did not extract assets/index.android.bundle. "
                    "Re-run apktool with -r (no-resource decoding) or "
                    "manually `unzip <apk> assets/index.android.bundle` "
                    "into resources_dir/assets/ and re-scan."
                ),
            )]

        try:
            head = bundle.read_bytes()[:_MAX_BUNDLE_BYTES]
        except OSError as e:
            self._log.warning("[RN_001] cannot read %s: %s", bundle, e)
            return []

        # Hermes short-circuit. The check is on the leading 4 bytes;
        # truncation has no effect because the magic is at the head.
        if head.startswith(_HERMES_MAGIC):
            self._log.info(
                "[RN_001] %s is Hermes bytecode — stopping JS analysis",
                bundle.name,
            )
            return [self._hermes_finding(bundle)]

        # Plain JS bundle.
        try:
            text = head.decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover — decode(errors='replace') won't raise
            self._log.warning("[RN_001] failed to decode bundle as UTF-8")
            return []

        findings: list[Finding] = []
        findings.extend(self._scan_async_storage(text, bundle))
        findings.extend(self._scan_cleartext(text, bundle))
        findings.extend(self._scan_secrets(text, bundle))
        findings.extend(self._scan_webview(text, bundle))
        findings.extend(self._scan_dangerous_html(text, bundle))
        return findings

    # ---------- Filesystem probes ----------

    def _find_bundle(self) -> Path | None:
        resources_dir = self._context.resources_dir
        if resources_dir is None:
            return None
        candidates = [
            resources_dir / "assets" / _RN_BUNDLE_NAME,
            resources_dir / "res" / "raw" / _RN_BUNDLE_NAME,
        ]
        for c in candidates:
            if c.exists() and c.is_file():
                return c
        # apktool sometimes drops index.android.bundle under unpacked/
        # in newer versions; fall back to rglob if the obvious paths
        # don't hit. The rglob is bounded — only one filename to find.
        for hit in resources_dir.rglob(_RN_BUNDLE_NAME):
            if hit.is_file():
                return hit
        return None

    def _has_rn_native_lib(self) -> bool:
        resources_dir = self._context.resources_dir
        if resources_dir is None:
            return False
        lib_root = resources_dir / "lib"
        if not lib_root.is_dir():
            return False
        for hint in _RN_NATIVE_LIB_HINTS:
            for _ in lib_root.rglob(hint):
                return True
        return False

    # ---------- Hermes notice ----------

    def _hermes_finding(self, bundle: Path) -> Finding:
        return self._make_finding(
            vuln_class=VC_HERMES_LIMIT,
            severity=Severity.INFO,
            confidence=0.95,
            evidence={
                "title": "Hermes bytecode detected — JS-source audit skipped",
                "bundle": str(bundle.name),
                "magic": "0xC61FBC03 (little-endian, Hermes BCFM)",
                "implication": (
                    "RN_001 source-level checks (AsyncStorage, "
                    "cleartext URLs, hardcoded secrets, WebView, "
                    "dangerouslySetInnerHTML) are disabled for this "
                    "bundle because the JS source is no longer present. "
                    "Most modern (RN 0.70+) apps ship Hermes by default."
                ),
            },
            recommendation=(
                "To audit JS-level issues in this app, disassemble the "
                "Hermes bundle with `hermes-dec` or `hbctool` and re-run "
                "the scan against the decompiled JS. SENTINEL does not "
                "perform Hermes disassembly itself; this is documented "
                "future work (see docs/CROSSPLATFORM.md)."
            ),
        )

    # ---------- Individual scanners ----------

    def _scan_async_storage(
        self, text: str, bundle: Path,
    ) -> Iterable[Finding]:
        hits: list[dict[str, str]] = []
        for m in _ASYNC_STORAGE_WRITE_RE.finditer(text):
            key = m.group(1)
            if not _SENSITIVE_KEY_RE.search(key):
                continue
            if len(hits) >= _MAX_HITS_PER_CATEGORY:
                break
            hits.append({
                "key": key,
                "snippet": _excerpt(text, m.start(), m.end()),
            })
        if not hits:
            return []
        return [self._make_finding(
            vuln_class=VC_INSEC_STORAGE,
            severity=Severity.HIGH,
            confidence=0.85,
            owasp="M9: Insecure Data Storage",
            masvs="MASVS-STORAGE-1",
            evidence={
                "title": (
                    f"{len(hits)} AsyncStorage/EncryptedStorage write(s) "
                    "with credential-shaped keys"
                ),
                "bundle": bundle.name,
                "hits": hits,
            },
            recommendation=(
                "AsyncStorage stores plaintext on internal storage. For "
                "tokens or credentials, use react-native-keychain (backed "
                "by Android Keystore + EncryptedSharedPreferences) or "
                "Expo SecureStore. Treat AsyncStorage as user-visible "
                "settings only."
            ),
        )]

    def _scan_cleartext(
        self, text: str, bundle: Path,
    ) -> Iterable[Finding]:
        hits: list[dict[str, str]] = []
        for m in _CLEARTEXT_URL_RE.finditer(text):
            url = m.group(1)
            if len(hits) >= _MAX_HITS_PER_CATEGORY:
                break
            hits.append({
                "url": url,
                "snippet": _excerpt(text, m.start(), m.end()),
            })
        if not hits:
            return []
        return [self._make_finding(
            vuln_class=VC_CLEARTEXT,
            severity=Severity.MEDIUM,
            confidence=0.85,
            owasp="M3: Insecure Communication",
            masvs="MASVS-NETWORK-1",
            evidence={
                "title": (
                    f"{len(hits)} cleartext http:// URL(s) in JS bundle"
                ),
                "bundle": bundle.name,
                "hits": hits,
            },
            recommendation=(
                "Replace http:// with https:// for every backend the JS "
                "code talks to. Pair with a Network Security Config that "
                "disables cleartext app-wide so a future regression can't "
                "silently re-introduce plaintext requests."
            ),
        )]

    def _scan_secrets(
        self, text: str, bundle: Path,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        for label, pat, sev, conf in _SECRET_PATTERNS:
            matches = list(pat.finditer(text))
            if not matches:
                continue
            hits = [
                {
                    "label": label,
                    "match": _redact(m.group(0)),
                    "snippet": _excerpt(text, m.start(), m.end()),
                }
                for m in matches[:_MAX_HITS_PER_CATEGORY]
            ]
            findings.append(self._make_finding(
                vuln_class=VC_SECRET,
                severity=sev,
                confidence=conf,
                owasp="M2: Inadequate Supply Chain Security",
                masvs="MASVS-CODE-3",
                evidence={
                    "title": f"Hardcoded secret in JS bundle: {label}",
                    "bundle": bundle.name,
                    "match_count": len(matches),
                    "hits": hits,
                },
                recommendation=(
                    f"A {label}-shaped value is embedded in the shipped "
                    "JS bundle. If it's a live credential, rotate it and "
                    "move the secret behind a server-side proxy. "
                    "react-native-config / build-time env injection only "
                    "obfuscates — strings ship verbatim in the bundle."
                ),
            ))
        return findings

    def _scan_webview(
        self, text: str, bundle: Path,
    ) -> Iterable[Finding]:
        dyn = list(_WEBVIEW_DYNAMIC_URI_RE.finditer(text))
        wild = list(_WEBVIEW_WILD_ORIGIN_RE.finditer(text))
        if not (dyn or wild):
            return []
        # Confidence climbs when both signals fire together.
        if dyn and wild:
            severity, confidence = Severity.MEDIUM, 0.75
            title = (
                "WebView with dynamic URI source AND wildcard origin "
                "whitelist — DOM injection / SOP-bypass risk"
            )
        else:
            severity, confidence = Severity.LOW, 0.55
            title = (
                "WebView with dynamic URI source OR wildcard origin "
                "whitelist — review for XSS"
            )
        return [self._make_finding(
            vuln_class=VC_WV_XSS,
            severity=severity,
            confidence=confidence,
            owasp="M4: Insufficient Input/Output Validation",
            masvs="MASVS-CODE-4",
            evidence={
                "title": title,
                "bundle": bundle.name,
                "dynamic_uri_hits": len(dyn),
                "wildcard_origin_hits": len(wild),
            },
            recommendation=(
                "Constrain WebView source URIs to an allow-list of "
                "trusted https hosts. Drop originWhitelist={['*']} — "
                "set it to the specific origins you intend to load. "
                "Disable JS in the WebView when possible; if not, audit "
                "every postMessage handler for XSS-like sinks."
            ),
        )]

    def _scan_dangerous_html(
        self, text: str, bundle: Path,
    ) -> Iterable[Finding]:
        hits = list(_DANGEROUSLY_SET_INNER_HTML_RE.finditer(text))
        if not hits:
            return []
        return [self._make_finding(
            vuln_class=VC_DANGEROUS_HTML,
            severity=Severity.LOW,
            confidence=0.55,
            owasp="M4: Insufficient Input/Output Validation",
            masvs="MASVS-CODE-4",
            evidence={
                "title": (
                    f"{len(hits)} use(s) of dangerouslySetInnerHTML in "
                    "the JS bundle"
                ),
                "bundle": bundle.name,
                "match_count": len(hits),
            },
            recommendation=(
                "dangerouslySetInnerHTML inserts unsanitised HTML. If "
                "the value flows from a network response or any "
                "user-controlled source, render the content as text or "
                "sanitise with DOMPurify (or a server-side equivalent) "
                "before injection. Audit the data path for every call."
            ),
        )]


# ---------- Small helpers ----------

def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    """Return a short, single-line excerpt of `text` around [start, end].

    Used to give the triager a glanceable hint without dumping the
    whole minified bundle line. Kept under 200 chars.
    """
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    return re.sub(r"\s+", " ", text[a:b]).strip()[:200]


def _redact(s: str) -> str:
    """Show the first 4 and last 4 characters of a secret; redact the rest.

    Lets the triager confirm the match shape without leaking the
    credential through scan logs.
    """
    if len(s) <= 8:
        return "***"
    return f"{s[:4]}…{s[-4:]}"


__all__ = ["ReactNativeAgent"]
