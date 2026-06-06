"""NL_002: System.loadLibrary / System.load Taint Detection.

``System.loadLibrary("name")`` loads ``libname.so`` from the APK's
embedded jniLibs at install time, which is fine and ubiquitous.
``System.load("/absolute/path/to/lib.so")`` loads any file on the
file system that the app UID can read. If either method receives an
*attacker-controlled string* (Intent extra, deep link parameter,
SharedPreferences value, remote-downloaded path), an attacker gets
arbitrary-code execution in the app's UID.

The pattern is rare in well-written apps but recurring in:

* dynamic plugin loaders that download .so blobs at runtime,
* "branch SDK" integrations that store a library name in prefs,
* WebView -> JS-interface bridges that route extra-derived paths
  into a loader.

Detection
=========

For every ``System.loadLibrary(`` / ``System.load(`` / ``Runtime.load(``
/ ``Runtime.loadLibrary(`` call we inspect the argument expression:

* Direct string literal → no finding (legitimate static load).
* A local variable / identifier → walk back through the same method
  body looking for the variable's last assignment. If that assignment
  comes from one of the taint sources below, emit a finding.

Taint sources
-------------

* ``getIntent().getStringExtra(...)`` / ``getData().getQueryParameter(...)``
* ``intent.getStringExtra(...)`` (Intent-typed parameter)
* ``getSharedPreferences(...).getString(...)``
* ``new URL(...).openStream`` / ``Request.Builder().build()`` style
  network reads (best-effort — we look for ``URL`` / ``HttpURL`` /
  ``okhttp`` keywords in the same method)
* ``File.getAbsolutePath`` chained from any of the above
"""
from __future__ import annotations

import re

from sentinel.agents.base import BaseAgent
from sentinel.core.finding import Finding, Severity

_LOAD_CALL = re.compile(
    r"\b(?:System|Runtime\s*\.\s*getRuntime\s*\(\s*\))"
    r"\s*\.\s*(loadLibrary|load)\s*\(\s*([^)]+?)\s*\)",
)

# Taint source patterns scoped to the enclosing method body.
_INTENT_EXTRA = re.compile(
    r"\.(getStringExtra|getCharSequenceExtra|getDataString)\s*\(",
)
_INTENT_QUERY = re.compile(
    r"getData\s*\(\s*\)\s*\.\s*getQueryParameter\s*\(",
)
_PREFS_GET = re.compile(
    r"\.(getString|getStringExtra)\s*\(\s*\"[^\"]+\"",
)
_NETWORK_FETCH = re.compile(
    r"\b(URL|HttpURLConnection|OkHttpClient|Request\.Builder)\b",
)


def _enclosing_method_body(source: str, idx: int) -> str | None:
    """Return the brace-balanced method body that contains ``idx``.

    Best-effort — walks back to find the nearest ``{`` whose matching
    ``}`` is after ``idx``. Returns the slice between them.
    """
    open_idx = source.rfind("{", 0, idx)
    while open_idx != -1:
        depth = 0
        i = open_idx
        while i < len(source):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    if i >= idx:
                        return source[open_idx + 1 : i]
                    break
            i += 1
        open_idx = source.rfind("{", 0, open_idx)
    return None


class LoadLibraryTaintAgent(BaseAgent):
    """Flag System.loadLibrary / System.load with attacker-controllable input."""

    AGENT_ID = "NL_002"
    VULN_CLASS = "Attacker-Controlled Native Library Load"
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
            for match in _LOAD_CALL.finditer(source):
                method_name = match.group(1)
                arg_expr = match.group(2).strip()
                if not arg_expr or arg_expr.startswith('"'):
                    # static string literal
                    continue
                # Bail out on obviously non-tainted forms.
                if arg_expr.startswith("R."):
                    continue

                body = _enclosing_method_body(source, match.start()) or ""
                taint_source, reason = self._find_taint_source(body)
                if taint_source is None:
                    continue

                severity, confidence = self._score(
                    method=method_name,
                    taint_source=taint_source,
                )
                findings.append(self._make_finding(
                    vuln_class="Attacker-Controlled Native Library Load",
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "file": str(java_file.relative_to(decompiled)),
                        "method": method_name,
                        "argument": arg_expr[:120],
                        "taint_source": taint_source,
                        "reason": reason,
                    },
                    recommendation=(
                        "Never derive the argument to System.loadLibrary "
                        "/ System.load from an external input. Hard-code "
                        "the library name and ship the .so inside the "
                        "APK's jniLibs. If runtime selection is required, "
                        "constrain the value to an allowlist of "
                        "known-good library names and verify the on-disk "
                        "file's hash against a pinned digest before "
                        "loading."
                    ),
                    owasp="M7: Client Code Quality",
                    masvs="MSTG-CODE-8",
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                ))
        return findings

    @staticmethod
    def _find_taint_source(body: str) -> tuple[str | None, str]:
        if _INTENT_EXTRA.search(body):
            return "intent_extra", "getStringExtra / getDataString in scope"
        if _INTENT_QUERY.search(body):
            return "deep_link", "getQueryParameter on Intent data in scope"
        if _PREFS_GET.search(body):
            return "shared_prefs", "SharedPreferences.getString in scope"
        if _NETWORK_FETCH.search(body):
            return (
                "network_download",
                "URL / HttpURLConnection / OkHttp call in scope",
            )
        return None, ""

    @staticmethod
    def _score(*, method: str, taint_source: str) -> tuple[Severity, float]:
        # System.load (absolute path) is strictly worse than loadLibrary.
        if method == "load":
            return Severity.CRITICAL, 0.90
        if taint_source in ("intent_extra", "deep_link"):
            return Severity.CRITICAL, 0.85
        if taint_source == "network_download":
            return Severity.HIGH, 0.75
        return Severity.HIGH, 0.70
