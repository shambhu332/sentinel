"""TAINT_001 — sources, sinks, sanitizers, and vuln-class mapping.

Three tables drive the data-flow tracer:

* ``SOURCES`` — call patterns whose return value is attacker-controlled.
  Each entry matches by simple method name; an optional ``receiver_hint``
  narrows the match to a specific chain segment (e.g. only treat
  ``getString`` as a source when it follows ``getSharedPreferences``,
  not every random ``getString``). Sources do not themselves carry a
  vulnerability class — the SINK determines what kind of flaw a tainted
  flow represents.

* ``SINKS`` — call patterns whose argument(s) are security-sensitive.
  Each entry names the argument positions to inspect (``arg_indices``)
  and the ``vuln_class`` to emit when one of those arguments is found
  tainted. ``key_arg_must_be_sensitive`` is set only for the
  SharedPreferences storage sink, which is only interesting when the
  *key* matches a sensitive pattern (token/password/jwt/…) — otherwise
  it's a benign settings write.

* ``SANITIZERS`` — call patterns that "scrub" their input. A taint flow
  that passes through any of these is downgraded: by default it is
  *not* emitted (sanitizer terminated the flow). Listing parameterised
  SQL placeholder binding via ``compileStatement`` / ``bindString`` here
  is what stops every prepared-statement query from being reported.

The tables are intentionally small. Precision matters more than
recall here — every false positive is a manual triage cost, and the
LLM triage pass is the safety net that catches what we miss.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.finding import Severity

# ---------- Sources ----------

@dataclass(frozen=True)
class SourceSpec:
    """A call pattern whose return value is attacker-controlled.

    ``method_name`` is the bare Java identifier (no parens, no dots).
    ``receiver_hint``, if set, must appear as a substring in the
    immediately preceding receiver chain. Keep these hints loose — the
    tracer matches them with ``in``, not equality.
    """
    method_name: str
    label: str
    receiver_hint: str | None = None


SOURCES: tuple[SourceSpec, ...] = (
    # Intent extras / data — the canonical untrusted-input source on
    # Android. Match the method name alone since the standard call is
    # ``getIntent().getStringExtra(...)`` and the chain is too variable
    # to pin down precisely.
    SourceSpec("getStringExtra",        "Intent extra (string)"),
    SourceSpec("getIntExtra",           "Intent extra (int)"),
    SourceSpec("getLongExtra",          "Intent extra (long)"),
    SourceSpec("getBooleanExtra",       "Intent extra (boolean)"),
    SourceSpec("getSerializableExtra",  "Intent extra (serializable)"),
    SourceSpec("getParcelableExtra",    "Intent extra (parcelable)"),
    SourceSpec("getExtras",             "Intent extras bundle"),
    SourceSpec("getData",               "Intent data URI", receiver_hint="getIntent"),
    SourceSpec("getDataString",         "Intent data string"),

    # UI input.
    SourceSpec("getText",               "UI text input"),

    # Cursor / DB — content the app reads back may have been written by
    # another app via an exported ContentProvider.
    SourceSpec("getString",             "Cursor field",     receiver_hint="Cursor"),
    SourceSpec("getBlob",               "Cursor blob",      receiver_hint="Cursor"),

    # SharedPreferences — on rooted devices the prefs file is editable
    # by an attacker; treat reads as untrusted.
    SourceSpec("getString",             "SharedPreferences read",  receiver_hint="getSharedPreferences"),

    # HTTP response bodies — server-side content the client should
    # validate (especially for downstream sinks that interpret it).
    SourceSpec("string",                "HTTP response body", receiver_hint="body"),
    SourceSpec("bytes",                 "HTTP response bytes", receiver_hint="body"),
)


# ---------- Sinks ----------

@dataclass(frozen=True)
class SinkSpec:
    """A call pattern whose tainted arguments mean a vulnerability."""
    method_name: str
    arg_indices: tuple[int, ...]
    vuln_class: str
    severity: Severity
    owasp: str
    masvs: str
    recommendation: str
    receiver_hint: str | None = None
    # SharedPreferences ``putString(key, value)`` — only interesting
    # when ``key`` (arg 0) names a credential. Otherwise it's a benign
    # settings write.
    key_arg_must_be_sensitive: bool = False
    key_arg_index: int = 0


# Vuln-class symbolic names. Kept as module constants so tests can
# reference them without string typos.
VC_SQLI       = "SQL_INJECTION"
VC_XSS_WV     = "WEBVIEW_XSS"
VC_CMD        = "COMMAND_INJECTION"
VC_PATH       = "PATH_TRAVERSAL"
VC_INSEC_STG  = "INSECURE_STORAGE_FLOW"
VC_SENS_LOG   = "SENSITIVE_LOG"


SINKS: tuple[SinkSpec, ...] = (
    # SQL — arg 0 is the query string.
    SinkSpec(
        method_name="rawQuery", arg_indices=(0,),
        vuln_class=VC_SQLI, severity=Severity.HIGH,
        owasp="M7: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "Use parameterised queries: pass user input via the "
            "selectionArgs array (the ? placeholders) rather than "
            "string-concatenating it into the SQL."
        ),
    ),
    SinkSpec(
        method_name="execSQL", arg_indices=(0,),
        vuln_class=VC_SQLI, severity=Severity.HIGH,
        owasp="M7: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "Replace execSQL(String) with execSQL(String, Object[]) and "
            "pass arguments as the second parameter."
        ),
    ),

    # WebView — JS in URL/data/eval becomes code in app's WebView origin.
    SinkSpec(
        method_name="loadUrl", arg_indices=(0,),
        vuln_class=VC_XSS_WV, severity=Severity.HIGH,
        owasp="M4: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "Validate URLs against an allow-list of schemes (https only) "
            "and hosts before loadUrl. Never construct javascript: URLs "
            "from external input."
        ),
    ),
    SinkSpec(
        method_name="loadData", arg_indices=(0,),
        vuln_class=VC_XSS_WV, severity=Severity.HIGH,
        owasp="M4: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "HTML-encode tainted content with TextUtils.htmlEncode before "
            "passing to loadData. Prefer loadDataWithBaseURL with a null "
            "base URL to deny same-origin access for the rendered page."
        ),
    ),
    SinkSpec(
        method_name="evaluateJavascript", arg_indices=(0,),
        vuln_class=VC_XSS_WV, severity=Severity.HIGH,
        owasp="M4: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "Do not pass attacker-controlled strings into "
            "evaluateJavascript. Serialise data as JSON via "
            "JSONObject.toString and quote it as a JS literal, never "
            "concatenate raw input into a script body."
        ),
    ),

    # Command — Runtime.exec / ProcessBuilder.
    SinkSpec(
        method_name="exec", arg_indices=(0,),
        vuln_class=VC_CMD, severity=Severity.CRITICAL,
        owasp="M7: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "Avoid Runtime.exec on user input entirely. If a subprocess "
            "is unavoidable, use the String[] overload with a fixed "
            "binary path and the input as an isolated argv element — "
            "never the single-String overload that goes through /bin/sh."
        ),
        receiver_hint="Runtime",
    ),
    SinkSpec(
        method_name="ProcessBuilder", arg_indices=(0,),
        vuln_class=VC_CMD, severity=Severity.CRITICAL,
        owasp="M7: Insufficient Input/Output Validation",
        masvs="MASVS-CODE-4",
        recommendation=(
            "Pass arguments as a List<String> with the binary fixed at "
            "index 0. Treat any user input as data, never an argv prefix."
        ),
    ),

    # Path traversal — `new File(...)` and openFileOutput.
    SinkSpec(
        method_name="File", arg_indices=(0, 1),
        vuln_class=VC_PATH, severity=Severity.HIGH,
        owasp="M4: Insufficient Input/Output Validation",
        masvs="MASVS-STORAGE-2",
        recommendation=(
            "Canonicalise the resolved path with File.getCanonicalPath() "
            "and reject results that escape the app's intended base "
            "directory. Strip ../ before resolution."
        ),
    ),
    SinkSpec(
        method_name="openFileOutput", arg_indices=(0,),
        vuln_class=VC_PATH, severity=Severity.HIGH,
        owasp="M4: Insufficient Input/Output Validation",
        masvs="MASVS-STORAGE-2",
        recommendation=(
            "Validate the filename — disallow '/', '..', and absolute "
            "paths. Use Context.getFilesDir() + File.getCanonicalPath() "
            "and confirm the result stays under the base directory."
        ),
    ),

    # SharedPreferences — writes only matter when the *key* names a
    # credential. The key check is done by the tracer before emitting.
    SinkSpec(
        method_name="putString", arg_indices=(1,),
        vuln_class=VC_INSEC_STG, severity=Severity.MEDIUM,
        owasp="M9: Insecure Data Storage",
        masvs="MASVS-STORAGE-1",
        recommendation=(
            "Sensitive material (tokens, passwords, keys) belongs in "
            "EncryptedSharedPreferences (androidx.security.crypto), the "
            "Android Keystore, or — for short-lived secrets — in-memory "
            "only. Never the default SharedPreferences."
        ),
        key_arg_must_be_sensitive=True,
        key_arg_index=0,
    ),

    # Logging — Log.d/v/i/w/e of tainted data leaks it to logcat.
    SinkSpec(
        method_name="d", arg_indices=(1,),
        vuln_class=VC_SENS_LOG, severity=Severity.LOW,
        owasp="M9: Insecure Data Storage",
        masvs="MASVS-STORAGE-2",
        recommendation=(
            "Strip the sensitive value before logging, or guard the "
            "call with BuildConfig.DEBUG so it never reaches production "
            "builds. Prefer Log.isLoggable() over commenting out calls."
        ),
        receiver_hint="Log",
    ),
    SinkSpec(
        method_name="v", arg_indices=(1,), vuln_class=VC_SENS_LOG,
        severity=Severity.LOW,
        owasp="M9: Insecure Data Storage", masvs="MASVS-STORAGE-2",
        recommendation="Same as Log.d — guard or strip before logging.",
        receiver_hint="Log",
    ),
    SinkSpec(
        method_name="i", arg_indices=(1,), vuln_class=VC_SENS_LOG,
        severity=Severity.LOW,
        owasp="M9: Insecure Data Storage", masvs="MASVS-STORAGE-2",
        recommendation="Same as Log.d — guard or strip before logging.",
        receiver_hint="Log",
    ),
    SinkSpec(
        method_name="w", arg_indices=(1,), vuln_class=VC_SENS_LOG,
        severity=Severity.LOW,
        owasp="M9: Insecure Data Storage", masvs="MASVS-STORAGE-2",
        recommendation="Same as Log.d — guard or strip before logging.",
        receiver_hint="Log",
    ),
    SinkSpec(
        method_name="e", arg_indices=(1,), vuln_class=VC_SENS_LOG,
        severity=Severity.LOW,
        owasp="M9: Insecure Data Storage", masvs="MASVS-STORAGE-2",
        recommendation="Same as Log.d — guard or strip before logging.",
        receiver_hint="Log",
    ),
)


# ---------- Sanitizers ----------

@dataclass(frozen=True)
class SanitizerSpec:
    """A call that scrubs its input enough to break a particular flow.

    ``applies_to_classes`` restricts the sanitizer to specific vuln
    classes. ``Integer.parseInt`` sanitises SQLi / path traversal / cmd
    injection because the parsed value is numeric, but it does *not*
    sanitise an INSECURE_STORAGE_FLOW finding (an integer token is still
    a token stored in cleartext prefs). Empty set ⇒ applies to all.
    """
    method_name: str
    receiver_hint: str | None = None
    applies_to_classes: frozenset[str] = field(default_factory=frozenset)


SANITIZERS: tuple[SanitizerSpec, ...] = (
    # Numeric coercion — breaks string-injection sinks, leaves storage
    # flows untouched.
    SanitizerSpec("parseInt",  receiver_hint="Integer",
                  applies_to_classes=frozenset({VC_SQLI, VC_PATH, VC_CMD, VC_XSS_WV})),
    SanitizerSpec("parseLong", receiver_hint="Long",
                  applies_to_classes=frozenset({VC_SQLI, VC_PATH, VC_CMD, VC_XSS_WV})),
    SanitizerSpec("valueOf",   receiver_hint="Integer",
                  applies_to_classes=frozenset({VC_SQLI, VC_PATH, VC_CMD, VC_XSS_WV})),

    # HTML encoding — breaks WebView XSS, not SQLi (encoded chars still
    # form valid SQL injections via '%2527' tricks etc).
    SanitizerSpec("htmlEncode", receiver_hint="TextUtils",
                  applies_to_classes=frozenset({VC_XSS_WV, VC_SENS_LOG})),

    # URL encoding — breaks command injection and WebView XSS by
    # turning shell/HTML metacharacters into %xx escapes.
    SanitizerSpec("encode", receiver_hint="URLEncoder",
                  applies_to_classes=frozenset({VC_XSS_WV, VC_CMD, VC_PATH})),

    # Parameterised-query plumbing. The presence of either of these in
    # a flow strongly suggests the tainted value is bound as a
    # parameter, not concatenated into SQL.
    SanitizerSpec("compileStatement",
                  applies_to_classes=frozenset({VC_SQLI})),
    SanitizerSpec("bindString",
                  applies_to_classes=frozenset({VC_SQLI})),
    SanitizerSpec("bindLong",
                  applies_to_classes=frozenset({VC_SQLI})),

    # Path canonicalisation — confirms the path is normalised; not a
    # complete defence on its own but the standard idiom is to follow
    # it with a startsWith allow-list check, which we treat as
    # sanitising for our purposes.
    SanitizerSpec("getCanonicalPath",
                  applies_to_classes=frozenset({VC_PATH})),
)


# ---------- Sensitive-key heuristic (for InsecureStorage sink) ----------

# Substrings (case-insensitive) that mark a SharedPreferences key as
# sensitive. The trace emits an INSECURE_STORAGE_FLOW finding only if
# the putString key matches one of these. Keeps benign settings keys
# (theme, locale, etc) out of the report.
SENSITIVE_KEY_HINTS: tuple[str, ...] = (
    "token", "jwt", "password", "passwd", "pwd", "secret",
    "auth", "session", "credential", "apikey", "api_key",
    "private", "refresh",
)


def key_looks_sensitive(literal: str) -> bool:
    """Case-insensitive substring match for sensitive-key hints."""
    if not isinstance(literal, str):
        return False
    needle = literal.strip("\"'").lower()
    return any(hint in needle for hint in SENSITIVE_KEY_HINTS)


# ---------- Confidence per IPA depth ----------

# Depth 0 = direct intra-procedural taint (sink and source in same
# method). Each call-graph hop discounts by 0.1, floored at 0.6.
def confidence_for_depth(depth: int) -> float:
    """0 → 0.9, 1 → 0.8, 2 → 0.7, 3 → 0.6, anything beyond → 0.6."""
    if depth < 0:
        depth = 0
    return max(0.6, 0.9 - 0.1 * depth)


# ---------- Public symbol list ----------

__all__ = [
    "SourceSpec", "SinkSpec", "SanitizerSpec",
    "SOURCES", "SINKS", "SANITIZERS",
    "SENSITIVE_KEY_HINTS", "key_looks_sensitive",
    "confidence_for_depth",
    "VC_SQLI", "VC_XSS_WV", "VC_CMD", "VC_PATH",
    "VC_INSEC_STG", "VC_SENS_LOG",
]
