"""Per-finding narrative enrichment for the VAPT advisory template.

For every finding we want the report to look like a Bishop-Fox / NCC
advisory: a short prose summary, an explicit reproduction recipe, an
impact bullet list, a fix bullet list, and a reference list. Agents
themselves only emit a short evidence dict, so this module fills in
the prose layer.

Strategy:

1. Try ``FreeProviderRouter.query_json`` (Groq → Cerebras → Ollama).
   The prompt asks for a strict JSON object that maps cleanly onto
   :class:`FindingSection.narrative`.

2. If every provider fails (no API key, circuit open, parse error,
   etc.) we fall back to a *deterministic* boilerplate keyed by
   ``Finding.agent_id``. The boilerplate is honest — it never invents
   PoCs we don't have evidence for.

The renderer reads ``section.narrative`` if present and otherwise
degrades to evidence-only output.
"""
from __future__ import annotations

import logging
from typing import Any

from sentinel.agents.reporting.models import FindingSection
from sentinel.core.finding import Finding, Severity

logger = logging.getLogger(__name__)


_DEFAULT_IMPACT_BY_SEVERITY: dict[Severity, list[str]] = {
    Severity.CRITICAL: [
        "Full compromise of the affected component is feasible from an "
        "unprivileged caller.",
        "Account takeover, credential theft, or persistent backdoor on "
        "the device user is realistic.",
    ],
    Severity.HIGH: [
        "An attacker can extract sensitive data or bypass a security "
        "control without elevated privileges.",
        "Materially weakens the app's trust boundary against a "
        "co-installed or remote attacker.",
    ],
    Severity.MEDIUM: [
        "Degrades the application's defence-in-depth.",
        "Useful reconnaissance for a longer exploit chain.",
    ],
    Severity.LOW: [
        "Low-impact misconfiguration; informational defence-in-depth "
        "regression.",
    ],
    Severity.INFO: [
        "Informational observation with no direct attacker capability.",
    ],
}


_SYSTEM_PROMPT = (
    "You are a senior mobile security consultant writing a one-page "
    "advisory for a Bishop-Fox / NCC-style VAPT report. You will "
    "expand a single finding into a strict JSON object. Be precise, "
    "concrete, and do not invent file paths, line numbers, PoC URLs, "
    "or CVEs that are not present in the input. If you do not have "
    "evidence for a field, write \"\" or [] — never fabricate."
)

_USER_TEMPLATE = """\
Finding to expand:

  agent_id:       {agent_id}
  vuln_class:     {vuln_class}
  severity:       {severity}
  owasp:          {owasp}
  masvs:          {masvs}
  cvss_vector:    {cvss}
  recommendation: {recommendation}
  triage:         {triage}
  evidence_keys:  {evidence_keys}
  evidence_json:  {evidence_json}

Return ONLY a JSON object with these keys:

  summary:             4-6 sentences of consultancy-grade prose
                       explaining the bug class, why it matters in this
                       app, and the attacker prerequisites.
  affected_components: array of strings (file paths, class names,
                       manifest entries) drawn ONLY from the evidence.
                       Empty array if none.
  evidence_notes:      1-3 sentence walk-through of what the scanner
                       actually saw, citing the keys from evidence_json.
  repro_steps:         array of imperative steps a reviewer could run
                       on a test device to confirm. Do not invent URLs.
  poc_snippet:         a short, runnable snippet (adb command, Java
                       fragment, manifest XML) that demonstrates the
                       bug. Empty string if not safe to invent.
  impact_bullets:      array of 2-4 short bullets describing concrete
                       attacker capability.
  fix_bullets:         array of 2-4 imperative bullets, code-level.
  references:          array of objects {{"label": str, "url": str}}.
                       Include the canonical OWASP MASTG, CWE, and
                       Android-developer doc URLs relevant to this bug.

Return nothing else. No prose outside the JSON.
"""


async def enrich_section(
    section: FindingSection,
    router: Any,  # FreeProviderRouter | None
) -> None:
    """Populate ``section.narrative`` in-place.

    ``router`` may be None or any object with ``query_json``. When the
    LLM path fails for any reason we degrade to ``_fallback_narrative``.
    """
    if section.narrative:
        return

    if router is not None:
        try:
            data = await _query_router(router, section.finding)
            if isinstance(data, dict) and data.get("summary"):
                section.narrative = _coerce_narrative(data, section.finding)
                return
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "enrich: router failed for %s — falling back (%s)",
                section.finding.agent_id, exc,
            )

    section.narrative = _fallback_narrative(section.finding)


async def enrich_sections(
    sections: list[FindingSection],
    router: Any,
) -> None:
    """Enrich every section serially; cheaper providers don't tolerate
    bursty parallel load and most reports have <30 findings."""
    for s in sections:
        await enrich_section(s, router)


# ---------- internals ----------


async def _query_router(router: Any, finding: Finding) -> dict:
    import json
    evidence = finding.evidence or {}
    user_msg = _USER_TEMPLATE.format(
        agent_id=finding.agent_id,
        vuln_class=finding.vuln_class,
        severity=finding.severity.name if hasattr(finding.severity, "name")
                 else str(finding.severity),
        owasp=finding.owasp or "—",
        masvs=finding.masvs or "—",
        cvss=finding.cvss_vector or "n/a",
        recommendation=finding.recommendation or "—",
        triage="",
        evidence_keys=list(evidence.keys()) if isinstance(evidence, dict)
                     else "—",
        evidence_json=json.dumps(evidence, default=str)[:2000],
    )
    result = await router.query_json(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        tier="T2",
    )
    return result.get("content") or {}


def _coerce_narrative(data: dict, finding: Finding) -> dict:
    """Validate types, fill missing fields from deterministic fallback."""
    fb = _fallback_narrative(finding)
    out = {
        "summary": _str(data.get("summary"), fb["summary"]),
        "affected_components": _strlist(
            data.get("affected_components"), fb["affected_components"],
        ),
        "evidence_notes": _str(data.get("evidence_notes"), fb["evidence_notes"]),
        "repro_steps": _strlist(data.get("repro_steps"), fb["repro_steps"]),
        "poc_snippet": _str(data.get("poc_snippet"), fb["poc_snippet"]),
        "impact_bullets": _strlist(
            data.get("impact_bullets"), fb["impact_bullets"],
        ),
        "fix_bullets": _strlist(data.get("fix_bullets"), fb["fix_bullets"]),
        "references": _reflist(data.get("references"), fb["references"]),
    }
    return out


def _str(v: Any, default: str) -> str:
    if isinstance(v, str) and v.strip():
        return v.strip()
    return default


def _strlist(v: Any, default: list[str]) -> list[str]:
    if isinstance(v, list):
        out = [str(x).strip() for x in v if str(x).strip()]
        if out:
            return out
    return default


def _reflist(v: Any, default: list[dict]) -> list[dict]:
    if isinstance(v, list):
        out: list[dict] = []
        for x in v:
            if isinstance(x, dict) and x.get("url"):
                out.append({
                    "label": str(x.get("label") or x["url"]),
                    "url": str(x["url"]),
                })
        if out:
            return out
    return default


# ---------- deterministic fallback ----------


_BOILERPLATE: dict[str, dict[str, Any]] = {
    "P_001": {
        "summary": (
            "The application registers a custom URI scheme on an "
            "exported activity. Custom URI schemes cannot be verified "
            "on Android: only ``https://`` filters paired with a hosted "
            "``assetlinks.json`` benefit from the autoVerify attribute. "
            "Any other installed application can register the same "
            "scheme, and the Android system will surface a chooser the "
            "user has a 50/50 chance of resolving the wrong way."
        ),
        "repro_steps": [
            "Build a tiny attacker app whose manifest declares the same "
            "scheme/host on an exported activity.",
            "Sideload both the target app and the attacker app on a "
            "test device.",
            "Fire the deep link from a web page or `adb shell am start "
            "-a android.intent.action.VIEW -d <uri>`.",
            "Observe Android's chooser dialog or, when the attacker app "
            "has higher priority, silent capture of the URI.",
        ],
        "poc_snippet": (
            "adb shell am start -a android.intent.action.VIEW "
            "-d \"<scheme>://<host>/path?token=ABC123\""
        ),
        "impact_bullets": [
            "Capture of one-time URIs (password reset, magic login, "
            "OAuth callbacks).",
            "Hijack of affiliate / referral parameters.",
            "Input vector for a downstream WebView / open-redirect chain.",
        ],
        "fix_bullets": [
            "Move sensitive deep links to verified HTTPS App Links "
            "(`autoVerify=\"true\"` + `/.well-known/assetlinks.json`).",
            "Validate the URI against a canonical allow-list before "
            "persisting or routing it.",
            "Never carry tokens in a custom-scheme URI.",
        ],
        "references": [
            {"label": "Android App Links",
             "url": "https://developer.android.com/training/app-links"},
            {"label": "Digital Asset Links",
             "url": "https://developers.google.com/digital-asset-links"},
            {"label": "CWE-940",
             "url": "https://cwe.mitre.org/data/definitions/940.html"},
        ],
    },
    "A_001": {
        "summary": (
            "Authentication tokens are persisted to plain file or "
            "shared-preferences storage. Any backup, ADB pull from a "
            "rooted device, or co-resident app with the right "
            "permission can read these tokens and impersonate the user."
        ),
        "repro_steps": [
            "On a rooted or emulator device, run `adb shell run-as "
            "<pkg> cat shared_prefs/<file>.xml`.",
            "Confirm a bearer / refresh token value is present in "
            "cleartext.",
        ],
        "poc_snippet": "adb shell run-as <pkg> cat shared_prefs/<file>.xml",
        "impact_bullets": [
            "Account takeover via stolen bearer / refresh tokens.",
            "Persistent compromise across token rotation if refresh "
            "tokens are captured.",
        ],
        "fix_bullets": [
            "Store secrets in the Android Keystore.",
            "Use EncryptedSharedPreferences with a Keystore-bound key.",
            "Disable Auto Backup for credential files via "
            "`android:allowBackup=\"false\"` or a `backup_rules.xml` "
            "exclusion.",
        ],
        "references": [
            {"label": "MASVS-STORAGE-1",
             "url": "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/"},
            {"label": "Android Keystore",
             "url": "https://developer.android.com/training/articles/keystore"},
        ],
    },
    "B_002": {
        "summary": (
            "The application uses `java.util.Random` or `Math.random()` "
            "for what looks like a security-relevant value. These "
            "generators are predictable from a single observed output."
        ),
        "repro_steps": [
            "Observe one token / nonce produced by the application.",
            "Seed a local `java.util.Random` with the observed value "
            "and predict subsequent outputs.",
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Predictable session identifiers or password-reset tokens.",
            "Trivial brute-force where the entropy was assumed adequate.",
        ],
        "fix_bullets": [
            "Replace with `java.security.SecureRandom`.",
            "For key material, derive via `KeyGenerator` /  "
            "`KeyPairGenerator`.",
        ],
        "references": [
            {"label": "CWE-330",
             "url": "https://cwe.mitre.org/data/definitions/330.html"},
        ],
    },
    "N_002": {
        "summary": (
            "The application allows cleartext HTTP traffic. Any network "
            "attacker (rogue Wi-Fi, captive portal, ISP) can intercept "
            "or modify the traffic in transit."
        ),
        "repro_steps": [
            "Place the device on a Wi-Fi network you control with "
            "mitmproxy / Burp acting as the gateway.",
            "Observe HTTP requests originating from the app.",
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Credential and session-cookie interception.",
            "Response tampering enabling further client-side exploits.",
        ],
        "fix_bullets": [
            "Set `android:usesCleartextTraffic=\"false\"`.",
            "Pin TLS certificates for high-value endpoints via "
            "Network Security Config.",
        ],
        "references": [
            {"label": "Network Security Configuration",
             "url": "https://developer.android.com/training/articles/security-config"},
        ],
    },
    "P_010": {
        "summary": (
            "The app forwards an attacker-controllable Intent through "
            "`startActivity` without validating its target. A malicious "
            "caller can re-target the inner Intent at a private "
            "component to bypass export restrictions (CWE-926)."
        ),
        "repro_steps": [
            "From an attacker app, construct an outer Intent for the "
            "vulnerable activity with an inner Intent extra pointing "
            "at the target component.",
            "Start the outer Intent and observe the private component "
            "being launched with attacker-controlled extras.",
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Bypass of `android:exported=false` on internal screens.",
            "Pivot into authenticated flows from an unprivileged caller.",
        ],
        "fix_bullets": [
            "Strip the forwarded Intent's component / package / data.",
            "Validate the target against an allow-list before launching.",
        ],
        "references": [
            {"label": "CWE-926",
             "url": "https://cwe.mitre.org/data/definitions/926.html"},
        ],
    },
    "D_001": {
        "summary": (
            "The application writes credential-shaped data to the "
            "system clipboard at runtime. The Android clipboard is "
            "process-wide shared state — every foregrounded app "
            "(and on Android 10+ every recently-foregrounded app) "
            "can read whatever the user last copied. Banking, "
            "auth, and crypto-wallet apps that push OTPs, "
            "recovery phrases, or session tokens onto the clipboard "
            "expose them to every other co-installed app silently. "
            "A malicious app can also use `ClipboardManager.OnPrimaryClipChangedListener` "
            "to receive a callback the instant the value lands."
        ),
        "repro_steps": [
            "Install a co-resident clipboard-monitor app on the "
            "test device.",
            "Exercise the flow in the target app that copies the "
            "credential.",
            "Observe the monitor app receive the same value.",
        ],
        "poc_snippet": (
            "// Co-resident app:\n"
            "ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);\n"
            "cm.addPrimaryClipChangedListener(() ->\n"
            "    Log.d(\"X\", cm.getPrimaryClip().getItemAt(0).getText().toString()));"
        ),
        "impact_bullets": [
            "Co-resident apps silently capture OTPs / tokens.",
            "Accessibility services and keyboards both read the clipboard.",
            "On Android 13+ the system surface-warns the user, but the "
            "secret has already reached every monitor running at the moment.",
        ],
        "fix_bullets": [
            "Do not write secrets to the system clipboard at all.",
            "If a copy affordance is required, mark the ClipData with "
            "`ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+) so the "
            "system suppresses preview.",
            "Auto-clear the entry on a short timer (5–30s).",
        ],
        "references": [
            {"label": "Android — Copy and Paste",
             "url": "https://developer.android.com/develop/ui/views/touch-and-input/copy-paste"},
        ],
    },
    "D_002": {
        "summary": (
            "An Activity that displays password / PIN / OTP-style "
            "input never asserts "
            "`WindowManager.LayoutParams.FLAG_SECURE` on its Window. "
            "The credential is visible to the system Recents preview "
            "(any app that has held foreground recently), to "
            "MediaProjection-based screen recorders, and to "
            "accessibility services. Banking apps are routinely "
            "fingerprinted on this missing flag."
        ),
        "repro_steps": [
            "Launch the Activity that displays the sensitive field.",
            "Press the system Recents button — observe the thumbnail "
            "renders the secret in cleartext.",
            "Run an accessibility-screen-recorder app — observe it "
            "captures the screen.",
        ],
        "poc_snippet": (
            "@Override protected void onCreate(Bundle s) {\n"
            "  getWindow().setFlags(\n"
            "    WindowManager.LayoutParams.FLAG_SECURE,\n"
            "    WindowManager.LayoutParams.FLAG_SECURE);  // ADD THIS\n"
            "  super.onCreate(s);\n"
            "}"
        ),
        "impact_bullets": [
            "Recents thumbnail leaks credentials to any future "
            "foreground app.",
            "Screen recorders and accessibility-grade tools capture "
            "the field in real time.",
            "Targeted screenshots from a parental-control or MDM "
            "agent retain the secret.",
        ],
        "fix_bullets": [
            "Call `getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)` "
            "in `onCreate()` before `setContentView()`.",
            "On Android 13+ set `android:windowFlagSecure=\"true\"` "
            "in the activity theme so the flag survives recreation.",
        ],
        "references": [
            {"label": "WindowManager.LayoutParams.FLAG_SECURE",
             "url": "https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE"},
        ],
    },
    "D_003": {
        "summary": (
            "BiometricPrompt is configured to accept downgraded "
            "authenticators (BIOMETRIC_WEAK / DEVICE_CREDENTIAL) or "
            "is not bound to a Keystore CryptoObject. The user's "
            "biometric assertion silently reduces to a yes/no signal "
            "the app can be tricked into faking, or to the device "
            "PIN — which the user explicitly opted *out* of by "
            "choosing biometrics."
        ),
        "repro_steps": [
            "Enable a Class-2 face unlock on a test device.",
            "Trigger the sensitive flow.",
            "Observe the biometric prompt accepts the weak unlock.",
        ],
        "poc_snippet": (
            "BiometricPrompt prompt = new BiometricPrompt.Builder(this)\n"
            "  .setAllowedAuthenticators(BIOMETRIC_STRONG)  // not WEAK\n"
            "  .build();\n"
            "prompt.authenticate(new CryptoObject(cipher), ...);  // bind to key"
        ),
        "impact_bullets": [
            "Class-2 face unlock spoofable from a photo on some OEMs.",
            "DEVICE_CREDENTIAL silently allows the device PIN.",
            "Unbound prompt is satisfied by a Java-level callback "
            "spoof — no Keystore key is actually unlocked.",
        ],
        "fix_bullets": [
            "Pass `BIOMETRIC_STRONG` to `setAllowedAuthenticators`.",
            "Bind the prompt to a Keystore-backed CryptoObject so "
            "success implies key unlock.",
            "Never call `setDeviceCredentialAllowed(true)` for "
            "sensitive operations.",
        ],
        "references": [
            {"label": "BiometricPrompt.Builder",
             "url": "https://developer.android.com/reference/androidx/biometric/BiometricPrompt.Builder"},
        ],
    },
    "D_005": {
        "summary": (
            "The application loads executable code at runtime from a "
            "non-APK source. The loaded module runs with the "
            "application's full Android permissions. Any attacker "
            "who can write to the source path achieves complete "
            "code execution under the app's identity. The Google "
            "Play policy explicitly forbids this for non-APK "
            "loads outside the standard split-APK mechanism."
        ),
        "repro_steps": [
            "Identify the source path from the captured event.",
            "If the path is on /sdcard, /storage/emulated, or "
            "/data/local/tmp, drop a small payload DEX or .so "
            "to the same path on a test device.",
            "Re-launch the app and observe the payload execute.",
        ],
        "poc_snippet": "echo 'malicious.dex' > /sdcard/Download/dynamic.dex",
        "impact_bullets": [
            "RCE under the app's UID and permissions.",
            "Persistence: the payload re-runs on every launch.",
            "Play Store delisting risk under Device & Network Abuse policy.",
        ],
        "fix_bullets": [
            "Do not load code from external storage, world-writable "
            "directories, or network-fetched paths.",
            "If dynamic modules are required, verify each module "
            "against a server-signed manifest and a pinned public "
            "key before loading.",
        ],
        "references": [
            {"label": "Google Play — Device & Network Abuse",
             "url": "https://support.google.com/googleplay/android-developer/answer/9888379"},
        ],
    },
    "D_007": {
        "summary": (
            "The application calls a value-affecting endpoint "
            "(claim / redeem / withdraw / transfer / refund) whose "
            "server-side eligibility check and side-effect commit "
            "are not in a single transaction. An attacker sending N "
            "parallel copies of the same request beats the TOCTOU "
            "window: more than one copy commits, the user double-"
            "spends a coupon, drains a balance twice, or duplicates "
            "a referral bonus."
        ),
        "repro_steps": [
            "Capture an authenticated request to the flagged "
            "endpoint with the mitmproxy session.",
            "Re-fire 5–10 copies of the request in parallel "
            "(`xargs -P 10 curl` works).",
            "Observe ≥2 commit a successful side-effect.",
        ],
        "poc_snippet": (
            "seq 10 | xargs -P 10 -I{} curl -X POST \\\n"
            "  -H \"Authorization: Bearer $TOKEN\" \\\n"
            "  https://api.example.com/api/v1/coupon/redeem"
        ),
        "impact_bullets": [
            "Double redemption of discounts / promotional credits.",
            "Direct financial loss on withdraw / transfer / cashout.",
            "Inventory exhaustion: book the last-seat flight N times.",
        ],
        "fix_bullets": [
            "Require an `Idempotency-Key` header per logical action; "
            "reject duplicate keys for 24h+.",
            "Wrap eligibility check + commit in a single DB transaction "
            "with `SELECT ... FOR UPDATE` on the owner row.",
            "Use conditional updates: `UPDATE ... WHERE balance >= ?`.",
        ],
        "references": [
            {"label": "Idempotency-Key HTTP Header (draft RFC)",
             "url": "https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/"},
        ],
    },
    "D_009": {
        "summary": (
            "The application addresses owner-scoped resources via a "
            "predictable identifier in the URL path or query string. "
            "If the server does not verify the bearer token's "
            "subject matches the resource owner, swapping the ID "
            "reveals other users' data (IDOR — OWASP API Top 10 #1). "
            "The mass-assignment dual is when the JSON request body "
            "carries privilege keys (is_admin, role, balance_override) "
            "that the server blindly binds to the model."
        ),
        "repro_steps": [
            "Capture the authenticated request and note the owner ID.",
            "Re-issue the same request with the same session token "
            "but a perturbed ID (±1 for integers, last-hex-flip for "
            "UUIDs).",
            "If the response returns 2xx with PII for a user you do "
            "not own, the IDOR is confirmed.",
        ],
        "poc_snippet": (
            "# Original\n"
            "curl -H \"Authorization: Bearer $TOKEN\" \\\n"
            "  https://api.example.com/api/v1/users/12345\n"
            "# Perturbed — should 403, observe whether it 200s\n"
            "curl -H \"Authorization: Bearer $TOKEN\" \\\n"
            "  https://api.example.com/api/v1/users/12346"
        ),
        "impact_bullets": [
            "Cross-account data disclosure (PII, balance, history).",
            "Account-level escalation when the perturbed ID points at "
            "an admin or service account.",
            "Bulk PII scrape via incrementing identifier enumeration.",
        ],
        "fix_bullets": [
            "Derive the owner identity from the session token's "
            "subject claim, not from the URL path.",
            "Reject mismatches with 403 before any read.",
            "For mass-assignment: maintain an explicit allow-list of "
            "writable fields per endpoint.",
        ],
        "references": [
            {"label": "OWASP API Security — Broken Object Level Authorization",
             "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
        ],
    },
    "D_010": {
        "summary": (
            "The application accepts JWTs configured with one or more "
            "of: `alg: \"none\"` (forgery), symmetric HS* signing "
            "(offline key-brute-force), missing `exp` (forever-valid "
            "stolen token), missing `aud` / `iss` (cross-tenant "
            "replay), or a `kid` header containing path-traversal / "
            "SQL fragments (key-confusion against the verifier)."
        ),
        "repro_steps": [
            "Capture a JWT from the session capture.",
            "Decode the three base64-URL segments with `jwt-cli` or "
            "`python -c 'import jwt'`.",
            "Inspect the header for `alg` and the payload for `exp`, "
            "`aud`, `iss`.",
        ],
        "poc_snippet": (
            "# alg=none forgery\n"
            "TOKEN=\"$(echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | base64 -w0)\"\n"
            "TOKEN+=\".$(echo -n '{\"sub\":\"victim\",\"role\":\"admin\"}' | base64 -w0).\"\n"
            "curl -H \"Authorization: Bearer $TOKEN\" \"$API\""
        ),
        "impact_bullets": [
            "alg=none accepted → full impersonation.",
            "Weak HS* key → offline brute force, mass forgery.",
            "Missing exp → stolen token never expires.",
            "Token in URL → leaked through proxy logs / browser history.",
        ],
        "fix_bullets": [
            "Pin the algorithm to RS256 / ES256 on the verifier; "
            "reject anything else before signature checking.",
            "Set `exp` to ≤1h and rotate refresh tokens.",
            "Require both `aud` and `iss` claims.",
            "Never carry JWTs in URLs — Authorization header only.",
        ],
        "references": [
            {"label": "OWASP JSON Web Token Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
            {"label": "CVE-2015-9235 (alg=none)",
             "url": "https://nvd.nist.gov/vuln/detail/CVE-2015-9235"},
        ],
    },
    "D_011": {
        "summary": (
            "The WebView registers a JavaScript bridge via "
            "`addJavascriptInterface` AND loads at least one URL "
            "that is not first-party. Any JS in that origin can call "
            "every `@JavascriptInterface`-annotated method on the "
            "bridge object with the application's full Android "
            "permissions. Combined with HTTP loads, "
            "`setAllowFileAccessFromFileURLs(true)`, "
            "`setMixedContentMode(0)`, or "
            "`setWebContentsDebuggingEnabled(true)` it becomes RCE."
        ),
        "repro_steps": [
            "Identify the bridge name and exposed methods from the "
            "captured event.",
            "Load attacker-controlled HTML into the WebView (HTTP "
            "redirect, file:// load, or XSS on the legitimate "
            "origin).",
            "From the HTML, call `window.<bridge>.<method>(args)` "
            "and observe the Java method execute.",
        ],
        "poc_snippet": (
            "<script>\n"
            "  // Bridge name from the captured event\n"
            "  Android.openUrl('https://attacker/x');\n"
            "  Android.getAuthToken();  // exfiltrate\n"
            "</script>"
        ),
        "impact_bullets": [
            "Arbitrary Java execution under the app's UID.",
            "Token / credential exfiltration through the bridge.",
            "Pivot into native code via JS-bridge → reflection chains.",
        ],
        "fix_bullets": [
            "Only load first-party HTTPS into a WebView with a bridge; "
            "use Network Security Config to pin.",
            "Use `WebMessageListener` (API 26+) instead of "
            "`addJavascriptInterface` — it scopes the bridge to a "
            "single JS origin you specify.",
            "Validate every loaded URL against an allow-list before "
            "`loadUrl`.",
        ],
        "references": [
            {"label": "MASTG-TEST-WEBVIEW-JS-BRIDGE",
             "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/"},
        ],
    },
    "D_012": {
        "summary": (
            "The application posts a notification carrying credential "
            "or financial content with default lockscreen visibility. "
            "Anyone with sight of the locked device (over-shoulder, "
            "evil maid, transit) reads the secret without unlocking. "
            "The heads-up preview also surfaces the value above the "
            "keyguard for several seconds."
        ),
        "repro_steps": [
            "Lock the test device.",
            "Trigger the OTP / transaction notification from the "
            "app's backend.",
            "Observe the secret on the lockscreen."
        ],
        "poc_snippet": (
            "Notification n = new NotificationCompat.Builder(this, CHANNEL)\n"
            "  .setContentTitle(\"OTP\")\n"
            "  .setContentText(\"Your code is \" + otp)  // ❌\n"
            "  .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)  // ✅ ADD\n"
            "  .setPublicVersion(publicStandIn)\n"
            "  .build();"
        ),
        "impact_bullets": [
            "Lockscreen OTP / balance leakage to bystanders.",
            "Persistent screenshot retains the secret.",
            "Smartwatch mirroring forwards the value beyond the device.",
        ],
        "fix_bullets": [
            "Set `setVisibility(VISIBILITY_PRIVATE)` and provide a "
            "generic `setPublicVersion()`.",
            "For high-sensitivity content use `VISIBILITY_SECRET` so "
            "the notification is suppressed on lockscreen entirely.",
        ],
        "references": [
            {"label": "Notification lockscreen visibility",
             "url": "https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder#setVisibility(int)"},
        ],
    },
    "D_013": {
        "summary": (
            "The application sends credentials, bearer tokens, or PII "
            "to a third-party telemetry / analytics / crash-report "
            "endpoint. Anyone with vendor-account access (vendor "
            "staff, marketing employee, leaked data export) reads "
            "the value in cleartext. Bearer tokens leaked in "
            "telemetry remain functional for the app's own backend, "
            "so the leak doubles as user impersonation."
        ),
        "repro_steps": [
            "Identify the third-party host + path from the captured event.",
            "Confirm the same value reaches the third-party by "
            "comparing the original first-party payload against the "
            "third-party request body."
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Credential / token exposure in vendor logs.",
            "Cross-flow account takeover via leaked Authorization headers.",
            "GDPR Art. 44 / India DPDP Act §7 transmission violation.",
        ],
        "fix_bullets": [
            "Configure the SDK's redaction allow-list "
            "(Sentry `beforeSend`, Datadog `beforeSend`, Segment "
            "transformations) to drop credential-named fields.",
            "Strip `Authorization` from every breadcrumb / "
            "auto-captured request before it leaves the device.",
            "Rotate any token observed in a vendor log.",
        ],
        "references": [
            {"label": "Sentry — Filtering events",
             "url": "https://docs.sentry.io/platforms/android/configuration/filtering/"},
        ],
    },
    "D_014": {
        "summary": (
            "Session cookies are emitted without one or more of the "
            "essential hardening attributes (Secure, HttpOnly, "
            "SameSite) or scoped to a parent domain. A network "
            "attacker, an XSS on any same-origin page, or any "
            "subdomain takeover on the parent domain captures the "
            "session token."
        ),
        "repro_steps": [
            "Inspect the Set-Cookie header on the flagged endpoint.",
            "For Secure: attempt to load the host over HTTP and "
            "observe the cookie attached.",
            "For HttpOnly: read `document.cookie` from a JS console.",
            "For Domain=.parent: take over any subdomain to receive "
            "the cookie."
        ],
        "poc_snippet": (
            "Set-Cookie: sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
        ),
        "impact_bullets": [
            "Cleartext cookie hijack on HTTP downgrade.",
            "XSS reads the session via `document.cookie`.",
            "CSRF without SameSite.",
            "Subdomain compromise leaks the cookie to attacker.",
        ],
        "fix_bullets": [
            "Emit every session cookie with `Secure; HttpOnly; "
            "SameSite=Lax` (or `Strict` for high-value).",
            "Drop the `Domain=` attribute so cookies are host-only.",
            "Pair with HSTS so browsers never attempt HTTP.",
        ],
        "references": [
            {"label": "OWASP Session Management Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"},
        ],
    },
    "D_015": {
        "summary": (
            "The application dispatches an Intent with no explicit "
            "component or package while carrying credential-named "
            "extras. `sendBroadcast` reaches every receiver "
            "registered for the action without any chooser; "
            "`startActivity` shows a chooser any malicious app can "
            "register for. CWE-927 runtime confirmation."
        ),
        "repro_steps": [
            "Install a co-resident app declaring an intent-filter "
            "for the flagged action.",
            "Trigger the flow in the target app.",
            "Observe the malicious receiver capture the extras."
        ],
        "poc_snippet": (
            "<!-- Attacker app manifest -->\n"
            "<receiver android:name=\".Sniffer\" android:exported=\"true\">\n"
            "  <intent-filter>\n"
            "    <action android:name=\"com.target.NEW_TOKEN\"/>\n"
            "  </intent-filter>\n"
            "</receiver>"
        ),
        "impact_bullets": [
            "Token / credential exfiltration to any matching app.",
            "Chooser-squat for startActivity dispatches.",
        ],
        "fix_bullets": [
            "Set an explicit component: `intent.setClass(this, Target.class)`.",
            "For cross-app broadcasts protect the receiver with a "
            "signature-level permission and pass it to "
            "`sendBroadcast(intent, permission)`.",
        ],
        "references": [
            {"label": "CWE-927",
             "url": "https://cwe.mitre.org/data/definitions/927.html"},
        ],
    },
    "D_016": {
        "summary": (
            "The application's AccessibilityService or "
            "NotificationListenerService receives events from third-"
            "party apps or synthesises input across them. This is "
            "the canonical banking-Trojan primitive: passive "
            "credential capture, OTP exfiltration from SMS apps, "
            "or cross-app input synthesis (overlay-style attacks)."
        ),
        "repro_steps": [
            "Enable the AccessibilityService grant on the test device.",
            "Foreground a third-party banking / messaging app.",
            "Observe the host app's service receive events / perform "
            "actions."
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Banking credentials captured from third-party apps.",
            "SMS-OTP exfiltration via NotificationListenerService.",
            "Overlay-style transaction confirmation bypass.",
        ],
        "fix_bullets": [
            "Set `android:packageNames` on the accessibility-service "
            "configuration XML to a single-element allow-list "
            "(the host's own package).",
            "Restrict the NotificationListener to the host package.",
            "Migrate SMS-OTP intake to SMS Retriever API.",
        ],
        "references": [
            {"label": "MASTG-TEST-ACCESSIBILITY-SERVICE",
             "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "D_017": {
        "summary": (
            "The GraphQL endpoint runs Apollo Automatic Persisted "
            "Queries (APQ) in production. APQ accepts an "
            "on-the-fly query registration: send "
            "`extensions.persistedQuery.sha256Hash` + a full `query` "
            "body, the server registers and executes it. The "
            "persisted-query allow-list is defeated entirely — "
            "including introspection and expensive arbitrary queries."
        ),
        "repro_steps": [
            "Send a POST with both `persistedQuery.sha256Hash` "
            "and `query` carrying `{ __schema { types { name } } }`.",
            "Observe the schema in the 200 response.",
        ],
        "poc_snippet": (
            "curl -X POST $GRAPHQL_URL -H 'Content-Type: application/json' \\\n"
            "  -d '{\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"deadbeef\"}},\n"
            "       \"query\":\"{ __schema { types { name } } }\"}'"
        ),
        "impact_bullets": [
            "Persisted-query allow-list defeated.",
            "Introspection reachable in production.",
            "Cost-blind queries DoS the resolver.",
        ],
        "fix_bullets": [
            "Apollo Server: `persistedQueries: false` or supply only "
            "a read-only manifest populated at build time.",
            "Apollo Router: `apq.enabled: false` and "
            "`persisted_queries.safelist.require_id: true`.",
            "Reject any request that carries both hash AND query body.",
        ],
        "references": [
            {"label": "Apollo Server — Persisted Queries",
             "url": "https://www.apollographql.com/docs/router/configuration/persisted-queries"},
        ],
    },
    "D_018": {
        "summary": (
            "The application receives SMS_RECEIVED broadcasts (or "
            "queries `content://sms/*`) without using the SMS "
            "Retriever API. The broad permission path receives "
            "every SMS on the device — banking OTPs, two-factor "
            "codes for other apps, personal messages. Google Play "
            "policy restricts the permission to default SMS "
            "handlers; other use cases are policy violations."
        ),
        "repro_steps": [
            "Send any SMS to the test device.",
            "Observe the host app's broadcast receiver fire / "
            "ContentResolver query content://sms."
        ],
        "poc_snippet": (
            "// Migrate to SMS Retriever API\n"
            "SmsRetrieverClient client = SmsRetriever.getClient(context);\n"
            "client.startSmsRetriever();  // single scoped delivery"
        ),
        "impact_bullets": [
            "OTP exfiltration for every app on the device.",
            "Personal message exfiltration.",
            "Play Store delisting risk under SMS/Call Log policy.",
        ],
        "fix_bullets": [
            "Migrate to `SmsRetriever.getClient(this).startSmsRetriever()`.",
            "Compute the app's 11-character hash and embed it in OTP SMSes.",
            "Remove `RECEIVE_SMS` / `READ_SMS` from the manifest.",
        ],
        "references": [
            {"label": "SMS Retriever API",
             "url": "https://developers.google.com/identity/sms-retriever/overview"},
        ],
    },
    "D_019": {
        "summary": (
            "The application configures a MediaProjection screen-"
            "capture pipeline at runtime. Once the user grants "
            "consent the pipeline reads frames silently until the "
            "app stops it — every other app on screen (banking, "
            "messaging, OTP screens) is captured. With a "
            "MediaRecorder bound to the surface, the session is "
            "encoded to a persistent file or stream."
        ),
        "repro_steps": [
            "Grant the MediaProjection consent prompt on a test device.",
            "Foreground a third-party app.",
            "Observe ImageReader frames containing the third-party UI."
        ],
        "poc_snippet": "",
        "impact_bullets": [
            "Silent capture of every third-party app on screen.",
            "Encoded archive of the user's session if MediaRecorder is bound.",
            "Banking-Trojan-grade screen-spy primitive.",
        ],
        "fix_bullets": [
            "Show a persistent foreground notification while the "
            "session is live.",
            "Stop the projection on `Activity.onPause` unless the "
            "feature is explicitly a background recorder.",
            "On Android 14+ use `createScreenCaptureIntent` with "
            "`isSingleApp` to scope to the host's own UI.",
        ],
        "references": [
            {"label": "MediaProjection — Single-App Capture (Android 14+)",
             "url": "https://developer.android.com/about/versions/14/features/screen-capture"},
        ],
    },
}


def _fallback_narrative(finding: Finding) -> dict:
    bp = _BOILERPLATE.get(finding.agent_id, {})
    evidence = finding.evidence or {}

    summary = bp.get("summary") or (
        finding.evidence.get("issue")
        if isinstance(evidence, dict) and evidence.get("issue") else None
    ) or (
        f"{finding.vuln_class}: the scanner identified a "
        f"{finding.severity.name.lower() if hasattr(finding.severity, 'name') else 'security'} "
        f"-relevant code or configuration pattern that warrants review."
    )

    affected: list[str] = []
    if isinstance(evidence, dict):
        for key in ("file", "files", "activity", "component", "class",
                    "manifest", "smali", "path", "location"):
            v = evidence.get(key)
            if isinstance(v, str):
                affected.append(v)
            elif isinstance(v, list):
                affected.extend(str(x) for x in v if x)

    evidence_notes = ""
    if isinstance(evidence, dict) and evidence:
        keys = list(evidence.keys())[:6]
        evidence_notes = (
            "Scanner evidence captured the following keys: "
            + ", ".join(f"``{k}``" for k in keys)
            + ". See the Evidence in the APK section for the raw payload."
        )

    repro = bp.get("repro_steps") or [
        "Pull the APK with `apkanalyzer` or `apktool d`.",
        "Locate the affected component listed above and confirm the "
        "scanner's pattern matches against the decompiled source.",
        "Where applicable, exercise the code path on a test device "
        "with `adb shell` or a small attacker app.",
    ]
    poc = bp.get("poc_snippet", "")
    impact = (
        bp.get("impact_bullets")
        or _DEFAULT_IMPACT_BY_SEVERITY.get(finding.severity, [])
    )

    fix_bullets = bp.get("fix_bullets")
    if not fix_bullets and finding.recommendation:
        # Split a long recommendation into bullets on '. ' boundaries.
        chunks = [
            c.strip().rstrip(".") + "."
            for c in finding.recommendation.split(". ") if c.strip()
        ]
        fix_bullets = chunks[:6] or [finding.recommendation]

    refs = list(bp.get("references", []))
    # Always add the OWASP/MASVS/CWE canonical URLs when present.
    if finding.owasp and "OWASP" not in " ".join(r["label"] for r in refs):
        refs.append({"label": finding.owasp,
                     "url": "https://mas.owasp.org/MASVS/"})
    if finding.masvs:
        refs.append({"label": finding.masvs,
                     "url": "https://mas.owasp.org/MASTG/"})

    return {
        "summary": summary,
        "affected_components": affected,
        "evidence_notes": evidence_notes,
        "repro_steps": repro,
        "poc_snippet": poc,
        "impact_bullets": impact,
        "fix_bullets": fix_bullets or [finding.recommendation or ""],
        "references": refs,
    }
