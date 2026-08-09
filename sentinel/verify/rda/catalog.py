"""RDA catalog — RASP detector definitions and bypass profiles.

Adapted from DragonJAR/Android-Pentesting-Skill detector-catalog.json
and bypass-profiles.json. Hardcoded as Python constants so the module
works without file I/O and is importable anywhere in the pipeline.
"""
from __future__ import annotations

# Each entry mirrors the DragonJAR catalog schema, adapted for Sentinel:
#   id               — stable identifier used as dict key and in findings
#   name             — human-readable SDK/vendor name
#   category         — resilience | platform | obfuscation | shielding |
#                      backend-validation | not-applicable
#   executable       — True if a Frida script can actively test/bypass it
#   detection_method — list of class-name / string signatures to scan for
#   frida_script     — primary Frida script path (in frida_agent/) or None
#   limits           — known limits of the bypass approach
DETECTOR_CATALOG: list[dict] = [
    {
        "id": "rootbeer",
        "name": "RootBeer",
        "category": "resilience",
        "executable": True,
        "detection_method": [
            "com.scottyab.rootbeer",
            "RootBeer",
            "com.scouteam.rootbeer",
        ],
        "frida_script": "frida_agent/root-detection-bypass.js",
        "limits": "Does not modify server-side risk scoring or remote attestation verdicts.",
    },
    {
        "id": "safetynet",
        "name": "SafetyNet / Play Integrity",
        "category": "resilience",
        "executable": True,
        "detection_method": [
            "SafetyNet",
            "com.google.android.gms.safetynet",
            "PlayIntegrityManager",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": (
            "Client hooks can exercise failure handling and token transport, "
            "but cannot forge Google-backed server verdicts. Validate backend "
            "behavior with authorized test configuration."
        ),
    },
    {
        "id": "emulator",
        "name": "Emulator Detection",
        "category": "resilience",
        "executable": True,
        "detection_method": [
            "Build.FINGERPRINT",
            "ro.kernel.qemu",
            "goldfish",
            "ranchu",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": "Native-only emulator heuristics may require app-specific hooks after tracing.",
    },
    {
        "id": "debug",
        "name": "Debugger Detection",
        "category": "resilience",
        "executable": True,
        "detection_method": [
            "Debug.isDebuggerConnected",
            "BuildConfig.DEBUG",
            "android.debuggable",
            "DEBUGGABLE",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": "Kernel-level or vendor-native anti-debug may require target-specific native hooks.",
    },
    {
        "id": "frida_detect",
        "name": "Frida Detection",
        "category": "resilience",
        "executable": True,
        "detection_method": [
            "frida",
            "/data/local/tmp/re.frida",
            "gum-js-loop",
            "linjector",
        ],
        "frida_script": "frida_agent/anti-frida-bypass.js",
        "limits": (
            "Highly customized native memory scanners may require a targeted "
            "hook generated from observed evidence."
        ),
    },
    {
        "id": "screenshot",
        "name": "Screenshot Protection (FLAG_SECURE)",
        "category": "platform",
        "executable": True,
        "detection_method": [
            "FLAG_SECURE",
            "WindowManager.LayoutParams.FLAG_SECURE",
        ],
        "frida_script": "frida_agent/flag-secure-bypass.js",
        "limits": "OEM-level DRM surfaces or media projection policy may remain protected.",
    },
    {
        "id": "screenrecorded",
        "name": "Screen Recording Detection",
        "category": "platform",
        "executable": True,
        "detection_method": [
            "MediaRecorder",
            "isScreenCaptureSupported",
        ],
        "frida_script": "frida_agent/flag-secure-bypass.js",
        "limits": "Platform/OEM DRM protections may remain non-bypassable in a generic script.",
    },
    {
        "id": "talsec",
        "name": "Talsec freeRASP",
        "category": "resilience",
        "executable": True,
        "detection_method": [
            "com.aheaditec.talsec",
            "TalsecSecurity",
            "com.aheaditec.talsec_security.security.api.Talsec",
            "TalsecConfig",
            "ThreatListener",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": (
            "Use detector evidence to add target-specific hooks for custom "
            "ThreatListener implementations."
        ),
    },
    {
        "id": "approov",
        "name": "Approov",
        "category": "backend-validation",
        "executable": False,
        "detection_method": [
            "io.approov",
            "ApproovService",
            "com.criticalblue.approovsdk.Approov",
        ],
        "frida_script": "frida_agent/network-security-bypass.js",
        "limits": (
            "Approov server-side token validation cannot be generically bypassed "
            "client-side. Use an authorized test tenant or backend allowlist for validation."
        ),
    },
    {
        "id": "dexguard",
        "name": "DexGuard",
        "category": "obfuscation",
        "executable": True,
        "detection_method": [
            "com.guardsquare.dexguard",
            "DexGuard",
            "Guardsquare",
            "dexguard",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": "DexGuard native checks are version/app specific; use traces to add precise hooks.",
    },
    {
        "id": "appdome",
        "name": "Appdome",
        "category": "shielding",
        "executable": True,
        "detection_method": [
            "com.appdome",
            "Appdome",
            "appdome",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": "Generated Appdome protections vary per build; inspect detector evidence before claiming bypass.",
    },
    {
        "id": "doverunner",
        "name": "Doverunner / AppSealing",
        "category": "shielding",
        "executable": True,
        "detection_method": [
            "com.doverunner",
            "appsealing",
            "SealEngine",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": "Native library checks may require targeted app-specific hooks.",
    },
    {
        "id": "digitalai",
        "name": "Digital.ai / Arxan",
        "category": "obfuscation",
        "executable": True,
        "detection_method": [
            "com.arxan",
            "Arxan",
            "digital.ai",
            "digitalai",
            "Guardit",
        ],
        "frida_script": "frida_agent/rasp-bypass.js",
        "limits": (
            "Native control-flow and checksum protections usually need "
            "app-specific dynamic analysis."
        ),
    },
    {
        "id": "contrast",
        "name": "Contrast Security",
        "category": "not-applicable",
        "executable": False,
        "detection_method": [],
        "frida_script": None,
        "limits": "Backend Java/.NET/Node RASP — no Android APK direct detector.",
    },
    {
        "id": "imperva",
        "name": "Imperva RASP",
        "category": "not-applicable",
        "executable": False,
        "detection_method": [],
        "frida_script": None,
        "limits": "Web/app/API RASP — not an Android APK detector.",
    },
    {
        "id": "dynatrace",
        "name": "Dynatrace",
        "category": "not-applicable",
        "executable": False,
        "detection_method": [],
        "frida_script": None,
        "limits": "OneAgent SDK for Android observability; Runtime Application Protection is backend.",
    },
    {
        "id": "accuknox",
        "name": "AccuKnox",
        "category": "not-applicable",
        "executable": False,
        "detection_method": [],
        "frida_script": None,
        "limits": "Cloud-native runtime protection — no public Android APK SDK verified.",
    },
    {
        "id": "custom",
        "name": "Custom RASP",
        "category": "custom",
        "executable": False,
        "detection_method": [],
        "frida_script": None,
        "limits": "Template for custom RASP rules — no generic bypass available.",
    },
]

# Maps detector family id → bypass profile with scripts and validation notes.
# Adapted from DragonJAR bypass-profiles.json.
BYPASS_PROFILES: dict[str, dict] = {
    "rootbeer": {
        "category": "root-detection",
        "scripts": [
            "frida_agent/root-detection-bypass.js",
            "frida_agent/rasp-bypass.js",
        ],
        "validates": [
            "RootBeer API checks",
            "su/busybox file checks",
            "root package checks",
            "build tag checks",
        ],
        "limits": "Does not modify server-side risk scoring or remote attestation verdicts.",
    },
    "safetynet": {
        "category": "attestation",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/network-security-bypass.js",
            "frida_agent/ssl-pinning-bypass.js",
        ],
        "validates": [
            "legacy SafetyNet client calls",
            "Play Integrity client-side call sites",
            "TLS interception feasibility",
        ],
        "limits": (
            "Client hooks can exercise failure handling and token transport, "
            "but cannot forge Google-backed server verdicts. Validate backend "
            "behavior with authorized test configuration."
        ),
    },
    "emulator": {
        "category": "environment-detection",
        "scripts": [
            "frida_agent/root-detection-bypass.js",
            "frida_agent/rasp-bypass.js",
        ],
        "validates": [
            "Build property spoofing",
            "goldfish/ranchu checks",
            "emulator package checks",
        ],
        "limits": "Native-only emulator heuristics may require app-specific hooks after tracing.",
    },
    "debug": {
        "category": "debugger-detection",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/anti-frida-bypass.js",
        ],
        "validates": [
            "Debug.isDebuggerConnected",
            "debuggable flag checks",
            "ptrace-style checks where covered",
        ],
        "limits": "Kernel-level or vendor-native anti-debug may require target-specific native hooks.",
    },
    "frida_detect": {
        "category": "instrumentation-detection",
        "scripts": [
            "frida_agent/anti-frida-bypass.js",
            "frida_agent/android-anti-frida-countermeasures.js",
            "frida_agent/rasp-bypass.js",
        ],
        "validates": [
            "/proc maps filtering",
            "Frida port checks",
            "thread/module/string detection",
            "common anti-Frida Java checks",
        ],
        "limits": (
            "Highly customized native memory scanners may require a targeted "
            "hook generated from observed evidence."
        ),
    },
    "screenshot": {
        "category": "screen-capture-protection",
        "scripts": [
            "frida_agent/flag-secure-bypass.js",
        ],
        "validates": [
            "FLAG_SECURE removal",
            "WindowManager addView hooks",
        ],
        "limits": "OEM-level DRM surfaces or media projection policy may remain protected.",
    },
    "screenrecorded": {
        "category": "screen-recording-protection",
        "scripts": [
            "frida_agent/flag-secure-bypass.js",
            "frida_agent/mediaprojection-bypass.js",
        ],
        "validates": [
            "screen recording callbacks",
            "MediaProjection-related checks",
            "FLAG_SECURE usage",
        ],
        "limits": "Platform/OEM DRM protections may remain non-bypassable in a generic script.",
    },
    "talsec": {
        "category": "commercial-rasp",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/anti-frida-bypass.js",
            "frida_agent/root-detection-bypass.js",
        ],
        "validates": [
            "freeRASP Java callback tampering",
            "root/debug/emulator checks",
            "Frida detection checks",
        ],
        "limits": (
            "Use detector evidence to add target-specific hooks for custom "
            "ThreatListener implementations."
        ),
    },
    "approov": {
        "category": "attestation",
        "scripts": [
            "frida_agent/network-security-bypass.js",
            "frida_agent/ssl-pinning-bypass.js",
            "frida_agent/network-interceptor-enhanced.js",
        ],
        "validates": [
            "client SDK integration points",
            "token transport visibility",
            "TLS interception feasibility",
        ],
        "limits": (
            "Approov server-side token validation cannot be generically bypassed "
            "client-side. Use an authorized test tenant or backend allowlist for validation."
        ),
    },
    "dexguard": {
        "category": "shielding-obfuscation",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/anti-frida-bypass.js",
            "frida_agent/packer-unpacker.js",
        ],
        "validates": [
            "anti-tamper signal handling",
            "Frida detection",
            "packing/unpacking triage",
        ],
        "limits": "DexGuard native checks are version/app specific; use traces to add precise hooks.",
    },
    "appdome": {
        "category": "commercial-shielding",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/anti-frida-bypass.js",
            "frida_agent/root-detection-bypass.js",
        ],
        "validates": [
            "root/debug/emulator callbacks",
            "anti-instrumentation checks",
            "generic shielding signals",
        ],
        "limits": "Generated Appdome protections vary per build; inspect detector evidence before claiming bypass.",
    },
    "doverunner": {
        "category": "commercial-shielding",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/anti-frida-bypass.js",
            "frida_agent/root-detection-bypass.js",
        ],
        "validates": [
            "AppSealing/Doverunner root/debug/instrumentation checks",
            "generic hardening callbacks",
        ],
        "limits": "Native library checks may require targeted app-specific hooks.",
    },
    "digitalai": {
        "category": "commercial-hardening",
        "scripts": [
            "frida_agent/rasp-bypass.js",
            "frida_agent/anti-frida-bypass.js",
            "frida_agent/packer-unpacker.js",
        ],
        "validates": [
            "Arxan/Digital.ai tamper and instrumentation checks",
            "anti-Frida checks",
            "packing triage",
        ],
        "limits": (
            "Native control-flow and checksum protections usually need "
            "app-specific dynamic analysis."
        ),
    },
}
