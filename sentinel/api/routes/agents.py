"""Agent registry endpoints — list the 88 SENTINEL agents."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/agents", tags=["agents"])


class AgentInfo(BaseModel):
    id: str
    name: str
    category: str
    phase: str
    severity: str
    description: str


# Compact registry. Full 88-agent implementations arrive sprint by sprint.
_REGISTRY: list[AgentInfo] = [
    # Auth (12)
    AgentInfo(id="A_001", name="Hardcoded Credentials", category="Authentication", phase="Phase 2", severity="Critical", description="API keys, passwords, private keys hardcoded in source flowing to auth sinks"),
    AgentInfo(id="A_002", name="Insecure Auth Token Storage", category="Authentication", phase="Phase 2", severity="High", description="Auth tokens stored in SharedPreferences/NSUserDefaults without encryption"),
    AgentInfo(id="A_003", name="JWT Algorithm Confusion", category="Authentication", phase="Phase 2", severity="High", description="JWT libraries accepting 'none' algorithm or weak HMAC secrets"),
    AgentInfo(id="A_004", name="Weak Session ID Generation", category="Authentication", phase="Phase 2", severity="High", description="Session IDs from java.util.Random or currentTimeMillis() instead of SecureRandom"),
    AgentInfo(id="A_005", name="Session Fixation", category="Authentication", phase="Phase 4", severity="Medium", description="Sessions not regenerated after authentication"),
    AgentInfo(id="A_006", name="OAuth Implicit Flow Misuse", category="Authentication", phase="Phase 2", severity="High", description="Deprecated implicit flow, missing PKCE, insecure redirect validation"),
    AgentInfo(id="A_007", name="Missing Re-Auth on Sensitive Ops", category="Authentication", phase="Phase 2", severity="Medium", description="Password changes or transfers without re-authentication"),
    AgentInfo(id="A_008", name="Biometric Bypass", category="Authentication", phase="Phase 3", severity="Critical", description="Biometric prompts bypassable at runtime via Frida hooks"),
    AgentInfo(id="A_009", name="Account Enumeration via Errors", category="Authentication", phase="Phase 4", severity="Medium", description="Login endpoints reveal valid usernames through differential errors"),
    AgentInfo(id="A_010", name="Password Policy Weakness", category="Authentication", phase="Phase 4", severity="Low", description="Client-side password rules weaker than NIST SP 800-63B"),
    AgentInfo(id="A_011", name="Insecure Password Reset Flow", category="Authentication", phase="Phase 2", severity="High", description="Predictable reset tokens, missing expiration, email enumeration"),
    AgentInfo(id="A_012", name="Credential Logging", category="Authentication", phase="Phase 2", severity="High", description="Passwords or tokens written to log files"),
    # Crypto (14) — condensed entries
    AgentInfo(id="C_001", name="Insecure SharedPreferences", category="Crypto/Storage", phase="Phase 2", severity="High", description="World-readable preferences or sensitive data in plain SharedPrefs"),
    AgentInfo(id="C_002", name="Insecure NSUserDefaults Storage", category="Crypto/Storage", phase="Phase 2", severity="High", description="Sensitive data in unencrypted iOS UserDefaults plist"),
    AgentInfo(id="C_003", name="Plaintext SQLite/Realm", category="Crypto/Storage", phase="Phase 2", severity="High", description="Unencrypted local databases containing sensitive columns"),
    AgentInfo(id="C_004", name="Insecure External Storage", category="Crypto/Storage", phase="Phase 2", severity="Medium", description="Sensitive data written to SD card or shared storage"),
    AgentInfo(id="C_005", name="Hardcoded Cryptographic Keys", category="Crypto/Storage", phase="Phase 2", severity="Critical", description="AES/RSA keys embedded in source as byte arrays"),
    AgentInfo(id="C_006", name="ECB Mode Cipher", category="Crypto/Storage", phase="Phase 2", severity="High", description="Encryption using ECB mode (leaks plaintext patterns)"),
    AgentInfo(id="C_007", name="Static IV in CBC/GCM", category="Crypto/Storage", phase="Phase 2", severity="High", description="Hardcoded or zero initialisation vectors"),
    AgentInfo(id="C_008", name="Weak Hash for Authentication", category="Crypto/Storage", phase="Phase 2", severity="Medium", description="MD5 or SHA1 used for password or signature verification"),
    AgentInfo(id="C_009", name="Custom Cryptography", category="Crypto/Storage", phase="Phase 2", severity="Medium", description="Developer-implemented encryption instead of standard libraries"),
    AgentInfo(id="C_010", name="Insecure Key Derivation", category="Crypto/Storage", phase="Phase 2", severity="High", description="PBKDF2/bcrypt with insufficient iterations or static salts"),
    AgentInfo(id="C_011", name="Android Keystore Misuse", category="Crypto/Storage", phase="Phase 2", severity="High", description="Keystore keys missing user auth or hardware backing"),
    AgentInfo(id="C_012", name="iOS Keychain Misuse", category="Crypto/Storage", phase="Phase 2", severity="High", description="Keychain items with wrong accessibility flags"),
    AgentInfo(id="C_013", name="Backup-Enabled Sensitive Data", category="Crypto/Storage", phase="Phase 2", severity="Medium", description="allowBackup=true combined with sensitive data storage"),
    AgentInfo(id="C_014", name="Clipboard Sensitive Data", category="Crypto/Storage", phase="Phase 3", severity="Low", description="Sensitive data copied to system clipboard"),
    # Network (11)
    AgentInfo(id="N_001", name="Cleartext HTTP Traffic", category="Network", phase="Phase 2", severity="High", description="Sensitive data sent over unencrypted HTTP"),
    AgentInfo(id="N_002", name="Missing Certificate Pinning", category="Network", phase="Phase 2", severity="High", description="HTTP clients without certificate pinning"),
    AgentInfo(id="N_003", name="Pinning Bypass-able", category="Network", phase="Phase 3", severity="High", description="Pinning bypassable with standard Frida hooks"),
    AgentInfo(id="N_004", name="TLS Version Downgrade", category="Network", phase="Phase 4", severity="Medium", description="Apps accepting TLS 1.0/1.1 or weak ciphers"),
    AgentInfo(id="N_005", name="Hostname Verification Disabled", category="Network", phase="Phase 2", severity="Critical", description="ALLOW_ALL_HOSTNAME_VERIFIER or always-true verifiers"),
    AgentInfo(id="N_006", name="API Key in Headers/URLs", category="Network", phase="Phase 3", severity="High", description="API keys leaked in HTTP headers or URL parameters"),
    AgentInfo(id="N_007", name="GraphQL Introspection Enabled", category="Network", phase="Phase 3", severity="Medium", description="GraphQL schema exposed via introspection in production"),
    AgentInfo(id="N_008", name="Insecure WebSocket", category="Network", phase="Phase 4", severity="Medium", description="ws:// unencrypted WebSockets or missing auth"),
    AgentInfo(id="N_009", name="Insecure Redirect Handling", category="Network", phase="Phase 2", severity="High", description="Auth headers retained across cross-domain redirects"),
    AgentInfo(id="N_010", name="API Schema Inference Leakage", category="Network", phase="Phase 3", severity="Medium", description="Stack traces and internals leaked in error responses"),
    AgentInfo(id="N_011", name="GraphQL Fuzzer", category="Network", phase="Phase 3", severity="High", description="IDOR, mass assignment, privilege escalation in GraphQL"),
    # Firebase (standalone high-ROI)
    AgentInfo(id="F_001", name="Firebase Misconfiguration", category="Firebase", phase="Phase 2", severity="Critical", description="Publicly accessible Firebase RealtimeDB, Firestore, Storage, Remote Config"),
    # Business Logic (5)
    AgentInfo(id="B_001", name="REST IDOR", category="Business Logic", phase="Phase 3", severity="Critical", description="Cross-user data access via object ID manipulation"),
    AgentInfo(id="B_002", name="Mass Assignment", category="Business Logic", phase="Phase 3", severity="High", description="Extra request fields set protected attributes (isAdmin etc)"),
    AgentInfo(id="B_003", name="Race Conditions & TOCTOU", category="Business Logic", phase="Phase 3", severity="Critical", description="Parallel request timing exploits (double-spend, double-redeem)"),
    AgentInfo(id="B_004", name="Receipt Purchase Bypass", category="Business Logic", phase="Phase 3", severity="Critical", description="In-app purchase validation failures (replay, forgery, swap)"),
    AgentInfo(id="B_005", name="Price/Quantity Manipulation", category="Business Logic", phase="Phase 3", severity="High", description="Negative quantities, zero prices, currency downgrade"),
    # Special/Meta (6)
    AgentInfo(id="S_001", name="Scope Ingestion", category="Special/Meta", phase="Phase 0", severity="N/A", description="Parse bug bounty program scope from any platform"),
    AgentInfo(id="R_001", name="Bounty Report Generator", category="Special/Meta", phase="Phase 8", severity="N/A", description="RAG-tuned HackerOne/Bugcrowd submission reports"),
    AgentInfo(id="M_001", name="Exploration Meta-Agent", category="Special/Meta", phase="Phase 9", severity="N/A", description="Time-bounded autonomous vulnerability research"),
    AgentInfo(id="VER_001", name="Verification Agent", category="Special/Meta", phase="Phase 5", severity="N/A", description="Re-executes tooling to catch LLM hallucinations"),
    AgentInfo(id="HON_001", name="Honeypot Detector", category="Special/Meta", phase="Phase 5", severity="N/A", description="Injects fake bugs to calibrate agent confidence"),
    AgentInfo(id="TEST_001", name="Pipeline Smoke Test Agent", category="Special/Meta", phase="Phase 2", severity="Info", description="Dummy agent used for pipeline integration testing"),
]


@router.get("", response_model=list[AgentInfo])
def list_agents(category: str | None = None) -> list[AgentInfo]:
    """List all agents. Optional ?category= filter."""
    if category:
        return [a for a in _REGISTRY if a.category.lower() == category.lower()]
    return _REGISTRY


@router.get("/{agent_id}", response_model=AgentInfo)
def get_agent(agent_id: str) -> AgentInfo:
    """Fetch a single agent by ID (e.g., F_001)."""
    for a in _REGISTRY:
        if a.id == agent_id.upper():
            return a
    raise HTTPException(status_code=404, detail=f"agent {agent_id} not found")