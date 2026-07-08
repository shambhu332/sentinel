"""Seed SENTINEL's RAG knowledge base with security knowledge.

Run once before using AI-autonomous agents:
  python scripts/seed_rag_knowledge_base.py [--workspace /path/to/workspace]

Data sources ingested:
  - OWASP MASVS v2 control texts (embedded inline — no file required)
  - CWE descriptions for the most common Android findings
  - Secure Android code examples
  - Exploitation technique summaries

For CVE/NVD feeds, set --nvd-feed to a local NVD JSON file.
For bug bounty writeups, set --writeups-dir to a directory of markdown files.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Inline MASVS v2 — subset covering the agents we ship               #
# ------------------------------------------------------------------ #

MASVS_ENTRIES: list[dict] = [
    {
        "id": "MASVS-STORAGE-2",
        "category": "Storage",
        "title": "The app does not contain hardcoded sensitive data.",
        "text": (
            "Sensitive data such as API keys, passwords, and private keys must not be hardcoded "
            "in source code, binary blobs, configuration files, or build outputs. "
            "Use Android Keystore for cryptographic material. Fetch secrets from secure backend services."
        ),
    },
    {
        "id": "MASVS-AUTH-2",
        "category": "Authentication",
        "title": "The app uses secure authentication mechanisms.",
        "text": (
            "JWT tokens must be verified with a whitelist of strong algorithms (RS256, ES256). "
            "Never accept alg:none. Validate issuer, audience, and expiry. "
            "Use PKCE for OAuth flows. Store session tokens in secure storage, not SharedPreferences."
        ),
    },
    {
        "id": "MASVS-CRYPTO-1",
        "category": "Cryptography",
        "title": "The app implements cryptography according to industry best practices.",
        "text": (
            "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption. "
            "Never use ECB mode. Generate IVs with SecureRandom. "
            "Use RSA-OAEP or ECDH for key exchange. Minimum RSA key size: 2048 bits. "
            "Use PBKDF2/Argon2 for password-based key derivation."
        ),
    },
    {
        "id": "MASVS-NETWORK-1",
        "category": "Network",
        "title": "Data is encrypted on the network.",
        "text": (
            "All network traffic must use TLS 1.2 or higher. "
            "Implement certificate pinning for sensitive endpoints. "
            "Validate the full certificate chain. Do not override TrustManager or HostnameVerifier "
            "in production builds. Use OkHttp's CertificatePinner."
        ),
    },
    {
        "id": "MASVS-PLATFORM-1",
        "category": "Platform",
        "title": "The app uses IPC mechanisms securely.",
        "text": (
            "Activities, Services, ContentProviders, and BroadcastReceivers that handle "
            "sensitive data must declare appropriate permissions. "
            "Deep link handlers must validate the full URI before processing. "
            "Implicit intents must not carry sensitive data. Use explicit intents where possible."
        ),
    },
]

# ------------------------------------------------------------------ #
# CWE descriptions — Android-relevant subset                          #
# ------------------------------------------------------------------ #

CWE_ENTRIES: list[dict] = [
    {
        "id": "CWE-798",
        "title": "Use of Hard-coded Credentials",
        "text": (
            "The software contains hard-coded credentials, such as a password or cryptographic key, "
            "which it uses for its own inbound authentication or for authentication with external components. "
            "Impact: Complete authentication bypass. Credential cannot be changed without patching. "
            "Mitigation: Use Android Keystore. Fetch credentials from secure backend. "
            "Rotate any exposed credentials immediately."
        ),
    },
    {
        "id": "CWE-287",
        "title": "Improper Authentication",
        "text": (
            "The software does not, or cannot, correctly authenticate the actor. "
            "JWT-specific: accepting alg:none, not verifying signature, accepting expired tokens. "
            "Mitigation: Whitelist allowed algorithms. Validate issuer, audience, expiry. "
            "Use a hardened JWT library with secure defaults."
        ),
    },
    {
        "id": "CWE-347",
        "title": "Improper Verification of Cryptographic Signature",
        "text": (
            "The software does not verify, or incorrectly verifies, the cryptographic signature "
            "for data. Key confusion attack: using RSA public key as HMAC secret allows forging tokens. "
            "Mitigation: Validate algorithm matches key type. Never pass RSA keys to HMAC functions."
        ),
    },
    {
        "id": "CWE-327",
        "title": "Use of a Broken or Risky Cryptographic Algorithm",
        "text": (
            "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may "
            "result in the exposure of sensitive information. Avoid: MD5, SHA-1, DES, RC4, ECB mode. "
            "Prefer: AES-GCM, ChaCha20-Poly1305, SHA-256+, RSA-OAEP."
        ),
    },
    {
        "id": "CWE-295",
        "title": "Improper Certificate Validation",
        "text": (
            "The software does not validate, or incorrectly validates, a certificate. "
            "Android-specific: overriding TrustManager with empty checkServerTrusted(), "
            "overriding HostnameVerifier to return true unconditionally. "
            "Allows MitM attacks even over TLS. Mitigation: Use default TrustManager in production."
        ),
    },
    {
        "id": "CWE-319",
        "title": "Cleartext Transmission of Sensitive Information",
        "text": (
            "The software transmits sensitive or security-critical data in cleartext. "
            "Android: usesCleartextTraffic=true, http:// URLs for API calls. "
            "Mitigation: Enforce HTTPS. Set android:usesCleartextTraffic=false. "
            "Use Network Security Config to block cleartext."
        ),
    },
    {
        "id": "CWE-940",
        "title": "Improper Verification of Source of a Communication Channel",
        "text": (
            "The software does not adequately verify the identity of actors at both ends of a "
            "communication channel, or does not adequately ensure the integrity of the channel. "
            "Android: deep link hijack via intent-filter without host/path validation. "
            "Mitigation: Validate scheme, host, and path. Use App Links with Digital Asset Links."
        ),
    },
]

# ------------------------------------------------------------------ #
# Secure code examples                                                #
# ------------------------------------------------------------------ #

SECURE_CODE_EXAMPLES: list[dict] = [
    {
        "id": "secure-jwt-verification-java",
        "title": "Secure JWT verification with algorithm whitelist",
        "source": "SENTINEL secure examples",
        "text": """
// Secure JWT verification — algorithm whitelist enforced
Algorithm algorithm = Algorithm.RSA256(publicKey, null);
JWTVerifier verifier = JWT.require(algorithm)
    .withIssuer("https://auth.example.com")
    .withAudience("com.example.app")
    .acceptLeeway(30)
    .build();
DecodedJWT jwt = verifier.verify(token);
// NEVER: Algorithm.none() or JWT.decode() without verify
""",
    },
    {
        "id": "secure-aes-gcm-java",
        "title": "Secure AES-GCM encryption in Android",
        "source": "SENTINEL secure examples",
        "text": """
// Secure AES-256-GCM with random nonce
byte[] nonce = new byte[12];
new SecureRandom().nextBytes(nonce);
SecretKey key = // from Android Keystore
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
byte[] ciphertext = cipher.doFinal(plaintext);
// Store nonce alongside ciphertext; never reuse nonce with same key
""",
    },
    {
        "id": "secure-network-pinning-java",
        "title": "Certificate pinning with OkHttp",
        "source": "SENTINEL secure examples",
        "text": """
// Certificate pinning — pin the leaf or intermediate, not root
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build();
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(pinner)
    .build();
// Use Network Security Config as backup: res/xml/network_security_config.xml
""",
    },
]


async def seed(workspace: Path, nvd_feed: Path | None, writeups_dir: Path | None) -> None:
    from sentinel.rag.knowledge_base import KnowledgeBase

    kb_path = KnowledgeBase.default_persist_path(workspace)
    kb = KnowledgeBase(persist_path=kb_path)
    await kb.connect()

    count_before = await kb.count()
    logger.info("Knowledge base at %s — %d passages before seeding", kb_path, count_before)

    ids: list[str] = []
    texts: list[str] = []
    metadatas: list[dict] = []

    def _add(doc_id: str, text: str, meta: dict) -> None:
        ids.append(doc_id)
        texts.append(text.strip())
        metadatas.append(meta)

    # MASVS
    for entry in MASVS_ENTRIES:
        _add(
            doc_id=f"masvs:{entry['id']}",
            text=f"{entry['title']}\n{entry['text']}",
            meta={"source": "MASVS", "control_id": entry["id"], "category": entry["category"], "title": entry["title"]},
        )

    # CWE
    for entry in CWE_ENTRIES:
        _add(
            doc_id=f"cwe:{entry['id']}",
            text=f"{entry['title']}\n{entry['text']}",
            meta={"source": "CWE", "control_id": entry["id"], "title": entry["title"], "category": "Security Weakness"},
        )

    # Secure code examples
    for entry in SECURE_CODE_EXAMPLES:
        _add(
            doc_id=f"example:{entry['id']}",
            text=f"{entry['title']}\n{entry['text']}",
            meta={"source": entry["source"], "control_id": entry["id"], "title": entry["title"], "category": "Secure Code"},
        )

    # Optional: NVD JSON feed
    if nvd_feed and nvd_feed.exists():
        logger.info("Ingesting NVD feed: %s", nvd_feed)
        raw = json.loads(nvd_feed.read_text())
        for vuln in raw.get("vulnerabilities", [])[:500]:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            if not desc or not cve_id:
                continue
            _add(
                doc_id=f"cve:{cve_id}",
                text=f"{cve_id}: {desc}",
                meta={"source": "NVD", "control_id": cve_id, "title": cve_id, "category": "CVE"},
            )
        logger.info("NVD: %d entries prepared", sum(1 for i in ids if i.startswith("cve:")))

    # Optional: markdown writeups directory
    if writeups_dir and writeups_dir.is_dir():
        logger.info("Ingesting writeups from %s", writeups_dir)
        for md_file in sorted(writeups_dir.rglob("*.md"))[:200]:
            text = md_file.read_text(errors="ignore")[:2000]
            doc_id = f"writeup:{hashlib.sha256(str(md_file).encode()).hexdigest()[:16]}"
            _add(
                doc_id=doc_id,
                text=text,
                meta={"source": "bug_bounty", "control_id": doc_id, "title": md_file.stem, "category": "Bug Bounty"},
            )

    # Batch upsert
    batch_size = 64
    for i in range(0, len(ids), batch_size):
        await kb.upsert(ids[i:i+batch_size], texts[i:i+batch_size], metadatas[i:i+batch_size])

    count_after = await kb.count()
    logger.info(
        "Seeding complete — %d new passages (total: %d)",
        count_after - count_before,
        count_after,
    )
    await kb.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed SENTINEL RAG knowledge base")
    parser.add_argument(
        "--workspace",
        default="./workspace",
        help="SENTINEL workspace directory (default: ./workspace)",
    )
    parser.add_argument("--nvd-feed", help="Path to NVD JSON feed file (optional)")
    parser.add_argument("--writeups-dir", help="Directory of bug bounty markdown writeups (optional)")
    args = parser.parse_args()

    asyncio.run(seed(
        workspace=Path(args.workspace),
        nvd_feed=Path(args.nvd_feed) if args.nvd_feed else None,
        writeups_dir=Path(args.writeups_dir) if args.writeups_dir else None,
    ))


if __name__ == "__main__":
    main()
