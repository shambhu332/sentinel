"""Unit tests for C_019 — missing key attestation challenge."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from sentinel.agents.crypto.c019_missing_key_attestation import (
    MissingKeyAttestationAgent,
    _first_string_literal,
    _builder_chain,
)


def _ctx(decompiled: Path):
    return SimpleNamespace(
        session_id="sess-c019-0001",
        workspace=decompiled.parent,
        manifest={"package": "com.example.app"},
        decompiled_dir=decompiled,
    )


def _make_agent(decompiled: Path) -> MissingKeyAttestationAgent:
    return MissingKeyAttestationAgent(_ctx(decompiled), SimpleNamespace())


def test_first_string_literal_extracts_alias():
    assert _first_string_literal('"signing_key", KeyProperties.PURPOSE_SIGN') == "signing_key"
    assert _first_string_literal("noQuotesHere") == ""


def test_builder_chain_runs_to_semicolon():
    src = (
        'new KeyGenParameterSpec.Builder("k", PURPOSE_SIGN)\n'
        "    .setDigests(\"SHA-256\")\n"
        "    .build();"
    )
    chain = _builder_chain(src, src.find("(") - len("Builder"))
    assert ".build()" in chain
    assert ";" in chain


def test_flags_sign_key_without_attestation_challenge(tmp_path: Path):
    (tmp_path / "Signing.java").write_text(
        """
        public class Signing {
          void gen() {
            KeyGenParameterSpec spec =
              new KeyGenParameterSpec.Builder("signing_key",
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build();
          }
        }
        """,
    )
    findings = asyncio.run(_make_agent(tmp_path).analyze())
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["alias_literal"] == "signing_key"
    assert "PURPOSE_SIGN" in f.evidence["purposes"]


def test_quiet_when_attestation_challenge_present(tmp_path: Path):
    (tmp_path / "OK.java").write_text(
        """
        new KeyGenParameterSpec.Builder("signing_key", PURPOSE_SIGN)
            .setAttestationChallenge(serverNonce)
            .build();
        """,
    )
    findings = asyncio.run(_make_agent(tmp_path).analyze())
    assert findings == []


def test_flags_sensitive_alias_even_without_purpose_constant(tmp_path: Path):
    (tmp_path / "Payment.java").write_text(
        """
        new KeyGenParameterSpec.Builder("payment_bind", 0)
            .setDigests("SHA-256")
            .build();
        """,
    )
    findings = asyncio.run(_make_agent(tmp_path).analyze())
    assert len(findings) == 1
    assert findings[0].evidence["alias_literal"] == "payment_bind"


def test_ignores_non_sensitive_keys(tmp_path: Path):
    (tmp_path / "Cache.java").write_text(
        """
        new KeyGenParameterSpec.Builder("cache_aes",
              KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .build();
        """,
    )
    findings = asyncio.run(_make_agent(tmp_path).analyze())
    assert findings == []
