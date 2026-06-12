"""Cryptographic primitive security agents."""
from sentinel.agents.crypto.c005_hardcoded_keys import HardcodedCryptoKeysAgent
from sentinel.agents.crypto.c006_ecb_mode import EcbModeAgent
from sentinel.agents.crypto.c010_sqlcipher_key_derivation import (
    SQLCipherKeyDerivationAgent,
)
from sentinel.agents.crypto.c011_keystore_misuse import KeystoreMisuseAgent
from sentinel.agents.crypto.c012_aes_gcm_nonce_reuse import AesGcmNonceReuseAgent
from sentinel.agents.crypto.c013_java_serialization import JavaSerializationAgent
from sentinel.agents.crypto.c014_cbc_predictable_iv import CbcPredictableIvAgent
from sentinel.agents.crypto.c015_weak_prng_seed import WeakPrngSeedAgent
from sentinel.agents.crypto.c016_hash_kdf import HashKdfAgent
from sentinel.agents.crypto.c017_hardcoded_cert_finder import HardcodedCertFinderAgent
from sentinel.agents.crypto.c018_crypto_constants import CryptoConstantsAgent
from sentinel.agents.crypto.weak_crypto_agent import WeakCryptoAgent

__all__ = [
    "HardcodedCryptoKeysAgent",
    "EcbModeAgent",
    "SQLCipherKeyDerivationAgent",
    "KeystoreMisuseAgent",
    "AesGcmNonceReuseAgent",
    "CbcPredictableIvAgent",
    "CryptoConstantsAgent",
    "HardcodedCertFinderAgent",
    "HashKdfAgent",
    "JavaSerializationAgent",
    "WeakCryptoAgent",
    "WeakPrngSeedAgent",
]
