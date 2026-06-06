"""Authentication and credentials security agents."""
from sentinel.agents.auth.a008_biometric_bypass import BiometricBypassAgent
from sentinel.agents.auth.a009_tap_jacking import TapJackingAgent
from sentinel.agents.auth.hardcoded_secrets_agent import HardcodedSecretsAgent

__all__ = ["BiometricBypassAgent", "HardcodedSecretsAgent", "TapJackingAgent"]
