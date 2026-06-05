"""Authentication and credentials security agents."""
from sentinel.agents.auth.a008_biometric_bypass import BiometricBypassAgent
from sentinel.agents.auth.hardcoded_secrets_agent import HardcodedSecretsAgent

__all__ = ["BiometricBypassAgent", "HardcodedSecretsAgent"]
