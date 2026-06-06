"""Authentication and credentials security agents."""
from sentinel.agents.auth.a008_biometric_bypass import BiometricBypassAgent
from sentinel.agents.auth.a009_tap_jacking import TapJackingAgent
from sentinel.agents.auth.a010_session_token_in_url import SessionTokenInUrlAgent
from sentinel.agents.auth.a011_refresh_token_reuse import RefreshTokenReuseAgent
from sentinel.agents.auth.a012_session_fixation import SessionFixationAgent
from sentinel.agents.auth.hardcoded_secrets_agent import HardcodedSecretsAgent

__all__ = [
    "BiometricBypassAgent",
    "HardcodedSecretsAgent",
    "RefreshTokenReuseAgent",
    "SessionFixationAgent",
    "SessionTokenInUrlAgent",
    "TapJackingAgent",
]
