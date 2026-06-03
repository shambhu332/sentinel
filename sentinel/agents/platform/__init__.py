"""Android platform/IPC security agents (deep links, content providers, broadcast receivers)."""
from sentinel.agents.platform.content_provider_agent import ContentProviderIDORAgent
from sentinel.agents.platform.intent_redirect_agent import IntentRedirectAgent

__all__ = ["ContentProviderIDORAgent", "IntentRedirectAgent"]
