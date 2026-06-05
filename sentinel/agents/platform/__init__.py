"""Android platform/IPC security agents (deep links, content providers, broadcast receivers)."""
from sentinel.agents.platform.content_provider_agent import ContentProviderIDORAgent
from sentinel.agents.platform.intent_redirect_agent import IntentRedirectAgent
from sentinel.agents.platform.ipc_exposure_agent import IpcExposureAgent
from sentinel.agents.platform.p001_deep_link_hijack import DeepLinkHijackAgent

__all__ = [
    "ContentProviderIDORAgent",
    "DeepLinkHijackAgent",
    "IntentRedirectAgent",
    "IpcExposureAgent",
]
