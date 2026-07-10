"""Android platform/IPC security agents (deep links, content providers, broadcast receivers)."""
from sentinel.agents.platform.content_provider_agent import ContentProviderIDORAgent
from sentinel.agents.platform.i001_component_cross_ref import ComponentCrossRefAgent
from sentinel.agents.platform.intent_redirect_agent import IntentRedirectAgent
from sentinel.agents.platform.ipc_exposure_agent import IpcExposureAgent
from sentinel.agents.platform.p001_deep_link_hijack import DeepLinkHijackAgent
from sentinel.agents.platform.p_001_deep_link_hijack import P001DeepLinkHijackAgent
from sentinel.agents.platform.p005_excessive_permissions import ExcessivePermissionsAgent
from sentinel.agents.platform.p006_unprotected_broadcast import UnprotectedBroadcastAgent
from sentinel.agents.platform.p007_activity_result_leak import ActivityResultLeakAgent
from sentinel.agents.platform.p011_receiver_chain_hijack import ReceiverChainHijackAgent
from sentinel.agents.platform.p012_mutable_pending_intent import MutablePendingIntentAgent
from sentinel.agents.platform.ui001_activity_graph import ActivityGraphAgent

__all__ = [
    "ActivityGraphAgent",
    "ActivityResultLeakAgent",
    "ComponentCrossRefAgent",
    "ContentProviderIDORAgent",
    "DeepLinkHijackAgent",
    "P001DeepLinkHijackAgent",
    "ExcessivePermissionsAgent",
    "IntentRedirectAgent",
    "IpcExposureAgent",
    "MutablePendingIntentAgent",
    "ReceiverChainHijackAgent",
    "UnprotectedBroadcastAgent",
]
