"""WebView security agents."""
from sentinel.agents.webview.insecure_webview_agent import InsecureWebViewAgent
from sentinel.agents.webview.js_interface_bridge_agent import (
    JavaScriptInterfaceBridgeAgent,
)

__all__ = ["InsecureWebViewAgent", "JavaScriptInterfaceBridgeAgent"]
