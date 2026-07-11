"""WebView security agents."""
from sentinel.agents.webview.insecure_webview_agent import InsecureWebViewAgent
from sentinel.agents.webview.js_interface_bridge_agent import (
    JavaScriptInterfaceBridgeAgent,
)
from sentinel.agents.webview.wv_001_js_bridge import WV001JSBridgeAgent

__all__ = ["InsecureWebViewAgent", "JavaScriptInterfaceBridgeAgent", "WV001JSBridgeAgent"]
