"""Cross-platform framework agents (React Native, Flutter)."""
from sentinel.agents.crossplatform.fl002_method_channel import (
    FlutterMethodChannelAgent,
)
from sentinel.agents.crossplatform.flutter_agent import FlutterAgent
from sentinel.agents.crossplatform.rn002_bridge_taint import (
    ReactNativeBridgeTaintAgent,
)
from sentinel.agents.crossplatform.rn_agent import ReactNativeAgent

__all__ = [
    "FlutterAgent",
    "FlutterMethodChannelAgent",
    "ReactNativeAgent",
    "ReactNativeBridgeTaintAgent",
]
