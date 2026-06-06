"""Meta agents (orchestration, detection of analysis conditions)."""
from sentinel.agents.meta.meta002_debuggable_manifest import DebuggableManifestAgent
from sentinel.agents.meta.obfuscation_detector import ObfuscationDetectorAgent

__all__ = ["DebuggableManifestAgent", "ObfuscationDetectorAgent"]
