"""LLM-powered triage layer for SENTINEL findings.

After agents emit raw findings via pattern matching (Layer 1), the triage
layer (Layer 3) sends each finding plus surrounding source code to an LLM
which decides:
- Is this a real bug or a false positive?
- What's the appropriate severity given the actual code context?
- What's a clear, code-specific explanation for the report?

The triager wraps the existing FreeProviderRouter (Cerebras + Ollama).
It does NOT modify agents — it post-processes their output.
"""
from sentinel.triage.models import TriageResult, TriageState, TriageVerdict
from sentinel.triage.triager import LLMTriager

__all__ = [
    "LLMTriager",
    "TriageResult",
    "TriageState",
    "TriageVerdict",
]
