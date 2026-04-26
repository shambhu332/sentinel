"""SENTINEL — multi-agent mobile application security scanner."""
import logging
import os

# Disable third-party telemetry before any submodule imports trigger their loaders.
# These must be set BEFORE chromadb is imported anywhere in the codebase.
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "True")
os.environ.setdefault("POSTHOG_DISABLED", "True")
os.environ.setdefault("DO_NOT_TRACK", "1")

# ChromaDB ignores its own env vars in some paths;
# brute-force silence its telemetry logger
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)
logging.getLogger("chromadb.telemetry").setLevel(logging.CRITICAL)
logging.getLogger("posthog").setLevel(logging.CRITICAL)

__version__ = "0.1.0"
