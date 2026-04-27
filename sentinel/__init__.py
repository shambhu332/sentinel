"""SENTINEL — multi-agent mobile application security scanner."""
import logging
import os
import sys
import warnings

# Disable third-party telemetry before any submodule imports trigger their loaders.
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("CHROMA_TELEMETRY_DISABLED", "True")
os.environ.setdefault("POSTHOG_DISABLED", "True")
os.environ.setdefault("DO_NOT_TRACK", "1")

warnings.filterwarnings("ignore", category=DeprecationWarning)

# Silence noisy third-party loggers package-wide
for noisy in (
    "androguard", "androguard.core", "androguard.core.apk",
    "androguard.core.axml", "androguard.core.api_specific_resources",
    "chromadb", "chromadb.telemetry", "chromadb.telemetry.product",
    "chromadb.telemetry.product.posthog",
    "posthog", "urllib3",
):
    logging.getLogger(noisy).setLevel(logging.CRITICAL)

# Loguru is what androguard actually uses; silence it package-wide
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
    _loguru_logger.add(sys.stderr, level="WARNING")
except ImportError:
    pass

__version__ = "0.1.0"
