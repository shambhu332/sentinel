"""Manifest parser — extracts structured metadata from an APK.

Uses androguard for rich manifest introspection: package name, target SDK,
permissions, exported components, deep link intent filters.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ManifestError(Exception):
    """Manifest parsing failed."""


class ManifestParser:
    """Extracts manifest data using androguard."""

    def parse(self, apk_path: Path) -> dict[str, Any]:
        """Parse an APK's manifest and return structured metadata.

        Returns a dict with keys:
            package, version_name, version_code, target_sdk, min_sdk,
            permissions, activities, services, receivers, providers,
            exported_components, deep_links, uses_cleartext_traffic,
            allow_backup, debuggable
        """
        try:
            from androguard.core.apk import APK
        except ImportError as e:
            raise ManifestError(f"androguard not installed: {e}") from e

        apk_path = apk_path.expanduser().resolve()
        if not apk_path.exists():
            raise ManifestError(f"APK not found: {apk_path}")

        try:
            apk = APK(str(apk_path))
        except Exception as e:
            raise ManifestError(f"androguard failed to parse APK: {e}") from e

        result: dict[str, Any] = {
            "package": apk.get_package() or "",
            "version_name": apk.get_androidversion_name() or "",
            "version_code": apk.get_androidversion_code() or "",
            "min_sdk": _safe_int(apk.get_min_sdk_version()),
            "target_sdk": _safe_int(apk.get_target_sdk_version()),
            "permissions": sorted(apk.get_permissions() or []),
            "activities": list(apk.get_activities() or []),
            "services": list(apk.get_services() or []),
            "receivers": list(apk.get_receivers() or []),
            "providers": list(apk.get_providers() or []),
            "exported_components": self._find_exported(apk),
            "deep_links": self._find_deep_links(apk),
            "uses_cleartext_traffic": self._cleartext_enabled(apk),
            "allow_backup": self._backup_enabled(apk),
            "debuggable": self._debuggable(apk),
        }

        logger.info(
            "Parsed manifest: %s v%s (targetSdk=%s, perms=%d, activities=%d)",
            result["package"], result["version_name"],
            result["target_sdk"], len(result["permissions"]),
            len(result["activities"]),
        )
        return result

    def _find_exported(self, apk: Any) -> list[dict[str, str]]:
        """Return all components with android:exported=true."""
        exported: list[dict[str, str]] = []
        for component_type in ("activity", "service", "receiver", "provider"):
            try:
                elements = apk.find_tags(component_type)
            except Exception:
                continue
            for elem in elements:
                name = elem.get(_ns("name")) or ""
                is_exported = elem.get(_ns("exported"))
                # Default exported=true if intent-filter present and not explicitly false
                has_filter = any(
                    child.tag == "intent-filter" for child in elem
                )
                is_public = (
                    is_exported == "true"
                    or (is_exported is None and has_filter)
                )
                if is_public and name:
                    # Capture android:permission so IPC_001 can flag
                    # exported components without an explicit guard. An
                    # empty/missing permission on an exported component
                    # is the canonical IPC-exposure bug.
                    permission = elem.get(_ns("permission")) or ""
                    exported.append({
                        "type": component_type,
                        "name": name,
                        "explicitly_exported": is_exported == "true",
                        "has_intent_filter": has_filter,
                        "permission": permission,
                    })
        return exported

    def _find_deep_links(self, apk: Any) -> list[dict[str, str]]:
        """Extract intent filters that look like deep link handlers."""
        deep_links: list[dict[str, str]] = []
        try:
            activities = apk.find_tags("activity")
        except Exception:
            return deep_links

        for activity in activities:
            name = activity.get(_ns("name")) or ""
            for intent_filter in activity:
                if intent_filter.tag != "intent-filter":
                    continue
                actions = [
                    child.get(_ns("name"))
                    for child in intent_filter if child.tag == "action"
                ]
                categories = [
                    child.get(_ns("name"))
                    for child in intent_filter if child.tag == "category"
                ]
                data_elements = [
                    {k.split("}")[-1]: v for k, v in child.attrib.items()}
                    for child in intent_filter if child.tag == "data"
                ]
                if "android.intent.action.VIEW" in actions and data_elements:
                    deep_links.append({
                        "activity": name,
                        "actions": ",".join(a for a in actions if a),
                        "categories": ",".join(c for c in categories if c),
                        "data": str(data_elements),
                    })
        return deep_links

    def _cleartext_enabled(self, apk: Any) -> bool:
        try:
            apps = apk.find_tags("application")
        except Exception:
            return False
        for app in apps:
            val = app.get(_ns("usesCleartextTraffic"))
            if val == "true":
                return True
        return False

    def _backup_enabled(self, apk: Any) -> bool:
        try:
            apps = apk.find_tags("application")
        except Exception:
            return False
        for app in apps:
            val = app.get(_ns("allowBackup"))
            # Default is true on old SDKs; explicit check
            if val == "true":
                return True
            if val == "false":
                return False
        return False  # Conservative: assume disabled if not set

    def _debuggable(self, apk: Any) -> bool:
        try:
            apps = apk.find_tags("application")
        except Exception:
            return False
        for app in apps:
            if app.get(_ns("debuggable")) == "true":
                return True
        return False


def _ns(attr: str) -> str:
    """Build the Android XML namespace attribute key."""
    return f"{{http://schemas.android.com/apk/res/android}}{attr}"


def _safe_int(value: Any) -> int:
    try:
        return int(value) if value else 0
    except (ValueError, TypeError):
        return 0
