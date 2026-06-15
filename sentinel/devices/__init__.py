"""Multi-device pool — round-robins scans across attached Android devices.

The orchestrator today implicitly uses ``adb`` against whatever device
``adb devices`` reports first. ``DeviceManager`` makes that explicit:

* Enumerate every attached device (real or emulator).
* Cache device metadata (manufacturer, sdk, abi, fingerprint).
* Hand each scan a leased slot via async lock so concurrent scans
  don't fight over the same device.
* Expose a Helm-chart-friendly REST surface (``/devices``) so a
  self-hosted deployment can audit pool health.

The pool is process-local (no Redis lock). For multi-process /
multi-worker deployments a Redis-backed lease is a follow-up.
"""
from sentinel.devices.pool import DeviceInfo, DeviceManager, DeviceUnavailable

__all__ = ["DeviceInfo", "DeviceManager", "DeviceUnavailable"]
