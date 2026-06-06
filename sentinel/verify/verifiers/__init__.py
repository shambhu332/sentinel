"""Concrete verifier implementations.

Verifiers are split across modules by *input source*, not by agent:

* ``manifest`` — re-parses ``AndroidManifest.xml`` and the
  associated ``res/xml/*.xml`` files (no device, no captures).
* ``mitm`` — replays the mitmproxy capture stored in
  ``ScanContext.sources['mitmproxy']``.
* ``frida`` — replays the Frida event capture stored in
  ``ScanContext.sources['frida']``.
"""
