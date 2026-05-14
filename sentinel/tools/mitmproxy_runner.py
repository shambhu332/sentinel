"""mitmproxy wrapper — intercepts HTTP/HTTPS traffic during DAST.

Runs `mitmdump` as a subprocess with a custom Python addon that captures
all flows to a JSONL file. The flows can then be analyzed by DAST agents
(N_003 ImproperTLS, N_004 SensitiveDataInTransit).

Architecture:
1. Start mitmdump on a port (default 8080) with our addon
2. Configure the test device to use laptop:8080 as its proxy
3. User exercises the app (manually for now, automated in Sprint 8.3)
4. mitmproxy captures every flow to a JSONL file
5. Stop mitmproxy, hand the JSONL to DAST agents
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentinel.tools.result import ToolResult

logger = logging.getLogger(__name__)


@dataclass
class CapturedFlow:
    """A single HTTP/HTTPS request-response pair captured by mitmproxy."""
    method: str                              # GET, POST, etc.
    url: str
    scheme: str                              # http or https
    host: str
    path: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    tls_failed: bool = False                 # True if TLS handshake failed
    timestamp: float = 0.0


@dataclass
class MitmproxyCapture:
    """Result of running mitmproxy for a session."""
    flows: list[CapturedFlow]
    capture_file: Path
    duration_seconds: float
    flow_count: int


def get_local_ip() -> str:
    """Return the laptop's LAN IP so phone can route through it.

    Uses a UDP socket trick to find the IP without actually sending.
    Returns "127.0.0.1" if no network detected.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


# Python addon code injected into mitmdump via -s flag.
# This addon writes every flow to a JSONL file the runner reads.
_ADDON_CODE = '''
"""SENTINEL mitmproxy addon — captures every flow to JSONL."""
import json
from pathlib import Path

CAPTURE_FILE = Path("{capture_file}")

def response(flow):
    """Called when a complete request/response cycle is captured."""
    try:
        req = flow.request
        resp = flow.response
        record = {{
            "method": req.method,
            "url": req.pretty_url,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "path": req.path,
            "request_headers": dict(req.headers),
            "request_body": req.get_text(strict=False)[:5000] if req.content else "",
            "response_status": resp.status_code if resp else 0,
            "response_headers": dict(resp.headers) if resp else {{}},
            "response_body": resp.get_text(strict=False)[:5000] if resp and resp.content else "",
            "tls_failed": False,
            "timestamp": flow.request.timestamp_start,
        }}
        with CAPTURE_FILE.open("a") as f:
            f.write(json.dumps(record) + "\\n")
    except Exception as e:
        with CAPTURE_FILE.open("a") as f:
            f.write(json.dumps({{"error": str(e)}}) + "\\n")


def tls_failed_client(flow):
    """Called when a TLS handshake fails — important for N_003!"""
    try:
        record = {{
            "method": "",
            "url": "",
            "scheme": "https",
            "host": flow.client_conn.sni if hasattr(flow.client_conn, "sni") else "",
            "path": "",
            "request_headers": {{}},
            "request_body": "",
            "response_status": 0,
            "response_headers": {{}},
            "response_body": "",
            "tls_failed": True,
            "timestamp": 0.0,
        }}
        with CAPTURE_FILE.open("a") as f:
            f.write(json.dumps(record) + "\\n")
    except Exception:
        pass
'''


class MitmproxyRunner:
    """Async wrapper for mitmdump that captures flows to JSONL.

    Crash-proof: returns ToolResult, never raises.
    """

    def __init__(self, mitmdump_path: Optional[str] = None,
                 port: int = 8080) -> None:
        self._path = mitmdump_path or shutil.which("mitmdump")
        self._port = port
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._capture_file: Optional[Path] = None
        self._addon_file: Optional[Path] = None
        self._start_time: float = 0
        self._missing_reason: Optional[str] = None
        if self._path is None:
            self._missing_reason = (
                "mitmdump not found in PATH. Install via: sudo pacman -S mitmproxy"
            )

    async def start(self, workspace: Path) -> ToolResult[dict]:
        """Spawn mitmdump as a background subprocess.

        Returns the local IP + port the device should be configured to use.
        """
        if self._missing_reason:
            return ToolResult.fail(self._missing_reason)

        workspace = workspace.expanduser().resolve()
        workspace.mkdir(parents=True, exist_ok=True)

        self._capture_file = workspace / "mitm_capture.jsonl"
        self._capture_file.write_text("")  # truncate / create

        # Write the addon to a tmp file with capture_file path baked in
        self._addon_file = workspace / "sentinel_addon.py"
        self._addon_file.write_text(
            _ADDON_CODE.format(capture_file=str(self._capture_file)),
        )

        cmd = [
            self._path,
            "-p", str(self._port),
            "-s", str(self._addon_file),
            "--set", "block_global=false",  # allow LAN devices
            "--ssl-insecure",                # accept self-signed for our cert
        ]

        self._start_time = time.monotonic()
        logger.info("Starting mitmdump: %s", " ".join(cmd))

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as e:
            return ToolResult.fail(f"Failed to start mitmdump: {e}")
        except Exception as e:  # noqa: BLE001
            return ToolResult.from_exception(e)

        # Give it a moment to bind to the port
        await asyncio.sleep(1.5)

        if self._proc.returncode is not None:
            stderr = b""
            try:
                stderr = await self._proc.stderr.read() if self._proc.stderr else b""
            except Exception:  # noqa: BLE001
                pass
            return ToolResult.fail(
                f"mitmdump died immediately. exit={self._proc.returncode} "
                f"stderr={stderr.decode(errors='replace')[:300]}",
            )

        proxy_host = get_local_ip()
        logger.info("mitmdump listening on %s:%d", proxy_host, self._port)
        return ToolResult.ok({
            "host": proxy_host,
            "port": self._port,
            "capture_file": str(self._capture_file),
        })

    async def stop(self) -> ToolResult[MitmproxyCapture]:
        """Stop mitmdump and parse the captured flows."""
        if self._proc is None:
            return ToolResult.fail("mitmproxy never started")

        # Send SIGTERM
        try:
            self._proc.terminate()
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            self._proc.kill()
            await self._proc.wait()
        except ProcessLookupError:
            pass

        duration = time.monotonic() - self._start_time

        # Parse the capture file
        flows: list[CapturedFlow] = []
        if self._capture_file and self._capture_file.exists():
            for line in self._capture_file.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if "error" in record:
                        continue
                    flows.append(CapturedFlow(
                        method=record.get("method", ""),
                        url=record.get("url", ""),
                        scheme=record.get("scheme", ""),
                        host=record.get("host", ""),
                        path=record.get("path", ""),
                        request_headers=record.get("request_headers", {}),
                        request_body=record.get("request_body", ""),
                        response_status=record.get("response_status", 0),
                        response_headers=record.get("response_headers", {}),
                        response_body=record.get("response_body", ""),
                        tls_failed=record.get("tls_failed", False),
                        timestamp=record.get("timestamp", 0.0),
                    ))
                except json.JSONDecodeError:
                    continue

        logger.info("mitmdump captured %d flows in %.1fs", len(flows), duration)

        return ToolResult.ok(
            MitmproxyCapture(
                flows=flows,
                capture_file=self._capture_file,
                duration_seconds=duration,
                flow_count=len(flows),
            ),
            duration=duration,
        )
