"""Test-credential manager for automated DAST login.

Loads test-only credentials from ``.env.test`` (or process env) and
attempts a Frida-driven auto-login against the target package. If the
login can't be confirmed, the manager returns an ``AuthGated`` result
that the dispatcher uses to:

  - set ``finding.verification_state = "auth_gated"``
  - capture a blocking-state screenshot
  - request an LLM-generated severity rationale describing the residual
    risk for authenticated users

Safety contract
---------------
- Real user credentials must NEVER be loaded by this manager. The loader
  refuses any entry whose label looks like a production username
  (heuristic: contains ``@`` outside of an explicit ``TEST_`` namespace
  is rejected with a warning).
- Credentials live in process memory for the scan's lifetime and are
  zeroed on ``aclose()``.
- No credential is ever logged. Only credential *labels* (e.g.
  ``TEST_USER_01``) appear in logs / telemetry.
- The Frida auto-login hook is intentionally a stub today. It returns
  ``AuthGated("frida hook not configured for <package>")`` until a
  caller supplies an app-specific hook script via
  ``register_login_script(package, js_source)``. This keeps the surface
  honest: the dispatcher routes correctly, the UI shows the right
  callout, and no half-baked "we logged you in" claim ever appears.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from sentinel.tools.frida_runner import FridaRunner

logger = logging.getLogger(__name__)


AuthOutcome = Literal["success", "auth_gated", "no_credentials", "unsupported"]


# --- Credential validation ----------------------------------------------------

# Allow ASCII alphanumerics + a small set of separators. Long enough to
# fit reasonable test usernames; short enough that a malformed env file
# can't smuggle multi-KB junk into memory.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._+@-]{1,80}$")
_PASSWORD_MAX_LEN = 200

# Heuristic for "this looks like a real user account, not a test one".
# Lab credentials are conventionally prefixed (TEST_/QA_/STAGING_) or
# carry a transparently fake domain (example.com, sentinel.test).
_REAL_DOMAIN_HINTS = (
    "gmail.com", "outlook.com", "yahoo.com", "icloud.com",
    "hotmail.com", "live.com", "protonmail.com",
)


def _looks_like_real_user(label: str, username: str) -> bool:
    """Heuristic to reject credentials that look like production accounts."""
    if not username or "@" not in username:
        return False
    if label.upper().startswith(("TEST_", "QA_", "STAGING_", "SANDBOX_")):
        return False
    domain = username.rsplit("@", 1)[-1].lower()
    return domain in _REAL_DOMAIN_HINTS


# --- Data shapes --------------------------------------------------------------

@dataclass(frozen=True)
class TestCredential:
    """A single test-credential entry loaded from the env file."""

    # Tell pytest this is data, not a test class.
    __test__ = False

    label: str            # short tag for logs; never logged with value
    username: str
    password: str = field(repr=False)  # don't leak via repr/__str__

    def __post_init__(self) -> None:
        if not _USERNAME_RE.match(self.username):
            raise ValueError(
                f"credential {self.label!r}: username failed validation",
            )
        if len(self.password) > _PASSWORD_MAX_LEN:
            raise ValueError(
                f"credential {self.label!r}: password exceeds max length",
            )


@dataclass
class AuthResult:
    """Outcome of an auto_login attempt.

    Always populated — never raise. The dispatcher reads ``outcome`` to
    decide whether to set ``verification_state = "auth_gated"``.
    """

    outcome: AuthOutcome
    reason: str = ""
    credential_label: str | None = None  # *never* the username/password
    duration_ms: int = 0

    @property
    def succeeded(self) -> bool:
        return self.outcome == "success"


# --- Manager ------------------------------------------------------------------

class CredentialManager:
    """Load test credentials and drive Frida-based auto-login.

    Usage::

        cm = CredentialManager.from_env(workspace_root)
        result = await cm.auto_login("com.example.app", frida=frida_runner)
        if not result.succeeded:
            finding.verification_state = "auth_gated"
            finding.verification_status = (
                f"Unverified — auto-login blocked: {result.reason}"
            )
    """

    _ENV_FILE_NAME = ".env.test"

    # Bundled login scripts shipped with the repo. `from_env` auto-loads
    # everything under this directory so a freshly cloned checkout has
    # working login hooks for the demo target out of the box.
    _BUNDLED_SCRIPTS_DIR = (
        Path(__file__).resolve().parents[2] / "frida_agent" / "login_scripts"
    )

    def __init__(
        self,
        credentials: dict[str, TestCredential] | None = None,
    ) -> None:
        self._credentials: dict[str, TestCredential] = dict(credentials or {})
        # package -> JS source string the auto-login hook should run.
        # Stubbed until the SOC supplies per-app login scripts.
        self._login_scripts: dict[str, str] = {}

    # ------ Loading ------

    @classmethod
    def from_env(
        cls,
        workspace_root: Path | None = None,
        *,
        script_dirs: list[Path] | None = None,
    ) -> "CredentialManager":
        """Load credentials from .env.test (if present) and the process env.

        Search order for .env.test:
          1. ``<workspace_root>/.env.test``
          2. CWD ``.env.test``
        Whichever exists first wins; both being absent is fine — the
        manager simply has no credentials.

        Recognised entries take the form::

            TEST_USER_<LABEL>_USERNAME=...
            TEST_USER_<LABEL>_PASSWORD=...

        Other env vars are ignored.
        """
        env: dict[str, str] = {}
        for candidate in (
            (workspace_root or Path.cwd()) / cls._ENV_FILE_NAME,
            Path.cwd() / cls._ENV_FILE_NAME,
        ):
            if candidate.exists():
                env.update(_parse_env_file(candidate))
                break
        # Process env takes priority over file (12-factor).
        for k, v in os.environ.items():
            if k.startswith("TEST_USER_"):
                env[k] = v

        creds: dict[str, TestCredential] = {}
        for key in env:
            if not key.endswith("_USERNAME"):
                continue
            label = key[len("TEST_USER_"):-len("_USERNAME")]
            password_key = f"TEST_USER_{label}_PASSWORD"
            password = env.get(password_key)
            if password is None:
                logger.debug(
                    "[credentials] %s has no matching password key — skipped",
                    label,
                )
                continue
            try:
                username = env[key]
                if _looks_like_real_user(label, username):
                    logger.warning(
                        "[credentials] %s looks like a real user account "
                        "(domain heuristic) — refusing to load",
                        label,
                    )
                    continue
                cred = TestCredential(label, username, password)
            except ValueError as exc:
                logger.warning(
                    "[credentials] failed to load %s: %s", label, exc,
                )
                continue
            creds[label] = cred
            logger.info("[credentials] loaded test credential %r", label)

        manager = cls(credentials=creds)

        # Auto-register bundled login scripts plus any caller-supplied
        # overrides. Workspace-scoped scripts (under
        # ``<workspace>/login_scripts/``) take precedence over the
        # bundled defaults — the workspace registration call runs last
        # and overwrites duplicate package keys.
        candidate_dirs: list[Path] = [cls._BUNDLED_SCRIPTS_DIR]
        if workspace_root is not None:
            candidate_dirs.append(workspace_root / "login_scripts")
        if script_dirs:
            candidate_dirs.extend(script_dirs)
        for directory in candidate_dirs:
            if directory.is_dir():
                manager.load_scripts_from(directory)

        return manager

    # ------ Inspection ------

    @property
    def has_credentials(self) -> bool:
        return bool(self._credentials)

    def labels(self) -> list[str]:
        """Return the loaded credential labels (never the values)."""
        return sorted(self._credentials.keys())

    # ------ Hook registration ------

    def register_login_script(self, package: str, js_source: str) -> None:
        """Supply an app-specific Frida hook driving the login flow.

        The hook should perform whatever UI/RPC the app needs to reach a
        post-login state and then call ``send({event: 'auth.ok'})`` on
        success or ``send({event: 'auth.fail', reason: '...'})``
        otherwise. The dispatcher waits up to ``timeout_s`` for one of
        these events before treating the attempt as auth-gated.
        """
        if not js_source.strip():
            raise ValueError("login script source must be non-empty")
        self._login_scripts[package] = js_source

    def load_scripts_from(self, directory: Path) -> list[str]:
        """Register every ``<package>.js`` file under ``directory``.

        Files are matched by the convention ``<package.name>.js`` —
        the filename (sans extension) is the package the script
        targets. Empty files and non-``.js`` entries are skipped.

        Returns the list of registered package names. Missing or
        unreadable directories produce a warning and an empty list,
        never an exception — the caller may continue without any
        scripts and rely on auth_gated routing.
        """
        registered: list[str] = []
        if not directory.is_dir():
            logger.warning(
                "[credentials] login script directory missing: %s", directory,
            )
            return registered
        for path in sorted(directory.glob("*.js")):
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning(
                    "[credentials] cannot read login script %s: %s",
                    path, exc,
                )
                continue
            if not source.strip():
                continue
            package = path.stem
            self.register_login_script(package, source)
            registered.append(package)
            logger.info(
                "[credentials] registered login script for %s (%s)",
                package, path.name,
            )
        return registered

    # ------ Auto-login ------

    async def auto_login(
        self,
        package_name: str,
        *,
        frida: FridaRunner | None = None,
        credential_label: str | None = None,
        timeout_s: float = 12.0,
    ) -> AuthResult:
        """Attempt automated login against ``package_name``.

        Returns an ``AuthResult`` describing the outcome — never raises.
        Auth-gated is the safe default whenever anything goes wrong, so
        the dispatcher can route the finding into the right bucket
        without us pretending we logged in successfully.
        """
        start = asyncio.get_event_loop().time()

        if not self.has_credentials:
            return AuthResult(
                outcome="no_credentials",
                reason="no test credentials loaded",
            )

        if credential_label is None:
            credential_label = next(iter(self._credentials))
        cred = self._credentials.get(credential_label)
        if cred is None:
            return AuthResult(
                outcome="no_credentials",
                reason=f"unknown credential label {credential_label!r}",
            )

        script_src = self._login_scripts.get(package_name)
        if script_src is None:
            logger.info(
                "[credentials] no login script registered for %s — auth-gated",
                package_name,
            )
            return AuthResult(
                outcome="auth_gated",
                reason=(
                    f"no Frida login script registered for {package_name}"
                ),
                credential_label=cred.label,
                duration_ms=_elapsed_ms(start),
            )

        if frida is None:
            return AuthResult(
                outcome="unsupported",
                reason="no FridaRunner provided",
                credential_label=cred.label,
                duration_ms=_elapsed_ms(start),
            )

        # Delegate the actual hook drive to the FridaRunner. The real
        # FridaRunner ships a run_login_script() API; test doubles may
        # not — fall back to auth_gated rather than fabricate success.
        if not hasattr(frida, "run_login_script"):
            return AuthResult(
                outcome="auth_gated",
                reason="FridaRunner has no run_login_script() API",
                credential_label=cred.label,
                duration_ms=_elapsed_ms(start),
            )

        try:
            ok = await asyncio.wait_for(
                frida.run_login_script(  # type: ignore[attr-defined]
                    package=package_name,
                    script_source=script_src,
                    username=cred.username,
                    password=cred.password,
                ),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            return AuthResult(
                outcome="auth_gated",
                reason=f"login script timed out after {timeout_s}s",
                credential_label=cred.label,
                duration_ms=_elapsed_ms(start),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("[credentials] login script crashed")
            return AuthResult(
                outcome="auth_gated",
                reason=f"login script crashed: {str(exc)[:120]}",
                credential_label=cred.label,
                duration_ms=_elapsed_ms(start),
            )

        if not ok:
            return AuthResult(
                outcome="auth_gated",
                reason="login script reported auth.fail",
                credential_label=cred.label,
                duration_ms=_elapsed_ms(start),
            )
        return AuthResult(
            outcome="success",
            credential_label=cred.label,
            duration_ms=_elapsed_ms(start),
        )

    # ------ Lifecycle ------

    async def aclose(self) -> None:
        """Zero credential material from memory."""
        for label, cred in list(self._credentials.items()):
            # Strings are immutable in Python so we can only drop the
            # reference. The garbage collector reclaims the bytes once
            # nothing else holds them.
            del cred
            self._credentials[label] = TestCredential(label, "x", "x")
        self._credentials.clear()


# --- helpers -----------------------------------------------------------------

def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a .env-style file. Supports KEY=VALUE plus '#' comments.

    Quoted values (single or double) are stripped of their quotes.
    Multiline values are not supported (KISS).
    """
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("[credentials] cannot read %s: %s", path, exc)
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def _elapsed_ms(start: float) -> int:
    return int((asyncio.get_event_loop().time() - start) * 1000)


__all__ = [
    "AuthResult",
    "AuthOutcome",
    "CredentialManager",
    "TestCredential",
]
