"""JWT authentication implementation.

Phase 1.3 additions:
    * `org_id` claim (mirrors User.tenant_id) so downstream RBAC and
      Postgres RLS can enforce tenant isolation without a DB lookup.
    * `jti` claim (UUID4) that admins can add to the revocation store
      to kill a stolen token before its natural expiry.
    * Revocation check on every `get_current_user` call.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from sentinel.auth.revocation import get_revocation_store
from sentinel.core.config import get_settings

if TYPE_CHECKING:
    from .models import User

# JWT configuration
_PROCESS_SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)

# In-memory user store (replace with database in production)
_users_db: dict[str, dict] = {}


def _secret_key() -> str:
    configured = get_settings().jwt_secret.get_secret_value().strip()
    return configured or _PROCESS_SECRET_KEY


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
    *,
    org_id: str | None = None,
    role: str | None = None,
) -> str:
    """Create a JWT access token.

    Phase 1.3 mandatory claims (in addition to `sub` and `exp`):
        * `org_id` — tenant identifier (nullable for unbound users)
        * `role`   — UserRole string
        * `jti`    — UUID4, indexed in the revocation store
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    if org_id is not None and "org_id" not in to_encode:
        to_encode["org_id"] = org_id
    if role is not None and "role" not in to_encode:
        to_encode["role"] = role
    to_encode.setdefault("jti", uuid.uuid4().hex)
    to_encode["exp"] = expire

    encoded_jwt = jwt.encode(to_encode, _secret_key(), algorithm=ALGORITHM)
    return encoded_jwt


async def revoke_token(jti: str, ttl_seconds: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60) -> None:
    """Mark a token's jti as revoked. Idempotent."""
    store = get_revocation_store()
    await store.revoke(jti, ttl_seconds)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, _secret_key(), algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> User:
    """Get the current authenticated user from JWT token."""
    from .models import User

    bypass_enabled = get_settings().dev_auth_bypass
    dev_user = User(
        id="local-dev-user",
        email="local-dev@example.com",
        username="local-dev-user",
        role="user",
        is_active=True,
    )

    if credentials is None:
        if not bypass_enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return dev_user

    token = credentials.credentials
    try:
        payload = decode_token(token)
    except HTTPException:
        # In dev-bypass mode, accept stale/invalid tokens left over in
        # localStorage so a developer never gets locked out of the dashboard.
        if bypass_enabled:
            return dev_user
        raise

    user_id: str | None = payload.get("sub")
    if user_id is None:
        if bypass_enabled:
            return dev_user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    # Revocation check — a stolen token can be killed by adding its
    # jti to the revocation store before its natural expiry.
    jti = payload.get("jti")
    if jti:
        store = get_revocation_store()
        if await store.is_revoked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Fetch user from database (mock for now)
    user_data = _users_db.get(user_id)
    if user_data is None:
        if bypass_enabled:
            return dev_user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    user = User(**user_data)
    # Overlay the org_id from the token if the DB row hasn't caught up yet
    # (e.g. mid-membership-transfer). Token is the source of truth on
    # tenant binding for the lifetime of the token.
    org_id = payload.get("org_id")
    if org_id and user.tenant_id != org_id:
        user = user.model_copy(update={"tenant_id": org_id})
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current active user (not disabled)."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def require_admin(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Require admin role."""
    from .models import UserRole

    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


def register_user(email: str, username: str, password: str) -> User:
    """Register a new user."""
    from .models import User, UserRole

    user_id = secrets.token_urlsafe(16)
    hashed_pw = hash_password(password)

    user_data = {
        "id": user_id,
        "email": email,
        "username": username,
        "role": UserRole.USER,
        "is_active": True,
        "created_at": datetime.utcnow(),
    }

    _users_db[user_id] = {**user_data, "hashed_password": hashed_pw}
    return User(**user_data)


def authenticate_user(email: str, password: str) -> User | None:
    """Authenticate a user by email and password."""
    from .models import User

    for _user_id, user_data in _users_db.items():
        if user_data["email"] == email:
            if verify_password(password, user_data["hashed_password"]):
                return User(**{k: v for k, v in user_data.items() if k != "hashed_password"})
    return None
