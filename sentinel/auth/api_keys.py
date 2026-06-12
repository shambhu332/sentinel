"""API key management for programmatic access."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from sentinel.auth.models import APIKey, User

# API key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# In-memory API key store (replace with database in production)
_api_keys_db: dict[str, dict] = {}


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _mask_key(key: str) -> str:
    return f"{key[:6]}...{key[-4:]}" if len(key) > 12 else "sk_..."


def generate_api_key(user: User, name: str) -> APIKey:
    """Generate a new API key for a user."""
    key = f"sk_{secrets.token_urlsafe(32)}"

    api_key_data = {
        "key": _mask_key(key),
        "key_hash": _hash_key(key),
        "user_id": user.id,
        "name": name,
        "created_at": datetime.utcnow(),
        "last_used": None,
        "is_active": True,
    }

    _api_keys_db[api_key_data["key_hash"]] = api_key_data
    return APIKey(**{**api_key_data, "key": key})


def revoke_api_key(key: str) -> bool:
    """Revoke an API key."""
    key_hash = _hash_key(key)
    if key_hash in _api_keys_db:
        _api_keys_db[key_hash]["is_active"] = False
        return True
    return False


def list_user_api_keys(user_id: str) -> list[APIKey]:
    """List all API keys for a user."""
    return [
        APIKey(**{k: v for k, v in data.items() if k != "key_hash"})
        for data in _api_keys_db.values()
        if data["user_id"] == user_id
    ]


async def get_user_from_api_key(
    api_key: str | None = Security(api_key_header),
) -> User | None:
    """Validate API key and return associated user."""
    from sentinel.auth.jwt_auth import _users_db

    if not api_key:
        return None

    # Check if key exists and is active
    key_data = _api_keys_db.get(_hash_key(api_key))
    if not key_data or not key_data["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )

    # Update last used timestamp
    key_data["last_used"] = datetime.utcnow()

    # Get user
    user_id = key_data["user_id"]
    user_data = _users_db.get(user_id)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return User(**{k: v for k, v in user_data.items() if k != "hashed_password"})


async def get_current_user_or_api_key(
    jwt_user: User | None = Depends(lambda: None),  # Will be replaced with actual JWT dep
    api_key_user: User | None = Depends(get_user_from_api_key),
) -> User:
    """Get user from either JWT token or API key."""
    user = jwt_user or api_key_user
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (JWT token or API key)",
        )
    return user
