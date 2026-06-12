"""JWT authentication implementation."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

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


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, _secret_key(), algorithm=ALGORITHM)
    return encoded_jwt


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

    if credentials is None:
        if not get_settings().dev_auth_bypass:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return User(
            id="local-dev-user",
            email="local-dev@example.com",
            username="local-dev-user",
            role="user",
            is_active=True,
        )

    token = credentials.credentials
    payload = decode_token(token)

    user_id: str | None = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    # Fetch user from database (mock for now)
    user_data = _users_db.get(user_id)
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return User(**user_data)


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
