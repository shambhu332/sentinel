"""Authentication API routes."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status

from sentinel.auth.api_keys import generate_api_key, list_user_api_keys, revoke_api_key
from sentinel.auth.jwt_auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    get_current_active_user,
    register_user,
)
from sentinel.auth.models import APIKey, Token, User, UserCreate, UserLogin

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate) -> User:
    """Register a new user account."""
    try:
        user = register_user(
            email=user_data.email,
            username=user_data.username,
            password=user_data.password,
        )
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration failed: {e}",
        ) from e


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin) -> Token:
    """Login and receive JWT access token."""
    user = authenticate_user(credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id}, expires_delta=access_token_expires
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_active_user)) -> User:
    """Get current user profile."""
    return current_user


@router.post("/refresh", response_model=Token)
async def refresh_token(current_user: User = Depends(get_current_active_user)) -> Token:
    """Refresh JWT access token."""
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": current_user.id}, expires_delta=access_token_expires
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/api-keys", response_model=APIKey, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    name: str,
    current_user: User = Depends(get_current_active_user),
) -> APIKey:
    """Generate a new API key for programmatic access."""
    return generate_api_key(current_user, name)


@router.get("/api-keys", response_model=list[APIKey])
async def get_api_keys(
    current_user: User = Depends(get_current_active_user),
) -> list[APIKey]:
    """List all API keys for current user."""
    return list_user_api_keys(current_user.id)


@router.delete("/api-keys/{key}")
async def delete_api_key(
    key: str,
    current_user: User = Depends(get_current_active_user),
) -> dict:
    """Revoke an API key."""
    success = revoke_api_key(key)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    return {"message": "API key revoked successfully"}
