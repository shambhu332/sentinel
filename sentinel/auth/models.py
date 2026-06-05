"""User models for authentication."""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class User(BaseModel):
    """User account model."""
    id: str
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    role: UserRole = UserRole.USER
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    api_key: str | None = None


class UserCreate(BaseModel):
    """User registration payload."""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=100)


class UserLogin(BaseModel):
    """User login payload."""
    email: EmailStr
    password: str


class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # 1 hour


class APIKey(BaseModel):
    """API key model."""
    key: str
    user_id: str
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: datetime | None = None
    is_active: bool = True
