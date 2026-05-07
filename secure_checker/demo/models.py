"""
demo/models.py

Simple in-memory user storage using Flask sessions.
No database layer — users are stored in the session.

For production, replace this with a proper database + password hashing library.
"""

import hashlib
import secrets
from typing import Optional, Dict, Any


class User:
    """Represents a user (stored in session)."""

    def __init__(
        self,
        username: str,
        email: str,
        password_hash: str,
        full_name: str = "",
        country: str = "",
    ):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.full_name = full_name
        self.country = country
        self.created_at = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dict for session storage."""
        return {
            "username": self.username,
            "email": self.email,
            "password_hash": self.password_hash,
            "full_name": self.full_name,
            "country": self.country,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "User":
        """Create a User from a dict (from session)."""
        u = User(
            username=data.get("username", ""),
            email=data.get("email", ""),
            password_hash=data.get("password_hash", ""),
            full_name=data.get("full_name", ""),
            country=data.get("country", ""),
        )
        u.created_at = data.get("created_at")
        return u


def hash_password(password: str) -> str:
    """
    Hash a password using SHA256 (not secure for production!).
    For production, use werkzeug.security.generate_password_hash
    or bcrypt / argon2.
    """
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${hashed}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a hash."""
    try:
        salt, hashed = password_hash.split("$")
    except ValueError:
        return False
    return hashlib.sha256((password + salt).encode()).hexdigest() == hashed
