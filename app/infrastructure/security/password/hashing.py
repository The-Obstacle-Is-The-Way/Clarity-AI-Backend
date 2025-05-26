"""
Password hashing and verification utilities using passlib.

This module uses passlib with bcrypt for robust password hashing and verification,
aligning with HIPAA Security Rule requirements for access control.
"""

from passlib.context import CryptContext

# Define the password context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str | None, hashed_password: str | None) -> bool:
    """
    Verify a plaintext password against a hashed password using passlib context.

    Args:
        plain_password: Plaintext password to verify
        hashed_password: Hashed password to compare against

    Returns:
        True if the password matches, False otherwise
    """
    # Handle None values gracefully
    if plain_password is None or hashed_password is None:
        return False

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Handle any exceptions by returning False
        return False


def get_password_hash(password: str) -> str:
    """
    Hash a plaintext password using passlib context (bcrypt).

    Args:
        password: Plaintext password to hash

    Returns:
        Hashed password string
    """
    return pwd_context.hash(password)
