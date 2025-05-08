"""
DEPRECATED: For backward compatibility only. 
Import from app.infrastructure.security.password.password_handler instead.
"""

import warnings

warnings.warn(
    "Importing from app.infrastructure.security.password_handler is deprecated. "
    "Please import from app.infrastructure.security.password.password_handler instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.security.password.password_handler import (
    PasswordHandler
)

# Re-export for backward compatibility
__all__ = ["PasswordHandler"]

import logging

from passlib.context import CryptContext

logger = logging.getLogger(__name__)


class PasswordHandler:
    """
    Secure password handling using Passlib.
    
    This class encapsulates password operations including hashing and verification
    using cryptographically secure algorithms that meet HIPAA requirements.
    """
    
    def __init__(
        self,
        schemes: list[str] | None = None,
        deprecated: list[str] | None = None
    ):
        """
        Initialize the password handler with hashing schemes.
        
        Args:
            schemes: List of hashing schemes to use (in order of preference)
            deprecated: List of deprecated schemes (for verification only)
        """
        # Default to bcrypt if no schemes provided (HIPAA-compliant)
        self._schemes = schemes or ["bcrypt"]
        self._deprecated = deprecated or []
        
        # Create the CryptContext with the specified schemes
        self._pwd_context = CryptContext(
            schemes=self._schemes,
            deprecated=self._deprecated
        )
        
        logger.info(f"PasswordHandler initialized with schemes: {self._schemes}")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: The plaintext password to verify
            hashed_password: The stored password hash
            
        Returns:
            True if the password matches the hash, False otherwise
        """
        return self._pwd_context.verify(plain_password, hashed_password)
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password securely.
        
        Uses the preferred hashing algorithm configured in the CryptContext.
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            The secure password hash
        """
        return self._pwd_context.hash(password)
    
    def check_needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if a password hash needs to be updated.
        
        This method determines if the hash was generated with a deprecated
        algorithm or parameters, or if the security parameters have been
        strengthened since the hash was created.
        
        Args:
            hashed_password: The stored password hash to check
            
        Returns:
            True if the hash should be updated, False otherwise
        """
        return self._pwd_context.needs_update(hashed_password)
    
    def update_hash(self, password: str, current_hash: str) -> str | None:
        """
        Generate an updated hash if needed.
        
        Args:
            password: The plaintext password
            current_hash: The current password hash
            
        Returns:
            A new hash if an update is needed, None otherwise
        """
        if self.check_needs_rehash(current_hash):
            return self.hash_password(password)
        return None