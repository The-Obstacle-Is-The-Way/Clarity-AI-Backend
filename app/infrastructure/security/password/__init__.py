# app.infrastructure.security.password

"""
Password management components for the Novamind Digital Twin Backend.

This module provides secure password handling, hashing, and validation
for HIPAA-compliant user authentication.
"""

# Import the correct functions from hashing.py
# from app.infrastructure.security.password.hashing import hash_data, secure_compare
from app.infrastructure.security.password.hashing import get_password_hash, verify_password
from app.infrastructure.security.password.password_handler import (
    PasswordHandler, 
)

# Create a factory function for easier access
def get_password_handler() -> PasswordHandler:
    """
    Get an instance of the password handler with default configuration.
    
    Returns:
        Configured PasswordHandler instance
    """
    return PasswordHandler()

__all__ = [
    'PasswordHandler',
    'get_password_handler',
    'get_password_hash',
    'verify_password'
]
