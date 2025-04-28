# app.infrastructure.security.password

"""
Password management components for the Novamind Digital Twin Backend.

This module provides secure password handling, hashing, and validation
for HIPAA-compliant user authentication.
"""

from app.infrastructure.security.password.password_handler import PasswordHandler
# Import the correct functions from hashing.py
# from app.infrastructure.security.password.hashing import hash_data, secure_compare
from app.infrastructure.security.password.hashing import get_password_hash, verify_password
