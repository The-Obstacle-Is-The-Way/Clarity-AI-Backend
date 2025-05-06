"""
Security infrastructure layer for the Novamind Digital Twin Platform.

This module serves as a bridge between the security core and application layers,
providing seamless integration with the clean architecture pattern.
"""

# PHI Security Components - imports moved to direct imports to avoid circular dependencies
# Audit Components  
from app.infrastructure.security.audit import AuditLogger

# Authentication Components
from app.infrastructure.security.auth import MFAService

# Encryption Components
from app.infrastructure.security.encryption import BaseEncryptionService, FieldEncryptor, get_encryption_key

# JWT Components
# from app.infrastructure.security.jwt import JWTService # Old import from subdirectory
from app.infrastructure.security.jwt_service import JWTService # Corrected import

# Password Components
from app.infrastructure.security.password import PasswordHandler, get_password_hash, verify_password
from app.infrastructure.security.phi.log_sanitizer import (
    LogSanitizer,
    PHIFormatter,
    PHIRedactionHandler,
)

# Rate Limiting Components
from app.infrastructure.security.rate_limiting import DistributedRateLimiter

# RBAC Components
from app.infrastructure.security.rbac import RBACService

from .auth.authentication_service import AuthenticationService
from app.infrastructure.security.auth_service import get_auth_service

__all__ = [
    # PHI Security
    'LogSanitizer',
    'PHIFormatter',
    'PHIRedactionHandler',
    
    # Authentication
    'MFAService',
    'AuthenticationService',
    
    # JWT
    'JWTService',
    
    # Encryption
    'BaseEncryptionService',
    
    # Password
    'PasswordHandler',
    'get_password_hash',
    'verify_password',
    
    # RBAC
    'RBACService',
    
    # Rate Limiting
    'DistributedRateLimiter',
    
    # Audit
    'AuditLogger',
]