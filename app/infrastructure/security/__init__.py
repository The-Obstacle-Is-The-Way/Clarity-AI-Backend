"""
Security infrastructure layer for the Clarity AI Digital Twin Platform.

This module consolidates all security-related functionality from subdirectories,
providing a clean, unified interface following clean architecture principles.
"""

import warnings

# Warn about direct imports from deprecated locations
warnings.warn(
    "Direct imports from app.infrastructure.security.auth_service, "
    "app.infrastructure.security.jwt_service, "
    "app.infrastructure.security.encryption_service, and "
    "app.infrastructure.security.password_handler are deprecated. "
    "Use the subdirectory versions instead.",
    DeprecationWarning,
    stacklevel=2
)

# PHI Security Components
from app.infrastructure.security.phi.sanitizer import PHISanitizer, get_sanitizer
from app.infrastructure.security.phi.log_sanitizer import (
    LogSanitizer,
    PHIFormatter,
    PHIRedactionHandler,
)

# Audit Components
from app.infrastructure.security.audit.audit import AuditLogger

# Authentication Components
from app.infrastructure.security.auth.auth_service import (
    AuthenticationService,
    get_auth_service,
)

# Encryption Components
from app.infrastructure.security.encryption import (
    EncryptionService,
    encrypt_field,
    decrypt_field,
    encrypt_phi,
    decrypt_phi,
    get_encryption_key
)

# JWT Components
from app.infrastructure.security.jwt.jwt_service import (
    JWTService,
    TokenPayload,
    TokenType,
    get_jwt_service
)

# Password Components
from app.infrastructure.security.password import (
    PasswordHandler,
    get_password_handler,
    get_password_hash,
    verify_password
)

# Rate Limiting Components
from app.infrastructure.security.rate_limiting.rate_limiter import DistributedRateLimiter

# RBAC Components
from app.infrastructure.security.rbac.rbac_service import RBACService

__all__ = [
    # PHI Security
    'LogSanitizer',
    'PHIFormatter',
    'PHIRedactionHandler',
    'PHISanitizer',
    'get_sanitizer',
    
    # Authentication
    'AuthenticationService',
    'get_auth_service',
    
    # JWT
    'JWTService',
    'TokenPayload',
    'TokenType',
    'get_jwt_service',
    
    # Encryption
    'EncryptionService',
    'encrypt_field',
    'decrypt_field',
    'encrypt_phi',
    'decrypt_phi',
    'get_encryption_key',
    
    # Password
    'PasswordHandler',
    'get_password_handler',
    'get_password_hash',
    'verify_password',
    
    # RBAC
    'RBACService',
    
    # Rate Limiting
    'DistributedRateLimiter',
    
    # Audit
    'AuditLogger',
]