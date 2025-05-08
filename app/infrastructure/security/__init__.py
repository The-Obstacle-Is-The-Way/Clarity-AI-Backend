"""
Security infrastructure layer for the Novamind Digital Twin Platform.

This module serves as a bridge between the security core and application layers,
providing seamless integration with the clean architecture pattern.
"""

# PHI Security Components
from app.infrastructure.security.phi import PHISanitizer
from app.infrastructure.security.phi.log_sanitizer import (
    LogSanitizer,
    PHIFormatter,
    PHIRedactionHandler,
)

# Audit Components
from app.infrastructure.security.audit import AuditLogger

# Authentication Components
from app.infrastructure.security.auth import (
    AuthService,
    AuthenticationService,
    MFAService,
    create_access_token,
    decode_token,
    get_auth_service,
    validate_access_token
)

# Encryption Components
from app.infrastructure.security.encryption import (
    BaseEncryptionService,
    EncryptionService,
    FieldEncryptor,
    decrypt_field,
    decrypt_phi,
    encrypt_field,
    encrypt_phi,
    get_encryption_key
)

# JWT Components
from app.infrastructure.security.jwt import (
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
from app.infrastructure.security.rate_limiting import DistributedRateLimiter

# RBAC Components
from app.infrastructure.security.rbac import RBACService

__all__ = [
    # PHI Security
    'LogSanitizer',
    'PHIFormatter',
    'PHIRedactionHandler',
    'PHISanitizer',
    
    # Authentication
    'AuthService',
    'AuthenticationService',
    'MFAService',
    'create_access_token',
    'decode_token',
    'get_auth_service',
    'validate_access_token',
    
    # JWT
    'JWTService',
    'TokenPayload',
    'TokenType',
    'get_jwt_service',
    
    # Encryption
    'BaseEncryptionService',
    'EncryptionService',
    'FieldEncryptor',
    'decrypt_field',
    'decrypt_phi',
    'encrypt_field',
    'encrypt_phi',
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