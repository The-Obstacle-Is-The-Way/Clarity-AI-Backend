"""
DEPRECATED: For backward compatibility only. 
Import from app.infrastructure.security.jwt.jwt_service instead.
"""

import warnings

warnings.warn(
    "Importing from app.infrastructure.security.jwt_service is deprecated. "
    "Please import from app.infrastructure.security.jwt.jwt_service instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.security.jwt.jwt_service import (
    JWTService,
    IJwtService,
    TokenPayload,
    TokenType,
    get_jwt_service
)

# Re-export for backward compatibility
__all__ = ["JWTService", "IJwtService", "TokenPayload", "TokenType", "get_jwt_service"]
