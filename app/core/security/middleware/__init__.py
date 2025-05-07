"""
Security middleware implementation for API protection.

This module implements security middleware components following clean architecture principles,
including authentication, authorization, request validation, and secure logging.
"""

# This file is being emptied as AuthenticationMiddleware has been moved to app.presentation.middleware.authentication
# and RoleBasedAccessControl was not part of the current refactoring scope for relocation.
# If RoleBasedAccessControl is needed, it should be in a more appropriate core/domain location or refactored separately.

# Keeping existing imports for now in case other core security modules might exist or be added here,
# but the main classes are gone.

import asyncio
import re
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint # RequestResponseEndpoint not used by new middleware
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.core.config.settings import Settings, get_settings
from app.core.interfaces.services.authentication_service import IAuthenticationService
from app.core.interfaces.services.jwt_service import IJwtService
from app.domain.exceptions.auth_exceptions import (
    AuthenticationException,
    UserNotFoundException,
)
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.infrastructure.logging.logger import get_logger
from app.infrastructure.security.auth_service import get_auth_service # Not used by new middleware directly
from app.infrastructure.security.jwt_service import get_jwt_service # Not used by new middleware directly

logger = get_logger(__name__)

# RoleBasedAccessControl class removed.

# AuthenticationMiddleware class removed.

# Example of how you might add this middleware to your app in main.py or app_factory.py:
# from app.presentation.middleware.authentication import AuthenticationMiddleware # Corrected import path
# app.add_middleware(AuthenticationMiddleware, jwt_service=my_jwt_service_instance, user_repo=my_user_repo_instance)
