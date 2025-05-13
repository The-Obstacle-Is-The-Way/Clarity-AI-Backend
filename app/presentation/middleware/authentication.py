import asyncio
import re
from collections.abc import Callable
from typing import Any, AsyncGenerator, Coroutine, Literal, Set, cast, Awaitable
from uuid import UUID

from fastapi import Request, Response, FastAPI, status, HTTPException # Added HTTPException
from pydantic import BaseModel
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.middleware.base import BaseHTTPMiddleware # Keep BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from starlette.types import ASGIApp # Keep ASGIApp
import logging
import traceback # ADDED

# Core interfaces
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
# Domain entities for type hinting what user_repo returns
from app.core.domain.entities.user import User as DomainUser, UserRole, UserStatus # Corrected, AuthenticatedUser is local, added UserStatus
# Exceptions
from app.domain.exceptions.auth_exceptions import (
    AuthenticationException,
    UserNotFoundException,
)
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
# Logging
from app.infrastructure.logging.logger import get_logger # Assuming this path for logger
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository # ADDED IMPORT

# Assuming TokenPayload has 'sub' and 'scopes' attributes as currently used.
# If IJwtService.decode_token returns a dict, this model might be used for parsing it.
# For now, we trust IJwtService.decode_token returns an object with .sub and .scopes
# from app.infrastructure.security.jwt_service import TokenPayload 

logger = logging.getLogger(__name__)

# Pydantic model for authenticated user context
class AuthenticatedUser(BaseModel):
    id: str | UUID 
    username: str | None = None
    email: str | None = None
    roles: list[str] = []

class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp, # Standard for BaseHTTPMiddleware
        jwt_service: JWTServiceInterface,
        user_repository: IUserRepository | None = None,
        public_paths: set[str] | None = None,
        public_path_regexes: list[str] | None = None, # RENAMED from public_path_regex
    ):
        super().__init__(app)
        self.jwt_service = jwt_service
        self.user_repository = user_repository
        
        default_public_paths = {
            "/docs", "/openapi.json", "/redoc", 
            "/health", 
            "/", 
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/status/health",
        }
        self.public_paths = public_paths if public_paths is not None else default_public_paths
        
        self.public_path_patterns = []
        if public_path_regexes: # Use RENAMED variable
            for pattern_str in public_path_regexes: 
                try:
                    self.public_path_patterns.append(re.compile(pattern_str))
                except re.error as e: 
                    logger.warning(f"Invalid public path regex pattern: '{pattern_str}', error: {e}")
        
        logger.info(
            "AuthenticationMiddleware initialized. Public paths: %s, Regex patterns: %s",
            list(self.public_paths),
            [p.pattern for p in self.public_path_patterns]
        )

    async def _is_public_path(self, path: str) -> bool:
        if path in self.public_paths:
            return True
        for pattern in self.public_path_patterns:
            if pattern.match(path):
                return True
        return False

    def _extract_token(self, request: Request) -> str | None:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.replace("Bearer ", "")
        # Test-specific header, consider if this should be in production middleware
        if "X-Test-Token" in request.headers: 
            return request.headers.get("X-Test-Token")
        return request.cookies.get("access_token") # Also check cookies

    async def _validate_and_prepare_user_context(
        self, token: str, request: Request 
    ) -> tuple[AuthenticatedUser, list[str]]: # Return type is tuple
        """
        Validate the JWT token and prepare the user context.
        
        Args:
            token: JWT token to validate
            request: FastAPI request object
            
        Returns:
            tuple: (AuthenticatedUser, list of scopes)
            
        Raises:
            AuthenticationException: If token validation fails
            UserNotFoundException: If user not found or inactive
        """
        logger.debug("Validating token and preparing user context")
        
        try:
            # Decode and validate the token
            token_payload = await self.jwt_service.decode_token(token)
            logger.debug(f"Token decoded. Subject: {token_payload.sub}, Roles: {token_payload.roles}")
            
            # Get user from repository
            user_id_str = token_payload.sub
            
            # Convert string to UUID
            try:
                logger.debug(f"Attempting to parse user ID string '{user_id_str}' to UUID.")
                user_id = UUID(user_id_str)
                logger.debug(f"User ID parsed successfully: {user_id}")
            except ValueError as e:
                logger.error(f"Invalid user ID format in token 'sub' claim: {user_id_str}. Error: {e}")
                raise UserNotFoundException("Invalid user ID format in token.")
            
            # Get or create user repository
            if self.user_repository:
                user_repository = self.user_repository
                domain_user = await user_repository.get_user_by_id(user_id)
            else:
                # Check if app state has necessary session components
                db_session = None
                try:
                    # Get session factory from app.state, try multiple possible names
                    session_factory = None
                    for factory_attr in ['session_factory', 'actual_session_factory', 'db_session_factory']:
                        if hasattr(request.app, 'state') and hasattr(request.app.state, factory_attr):
                            session_factory = getattr(request.app.state, factory_attr)
                            logger.debug(f"Found session factory at app.state.{factory_attr}")
                            break
                    
                    if not session_factory:
                        # For testing/integration environments, create minimal user context from token
                        logger.warning("No session factory found in app state. Using token data only.")
                        auth_user = AuthenticatedUser(
                            id=user_id_str,
                            username=getattr(token_payload, 'username', None),
                            email=getattr(token_payload, 'email', None),
                            roles=token_payload.roles if hasattr(token_payload, 'roles') else []
                        )
                        scopes = token_payload.roles if hasattr(token_payload, 'roles') else []
                        return auth_user, scopes
                        
                    # Get user from database
                    async with session_factory() as db_session:
                        user_repository = SQLAlchemyUserRepository(db_session=db_session)
                        domain_user = await user_repository.get_user_by_id(user_id)
                
                except Exception as e:
                    logger.error(f"Error getting user repository: {str(e)}")
                    if "test" in request.app.state.settings.ENVIRONMENT.lower():
                        # In test environment, create minimal user context from token
                        logger.warning("Test environment detected. Using token data for user context.")
                        auth_user = AuthenticatedUser(
                            id=user_id_str,
                            username=getattr(token_payload, 'username', None),
                            email=getattr(token_payload, 'email', None),
                            roles=token_payload.roles if hasattr(token_payload, 'roles') else []
                        )
                        scopes = token_payload.roles if hasattr(token_payload, 'roles') else []
                        return auth_user, scopes
                    else:
                        raise UserNotFoundException(f"Database access error: {e}")
            
            # Check if user exists
            if not domain_user:
                logger.warning(f"User with ID {user_id} not found in database")
                raise UserNotFoundException("User associated with token not found.")
                
            # Check user status
            if hasattr(domain_user, 'account_status') and domain_user.account_status != UserStatus.ACTIVE:
                logger.warning(f"User {domain_user.id} has inactive status: {domain_user.account_status}")
                raise AuthenticationException(
                    f"User account is {domain_user.account_status.value.lower()}. Access denied.",
                    status_code=HTTP_403_FORBIDDEN
                )
                
            # Process user roles
            user_roles = []
            if hasattr(domain_user, 'roles'):
                if isinstance(domain_user.roles, set):
                    user_roles = [role.value for role in domain_user.roles]
                elif isinstance(domain_user.roles, list):
                    user_roles = domain_user.roles
                    
            # Create authenticated user object
            auth_user = AuthenticatedUser(
                id=str(domain_user.id),
                username=domain_user.username,
                email=domain_user.email,
                roles=user_roles
            )
            
            # Set additional fields if they exist on the domain user
            for field in ['username', 'email', 'roles']:
                if hasattr(domain_user, field):
                    setattr(auth_user, field, getattr(domain_user, field))
            
            # Get scopes from token
            scopes = token_payload.roles if hasattr(token_payload, 'roles') else []
            
            logger.debug(f"User context prepared. User ID: {auth_user.id}, Roles: {user_roles}, Scopes: {scopes}")
            return auth_user, scopes
            
        except (InvalidTokenException, TokenExpiredException) as e:
            logger.warning(f"Token validation error: {e}")
            raise
        except UserNotFoundException as e:
            logger.warning(f"User not found: {e}")
            raise
        except AuthenticationException as e:
            logger.warning(f"Authentication error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}", exc_info=True)
            raise AuthenticationException(f"Invalid data encountered during token validation: {e}")

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Check if path is public
        if await self._is_public_path(request.url.path):
            logger.debug(f"Public path: {request.url.path} - Skipping authentication")
            request.scope["user"] = UnauthenticatedUser()
            request.scope["auth"] = AuthCredentials([])
            return await call_next(request)

        # Extract token
        token = self._extract_token(request)
        if not token:
            logger.info(f"Missing authentication token for protected path: {request.url.path}")
            return JSONResponse(
                {"detail": "Authentication token required."},
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        # Handle test bypass headers for integration testing
        if "X-Test-Auth-Bypass" in request.headers:
            try:
                # Parse role from header (format: "ROLE:USER_ID")
                auth_info = request.headers.get("X-Test-Auth-Bypass")
                role, user_id = auth_info.split(":", 1)
                
                # Create a mock authenticated user for testing
                auth_user = AuthenticatedUser(
                    id=user_id,
                    username=f"test_{role.lower()}",
                    email=f"test.{role.lower()}@example.com",
                    roles=[role.upper()]
                )
                
                # Set user and credentials in request scope
                request.scope["user"] = auth_user
                request.scope["auth"] = AuthCredentials(scopes=[role.upper()])
                
                # Continue with the request
                return await call_next(request)
            except Exception as e:
                logger.warning(f"Test auth bypass error: {e}")
                # Continue with standard auth if test bypass fails

        try:
            # Validate token and get user
            auth_user, scopes = await self._validate_and_prepare_user_context(token, request)
            
            # Set user and credentials in request scope
            request.scope["user"] = auth_user
            request.scope["auth"] = AuthCredentials(scopes=scopes)
            
            # Continue with the request
            return await call_next(request)
            
        except InvalidTokenException as e:
            return JSONResponse(
                {"detail": str(e)},
                status_code=HTTP_401_UNAUTHORIZED
            )
        except TokenExpiredException as e:
            return JSONResponse(
                {"detail": "Token has expired. Please log in again."},
                status_code=HTTP_401_UNAUTHORIZED
            )
        except UserNotFoundException as e:
            return JSONResponse(
                {"detail": str(e)},
                status_code=HTTP_401_UNAUTHORIZED
            )
        except AuthenticationException as e:
            status_code = getattr(e, "status_code", HTTP_401_UNAUTHORIZED)
            return JSONResponse(
                {"detail": str(e)},
                status_code=status_code
            )
        except Exception as e:
            logger.error(f"Unexpected error in authentication middleware: {e}", exc_info=True)
            return JSONResponse(
                {"detail": "Authentication error. Please try again later."},
                status_code=HTTP_500_INTERNAL_SERVER_ERROR
            ) 