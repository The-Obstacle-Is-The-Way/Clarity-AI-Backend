import asyncio
import re
from collections.abc import Callable
from typing import Any, List # Added List for AuthenticatedUser.roles
from uuid import UUID

from fastapi import Request, Response # Removed FastAPI from here, app type is Any in __init__
from pydantic import BaseModel
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

# Core interfaces
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service import IJwtService
# Domain entities for type hinting what user_repo returns
from app.core.domain.entities.user import User as DomainUser 
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

# Assuming TokenPayload has 'sub' and 'scopes' attributes as currently used.
# If IJwtService.decode_token returns a dict, this model might be used for parsing it.
# For now, we trust IJwtService.decode_token returns an object with .sub and .scopes
# from app.infrastructure.security.jwt_service import TokenPayload 

logger = get_logger(__name__)

# Pydantic model for authenticated user context
class AuthenticatedUser(BaseModel):
    id: str | UUID 
    # Consider adding other fields like roles, username if they are commonly needed by endpoints from request.scope.user
    # For now, keeping it minimal based on direct user fetching.
    # roles: List[str] = [] 
    # username: str | None = None

class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Any, # Standard for BaseHTTPMiddleware
        jwt_service: IJwtService,
        user_repo: IUserRepository,
        public_paths: set[str] | None = None,
        public_path_regex: list[str] | None = None, # Changed from List to list
    ):
        super().__init__(app)
        self.jwt_service = jwt_service
        self.user_repo = user_repo

        # Simplified default public paths. In a real app, these might come from settings injected or passed.
        default_public_paths = {
            "/docs", "/openapi.json", "/redoc", # API docs
            "/health", # Health check
            "/", # Root/landing page if public
            # Add more paths like /metrics, /auth/login, /auth/register if they are public
            # Example: "/api/v1/auth/login", "/api/v1/auth/register"
        }
        self.public_paths = public_paths if public_paths is not None else default_public_paths
        
        self.public_path_patterns = []
        if public_path_regex:
            for pattern_str in public_path_regex: # Changed variable name for clarity
                try:
                    self.public_path_patterns.append(re.compile(pattern_str))
                except re.error as e: # Added specific exception type
                    logger.warning(f"Invalid public path regex pattern: '{pattern_str}', error: {e}")
        
        logger.info(
            "AuthenticationMiddleware initialized in presentation layer. Public paths: %s, Regex patterns: %s",
            list(self.public_paths),
            [p.pattern for p in self.public_path_patterns] # Log compiled pattern strings
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
        # if "X-Test-Token" in request.headers: 
        #     return request.headers.get("X-Test-Token")
        return request.cookies.get("access_token") # Also check cookies

    async def _validate_and_prepare_user_context(
        self, token: str
    ) -> tuple[AuthenticatedUser, list[str]]: # Return Pydantic model and scopes
        
        # self.jwt_service.decode_token is async as per IJwtService and recent JwtService change
        # It's expected to return an object with .sub and .scopes (like TokenPayload)
        token_payload = await self.jwt_service.decode_token(token) 

        # self.user_repo.get_user_by_id is async as per IUserRepository
        domain_user: DomainUser | None = await self.user_repo.get_user_by_id(token_payload.sub) # type: ignore

        if not domain_user:
            logger.warning(f"User not found for ID from token: {token_payload.sub}") # type: ignore
            raise UserNotFoundException(f"User with ID {token_payload.sub} not found.") # type: ignore

        if not domain_user.is_active: # Assuming DomainUser has is_active
            logger.warning(f"Attempt to authenticate inactive user: {domain_user.id}")
            raise AuthenticationException("User account is inactive.")

        authenticated_user_context = AuthenticatedUser(id=str(domain_user.id))
        
        token_scopes = getattr(token_payload, 'scopes', [])
        if token_scopes is None: 
            token_scopes = []
        elif not isinstance(token_scopes, list):
            logger.warning(f"Token scopes for user {domain_user.id} are not a list: {type(token_scopes)}. Using empty list.")
            token_scopes = []
            
        return authenticated_user_context, token_scopes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request.scope["user"] = UnauthenticatedUser() # Default for all requests
        request.scope["auth"] = None # Default for all requests
        
        if await self._is_public_path(request.url.path):
            logger.debug(f"Public path '{request.url.path}', skipping authentication.")
            return await call_next(request)
        
        token = self._extract_token(request)
        if not token:
            logger.info(f"Authentication token missing for protected path: {request.url.path}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication token required."}, # Clearer message
            )
            
        try:
            user_context, token_scopes = await self._validate_and_prepare_user_context(token)
            request.scope["user"] = user_context # Set our Pydantic model
            request.scope["auth"] = AuthCredentials(scopes=token_scopes)
            logger.debug(f"User {user_context.id} authenticated for path {request.url.path}. Scopes: {token_scopes}")

        except (AuthenticationException, UserNotFoundException, InvalidTokenException, TokenExpiredException) as exc:
            status_code = HTTP_401_UNAUTHORIZED 
            detail = str(exc) 

            if isinstance(exc, (InvalidTokenException, TokenExpiredException)):
                 detail = str(exc) 
            elif isinstance(exc, UserNotFoundException):
                detail = "User associated with token not found." 
            elif isinstance(exc, AuthenticationException):
                if "User account is inactive" in str(exc): # Specific check
                    status_code = HTTP_403_FORBIDDEN
                    detail = "User account is inactive."
                # else, detail remains str(exc) which is fine for other AuthExceptions
            
            logger.warning(f"Authentication failed for path {request.url.path}: {type(exc).__name__} - {detail}")
            return JSONResponse(status_code=status_code, content={"detail": detail})
        except Exception as e: # Catch any other unexpected errors
            logger.exception(f"Unexpected error during authentication process for path {request.url.path}: {e}")
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "An internal server error occurred during authentication."}
            )
        
        return await call_next(request) 