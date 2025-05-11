import asyncio
import re
from collections.abc import Callable
from typing import Any, AsyncGenerator, Coroutine, Literal, Set, cast
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
        # user_repo: IUserRepository, # REMOVED
        public_paths: set[str] | None = None,
        public_path_regexes: list[str] | None = None, # RENAMED from public_path_regex
    ):
        super().__init__(app)
        self.jwt_service = jwt_service
        # self.user_repo = user_repo # REMOVED

        default_public_paths = {
            "/docs", "/openapi.json", "/redoc", 
            "/health", 
            "/", 
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
        # if "X-Test-Token" in request.headers: 
        #     return request.headers.get("X-Test-Token")
        return request.cookies.get("access_token") # Also check cookies

    async def _validate_and_prepare_user_context(
        self, token: str, request: Request # ADDED request to access app.state
    ) -> tuple[AuthenticatedUser, list[str]]: 
        
        token_payload = self.jwt_service.decode_token(token) 

        # --- Instantiate UserRepository on-the-fly ---
        session_factory = request.app.state.actual_session_factory
        if not session_factory:
            logger.critical("actual_session_factory not found on request.app.state. Cannot create UserRepository.")
            raise AuthenticationException("Internal server configuration error for authentication.")
        
        # Import SQLAlchemyUserRepository locally to avoid circular import at module level if not already handled
        from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
        user_repo_instance = SQLAlchemyUserRepository(session_factory=session_factory)
        # --- End UserRepository instantiation ---

        user_id_from_token: str | None = token_payload.get("sub")
        if not user_id_from_token:
            logger.warning("AuthenticationMiddleware: 'sub' (user ID) not found in token payload.")
            raise InvalidTokenException("'sub' claim missing from token")

        try:
            # Attempt to convert to UUID if your user IDs are UUIDs
            user_id_as_uuid = UUID(user_id_from_token)
        except ValueError:
            logger.warning(f"AuthenticationMiddleware: 'sub' claim ('{user_id_from_token}') is not a valid UUID.")
            raise InvalidTokenException("'sub' claim is not a valid UUID")

        # Fetch user from repository
        # Ensure user_repo_instance is correctly initialized and available
        domain_user: DomainUser | None = await user_repo_instance.get_user_by_id(user_id_as_uuid)

        if not domain_user:
            logger.warning(f"User not found for ID from token: {user_id_as_uuid}")
            raise UserNotFoundException(f"User with ID {user_id_as_uuid} not found.")

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
        request.scope["user"] = UnauthenticatedUser() 
        request.scope["auth"] = None 
        
        # Attach app state to request state if not already done by an earlier middleware
        # This is a fallback/ensure mechanism. Ideally, an earlier middleware handles this.
        if not hasattr(request.state, 'actual_session_factory') and hasattr(request.app.state, 'actual_session_factory'):
            request.state.actual_session_factory = request.app.state.actual_session_factory
        if not hasattr(request.state, 'settings') and hasattr(request.app.state, 'settings'):
            request.state.settings = request.app.state.settings
            
        if await self._is_public_path(request.url.path):
            logger.debug(f"Public path '{request.url.path}', skipping authentication.")
            return await call_next(request)
        
        token = self._extract_token(request)
        if not token:
            logger.info(f"Authentication token missing for protected path: {request.url.path}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication token required."}, 
            )
            
        try:
            # Pass the request object to _validate_and_prepare_user_context
            user_context, token_scopes = await self._validate_and_prepare_user_context(token, request)
            request.scope["user"] = user_context 
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