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
    # Consider adding other fields like roles, username if they are commonly needed by endpoints from request.scope.user
    # For now, keeping it minimal based on direct user fetching.
    # roles: List[str] = [] 
    # username: str | None = None

class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp, # Standard for BaseHTTPMiddleware
        jwt_service: JWTServiceInterface,
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
        self, token: str, request: Request 
    ) -> tuple[AuthenticatedUser, list[str]]: # Return type is tuple
        logger.debug("Attempting to validate token and prepare user context.")
        
        # === MORE DETAILED DEBUGGING ===
        the_app_on_request = request.app
        logger.info(f"MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request ID: {id(the_app_on_request)}, type: {type(the_app_on_request)}")
        logger.info(f"MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request.__class__ is {the_app_on_request.__class__}")
        try:
            logger.info(f"MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request.__dict__ is {the_app_on_request.__dict__}")
        except AttributeError:
            logger.warning("MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request has no __dict__ attribute.")

        if hasattr(the_app_on_request, 'state'):
            logger.info(f"MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request.state exists. State ID: {id(the_app_on_request.state)}")
            if hasattr(the_app_on_request.state, 'actual_session_factory'):
                logger.info("MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request.state.actual_session_factory exists.")
            else:
                logger.warning("MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request.state.actual_session_factory DOES NOT EXIST.")
        else:
            logger.warning("MIDDLEWARE_VALIDATE_PREPARE_APP_VAR: the_app_on_request has NO state attribute.")
        # === END MORE DETAILED DEBUGGING ===

        try:
            token_payload: TokenPayload = await self.jwt_service.decode_token(token)
            logger.debug(f"Token decoded. Payload sub: {token_payload.sub if hasattr(token_payload, 'sub') else 'N/A'}, Roles from token: {token_payload.roles if hasattr(token_payload, 'roles') else 'N/A'}")

            # === HAIL MARY GETATTR ===
            logger.info(f"Attempting getattr(the_app_on_request, 'state')")
            retrieved_state = getattr(the_app_on_request, 'state')
            logger.info(f"getattr(the_app_on_request, 'state') returned: {type(retrieved_state)}")
            logger.info(f"Attempting getattr(retrieved_state, 'actual_session_factory')")
            session_factory = getattr(retrieved_state, 'actual_session_factory')
            logger.info(f"Successfully retrieved session_factory via getattr: {type(session_factory)}")
            # === END HAIL MARY GETATTR ===

            async with session_factory() as db_session:
                user_repo_instance = SQLAlchemyUserRepository(db_session=db_session)
                
                user_id_as_uuid = UUID(str(token_payload.sub))
                domain_user: DomainUser | None = await user_repo_instance.get_user_by_id(user_id_as_uuid)

            if not domain_user:
                logger.warning(f"User with id {user_id_as_uuid} not found in repository.")
                raise UserNotFoundException("User associated with token not found.")

            logger.debug(f"User {domain_user.id} found. Checking status: {domain_user.account_status}")
            if domain_user.account_status != UserStatus.ACTIVE:
                logger.warning(f"User {domain_user.id} is not active (status: {domain_user.account_status}). Access denied.")
                raise AuthenticationException(
                    f"User account is {domain_user.account_status.value.lower()}. Access denied.", 
                    status_code=HTTP_403_FORBIDDEN # Set 403 for inactive user
                )
            
            logger.debug(f"User {domain_user.id} is active.")

            # Prepare roles for AuthenticatedUser Pydantic model
            # domain_user.roles is typically a set of UserRole enums or list of role strings from mock
            if isinstance(domain_user.roles, set):
                user_roles_for_model = sorted([role.value for role in domain_user.roles]) # sort for consistency
            elif isinstance(domain_user.roles, list):
                user_roles_for_model = sorted(domain_user.roles) # sort for consistency
            else:
                user_roles_for_model = []

            auth_user_for_scope = AuthenticatedUser(
                id=str(domain_user.id),
                username=domain_user.username,
                email=getattr(domain_user, 'email', None), # Ensure email attribute exists or handle gracefully
                roles=user_roles_for_model
            )
            
            # Scopes for AuthCredentials should come from the token payload's 'roles' field
            auth_scopes_for_starlette = token_payload.roles if token_payload.roles is not None else []
            
            logger.info(f"User {domain_user.id} validated. User object roles: {user_roles_for_model}, Auth Scopes from token: {auth_scopes_for_starlette}")
            return auth_user_for_scope, auth_scopes_for_starlette # Return the user and the token's scopes

        except (AuthenticationException, UserNotFoundException, InvalidTokenException, TokenExpiredException) as exc:
            logger.warning(f"Handled auth exception in _validate_and_prepare_user_context: {type(exc).__name__} - {exc}")
            raise 
        except ValueError as ve: # Handles UUID conversion errors or other ValueErrors
            logger.error(f"ValueError during token validation: {ve}. Traceback: {traceback.format_exc()}")
            raise AuthenticationException(f"Invalid data encountered during token validation: {ve}")
        except Exception as e:
            logger.error(f"UNEXPECTED error in _validate_and_prepare_user_context: {type(e).__name__} - {e}. Traceback: {traceback.format_exc()}")
            # For unexpected errors, re-raise as a generic AuthenticationException that leads to 401
            # Or, consider a more specific internal server error if appropriate
            raise AuthenticationException(f"Unexpected internal error during token validation: {str(e)}")

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Log the app instance ID from the request scope
        logger.info(f"MIDDLEWARE_DISPATCH: request.app ID: {id(request.app)}, type: {type(request.app)}")
        
        # Try to access state to see if it exists on this app instance
        if hasattr(request.app, 'state') and request.app.state:
            logger.info(f"MIDDLEWARE_DISPATCH: request.app.state exists. Factory ID: {id(getattr(request.app.state, 'actual_session_factory', None))}")
        else:
            logger.warning("MIDDLEWARE_DISPATCH: request.app has no state or state is empty.")

        # Bypass authentication for public paths
        if request.url.path in self.public_paths:
            logger.debug(f"Dispatch: Path '{request.url.path}' is in public_paths. Skipping auth.")
            request.scope["user"] = UnauthenticatedUser()
            request.scope["auth"] = AuthCredentials([])
            return await call_next(request)

        for regex_pattern in self.public_path_patterns:
            if regex_pattern.match(request.url.path):
                logger.debug(f"Dispatch: Path '{request.url.path}' matches public regex '{regex_pattern.pattern}'. Skipping auth.")
                request.scope["user"] = UnauthenticatedUser()
                request.scope["auth"] = AuthCredentials([])
                return await call_next(request)

        token = self._extract_token(request)
        if not token:
            logger.info(f"Authentication token missing for protected path: {request.url.path}")
            return JSONResponse(
                {"detail": "Authentication token required."},
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        try:
            auth_user_obj, token_scopes = await self._validate_and_prepare_user_context(token, request)
            
            request.scope["user"] = auth_user_obj
            request.scope["auth"] = AuthCredentials(scopes=token_scopes) 
            
        # Explicitly catch specific token exceptions first, then broader AuthenticationException
        except (InvalidTokenException, TokenExpiredException) as te:
            logger.warning(f"Token validation error for path {request.url.path}: {type(te).__name__} - {te}. Status code: {getattr(te, 'status_code', status.HTTP_401_UNAUTHORIZED)}")
            return JSONResponse(
                {"detail": str(te)},
                status_code=getattr(te, 'status_code', status.HTTP_401_UNAUTHORIZED)
            )
        except AuthenticationException as e: # Catches other auth-related known issues like UserNotFound, Inactive user
            logger.warning(f"Authentication failed for path {request.url.path}: {type(e).__name__} - {e}. Status code: {getattr(e, 'status_code', status.HTTP_401_UNAUTHORIZED)}")
            return JSONResponse(
                {"detail": str(e)},
                status_code=getattr(e, 'status_code', status.HTTP_401_UNAUTHORIZED)
            )
        except Exception as e: # Catch-all for truly unexpected issues during auth prep
            logger.error(f"CRITICAL UNEXPECTED error during dispatch auth phase for {request.url.path}: {type(e).__name__} - {e}. Traceback: {traceback.format_exc()}")
            return JSONResponse(
                {"detail": "An unexpected server error occurred during authentication."},
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        return await call_next(request) 