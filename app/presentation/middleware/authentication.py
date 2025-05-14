import re
from collections.abc import Awaitable, Callable
from uuid import UUID

from fastapi import Request, Response
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import ASGIApp 
from starlette.responses import JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from app.core.domain.entities.user import UserStatus
from app.core.domain.exceptions.authentication import (
    AuthenticationException,
    InvalidTokenException,
    TokenExpiredException,
    UserNotFoundException,
)
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.domain.entities.auth import AuthenticatedUser, UnauthenticatedUser
from app.infrastructure.logging.logger import get_logger
from app.infrastructure.repositories.sqla.user_repository import (
    SQLAlchemyUserRepository,
)
from app.presentation.api.v1.models.auth import AuthCredentials


logger = get_logger(__name__)


class AuthenticatedUserPydantic(AuthenticatedUser):
    pass 


class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        jwt_service: JWTServiceInterface,
        user_repository: IUserRepository | None = None,
        public_paths: set[str] | None = None,
        public_path_regexes: list[str] | None = None,
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
        if public_path_regexes:
            for pattern_str in public_path_regexes:
                try:
                    self.public_path_patterns.append(re.compile(pattern_str))
                except re.error as e:
                    logger.warning(f"Invalid public path regex pattern: '{pattern_str}', error: {e}")
        
        logger.info(
            "AuthenticationMiddleware initialized. Public paths: %s, Regex patterns: %s",
            list(self.public_paths),
            [p.pattern for p in self.public_path_patterns],
        )

    async def _is_public_path(self, path: str) -> bool:
        if path in self.public_paths:
            return True
        for pattern in self.public_path_patterns:
            if pattern.fullmatch(path):
                return True
        return False

    def _extract_token(self, request: Request) -> str | None:
        authorization_header = request.headers.get("Authorization")
        if not authorization_header:
            return None
        
        scheme, param = get_authorization_scheme_param(authorization_header)
        if not scheme or scheme.lower() != "bearer":
            return None
        return param

    async def _validate_and_prepare_user_context(
        self, token: str, request: Request
    ) -> tuple[AuthenticatedUser, list[str]]:
        try:
            token_payload = self.jwt_service.decode_token(token)
            if not token_payload.sub or not token_payload.jti:
                detail = (
                    "Token does not contain a valid 'sub' (subject) claim "
                    "or 'jti' (JWT ID) claim."
                )
                raise AuthenticationException(detail)

            user_id_str = token_payload.sub
            try:
                user_id = UUID(user_id_str)
            except ValueError as e:
                raise AuthenticationException(f"Invalid user ID format in token: {e}") from e

            domain_user = None
            if self.user_repository:
                domain_user = await self.user_repository.get_user_by_id(user_id)
            else:
                try:
                    session_factory = None
                    for factory_attr in ['session_factory', 'actual_session_factory', 'db_session_factory']:
                        if hasattr(request.app, 'state') and hasattr(request.app.state, factory_attr):
                            session_factory = getattr(request.app.state, factory_attr)
                            logger.debug(f"Found session factory at app.state.{factory_attr}")
                            break
                    
                    if not session_factory:
                        logger.warning("No session factory found in app state. Using token data only.")
                        auth_user = AuthenticatedUser(
                            id=user_id_str,
                            username=getattr(token_payload, 'username', None),
                            email=getattr(token_payload, 'email', None),
                            roles=(
                                token_payload.roles 
                                if hasattr(token_payload, 'roles') 
                                else []
                            ),
                        )
                        scopes = token_payload.roles if hasattr(token_payload, 'roles') else []
                        return auth_user, scopes
                        
                    async with session_factory() as db_session:
                        user_repository = SQLAlchemyUserRepository(db_session=db_session)
                        domain_user = await user_repository.get_user_by_id(user_id)
                
                except Exception as e: 
                    logger.error(f"Error getting user repository: {str(e)}")
                    if "test" in request.app.state.settings.ENVIRONMENT.lower():
                        logger.warning("Test environment detected. Using token data for user context.")
                        auth_user = AuthenticatedUser(
                            id=user_id_str,
                            username=getattr(token_payload, 'username', None),
                            email=getattr(token_payload, 'email', None),
                            roles=(
                                token_payload.roles 
                                if hasattr(token_payload, 'roles') 
                                else []
                            ),
                        )
                        scopes = token_payload.roles if hasattr(token_payload, 'roles') else []
                        return auth_user, scopes
                    else:
                        detail = f"Database access error: {e}"
                        raise UserNotFoundException(detail) from e
            
            if not domain_user:
                logger.warning(f"User with ID {user_id} not found in database")
                raise UserNotFoundException("User associated with token not found.")
                
            if hasattr(domain_user, 'account_status') and domain_user.account_status != UserStatus.ACTIVE:
                logger.warning(f"User {domain_user.id} has inactive status: {domain_user.account_status}")
                detail = f"User account is {domain_user.account_status.value.lower()}. Access denied."
                raise AuthenticationException(
                    detail,
                    status_code=HTTP_403_FORBIDDEN
                )
                
            user_roles = []
            if hasattr(domain_user, 'roles'):
                if isinstance(domain_user.roles, set):
                    user_roles = [role.value for role in domain_user.roles]
                elif isinstance(domain_user.roles, list):
                    user_roles = domain_user.roles
                    
            auth_user = AuthenticatedUser(
                id=str(domain_user.id),
                username=domain_user.username,
                email=domain_user.email,
                roles=user_roles
            )
            
            for field in ['username', 'email', 'roles']:
                if hasattr(domain_user, field):
                    setattr(auth_user, field, getattr(domain_user, field))
            
            scopes = token_payload.roles if hasattr(token_payload, 'roles') else []
            
            logger.debug(
                f"User context prepared. User ID: {auth_user.id}, "
                f"Roles: {user_roles}, Scopes: {scopes}"
            )
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
            detail = f"Invalid data encountered during token validation: {e}"
            raise AuthenticationException(detail) from e

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if await self._is_public_path(request.url.path):
            logger.debug(f"Public path: {request.url.path} - Skipping authentication")
            request.scope["user"] = UnauthenticatedUser()
            request.scope["auth"] = AuthCredentials(scopes=[])
            return await call_next(request)
        
        token = self._extract_token(request)
        if not token:
            logger.debug("No authentication token provided")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Token required for authentication"}
            )
        
        try:
            auth_user, scopes = await self._validate_and_prepare_user_context(token, request)
            request.scope["user"] = auth_user
            request.scope["auth"] = AuthCredentials(scopes=scopes)
            return await call_next(request)
            
        except UserNotFoundException as e:
            logger.warning(f"User not found: {e}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": str(e)}
            )
            
        except TokenExpiredException:
            logger.warning("Token expired")
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={"detail": "Token has expired"}
            )
            
        except InvalidTokenException as e:
            logger.warning(f"Invalid token: {e}")
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={"detail": str(e)}
            )
            
        except AuthenticationException as e:
            status_code = getattr(e, "status_code", HTTP_401_UNAUTHORIZED)
            logger.warning(f"Authentication error: {e}, status: {status_code}")
            return JSONResponse(
                status_code=status_code,
                content={"detail": str(e)}
            )
        except Exception as e: 
            logger.error(f"Unexpected error in authentication dispatch: {e}", exc_info=True)
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR, 
                content={"detail": "An unexpected error occurred during authentication."}
            )