from collections.abc import AsyncIterator, Awaitable, Callable
from uuid import UUID

from fastapi import Request, Response
from fastapi.security.utils import get_authorization_scheme_param
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import ASGIApp, BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.status import (
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.core.domain.entities.user import UserStatus
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.domain.entities.auth import UnauthenticatedUser
from app.domain.exceptions.auth_exceptions import (
    AuthenticationException,
    UserNotFoundException,
)
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.infrastructure.logging.logger import get_logger
from app.infrastructure.repositories.sqla.user_repository import SQLAlchemyUserRepository
from app.presentation.schemas.auth import AuthenticatedUser, AuthCredentials

logger = get_logger(__name__)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        jwt_service: JWTServiceInterface,
        user_repository: type[IUserRepository],
        public_paths: set[str],
        session_factory: Callable[[], AsyncIterator[AsyncSession]],
    ):
        super().__init__(app)
        self.jwt_service = jwt_service
        self.public_paths = public_paths if public_paths else set()
        self.session_factory = session_factory
        logger.info(
            f"AuthenticationMiddleware initialized. Public paths: {self.public_paths}"
        )

    async def _is_public_path(self, path: str) -> bool:
        return path in self.public_paths

    def _extract_token(self, request: Request) -> str | None:
        authorization: str | None = request.headers.get("Authorization")
        if not authorization:
            return None
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            return None
        return param

    async def _validate_and_prepare_user_context(
        self, token: str, request: Request
    ) -> tuple[AuthenticatedUser, list[str]]:
        try:
            token_payload = self.jwt_service.decode_token(token)
        except (InvalidTokenException, TokenExpiredException) as e:
            logger.warning(f"Token decoding/validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error decoding token: {e}", exc_info=True)
            raise AuthenticationException("Error decoding token") from e

        user_id_str = token_payload.sub
        if not user_id_str:
            raise AuthenticationException("Subject (user ID) not found in token")

        try:
            user_id = UUID(user_id_str)
        except ValueError as e:
            raise AuthenticationException(f"Invalid user ID format in token: {e}") from e

        try:
            async with self.session_factory() as db_session:
                user_repository = SQLAlchemyUserRepository(db_session=db_session)
                domain_user = await user_repository.get_user_by_id(user_id)
        except Exception as e:
            logger.error(f"Database error retrieving user {user_id}: {e}", exc_info=True)
            raise UserNotFoundException(f"Error retrieving user {user_id}") from e

        if not domain_user:
            logger.warning(f"User with ID {user_id} not found in database")
            raise UserNotFoundException(f"User {user_id} not found")

        if domain_user.status != UserStatus.ACTIVE:
            logger.warning(
                f"User {user_id} is not active. Status: {domain_user.status}"
            )
            raise AuthenticationException(
                f"User {user_id} is not active. Status: {domain_user.status}"
            )

        roles = getattr(token_payload, 'roles', [])
        auth_user = AuthenticatedUser(
            id=str(domain_user.id),
            username=domain_user.username,
            email=domain_user.email,
            roles=roles,
            status=domain_user.status,
        )
        scopes = roles
        return auth_user, scopes

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if await self._is_public_path(request.url.path):
            logger.debug(f"Public path: {request.url.path} - Skipping authentication")
            request.scope["user"] = UnauthenticatedUser()
            request.scope["auth"] = AuthCredentials(scopes=[])
            return await call_next(request)

        token = self._extract_token(request)
        if not token:
            logger.warning("No token found in request")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": "Not authenticated"},
            )

        try:
            user_context, scopes = await self._validate_and_prepare_user_context(
                token, request
            )
            request.scope["user"] = user_context
            request.scope["auth"] = AuthCredentials(scopes=scopes)
        except TokenExpiredException as e:
            logger.warning(f"Token expired: {e}")
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={"detail": "Token has expired"},
            )
        except InvalidTokenException as e:
            logger.warning(f"Invalid token: {e}")
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={"detail": "Invalid token"},
            )
        except UserNotFoundException as e:
            logger.warning(f"User not found during auth: {e}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": str(e)},
            )
        except AuthenticationException as e:
            logger.warning(f"Authentication failed: {e}")
            return JSONResponse(
                status_code=HTTP_401_UNAUTHORIZED,
                content={"detail": str(e)},
            )
        except Exception as e:
            logger.exception(f"Unexpected error in authentication middleware: {e}")
            return JSONResponse(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "An unexpected error occurred during authentication."},
            )
        return await call_next(request)