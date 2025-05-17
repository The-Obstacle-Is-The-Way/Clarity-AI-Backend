import asyncio
import enum
import logging
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any, TypeVar, Optional

from jose import ExpiredSignatureError as JoseExpiredSignatureError
from jose import JWTError, jwt
from pydantic import BaseModel, ValidationError

# Core Layer Imports
from app.core.config.settings import settings
from app.core.interfaces.repositories.token_blacklist_repository_interface import (
    ITokenBlacklistRepository,
)
from app.core.interfaces.services.jwt_service_interface import IJwtService

# Domain Layer Imports - alphabetically sorted
from app.domain.entities.token import TokenPayload, TokenType
from app.domain.entities.user import User
from app.domain.exceptions.token_exceptions import (
    InvalidTokenError,
    TokenBlacklistedException,
    TokenCreationError,
    TokenExpiredException,
)

from fastapi import Request

RevokedTokenType = dict[str, datetime]


class InMemoryTokenBlacklistRepository(ITokenBlacklistRepository):
    def __init__(self) -> None:
        self._blacklist: RevokedTokenType = {}
        self.logger: logging.Logger = logging.getLogger(__name__)

    async def add_to_blacklist(
        self,
        token: str,
        jti: str,
        expires_at: datetime,
    ) -> None:
        self.logger.info(f"Blacklisting token with JTI: {jti[:10]}... until {expires_at}")
        self._blacklist[jti] = expires_at

    async def is_blacklisted(self, jti: str) -> bool:
        if jti in self._blacklist:
            if datetime.now(UTC) < self._blacklist[jti]:
                self.logger.debug(f"Token JTI {jti[:10]}... found in blacklist and is still active.")
                return True
            self.logger.debug(f"Token JTI {jti[:10]}... found in blacklist but has expired. Removing.")
            del self._blacklist[jti]
        return False

    async def remove_expired_tokens(self) -> None:
        now = datetime.now(UTC)
        expired_jtis = [jti for jti, exp in self._blacklist.items() if exp < now]
        for jti in expired_jtis:
            del self._blacklist[jti]
            self.logger.info(f"Removed expired JTI {jti[:10]}... from blacklist.")


T = TypeVar("T", bound=BaseModel)


class JWTService(IJwtService):
    def __init__(
        self,
        secret_key: str,
        algorithm: str,
        token_blacklist_repository: ITokenBlacklistRepository | None = None,
    ):
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.secret_key = secret_key
        self.algorithm = algorithm.upper()

        self.token_blacklist_repository = (
            token_blacklist_repository or InMemoryTokenBlacklistRepository()
        )

        if not token_blacklist_repository:
            self.logger.warning(
                "No token blacklist repository provided. "
                "Using in-memory blacklist (NOT for production)."
            )
        self.logger.info(f"JWT service initialized with algorithm {self.algorithm}")

    def _make_payload_serializable(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = {}
        for k, v in payload.items():
            if isinstance(v, datetime):
                result[k] = v.isoformat()
            elif isinstance(v, date):
                result[k] = v.isoformat()
            elif isinstance(v, timedelta):
                result[k] = v.total_seconds()
            elif isinstance(v, uuid.UUID):
                result[k] = str(v)
            elif isinstance(v, enum.Enum):
                result[k] = v.value
            elif isinstance(v, dict):
                result[k] = self._make_payload_serializable(v)
            elif isinstance(v, list):
                serialized_list = []
                for i in v:
                    if isinstance(i, dict):
                        serialized_list.append(self._make_payload_serializable(i))
                    elif isinstance(i, uuid.UUID):
                        serialized_list.append(str(i))
                    else:
                        serialized_list.append(i)
                result[k] = serialized_list
            else:
                result[k] = v
        return result

    def create_access_token(
        self,
        data: dict[str, Any],
        expires_delta: timedelta | None = None,
    ) -> str:
        if not expires_delta:
            expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token = self._create_token(
            data=data,
            token_type=TokenType.ACCESS,
            expires_delta=expires_delta,
        )
        self.logger.info(
            f"Created access_token for subject {data.get('sub', 'unknown')[:10]}..."
        )
        return token

    def create_refresh_token(
        self,
        data: dict[str, Any],
        expires_delta: timedelta | None = None,
    ) -> str:
        if not expires_delta:
            days_setting = settings.REFRESH_TOKEN_EXPIRE_DAYS
            days_float = float(days_setting) if days_setting is not None else 7.0
            expires_delta = timedelta(days=days_float)

        token = self._create_token(
            data=data,
            token_type=TokenType.REFRESH,
            expires_delta=expires_delta,
        )
        self.logger.info(
            f"Created refresh_token for subject {data.get('sub', 'unknown')[:10]}..."
        )
        return token

    async def blacklist_token(self, token: str) -> None:
        try:
            payload = self.decode_token(token, leeway=10)
            if payload.jti and payload.exp:
                exp_datetime = (
                    datetime.fromtimestamp(payload.exp, UTC)
                    if isinstance(payload.exp, int | float)
                    else payload.exp
                )
                if isinstance(exp_datetime, datetime):
                    await self.token_blacklist_repository.add_to_blacklist(
                        token=token,
                        jti=payload.jti,
                        expires_at=exp_datetime
                    )
                    self.logger.info(
                        f"Token with JTI {payload.jti[:10]}... added to blacklist."
                    )
                else:
                    self.logger.error(
                        f"Cannot blacklist token: exp_datetime is not a valid datetime object. Got type: {type(exp_datetime)}"
                    )
            else:
                self.logger.warning(
                    "Cannot blacklist token: JTI or EXP not found in payload."
                )
        except InvalidTokenError as e:
            self.logger.warning(f"Attempted to blacklist an invalid token: {e}")
        except Exception as e:
            self.logger.error(f"Error blacklisting token: {e}", exc_info=True)

    async def is_token_blacklisted(self, jti: str) -> bool:
        return await self.token_blacklist_repository.is_blacklisted(jti)

    def _create_token(
        self,
        data: dict[str, Any],
        token_type: TokenType,
        expires_delta: timedelta,
        **kwargs: Any
    ) -> str:
        now = datetime.now(UTC)
        expire = now + expires_delta
        to_encode = data.copy()
        to_encode.update({
            "exp": expire,
            "iat": now,
            "nbf": now,
            "type": token_type.value,
            "jti": str(uuid.uuid4())
        })

        to_encode.update(kwargs)

        serializable_payload = self._make_payload_serializable(to_encode)

        try:
            encoded_jwt = jwt.encode(
                serializable_payload, self.secret_key, algorithm=self.algorithm
            )
        except JWTError as e:
            self.logger.error(f"Error encoding JWT: {e}", exc_info=True)
            raise TokenCreationError(f"Could not create token: {e}") from e
        return encoded_jwt

    def decode_token(self, token: str, leeway: int = 0) -> TokenPayload:
        if not token:
            self.logger.warning("Decode attempt with empty token string.")
            raise InvalidTokenError("Token string cannot be empty.")
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                leeway=leeway,
                options={"verify_aud": False}
            )
        except JoseExpiredSignatureError as e:
            self.logger.warning(f"Expired token signature: {e}")
            raise TokenExpiredException(f"Token has expired: {e}") from e
        except JWTError as e:
            self.logger.warning(f"Invalid JWT token: {e}")
            raise InvalidTokenError(f"Invalid token: {e}") from e
        except Exception as e:
            self.logger.error(f"Unexpected error decoding token: {e}", exc_info=True)
            raise InvalidTokenError(f"Unable to decode token: {e}") from e

        try:
            if "type" not in payload or not payload["type"]:
                self.logger.warning("Token 'type' field missing or empty, defaulting to ACCESS.")
                payload["type"] = TokenType.ACCESS.value
            else:
                try:
                    if payload["type"] not in [e.value for e in TokenType]:
                        self.logger.warning(
                            f"Unrecognized token type '{payload['type']}', defaulting to ACCESS."
                        )
                        payload["type"] = TokenType.ACCESS.value
                except Exception as e:
                    self.logger.warning(
                        f"Error processing token type, defaulting to ACCESS: {e}"
                    )
                    payload["type"] = TokenType.ACCESS.value
            
            if "role" in payload and "roles" not in payload:
                payload["roles"] = [payload["role"]]
            elif "roles" not in payload:
                payload["roles"] = []
            
            token_payload = TokenPayload.model_validate(payload)

        except ValidationError as ve:
            self.logger.error(f"Token payload validation error: {ve}")
            raise InvalidTokenError(f"Invalid token payload: {ve}") from ve
        except Exception as general_e:
            self.logger.error(
                f"Unexpected error creating TokenPayload: {general_e}", exc_info=True
            )
            raise InvalidTokenError(f"Invalid token: {general_e}") from general_e

        if token_payload.jti and self._is_token_blacklisted_sync(token_payload.jti):
            self.logger.warning(f"Token with JTI {token_payload.jti} is blacklisted")
            raise TokenBlacklistedException("Token has been blacklisted")

        return token_payload

    def _is_token_blacklisted_sync(self, jti: str) -> bool:
        if isinstance(self.token_blacklist_repository, InMemoryTokenBlacklistRepository):
            if jti in self.token_blacklist_repository._blacklist:
                if datetime.now(UTC) < self.token_blacklist_repository._blacklist[jti]:
                    return True
                del self.token_blacklist_repository._blacklist[jti]
            return False
        else:
            self.logger.warning(
                "Sync blacklist check on a potentially async repo. May block."
            )
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    self.logger.error(
                        "Cannot sync check blacklist: event loop running. Assume not blacklisted."
                    )
                    return False
                return loop.run_until_complete(self.token_blacklist_repository.is_blacklisted(jti))
            except RuntimeError:
                try:
                    return asyncio.run(self.token_blacklist_repository.is_blacklisted(jti))
                except Exception as e:
                    self.logger.error(
                        f"Error during sync blacklist check (asyncio.run): {e}", exc_info=True
                    )
                    return False
            except Exception as e:
                self.logger.error(
                    f"Unexpected error during sync blacklist check: {e}", exc_info=True
                )
                return False

    def verify_token(
        self, token: str, expected_type: TokenType | None = None
    ) -> TokenPayload:
        payload = self.decode_token(token)

        if expected_type and payload.type != expected_type:
            self.logger.warning(
                f"Token type mismatch. Expected {expected_type.value}, got {payload.type.value}"
            )
            raise InvalidTokenError(
                f"Invalid token type. Expected {expected_type.value}, but got {payload.type.value}"
            )

        if payload.is_expired():
            self.logger.warning(f"Token expired at {payload.exp_datetime}")
            raise TokenExpiredException("Token has expired")
        
        return payload

    async def get_current_user_from_token(
        self, token: str, request: Optional[Request] = None
    ) -> User | None:
        try:
            payload = self.decode_token(token)
            if payload.is_expired():
                raise TokenExpiredException("Token has expired")
            
            user_id = payload.sub
            user = User(id=str(user_id), roles=payload.roles or [], username=payload.username or "")
            self.logger.info(f"User {user.id[:10]}... authenticated via token.")
            return user
        except TokenExpiredException:
            self.logger.warning("Attempt to use expired token for current user.")
            raise
        except InvalidTokenError:
            self.logger.warning("Attempt to use invalid token for current user.")
            raise
        except TokenBlacklistedException:
            self.logger.warning("Attempt to use blacklisted token for current user.")
            raise
        except Exception as e:
            self.logger.error(f"Error retrieving user from token: {e}", exc_info=True)
            raise InvalidTokenError("Could not retrieve user from token.") from e
        return None


_jwt_service_instance: IJwtService | None = None

def get_jwt_service(
    token_blacklist_repo: ITokenBlacklistRepository | None = None
) -> IJwtService:
    global _jwt_service_instance
    if _jwt_service_instance is None:
        if not settings.JWT_SECRET_KEY:
            import secrets
            temp_key = secrets.token_hex(32)
            logging.warning(
                "JWT_SECRET_KEY not set. Using temporary, insecure key (NOT FOR PRODUCTION!)"
            )
            _jwt_service_instance = JWTService(
                secret_key=temp_key,
                algorithm=settings.JWT_ALGORITHM,
                token_blacklist_repository=token_blacklist_repo
            )
        else:
            _jwt_service_instance = JWTService(
                secret_key=settings.JWT_SECRET_KEY,
                algorithm=settings.JWT_ALGORITHM,
                token_blacklist_repository=token_blacklist_repo
            )
    elif token_blacklist_repo and _jwt_service_instance.token_blacklist_repository is not token_blacklist_repo:
        _jwt_service_instance = JWTService(
            secret_key=settings.JWT_SECRET_KEY if settings.JWT_SECRET_KEY else secrets.token_hex(32),
            algorithm=settings.JWT_ALGORITHM,
            token_blacklist_repository=token_blacklist_repo
        )
    return _jwt_service_instance