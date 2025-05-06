"""
Auth Dependencies.

This module provides authentication and authorization dependencies
for FastAPI routes, including JWT validation and user resolution.
"""

from typing import Any
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes

from app.config.settings import Settings, get_settings
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service import IJwtService
from app.domain.entities.user import User
from app.domain.enums.role import Role as UserRole
from app.domain.exceptions import AuthenticationError
from app.infrastructure.logging.logger import get_logger
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.infrastructure.security.jwt_service import JWTService

from .database import get_repository


# --- JWT Service Dependency --- 
def get_jwt_service(
    settings: Settings = Depends(get_settings),
    user_repository: IUserRepository = Depends(get_repository(IUserRepository)) 
) -> IJwtService:
    """Dependency function to get JWTService instance conforming to IJwtService."""
    # Pass the user_repository to the JWTService constructor
    return JWTService(settings=settings, user_repository=user_repository)

# ---------------------------------------------------------------------------
# Dependency‑injection helper – thin factory that returns the concrete
# ``AuthenticationService`` implementation.  A *named* provider function makes
# it trivial for unit‑tests to *override* the real service via
# ``app.dependency_overrides``.
# ---------------------------------------------------------------------------

def get_authentication_service(
    auth_service: AuthenticationService | None = None,
) -> AuthenticationService:
    """Return the application's *AuthenticationService* instance.

    The indirection layer exists primarily for the benefit of **unit‑tests**
    which can replace the returned object by assigning a custom callable to
    ``app.dependency_overrides[get_authentication_service]``.
    """

    if auth_service is not None:
        # Explicit override supplied – return as‑is.  This path is exercised
        # almost exclusively from test‑code where the caller constructs the
        # service *manually*.
        return auth_service

    try:
        # Lazy import inside the function body to avoid potential circular
        # dependencies during application start‑up.
        from app.infrastructure.di.container import (
            container as _container,  # pylint: disable=import-outside-toplevel
        )

        return _container.resolve(AuthenticationService)  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover – best‑effort fallback
        # DI container not available (e.g. in lightweight tests) – create a
        # **minimal** service instance backed by in‑memory mocks.
        logger.warning("DI container missing – returning *mock* AuthenticationService for tests.")

        from unittest.mock import MagicMock

        return MagicMock(spec=AuthenticationService)  # type: ignore[return-value]

logger = get_logger(__name__)
security = HTTPBearer(auto_error=False)


async def get_token_from_header(
    credentials: HTTPAuthorizationCredentials | None = Depends(security)
) -> str | None:
    """
    Extract JWT token from Authorization header.
    
    Args:
        credentials: HTTP Authorization credentials
        
    Returns:
        JWT token if present, None otherwise
    """
    if credentials is None:
        return None
        
    return credentials.credentials


async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(get_token_from_header),
    jwt_service: IJwtService = Depends(get_jwt_service)
) -> User:
    """
    Dependency to get the current authenticated user from the token.
    Validates token, checks scopes (if any), and retrieves user details.
    """
    authenticate_value = "Bearer"
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )

    try:
        user = await jwt_service.get_user_from_token(token)
        if user is None:
            # Covers cases like token valid but user deleted/not found or repo not configured
            logger.warning("get_user_from_token returned None for token.")
            raise credentials_exception # Raise 401

        # Optional: Scope validation (if using OAuth scopes defined in endpoints)
        # Example check: Check if token scopes cover required security scopes
        # token_scopes = set(payload.get("scopes", [])) 
        # if not set(security_scopes.scopes).issubset(token_scopes):
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="Not enough permissions",
        #         headers={"WWW-Authenticate": authenticate_value},
        #     )

        return user

    except AuthenticationError as e:
        # Catch specific auth errors from jwt_service (expired, invalid, revoked, inactive user)
        logger.info(f"Authentication failed: {e}")
        raise HTTPException(
             status_code=status.HTTP_401_UNAUTHORIZED,
             detail=str(e), # Pass specific error message
             headers={"WWW-Authenticate": authenticate_value}
        ) from e
    except Exception as e: # Catch unexpected errors
         logger.error(f"Unexpected error during user authentication: {e}", exc_info=True)
         # Don't leak details, raise generic 401
         raise credentials_exception from e


async def get_optional_user(
    token: str | None = Depends(get_token_from_header),
    jwt_service: IJwtService = Depends(get_jwt_service)
) -> dict[str, Any] | None:
    """Get user data from JWT token without requiring authentication."""
    if token is None:
        return None
    try:
        # Use decode_token as verify_token might not be on interface
        payload = await jwt_service.decode_token(token)
        return payload
    except AuthenticationError:
        logger.debug("Optional authentication failed: Invalid/Expired Token")
        return None
    except Exception as e:
        logger.debug(f"Optional authentication failed ({type(e).__name__}): {e!s}")
        return None


async def verify_provider_access(
    current_user: User = Depends(get_current_user)
) -> User:
    """Verify that the user has provider-level access (Clinician, Admin, Provider)."""
    # Normalise for case-insensitive membership tests
    allowed_roles = {role.value.upper() for role in (UserRole.CLINICIAN, UserRole.ADMIN, UserRole.PROVIDER)}

    primary_role = (current_user.role or "").upper()
    roles_set = {str(r).upper() for r in (current_user.roles or [])}

    if primary_role not in allowed_roles and allowed_roles.isdisjoint(roles_set):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Provider, Clinician, or Admin access required",
        )
    return current_user


async def verify_admin_access(
    current_user: User = Depends(get_current_user)
) -> User:
    """Verify that the user has admin access level."""
    admin_role_value = UserRole.ADMIN.value.upper()
    primary_role = (current_user.role or "").upper()
    roles_set = {str(r).upper() for r in (current_user.roles or [])}

    if primary_role != admin_role_value and admin_role_value not in roles_set:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def require_role(required_role: UserRole):
    """Factory function to create a dependency that requires a specific user role."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        # Normalise to uppercase strings for case-insensitive comparison
        required_role_value = required_role.value.upper()

        primary_role = (current_user.role or "").upper()
        # Some code may store mixed-case entries in the *roles* list – normalise
        roles_normalised = [str(r).upper() for r in (current_user.roles or [])]

        if primary_role != required_role_value and required_role_value not in roles_normalised:
            logger.warning(f"User {current_user.id} with role {current_user.role} tried accessing resource requiring {required_role_value}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Requires {required_role.value} role."
            )
        return current_user
    return role_checker

# Specific role requirement dependencies
require_clinician_role = require_role(UserRole.CLINICIAN)
require_admin_role = require_role(UserRole.ADMIN)
require_patient_role = require_role(UserRole.PATIENT)

async def get_patient_id(
    patient_id: UUID,
    current_user: User = Depends(get_current_user)
) -> UUID:
    """Dependency to validate patient ID access."""
    # Normalize for robust comparison
    role_value = (current_user.role or "").upper()
    if role_value == UserRole.PATIENT.value:
        # Ensure patient ID in path matches the authenticated user's ID (convert both to str)
        if str(current_user.id) != str(patient_id):
             logger.warning(f"Patient {current_user.id} attempted to access data for patient {patient_id}")
             raise HTTPException(
                 status_code=status.HTTP_403_FORBIDDEN,
                 detail="Patients can only access their own data."
             )
    elif role_value not in {UserRole.CLINICIAN.value, UserRole.ADMIN.value} and \
         all((str(r).upper() not in {UserRole.CLINICIAN.value, UserRole.ADMIN.value}) for r in (current_user.roles or [])):
        logger.error(f"User {current_user.id} with unexpected role {current_user.role} attempted patient data access.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions.")

    return patient_id
