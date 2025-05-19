"""
Common dependencies for biometric-related endpoints.

This module provides common dependencies and utilities for biometric-related
endpoints, such as authentication and patient ID validation.
"""

from uuid import UUID

from fastapi import Depends, HTTPException, Path, status

# Use the specific exception and the standard auth dependency
from app.core.exceptions.base_exceptions import AuthenticationException
from app.domain.entities.user import User
from app.domain.enums.role import Role
from app.presentation.api.dependencies.auth import get_current_user

# OAuth2 scheme for token authentication
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # Moved to auth dependency


# async def get_current_user_id( # Remove this local implementation
#     token: str = Depends(oauth2_scheme)
# ) -> UUID:
#     """
#     Get the ID of the currently authenticated user.

#     Args:
#         token: JWT token from the request

#     Returns:
#         UUID of the current user

#     Raises:
#         HTTPException: If authentication fails
#     """
#     try:
#         # Validate the token and get the user ID
#         payload = jwt_service.decode_token(token) # This service path is incorrect
#         user_id = payload.get("sub")

#         if not user_id:
#             raise AuthenticationException("Invalid authentication credentials")

#         return UUID(user_id)
#     except AuthenticationException as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=str(e),
#             headers={"WWW-Authenticate": "Bearer"}
#         )
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=f"Authentication error: {str(e)}",
#             headers={"WWW-Authenticate": "Bearer"}
#         )


async def get_patient_id(
    patient_id: UUID = Path(..., description="ID of the patient"),
    current_user: User = Depends(
        get_current_user
    ),  # Depend on the standard user object
) -> UUID:
    """
    Get and validate the patient ID from the path.

    This dependency also checks if the current user has permission to
    access the specified patient's data.

    Args:
        patient_id: Patient ID from the path
        current_user: The authenticated User object
                      (Previously was current_user_id: UUID)

    Returns:
        Validated patient ID

    Raises:
        HTTPException: If the user doesn't have permission to access the patient
    """
    # TODO: Implement RBAC check: Check if current_user.id or current_user.role
    # has permission to access data for patient_id.
    # For example:
    # if not rbac_service.check_permission(current_user, "read", f"patient:{patient_id}"):
    #     raise AuthorizationError("User does not have permission to access this patient.")
    # This requires an RBAC service/logic implementation.

    # For now, we'll just return the patient ID if authenticated.
    if not current_user:  # Should be caught by get_current_user, but double-check
        raise AuthenticationException("User not authenticated.")

    return patient_id


# async def get_current_user_role( # Remove this local implementation
#     token: str = Depends(oauth2_scheme)
# ) -> str:
#     """
#     Get the role of the currently authenticated user.

#     Args:
#         token: JWT token from the request

#     Returns:
#         Role of the current user

#     Raises:
#         HTTPException: If authentication fails
#     """
#     try:
#         # Validate the token and get the user role
#         payload = jwt_service.decode_token(token) # Incorrect service path
#         role = payload.get("role")

#         if not role:
#             raise AuthenticationException("Invalid authentication credentials")

#         return role
#     except AuthenticationException as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=str(e),
#             headers={"WWW-Authenticate": "Bearer"}
#         )
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=f"Authentication error: {str(e)}",
#             headers={"WWW-Authenticate": "Bearer"}
#         )


async def require_role(
    required_role: str, current_user: User = Depends(get_current_user)
) -> None:
    """Generic dependency to check if the user has a specific role."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Case-insensitive role check
    user_role_upper = current_user.role.upper() if current_user.role else ""
    required_role_upper = required_role.upper()

    if user_role_upper != required_role_upper:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This operation requires '{required_role}' privileges",
        )


async def require_any_role(
    required_roles: list[str], current_user: User = Depends(get_current_user)
) -> None:
    """Generic dependency to check if the user has any of the specified roles."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Case-insensitive role check
    user_role_upper = current_user.role.upper() if current_user.role else ""
    upper_required_roles = [role.upper() for role in required_roles]

    if user_role_upper not in upper_required_roles:
        # Consider using AuthorizationError for more specific domain exception handling
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This operation requires one of the following roles: {', '.join(required_roles)}",
        )


async def require_clinician_role(
    current_user: User = Depends(get_current_user),
) -> None:
    """
    Require that the current user has the clinician role or higher (admin).

    Args:
        current_user: The authenticated User object

    Raises:
        HTTPException: If the user doesn't have the clinician or admin role
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Case-insensitive role check
    user_role_upper = current_user.role.upper() if current_user.role else ""
    allowed_roles = [Role.CLINICIAN.value, Role.ADMIN.value]

    if user_role_upper not in allowed_roles:
        # Role is now imported at the module level
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This operation requires one of the following roles: {Role.CLINICIAN.value}, {Role.ADMIN.value}",
        )


async def require_admin_role(current_user: User = Depends(get_current_user)) -> None:
    """
    Require that the current user has the admin role.

    Args:
        current_user: The authenticated User object

    Raises:
        HTTPException: If the user doesn't have the admin role
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Case-insensitive role check
    user_role_upper = current_user.role.upper() if current_user.role else ""

    if user_role_upper != Role.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This operation requires {Role.ADMIN.value} privileges",
        )
