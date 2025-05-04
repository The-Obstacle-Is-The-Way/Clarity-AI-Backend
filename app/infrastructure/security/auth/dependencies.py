"""
FastAPI Dependencies for Authorization Checks.

These dependencies use the RBACService to verify user roles and permissions
based on the authenticated user attached to `request.state.user`.
"""

import logging
from collections.abc import Sequence

from fastapi import Depends, HTTPException, Request, status

from app.domain.entities.user import User  # Import User entity

# Use absolute paths for services and domain types
from app.infrastructure.security.rbac.rbac_service import RBACService
from app.infrastructure.security.rbac.roles import Role  # Import Role enum

# This assumes RBACService is provided via FastAPI's dependency injection system.
# You would need to setup a provider for RBACService in your main application.
# Example (conceptual - needs actual DI setup):
# def get_rbac_service() -> RBACService:
#     return RBACService() # Or get singleton instance

logger = logging.getLogger(__name__)


def get_current_active_user(request: Request) -> User:
    """
    Dependency to get the currently authenticated and active user from request state.
    
    Raises HTTPException 401 if no authenticated user is found on the request state.
    Raises HTTPException 403 if the user is inactive.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        logger.warning("Dependency error: No authenticated user found in request.state.")
        # This indicates AuthenticationMiddleware might not have run or failed silently
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not isinstance(user, User):
         logger.error(f"Dependency error: request.state.user is not a User object (type: {type(user)}). Check AuthenticationMiddleware.")
         raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Internal server error: Invalid user state.",
        )
        
    if not user.is_active:
        logger.warning(f"Authorization denied: User {user.id} is inactive.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="User is inactive",
        )
        
    return user

# Dependency injector for RBACService (replace with your actual DI mechanism)
# For now, we instantiate it directly, but this is NOT ideal for production.
# Proper DI setup is required in main.py or equivalent.
def get_rbac_service_dependency() -> RBACService:
    logger.warning("RBACService is being instantiated directly in dependency. Setup proper DI provider.")
    return RBACService()

# --- Permission Checking Dependencies --- 

class PermissionsChecker:
    """
    Provides dependency methods for checking permissions.
    Inject RBACService dependency.
    """
    def __init__(self, required_permissions: Sequence[str]):
        self.required_permissions = set(required_permissions)

    async def __call__(self, 
        user: User = Depends(get_current_active_user),
        rbac_service: RBACService = Depends(get_rbac_service_dependency)
    ):
        """
        Check if the user has ALL required permissions.
        """
        user_roles = getattr(user, 'roles', [])
        if not user_roles:
             logger.warning(f"User {user.id} has no roles, denying permission check for: {self.required_permissions}")
             raise HTTPException(
                 status_code=status.HTTP_403_FORBIDDEN,
                 detail="User has no assigned roles.",
             )
             
        logger.debug(f"Checking permissions {self.required_permissions} for user {user.id} with roles {user_roles}")
        
        allowed_permissions = set(rbac_service.get_permissions_for_roles(user_roles))
        
        missing_permissions = self.required_permissions - allowed_permissions

        if missing_permissions:
            logger.warning(f"Authorization Denied for User {user.id}: Missing permissions: {missing_permissions}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not enough permissions. Missing: {', '.join(missing_permissions)}",
            )
        
        logger.debug(f"Authorization Granted for User {user.id} for permissions: {self.required_permissions}")

# --- Role Checking Dependencies --- 

class RoleChecker:
    """
    Provides dependency methods for checking roles.
    """
    def __init__(self, required_roles: Sequence[Role]):
        # Ensure roles are Role enum members
        if not all(isinstance(r, Role) for r in required_roles):
            raise TypeError("required_roles must be a sequence of Role enums")
        self.required_roles = set(required_roles)

    async def __call__(self, user: User = Depends(get_current_active_user)):
        """
        Check if the user has AT LEAST ONE of the required roles.
        """
        user_roles = set(getattr(user, 'roles', []))
        if not user_roles:
             logger.warning(f"User {user.id} has no roles, denying role check for: {self.required_roles}")
             raise HTTPException(
                 status_code=status.HTTP_403_FORBIDDEN,
                 detail="User has no assigned roles.",
             )
             
        logger.debug(f"Checking roles {self.required_roles} for user {user.id} with roles {user_roles}")

        if not self.required_roles.intersection(user_roles):
            logger.warning(f"Authorization Denied for User {user.id}: Missing required roles. Needs one of: {self.required_roles}, Has: {user_roles}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of the following roles: {', '.join(r.value for r in self.required_roles)}",
            )
            
        logger.debug(f"Authorization Granted for User {user.id} for roles: {self.required_roles}")

# --- Convenience Dependency Functions --- 

def require_permissions(*permissions: str) -> PermissionsChecker:
    """FastAPI Dependency: Checks if the user has ALL specified permissions."""
    return PermissionsChecker(required_permissions=permissions)

def require_roles(*roles: Role) -> RoleChecker:
    """FastAPI Dependency: Checks if the user has AT LEAST ONE of the specified roles."""
    return RoleChecker(required_roles=roles)

# Example specific role checks (can be created using require_roles)
def require_admin_role() -> RoleChecker:
    """Dependency requiring the ADMIN role."""
    return require_roles(Role.ADMIN)

def require_clinician_role() -> RoleChecker:
    """Dependency requiring the CLINICIAN role."""
    return require_roles(Role.CLINICIAN)

# Add other specific role/permission checks as needed...
