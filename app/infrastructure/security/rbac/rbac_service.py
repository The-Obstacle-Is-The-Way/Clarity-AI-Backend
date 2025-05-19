"""
Unified Role-Based Access Control (RBAC) Service.

This service provides a centralized way to manage and check roles and permissions,
drawing definitions from the `roles` module.
"""

import logging

# Use relative import within the same package
from .roles import ROLE_PERMISSIONS, Role

# Assuming User entity might be needed for context later
# from app.domain.entities.user import User

logger = logging.getLogger(__name__)

# Ensure the legacy *RoleBasedAccessControl* alias is always available as a side
# effect of importing this module (many historical tests rely on it without an
# explicit import).
from importlib import import_module

# Importing registers the symbol into ``builtins`` (see implementation for
# details).  A conditional reload guards against repeated side‑effects when the
# module gets re‑imported during the same interpreter session (e.g. via
# `pytest --reload` plug‑ins).

try:
    import_module("app.infrastructure.security.rbac.role_based_access_control")
except ModuleNotFoundError:  # pragma: no cover – should never happen
    pass


class RBACService:
    """
    Provides methods to check user permissions based on their roles.

    Uses the definitive roles and permissions defined in `roles.py`.
    """

    def __init__(self):
        """Initialize the RBAC service."""
        # Roles and permissions are loaded directly from the imported roles module
        pass

    def check_permission(
        self, user_roles: list[Role], required_permission: str
    ) -> bool:
        """
        Check if a user with the given roles has a specific permission.

        Args:
            user_roles: List of Role enums the user possesses.
            required_permission: The permission string to check for.

        Returns:
            True if any of the user's roles grant the permission, False otherwise.
        """
        if not user_roles:
            return False

        # Check against the ROLE_PERMISSIONS mapping, allowing dynamic overrides
        has_perm = any(
            required_permission in ROLE_PERMISSIONS.get(role, []) for role in user_roles
        )

        # Future: Implement context-aware checks here if needed
        # (e.g., checking resource ownership for 'own_' permissions)
        # Example:
        # if not has_perm and required_permission.startswith("read:"):
        #     own_perm = f"read:own_{required_permission.split(':', 1)[1]}"
        #     if check_role_has_permission(user_roles, own_perm):
        #          # Need resource_owner_id and user_id context here
        #          pass # Logic to compare owner_id and user_id

        logger.debug(
            f"Permission check: Roles={user_roles}, Required='{required_permission}', Result={has_perm}"
        )
        return has_perm

    def get_permissions_for_roles(self, roles: list[Role]) -> list[str]:
        """
        Get the combined set of unique permissions for the given roles.

        Args:
            roles: List of Role enums.

        Returns:
            A list of unique permission strings.
        """
        all_permissions: set[str] = set()
        for role in roles:
            # Use the imported dictionary directly
            all_permissions.update(ROLE_PERMISSIONS.get(role, []))
        return list(all_permissions)


# Optional: Singleton pattern if desired, similar to role_manager.py
# from functools import lru_cache
# @lru_cache(maxsize=1)
# def get_rbac_service() -> RBACService:
#     return RBACService()
