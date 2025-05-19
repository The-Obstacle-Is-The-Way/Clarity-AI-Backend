"""
Role validation service for checking user permissions and access control.
"""


from app.domain.entities.user import User
from app.domain.enums.role import Role as UserRole


class RoleValidator:
    """
    Service for validating user roles and permissions.

    Handles both production role validation using UserRole enums and
    test scenarios using string-based roles.
    """

    def __init__(self):
        """Initialize the RoleValidator."""
        pass

    def has_required_roles(self, user: User, required_roles: list[UserRole | str]) -> bool:
        """
        Check if a user has any of the required roles.

        Args:
            user: The user to check roles for
            required_roles: List of roles that are allowed access

        Returns:
            bool: True if user has at least one required role
        """
        # Handle test tokens with string roles
        if isinstance(user.roles, list) and all(isinstance(r, str) for r in user.roles):
            # Test user with string roles
            return any(role.lower() in [r.lower() for r in user.roles] for role in required_roles)

        # Handle production users with UserRole enums
        try:
            # Convert required_roles to UserRole if they're strings
            normalized_required = [
                role if isinstance(role, UserRole) else UserRole[role.upper()]
                for role in required_roles
            ]

            # Check if user has any of the required roles
            return any(role in user.roles for role in normalized_required)
        except (KeyError, AttributeError):
            # If there's an error converting roles, deny access
            return False
