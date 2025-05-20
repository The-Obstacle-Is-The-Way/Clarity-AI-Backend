"""
User entity for the Clarity Digital Twin Backend.

COMPATIBILITY LAYER: This module re-exports the User entity from app.core.domain.entities.user
to maintain backward compatibility while ensuring type consistency across the codebase.

All new code should import User directly from app.core.domain.entities.user.
"""
# Python 3.9 compatibility layer
from __future__ import annotations

import warnings
from typing import Any

# Import the original User class and re-export related types
from app.core.domain.entities.user import User as CoreUser
from app.core.domain.entities.user import UserRole, UserStatus  # Re-exported for compatibility

# Explicitly define what symbols are exported from this module
__all__ = ['User', 'UserRole', 'UserStatus', 'set_test_mode']

# Define a test mode flag for backward compatibility
_IN_TEST_MODE = False

# Show a deprecation warning when this module is imported
warnings.warn(
    "Importing User from app.domain.entities.user is deprecated. "
    "Import from app.core.domain.entities.user instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Create a compatibility wrapper for the User class
class User(CoreUser):
    """Compatibility wrapper for the User entity.

    This class extends the core User entity to provide backward compatibility
    with existing code that expects different behavior.
    """

    def __init__(self, **data: Any):
        """Initialize a User entity with backward compatibility support.

        This constructor adds default values for required fields that might be
        missing in older code, particularly in tests.

        Args:
            **data: User data as keyword arguments
        """
        # Add default values for required fields if in test mode
        if _IN_TEST_MODE:
            if 'first_name' not in data:
                data['first_name'] = 'Test'
            if 'last_name' not in data:
                data['last_name'] = 'User'

        # Handle 'role' field for backward compatibility
        if 'role' in data and 'roles' not in data:
            role_value = data.pop('role')
            data['roles'] = [role_value]

        # Initialize the parent class
        super().__init__(**data)

def set_test_mode(enabled: bool = True) -> None:
    """Set the test mode flag for the User entity.

    This is used by tests to enable test-specific behavior.

    Args:
        enabled: Whether to enable test mode
    """
    global _IN_TEST_MODE
    _IN_TEST_MODE = enabled
