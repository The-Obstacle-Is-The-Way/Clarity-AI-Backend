"""
Role-Based Access Control (RBAC) module for the Novamind Digital Twin Backend.

This module provides role and permission management for restricting
access to resources based on user roles.
"""

# Import from correct file name using the correct class name
# from app.infrastructure.security.rbac.rbac import RoleBasedAccessControl
# from app.infrastructure.security.rbac.rbac_service import RoleBasedAccessControl
from app.infrastructure.security.rbac.rbac_service import (
    RBACService,  # Import the actual service class
)

# Imports seem potentially incorrect - RoleAccessManager might be in rbac_service? RoleManager in roles.py?
# from app.infrastructure.security.rbac.role_access import RoleAccessManager
# from app.infrastructure.security.rbac.role_manager import RoleManager

# Assuming only RoleBasedAccessControl is needed for export based on __all__
# __all__ = ['RoleBasedAccessControl'] # Keep __all__ as is for now
# Update __all__ to export the correct service class
__all__ = ["RBACService"]
