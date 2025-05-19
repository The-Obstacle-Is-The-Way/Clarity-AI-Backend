"""
FastAPI Middleware for Role-Based Access Control (RBAC).

This middleware integrates with the RBACService to enforce permissions based
on user roles attached to the request state.
"""

import logging
from typing import Any

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# Use absolute path for domain enums/entities if needed, adjust if moved
# Use absolute path for infrastructure service
from app.infrastructure.security.rbac.rbac_service import RBACService

# from app.domain.entities.user import User # Import User if type hint is needed

logger = logging.getLogger(__name__)


class RBACMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce role-based access control using RBACService.

    Checks for user roles in `request.state.user.roles` and verifies against
    endpoint-specific permissions or general rules.
    """

    def __init__(self, app, rbac_service: RBACService):
        """Initialize middleware with the RBAC service instance."""
        super().__init__(app)
        self.rbac_service = rbac_service

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process the request, perform RBAC checks, and call the next middleware/endpoint.
        """
        # --- Authentication Check ---
        # Ensure authentication middleware has run first and attached user state
        # This middleware ASSUMES request.state.user exists and has roles.
        # If user is not attached, authentication failed earlier.
        user = getattr(request.state, "user", None)
        if user is None:
            # This case should ideally be handled by Auth middleware returning 401.
            # If RBAC runs and finds no user, it implies an issue upstream.
            # However, for robustness, we can deny access here too.
            logger.warning(
                "RBACMiddleware executed but no user found in request.state. Denying access."
            )
            # Using 403 Forbidden as the lack of user implies they shouldn't get past auth
            return Response(
                status_code=status.HTTP_403_FORBIDDEN,
                content="Access Denied: User context missing.",
            )

        user_roles = getattr(
            user, "roles", []
        )  # Expecting user object with roles attribute
        if not user_roles:
            logger.warning(
                f"User {getattr(user, 'id', 'Unknown')} has no roles assigned. Denying access potentially."
            )
            # Depending on policy, no roles might mean deny all or allow basic access.
            # For strict RBAC, no roles usually means no access beyond public endpoints.
            # We proceed, specific checks later will fail if roles are needed.

        # --- Endpoint-Specific RBAC Rules (Example) ---
        # In a real app, these rules might come from endpoint decorators or a config map.
        required_permission: str | None = None
        path = request.url.path
        method = request.method

        # Example: Protecting an admin section
        if path.startswith("/api/v1/admin"):
            # Check if user has *any* role that grants the specific admin permission
            if not self.rbac_service.check_permission(
                user_roles, "manage:system"
            ):  # Example permission
                logger.warning(
                    f"RBAC Denied: User {getattr(user, 'id', 'Unknown')} roles {user_roles} lack 'manage:system' for {path}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Administrator access required for this section.",
                )

        # Example: Protecting patient data write access
        if path.startswith("/api/v1/patients/") and method in [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]:
            if not self.rbac_service.check_permission(
                user_roles, "write:patients"
            ):  # Example permission
                logger.warning(
                    f"RBAC Denied: User {getattr(user, 'id', 'Unknown')} roles {user_roles} lack 'write:patients' for {method} {path}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Permission denied to modify patient data.",
                )

        # --- PHI Access Auditing Placeholder ---
        # Check if endpoint is considered PHI-sensitive
        if self._endpoint_contains_phi(path, method):
            # Pass user context for detailed auditing
            self._audit_phi_access(request, user)

        # If all checks pass, proceed to the next middleware or endpoint
        response = await call_next(request)
        return response

    # --- Helper methods (from old RBACMiddleware) ---

    def _endpoint_contains_phi(self, path: str, method: str) -> bool:
        """Determine if an endpoint involves PHI access (Example implementation)."""
        # Define endpoints that contain PHI - adjust based on actual API structure
        phi_read_patterns = [
            "/api/v1/patients",
            "/api/v1/clinical-notes",
            "/api/v1/assessments",
            "/api/v1/medical-records",
            "/api/v1/diagnoses",
        ]
        phi_write_patterns = [
            "/api/v1/patients",
            "/api/v1/clinical-notes",
            "/api/v1/assessments",
        ]

        # Allow reads more broadly for certain roles if needed, writes are stricter
        if method in ["GET", "OPTIONS", "HEAD"]:
            return any(path.startswith(pattern) for pattern in phi_read_patterns)
        elif method in ["POST", "PUT", "PATCH", "DELETE"]:
            return any(path.startswith(pattern) for pattern in phi_write_patterns)

        return False  # Default to false for unknown methods

    def _audit_phi_access(self, request: Request, user: Any) -> None:
        """Record PHI access for auditing purposes (Placeholder)."""
        user_id = getattr(user, "id", "Unknown")
        user_roles_str = ",".join(map(str, getattr(user, "roles", [])))

        # In a real implementation, log to a secure, immutable audit trail:
        # - Timestamp
        # - User ID, User Roles
        # - Source IP
        # - Request Method & Path
        # - Action performed (e.g., READ_PHI, WRITE_PHI)
        # - Resource ID accessed (if applicable, might need parsing from path)
        # - Success/Failure (though middleware usually runs before failure is known)
        logger.info(
            f"AUDIT: PHI Access by User ID: {user_id} (Roles: {user_roles_str}) - {request.method} {request.url.path}"
        )
        # Example: AuditLogService.log_phi_access(user_id=user_id, roles=user_roles, ...)
        pass  # Placeholder


# Note: How this middleware is registered in main.py determines if it runs
# for all routes. Specific endpoint permissions are often handled via
# FastAPI Dependencies using the RBACService directly.
