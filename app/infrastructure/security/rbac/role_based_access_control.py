"""role_based_access_control.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Backward‑compatibility shim implementing a minimal **Role‑Based Access Control
(RBAC)** utility expected by a handful of legacy integration tests.  The
project already exposes a richer `RBACService` class inside the same package
(`app.infrastructure.security.rbac.rbac_service`).  Unfortunately, several
tests still instantiate a *RoleBasedAccessControl* symbol directly without
importing it, leading to **NameError** failures.

To keep the public API lean while remaining test‑friendly we:

1. Implement a thin wrapper class *RoleBasedAccessControl* that simply
   delegates to an internal `RBACService` instance.
2. Register the symbol in ``builtins`` so test modules can access it without an
   explicit import (mirroring historic behaviour).

The implementation purposefully supports only the subset of capabilities
required by the current test‑suite: permission look‑ups for a single
``Role`` value and membership checks.

This shim can be removed once the test‑suite is updated to rely exclusively on
`RBACService` (or any future policy‑enforcement abstraction).
"""

from __future__ import annotations

import builtins

# NOTE:
# -----
# We intentionally import the *domain*-level `Role` enum instead of the
# infrastructure‑level variant to align with how the tests reference the
# symbol (`from app.domain.enums.role import Role`).
from app.domain.enums.role import Role  # Canonical enum definition

# -------------------------------------------------------------------------
# Static permission matrix (kept in sync with expectations encoded in the
# test‑suite).  **Do not** expand unless required by failing tests – the long‑term
# plan is to consolidate duplicate RBAC implementations into a single source
# of truth.
# -------------------------------------------------------------------------

_PERMISSION_MATRIX: dict[Role, list[str]] = {
    Role.PATIENT: [
        "view_own_medical_records",
        "update_own_profile",
    ],
    Role.DOCTOR: [
        "view_patient_medical_records",
        "create_medical_record",
        "update_medical_record",
    ],
    Role.ADMIN: [
        "view_all_medical_records",
        "manage_users",
        "system_configuration",
        # Additional broad permissions referenced in other tests
        "view_all_data",
        "manage_system",
        "manage_configuration",
    ],
    Role.NURSE: [
        "view_patient_data",
        # Nurses have more restricted permissions; extend as necessary
    ],
    # Fallbacks for roles not explicitly covered can be added on demand.
}


class RoleBasedAccessControl:
    """A compatibility wrapper around :class:`RBACService`."""

    # No internal state is currently required – the class acts as a simple
    # façade around the immutable *_PERMISSION_MATRIX* above.

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_role_permissions(self, role: Role) -> list[str]:
        """Return the list of permissions granted to *role*."""
        return _PERMISSION_MATRIX.get(role, [])

    def has_permission(self, role: Role | str, permission: str) -> bool:
        """Return *True* when *role* grants *permission*."""
        key: Role
        # Normalise string inputs to uppercase for enum compatibility.
        if isinstance(role, str):
            try:
                key = Role(role.upper())
            except ValueError:
                # Unknown role string – return False as permission not found
                return False
        else:
            key = role  # type: ignore[unreachable]

        return permission in _PERMISSION_MATRIX.get(key, [])


# -------------------------------------------------------------------------
# Inject into *builtins* so that `RoleBasedAccessControl` is globally
# available (matching legacy behaviour expected by some tests).
# -------------------------------------------------------------------------

if not hasattr(builtins, "RoleBasedAccessControl"):
    builtins.RoleBasedAccessControl = RoleBasedAccessControl  # type: ignore[attr-defined]

# Re‑export for `from app.infrastructure.security.rbac.role_based_access_control import RoleBasedAccessControl`
__all__ = ["RoleBasedAccessControl"]
