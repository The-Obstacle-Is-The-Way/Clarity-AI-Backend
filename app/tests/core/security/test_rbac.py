"""
Role-Based Access Control Tests

This module contains tests for the RBAC component, ensuring
proper role and permission management for security.
"""


import pytest

# Keep User import if needed for setup, but roles list is passed to check_permission
from app.core.domain.entities.user import User, UserRole

# Corrected import for RBACService
from app.infrastructure.security.rbac.rbac_service import RBACService


@pytest.mark.venv_only()
class TestRoleBasedAccessControl:
    """Test suite for Role-Based Access Control functionality."""

    def setup_method(self) -> None:
        """Set up test environment."""
        # Instantiate the service (assuming direct instantiation is possible)
        # If RBACService requires dependencies (e.g., RoleManager), mock them:
        # mock_role_manager = MagicMock()
        # self.rbac_service = RBACService(role_manager=mock_role_manager)
        self.rbac_service = RBACService()

        # Create mock users with different roles
        self.admin_user = User(
            id="admin-id",
            email="admin@example.com",
            full_name="Admin User",
            roles=[Role.ADMIN],  # Ensure roles is a list
            hashed_password="hashed_password",
            is_active=True,
        )

        self.clinician_user = User(
            id="clinician-id",
            email="clinician@example.com",
            full_name="Clinician User",
            roles=[Role.CLINICIAN],
            hashed_password="hashed_password",
            is_active=True,
        )

        self.patient_user = User(
            id="patient-id",
            email="patient@example.com",
            full_name="Patient User",
            roles=[Role.USER],
            hashed_password="hashed_password",
            is_active=True,
        )

        self.researcher_user = User(
            id="researcher-id",
            email="researcher@example.com",
            full_name="Researcher User",
            roles=[Role.RESEARCHER],
            hashed_password="hashed_password",
            is_active=True,
        )

    def test_check_permission_admin(self) -> None:
        """Test permission check for admin role."""
        # Admin should have all permissions
        assert self.rbac_service.check_permission(self.admin_user.roles, "read:all_data") is True
        assert self.rbac_service.check_permission(self.admin_user.roles, "update:all_data") is True
        assert self.rbac_service.check_permission(self.admin_user.roles, "delete:all_data") is True
        assert (
            self.rbac_service.check_permission(self.admin_user.roles, "read:patient_data") is True
        )
        assert self.rbac_service.check_permission(self.admin_user.roles, "manage:users") is True

    def test_check_permission_clinician(self) -> None:
        """Test permission check for clinician role."""
        # Clinician should have patient data access but not all admin permissions
        assert (
            self.rbac_service.check_permission(self.clinician_user.roles, "read:patient_data")
            is True
        )
        assert (
            self.rbac_service.check_permission(self.clinician_user.roles, "update:patient_data")
            is True
        )
        # Assuming clinicians can also read their own data if applicable permission exists
        # assert self.rbac_service.check_permission(self.clinician_user.roles, "read:own_data") is True

        # Clinician should not have admin-level permissions
        assert (
            self.rbac_service.check_permission(self.clinician_user.roles, "delete:all_data")
            is False
        )
        assert (
            self.rbac_service.check_permission(self.clinician_user.roles, "manage:users") is False
        )

    def test_check_permission_patient(self) -> None:
        """Test permission check for patient role (using Role.USER)."""
        # User (patient) should only have access to own data
        assert self.rbac_service.check_permission(self.patient_user.roles, "read:own_data") is True
        assert (
            self.rbac_service.check_permission(self.patient_user.roles, "update:own_data") is True
        )  # Assuming update:own_data exists
        assert (
            self.rbac_service.check_permission(self.patient_user.roles, "access_own_reports")
            is True
        )  # Check defined USER permissions

        # User (patient) should not have access to other data/roles
        assert self.rbac_service.check_permission(self.patient_user.roles, "read:all_data") is False
        assert (
            self.rbac_service.check_permission(self.patient_user.roles, "read:patient_data")
            is False
        )
        assert self.rbac_service.check_permission(self.patient_user.roles, "manage:users") is False
        assert (
            self.rbac_service.check_permission(self.patient_user.roles, "access_anonymized_data")
            is False
        )

    def test_check_permission_researcher(self) -> None:
        """Test permission check for researcher role."""
        # Researcher should have read access to anonymized data
        assert (
            self.rbac_service.check_permission(self.researcher_user.roles, "read:anonymized_data")
            is True
        )
        # Assuming researchers can also read their own data if applicable permission exists
        # assert self.rbac_service.check_permission(self.researcher_user.roles, "read:own_data") is True

        # Researcher should not have access to identifiable patient data or admin functions
        assert (
            self.rbac_service.check_permission(self.researcher_user.roles, "read:patient_data")
            is False
        )
        assert (
            self.rbac_service.check_permission(self.researcher_user.roles, "update:patient_data")
            is False
        )
        assert (
            self.rbac_service.check_permission(self.researcher_user.roles, "manage:users") is False
        )

    def test_check_permission_nonexistent_permission(self) -> None:
        """Test checking for a non-existent permission."""
        # No role should have a non-existent permission
        assert (
            self.rbac_service.check_permission(self.admin_user.roles, "nonexistent:permission")
            is False
        )
        assert (
            self.rbac_service.check_permission(self.clinician_user.roles, "nonexistent:permission")
            is False
        )
        assert (
            self.rbac_service.check_permission(self.patient_user.roles, "nonexistent:permission")
            is False
        )
        assert (
            self.rbac_service.check_permission(self.researcher_user.roles, "nonexistent:permission")
            is False
        )

    def test_check_permission_with_empty_roles(self) -> None:
        """Test permission check with an empty roles list."""
        assert self.rbac_service.check_permission([], "read:own_data") is False
        assert self.rbac_service.check_permission([], "read:all_data") is False

    def test_check_permission_with_none_permission(self) -> None:
        """Test permission check with None permission."""
        # Should handle None permission gracefully
        assert self.rbac_service.check_permission(self.admin_user.roles, None) is False

    # The patch target needs to be updated to the actual location of ROLE_PERMISSIONS
    # Assuming it's within the RBACService module or RoleManager
    def test_check_permission_with_custom_permissions(self) -> None:
        """Test permission check with custom permissions configuration."""
        # Temporarily override ROLE_PERMISSIONS for this test
        import app.infrastructure.security.rbac.rbac_service as rbac_mod

        original = rbac_mod.ROLE_PERMISSIONS
        try:
            rbac_mod.ROLE_PERMISSIONS = {
                Role.ADMIN: {"custom:permission"},
                Role.CLINICIAN: set(),
                Role.USER: set(),
                Role.RESEARCHER: set(),
                Role.SUPERVISOR: set(),
                Role.SYSTEM: set(),
            }
            # Admin should have the custom permission
            assert (
                self.rbac_service.check_permission(self.admin_user.roles, "custom:permission")
                is True
            )
            # Other roles should not have the custom permission
            assert (
                self.rbac_service.check_permission(self.clinician_user.roles, "custom:permission")
                is False
            )
            assert (
                self.rbac_service.check_permission(self.patient_user.roles, "custom:permission")
                is False
            )
            assert (
                self.rbac_service.check_permission(self.researcher_user.roles, "custom:permission")
                is False
            )
        finally:
            rbac_mod.ROLE_PERMISSIONS = original
