"""
Test module for Role enumeration.

This module tests the functionality of the Role enum used for
authentication and authorization in the application.
"""

from app.domain.enums.role import Role


class TestRole:
    """Test suite for the Role enumeration."""

    def test_role_values(self) -> None:
        """Test that all expected roles exist with correct values."""
        assert Role.ADMIN.value == "ADMIN"
        assert Role.CLINICIAN.value == "CLINICIAN"
        assert Role.DOCTOR.value == "DOCTOR"
        assert Role.NURSE.value == "NURSE"
        assert Role.RESEARCHER.value == "RESEARCHER"
        assert Role.PATIENT.value == "PATIENT"
        assert Role.USER.value == "USER"
        assert Role.PROVIDER.value == "PROVIDER"

    def test_str_representation(self) -> None:
        """Test that the string representation of roles works correctly."""
        assert str(Role.ADMIN) == "ADMIN"
        assert str(Role.CLINICIAN) == "CLINICIAN"
        assert str(Role.DOCTOR) == "DOCTOR"

    def test_role_equality(self) -> None:
        """Test role equality operations."""
        assert Role.ADMIN == Role.ADMIN
        assert Role.ADMIN == "ADMIN"
        assert Role.ADMIN != Role.USER  # type: ignore[unreachable]
        assert Role.ADMIN != "USER"

    def test_role_in_operations(self) -> None:
        """Test that roles work correctly in collections."""
        roles = [Role.ADMIN, Role.DOCTOR]
        assert Role.ADMIN in roles
        assert Role.DOCTOR in roles
        assert Role.USER not in roles

        # Test with string comparison
        assert "ADMIN" in [r.value for r in roles]
        assert "DOCTOR" in [str(r) for r in roles]

    def test_role_serialization(self) -> None:
        """Test that roles can be serialized to strings."""
        # This tests the primary purpose of using str enum
        roles_list = [Role.ADMIN, Role.CLINICIAN]
        serialized = [str(r) for r in roles_list]
        assert serialized == ["ADMIN", "CLINICIAN"]
