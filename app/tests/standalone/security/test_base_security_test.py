"""
Base Security Test Class Tests

This module contains tests for the BaseSecurityTest class to ensure
proper functionality of the security test infrastructure.
"""

import unittest
import pytest
import json
from unittest.mock import patch, MagicMock
import uuid

from app.tests.security.utils.base_security_test import BaseSecurityTest


class TestBaseSecurityTest(BaseSecurityTest):
    """Tests for the BaseSecurityTest utility class itself (using pytest style)."""

    @pytest.mark.standalone()
    def test_initialization(self):
        """Test that BaseSecurityTest initializes with correct attributes via fixtures."""
        # Fixtures are auto-used, attributes should be set on self
        assert hasattr(self, 'test_user_id')
        assert isinstance(self.test_user_id, str)
        assert hasattr(self, 'test_roles')
        assert isinstance(self.test_roles, list)
        assert hasattr(self, 'db_session') # Provided by fixture
        assert hasattr(self, 'entity_factory') # Provided by fixture
        assert hasattr(self, 'rbac') # Provided by fixture

    @pytest.mark.standalone()
    def test_has_permission(self):
        """Test permission checking functionality."""
        # Test existing permissions
        assert self.has_permission("read:own_data", roles=["user"])
        assert self.has_permission("read:patient_data", roles=["clinician"])
        assert self.has_permission("delete:all_data", roles=["admin"])
        assert self.has_permission("read:own_data") # Uses self.test_roles = ["user", "clinician"]

        # Test non-existent permissions
        assert not self.has_permission("delete:all_data", roles=["user"])
        assert not self.has_permission("admin:access")
        assert not self.has_permission("read:something_else", roles=["guest"])

    @pytest.mark.standalone()
    def test_generate_auth_token(self):
        """Test JWT token generation."""
        # Test default token
        token1 = self.get_auth_token()
        assert isinstance(token1, str)
        assert f"'sub': '{self.test_user_id}'" in token1
        assert f"'roles': {self.test_roles}" in token1

        # Test token with specific user and roles
        user2_id = str(uuid.uuid4())
        roles2 = ["admin", "auditor"]
        token2 = self.get_auth_token(user_id=user2_id, roles=roles2)
        assert f"'sub': '{user2_id}'" in token2
        assert f"'roles': {roles2}" in token2

        # Test token with custom claims
        custom_claims = {"tenant_id": "t123", "session_id": "s456"}
        token3 = self.get_auth_token(custom_claims=custom_claims)
        assert f"'tenant_id': 't123'" in token3
        assert f"'session_id': 's456'" in token3
        assert f"'sub': '{self.test_user_id}'" in token3 # Default user id

    @pytest.mark.standalone()
    def test_get_auth_headers(self):
        """Test generating authorization headers."""
        # Test default headers
        headers1 = self.get_auth_headers()
        assert isinstance(headers1, dict)
        assert "Authorization" in headers1
        assert headers1["Authorization"].startswith("Bearer mock_token.")
        assert f"'sub': '{self.test_user_id}'" in headers1["Authorization"]

        # Test headers with custom token
        custom_token = "my_custom_token"
        headers2 = self.get_auth_headers(token=custom_token)
        assert headers2["Authorization"] == f"Bearer {custom_token}"

    @pytest.mark.standalone()
    def test_entity_factory_setup(self):
        """Test entity factory is properly set up via fixture."""
        assert hasattr(self, 'entity_factory')


if __name__ == "__main__":
    unittest.main()