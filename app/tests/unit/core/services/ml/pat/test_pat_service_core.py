"""
Unit tests for the PAT (Patient Assessment Tool) service.

These tests validate the functionality of the PAT service implementation.
"""


import pytest

# Import exceptions directly
from app.core.services.ml.pat.mock import MockPATService


@pytest.mark.venv_only()
class TestPATService:
    """Tests for the PAT service."""

    @pytest.fixture
    def pat_service(self) -> MockPATService:
        """Create a PAT service instance for testing."""
        service = MockPATService()
        service.initialize({})
        return service

    def test_initialization(self) -> None:
        """Test service initialization."""
        service = MockPATService()
        assert not service.is_healthy()
        service.initialize({})
        assert service.is_healthy()
        service.shutdown()
        assert not service.is_healthy()

    # ... (Keep any other relevant tests if they exist and are compatible)
