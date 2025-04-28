"""
Standalone Unit tests for the mock PAT service implementation.

This module contains standalone tests that can be run independently
without requiring external dependencies.
"""

from app.core.services.ml.pat.mock import MockPATService
import pytest
from datetime import datetime
from unittest.mock import MagicMock

from app.core.services.ml.pat.exceptions import (
    ValidationError,
    InitializationError,
    ResourceNotFoundError
)


@pytest.fixture
def mock_pat():
    """Create a MockPATService instance for testing."""
    return MockPATService()


@pytest.fixture
def initialized_mock_pat():
    """Create an initialized MockPATService instance for testing."""
    service = MockPATService()
    service.initialize({"mock_delay_ms": 0})  # No delay for faster tests
    return service


@pytest.fixture
def valid_readings():
    """Create a list of valid accelerometer readings for testing."""
    return [
        {"x": 0.1, "y": 0.2, "z": 0.9},
        {"x": 0.2, "y": 0.3, "z": 0.8},
        {"x": 0.3, "y": 0.4, "z": 0.7},
    ]


@pytest.fixture
def valid_device_info():
    """Create valid device information for testing."""
    return {
        "device_type": "Actigraph wGT3X-BT",
        "manufacturer": "Actigraph",
        "placement": "wrist",
    }


@pytest.fixture
def valid_analysis_types():
    """Create a list of valid analysis types for testing."""
    return ["sleep", "activity"]


class TestStandaloneMockPAT:
    """Tests for MockPATService that can be run in isolation."""

    @pytest.mark.standalone()
    def test_initialization(self, mock_pat):
        """Test initialization works properly."""
        # Test uninitialized state
        assert not mock_pat._initialized

        # Test initialization raising error
        with pytest.raises(InitializationError):
            mock_pat._check_initialized()

        # Initialize and check state
        mock_pat.initialize({"mock_delay_ms": 100})
        assert mock_pat._initialized
        assert mock_pat._mock_delay_ms == 100

        # Should not raise error now
        mock_pat._check_initialized()

    @pytest.mark.standalone()
    def test_device_info_validation(self, mock_pat):
        """Test validation of device info."""
        # Empty device info
        with pytest.raises(ValidationError):
            mock_pat._validate_device_info({})

        # Missing required field
        with pytest.raises(ValidationError):
            mock_pat._validate_device_info({"device_type": "Actigraph"})

        # Valid device info should not raise
        mock_pat._validate_device_info({
            "device_type": "Actigraph",
            "manufacturer": "Actigraph"
        })

    @pytest.mark.standalone()
    def test_analysis_types_validation(self, mock_pat):
        """Test validation of analysis types."""
        # Empty analysis types
        with pytest.raises(ValidationError):
            mock_pat._validate_analysis_types([])

        # Invalid analysis type
        with pytest.raises(ValidationError):
            mock_pat._validate_analysis_types(["sleep", "invalid_type"])

        # Valid analysis types should not raise
        mock_pat._validate_analysis_types(["sleep", "activity"])

    @pytest.mark.standalone()
    def test_analyze_actigraphy(self, initialized_mock_pat, valid_readings, valid_device_info, valid_analysis_types):
        """Test actigraphy analysis with valid data."""
        result = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types
        )

        # Verify result structure
        assert isinstance(result, dict)
        assert "analysis_id" in result
        assert "status" in result
        assert result["status"] == "processing"
        assert "created_at" in result
        assert "estimated_completion_time" in result

        # Verify the analysis was added to the mock service's storage
        assert result["analysis_id"] in initialized_mock_pat._analyses

    @pytest.mark.standalone()
    def test_get_analysis_by_id(self, initialized_mock_pat, valid_readings, valid_device_info, valid_analysis_types):
        """Test getting analysis by ID."""
        # Create an analysis
        analysis = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types
        )

        # Get the analysis by ID
        result = initialized_mock_pat.get_analysis(analysis["analysis_id"])
        
        # Verify result structure
        assert isinstance(result, dict)
        assert result["analysis_id"] == analysis["analysis_id"]
        assert "status" in result
        assert "results" in result
        assert "patient_id" in result
        assert result["patient_id"] == "patient-123"

    @pytest.mark.standalone()
    def test_get_nonexistent_analysis(self, initialized_mock_pat):
        """Test getting an analysis that doesn't exist."""
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.get_analysis("non-existent-id")


if __name__ == "__main__":
    pytest.main(["-v", __file__])
