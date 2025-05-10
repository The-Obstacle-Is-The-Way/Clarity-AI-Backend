"""
Standalone Unit tests for the mock PAT service implementation.

This module contains standalone tests that can be run independently
without requiring external dependencies.
"""


import pytest
from datetime import datetime, timedelta, timezone

from app.core.services.ml.pat.exceptions import (
    InitializationError,
    ResourceNotFoundError,
    ValidationError,
)
from app.core.services.ml.pat.mock import MockPATService


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
    """Create a list of valid accelerometer readings for testing (10 readings)."""
    # Ensure enough readings to pass validation (e.g., >= 10)
    return [
        {"timestamp": (datetime.now(timezone.utc) - timedelta(seconds=i)).isoformat(), "x": 0.1 + i*0.01, "y": 0.2 + i*0.01, "z": 0.9 - i*0.01} 
        for i in range(10)  # Generate 10 readings
    ]


@pytest.fixture
def valid_device_info():
    """Create valid device information for testing."""
    return {
        "device_type": "Actigraph wGT3X-BT",
        "manufacturer": "Actigraph",
        "model": "wGT3X-BT",
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
        assert not mock_pat.initialized

        # Test initialization raising error before init
        with pytest.raises(InitializationError):
            mock_pat._check_initialized()

        # Initialize and check state
        mock_pat.initialize({"mock_delay_ms": 100})
        assert mock_pat.initialized
        assert mock_pat.delay_ms == 100

        # Should not raise error now
        mock_pat._check_initialized()

    @pytest.mark.standalone()
    def test_device_info_validation(self, initialized_mock_pat, valid_readings, valid_analysis_types):
        """Test validation of device info by calling _validate_actigraphy_inputs."""
        # Base valid args
        base_args = {
            "patient_id": "test-patient",
            "readings": valid_readings,
            "sampling_rate_hz": 30.0,
            "analysis_types": valid_analysis_types
        }

        # Empty device info
        with pytest.raises(ValidationError, match="Device info is required"):
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, device_info={})

        # Missing required field (manufacturer)
        with pytest.raises(ValidationError, match="Device info must contain required keys: \['manufacturer', 'model'\]"):
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, device_info={"device_type": "Actigraph", "model": "TestModel"})
            
        # Missing required field (model)
        with pytest.raises(ValidationError, match="Device info must contain required keys: \['manufacturer', 'model'\]"):
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, device_info={"device_type": "Actigraph", "manufacturer": "TestManu"})

        # Valid device info should not raise
        initialized_mock_pat._validate_actigraphy_inputs(**base_args, device_info={
            "device_type": "Actigraph",
            "manufacturer": "Actigraph",
            "model": "wGT3X-BT"
        })

    @pytest.mark.standalone()
    def test_analysis_types_validation(self, initialized_mock_pat, valid_readings, valid_device_info):
        """Test validation of analysis types via _validate_actigraphy_inputs."""
        # Base valid args
        base_args = {
            "patient_id": "test-patient",
            "readings": valid_readings,
            "sampling_rate_hz": 30.0,
            "device_info": valid_device_info
        }
        
        # Empty analysis types
        with pytest.raises(ValidationError, match="At least one analysis type is required"):
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, analysis_types=[])

        # Invalid analysis type
        with pytest.raises(ValidationError, match="Invalid analysis type: invalid_type."):
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, analysis_types=["sleep", "invalid_type"])

        # Valid analysis types should not raise
        initialized_mock_pat._validate_actigraphy_inputs(**base_args, analysis_types=["sleep", "activity"])

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
        analysis_request_details = {
            "patient_id": "patient-123",
            "readings": valid_readings,
            "start_time": "2025-03-27T12:00:00Z",
            "end_time": "2025-03-28T12:00:00Z",
            "sampling_rate_hz": 30.0,
            "device_info": valid_device_info,
            "analysis_types": valid_analysis_types
        }
        analysis = initialized_mock_pat.analyze_actigraphy(**analysis_request_details)

        # Get the analysis by ID
        result = initialized_mock_pat.get_analysis_by_id(analysis["analysis_id"])
        
        # Verify result structure
        assert isinstance(result, dict)
        assert result["analysis_id"] == analysis["analysis_id"]
        assert "status" in result
        assert result["status"] == "completed"
        assert "results" in result
        assert "patient_id" in result
        assert result["patient_id"] == "patient-123"

    @pytest.mark.standalone()
    def test_get_nonexistent_analysis(self, initialized_mock_pat):
        """Test getting an analysis that doesn't exist."""
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.get_analysis_by_id("non-existent-id")


if __name__ == "__main__":
    pytest.main(["-v", __file__])
