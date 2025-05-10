"""
Standalone Unit tests for the mock PAT service implementation.

This module contains standalone tests that can be run independently
without requiring external dependencies.
"""


import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from app.core.exceptions.base_exceptions import (
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
        with pytest.raises(InitializationError) as excinfo:
            mock_pat._check_initialized()
        excinfo.match(r"Mock PAT service not initialized")

        # Initialize and check state
        mock_pat.initialize({"mock_delay_ms": 100})
        assert mock_pat.initialized
        assert mock_pat.delay_ms == 100

        # Should not raise error now
        try:
            mock_pat._check_initialized()
        except InitializationError:
            pytest.fail("InitializationError was raised for an initialized service")

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

        # None device info
        with pytest.raises(ValidationError) as excinfo:
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, device_info=None)
        excinfo.match(r"Device info is required")

        # Missing keys in device info
        with pytest.raises(ValidationError) as excinfo:
            initialized_mock_pat._validate_actigraphy_inputs(
                **base_args, device_info={"manufacturer": "TestDevice"} # Missing 'model'
            )
        excinfo.match(r"Device info must contain required keys: \['manufacturer', 'model'\]")

        # Valid device_info (should not raise)
        try:
            initialized_mock_pat._validate_actigraphy_inputs(
                **base_args, device_info={"manufacturer": "TestCorp", "model": "DeviceX"}
            )
        except ValidationError:
            pytest.fail("ValidationError raised unexpectedly for valid device info")

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
        
        # Test with None analysis_types
        with pytest.raises(ValidationError) as excinfo:
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, analysis_types=None)
        excinfo.match(r"At least one analysis type is required")
        
        # Test with empty list for analysis_types
        with pytest.raises(ValidationError) as excinfo:
            initialized_mock_pat._validate_actigraphy_inputs(**base_args, analysis_types=[])
        excinfo.match(r"At least one analysis type is required")

        # Test with an invalid analysis type string
        invalid_type = "non_existent_type"
        with pytest.raises(ValidationError) as excinfo:
            initialized_mock_pat._validate_actigraphy_inputs(
                **base_args, analysis_types=[invalid_type, "sleep"]
            )
        excinfo.match(rf"Invalid analysis type: {invalid_type}\. Valid types are: {{.*}}") 

        # Test with a mix of valid and one specifically invalid type string (as above)
        with pytest.raises(ValidationError) as excinfo:
            initialized_mock_pat._validate_actigraphy_inputs(
                **base_args, analysis_types=["sleep", invalid_type, "activity"]
            )
        excinfo.match(rf"Invalid analysis type: {invalid_type}\. Valid types are: {{.*}}") 

        # Valid analysis types (should not raise)
        try:
            initialized_mock_pat._validate_actigraphy_inputs(
                **base_args, analysis_types=["sleep", "activity"]
            )
        except ValidationError:
            pytest.fail("ValidationError raised unexpectedly for valid analysis types")

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
        assert result["status"] == "completed"
        assert "created_at" in result

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
        with pytest.raises(ResourceNotFoundError) as excinfo:
            initialized_mock_pat.get_analysis_by_id("nonexistent_id")
        excinfo.match(r"Analysis not found: nonexistent_id")


if __name__ == "__main__":
    pytest.main(["-v", __file__])
