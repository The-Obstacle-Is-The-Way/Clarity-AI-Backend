"""
Unit tests for the mock PAT service implementation.

This module contains tests for all methods of the MockPATService class,
verifying both success paths and error handling.
"""

import sys
from pathlib import Path

import pytest

# Imports first
from app.core.services.ml.pat.exceptions import (
    AuthorizationError,
    InitializationError,
    ResourceNotFoundError,
    ValidationError,
)
from app.tests.standalone.mock_pat_service import MockPATService

# Add project root to sys.path AFTER imports
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root))

# Replaced List, Dict with list, dict
# Removed unused imports (UTC, Optional, Any)

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
        "model": "TestModel"
    }


@pytest.fixture
def valid_analysis_types():
    """Create a list of valid analysis types for testing."""
    return ["sleep", "activity"]


class TestMockPATInitialization:
    """Tests for MockPATService initialization."""

    @pytest.mark.standalone()
    def test_initialize_success(self, mock_pat):
        """Test successful initialization."""
        config = {"mock_delay_ms": 100}
        mock_pat.initialize(config)
        assert mock_pat._initialized is True
        assert mock_pat._mock_delay_ms == 100

    @pytest.mark.standalone()
    def test_initialize_invalid_config(self, mock_pat):
        """Test initialization with invalid configuration."""
        # None config
        with pytest.raises(ValidationError):
            mock_pat.initialize(None)

        # Invalid mock_delay_ms
        with pytest.raises(ValidationError):
            mock_pat.initialize({"mock_delay_ms": "invalid"})

    @pytest.mark.standalone()
    def test_initialize_twice(self, initialized_mock_pat):
        """Test initializing an already initialized service."""
        with pytest.raises(InitializationError):
            initialized_mock_pat.initialize({"mock_delay_ms": 100})

    @pytest.mark.standalone()
    def test_is_healthy(self, mock_pat, initialized_mock_pat):
        """Test health check functionality."""
        # Uninitialized service should not be healthy
        assert mock_pat.is_healthy() is False

        # Initialized service should be healthy
        assert initialized_mock_pat.is_healthy() is True

        # After shutdown, service should not be healthy
        initialized_mock_pat.shutdown()
        assert initialized_mock_pat.is_healthy() is False

    @pytest.mark.standalone()
    def test_shutdown(self, initialized_mock_pat):
        """Test shutdown functionality."""
        assert initialized_mock_pat.is_healthy() is True
        initialized_mock_pat.shutdown()
        assert initialized_mock_pat.is_healthy() is False

        # Calling shutdown again should not raise an error
        initialized_mock_pat.shutdown()
        assert initialized_mock_pat.is_healthy() is False


class TestMockPATAnalysis:
    """Tests for MockPATService analysis functionality."""

    @pytest.mark.standalone()
    def test_analyze_actigraphy_success(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test successful actigraphy analysis."""
        result = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types,
        )

        # Verify result structure
        assert "analysis_id" in result
        assert "patient_id" in result
        assert "timestamp" in result
        assert "results" in result
        assert "metadata" in result

        # Verify patient ID is preserved
        assert result["patient_id"] == "patient-123"

        # Verify results contain expected analysis types
        assert "sleep" in result["results"]
        assert "activity" in result["results"]

        # Verify metadata contains expected fields
        assert "device_info" in result["metadata"]
        assert "start_time" in result["metadata"]
        assert "end_time" in result["metadata"]
        assert "sampling_rate_hz" in result["metadata"]
        assert "reading_count" in result["metadata"]

        # Verify reading count matches input
        assert result["metadata"]["reading_count"] == len(valid_readings)

    @pytest.mark.standalone()
    def test_analyze_actigraphy_not_initialized(
        self,
        mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_missing_patient_id(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails with missing patient ID."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id=None,
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_empty_readings(
        self,
        initialized_mock_pat,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails with empty readings."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=[],
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_invalid_readings(
        self,
        initialized_mock_pat,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails with invalid readings."""
        # Missing x coordinate
        invalid_readings = [
            {"y": 0.2, "z": 0.9},
            {"x": 0.2, "y": 0.3, "z": 0.8},
        ]

        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=invalid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

        # Invalid coordinate value
        invalid_readings = [
            {"x": "invalid", "y": 0.2, "z": 0.9},
            {"x": 0.2, "y": 0.3, "z": 0.8},
        ]

        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=invalid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_invalid_time_format(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails with invalid time format."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="invalid-time",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_end_before_start(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails when end time is before start time."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-28T12:00:00Z",
                end_time="2025-03-27T12:00:00Z",  # Before start time
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_invalid_sampling_rate(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test analysis fails with invalid sampling rate."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=0.0,  # Invalid rate
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_missing_device_info(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_analysis_types
    ):
        """Test analysis fails with missing device info."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=None,
                analysis_types=valid_analysis_types,
            )

    @pytest.mark.standalone()
    def test_analyze_actigraphy_invalid_analysis_types(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info
    ):
        """Test analysis fails with invalid analysis types."""
        # Empty analysis types
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=[],
            )

        # Unsupported analysis type
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=["unsupported_type"],
            )


class TestMockPATProfileManagement:
    """Tests for MockPATService profile management functionality."""

    @pytest.mark.standalone()
    def test_create_patient_profile_success(self, initialized_mock_pat):
        """Test successful patient profile creation."""
        profile_data = {
            "age": 35,
            "gender": "female",
            "height_cm": 165,
            "weight_kg": 60,
            "medical_conditions": ["insomnia", "anxiety"]
        }

        result = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data=profile_data
        )

        # Verify result structure
        assert "profile_id" in result
        assert "patient_id" in result
        assert "timestamp" in result
        assert "data" in result

        # Verify patient ID is preserved
        assert result["patient_id"] == "patient-123"

        # Verify profile data is preserved
        assert result["data"] == profile_data

    @pytest.mark.standalone()
    def test_create_patient_profile_not_initialized(self, mock_pat):
        """Test profile creation fails when service is not initialized."""
        profile_data = {"age": 35, "gender": "female"}

        with pytest.raises(InitializationError):
            mock_pat.create_patient_profile(
                patient_id="patient-123",
                profile_data=profile_data
            )

    @pytest.mark.standalone()
    def test_create_patient_profile_missing_patient_id(self, initialized_mock_pat):
        """Test profile creation fails with missing patient ID."""
        profile_data = {"age": 35, "gender": "female"}

        with pytest.raises(ValidationError):
            initialized_mock_pat.create_patient_profile(
                patient_id=None,
                profile_data=profile_data
            )

    @pytest.mark.standalone()
    def test_create_patient_profile_empty_data(self, initialized_mock_pat):
        """Test profile creation fails with empty profile data."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.create_patient_profile(
                patient_id="patient-123",
                profile_data={}
            )

    @pytest.mark.standalone()
    def test_get_patient_profile_success(self, initialized_mock_pat):
        """Test successful retrieval of patient profile."""
        # First create a profile
        profile_data = {"age": 35, "gender": "female"}
        created_profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data=profile_data
        )

        profile_id = created_profile["profile_id"]

        # Now retrieve it
        retrieved_profile = initialized_mock_pat.get_patient_profile(
            patient_id="patient-123"
        )

        # Verify retrieved profile matches created profile
        assert retrieved_profile["profile_id"] == profile_id
        assert retrieved_profile["patient_id"] == "patient-123"
        assert retrieved_profile["data"] == profile_data

    @pytest.mark.standalone()
    def test_get_patient_profile_not_initialized(self, mock_pat):
        """Test profile retrieval fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.get_patient_profile(
                patient_id="patient-123"
            )

    @pytest.mark.standalone()
    def test_get_patient_profile_not_found(self, initialized_mock_pat):
        """Test profile retrieval fails when profile doesn't exist."""
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.get_patient_profile(
                patient_id="non-existent-profile"
            )

    @pytest.mark.standalone()
    def test_get_patient_profile_wrong_patient(self, initialized_mock_pat):
        """Test profile retrieval fails when profile belongs to different patient."""
        # Create a profile for patient-123
        profile_data = {"age": 35, "gender": "female"}
        created_profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data=profile_data
        )

        profile_id = created_profile["profile_id"]

        # Try to retrieve it with a different patient ID
        with pytest.raises(AuthorizationError):
            initialized_mock_pat.get_patient_profile(
                patient_id="patient-456"  # Different patient
            )

    @pytest.mark.standalone()
    def test_update_patient_profile_success(self, initialized_mock_pat):
        """Test successful update of patient profile."""
        # First create a profile
        initial_data = {"age": 35, "gender": "female"}
        created_profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data=initial_data
        )

        profile_id = created_profile["profile_id"]

        # Now update it
        updated_data = {
            "age": 36,  # Changed
            "gender": "female",
            "weight_kg": 65  # Added
        }

        updated_profile = initialized_mock_pat.update_patient_profile(
            patient_id="patient-123",
            profile_data=updated_data
        )

        # Verify updated profile has new data
        assert updated_profile["profile_id"] == profile_id
        assert updated_profile["patient_id"] == "patient-123"
        assert updated_profile["data"]["age"] == 36
        assert updated_profile["data"]["weight_kg"] == 65
        assert updated_profile["data"]["gender"] == "female"

    @pytest.mark.standalone()
    def test_update_patient_profile_not_initialized(self, mock_pat):
        """Test profile update fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.update_patient_profile(
                patient_id="patient-123",
                profile_data={"age": 36}
            )

    @pytest.mark.standalone()
    def test_update_patient_profile_not_found(self, initialized_mock_pat):
        """Test profile update fails when profile doesn't exist."""
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.update_patient_profile(
                patient_id="non-existent-profile",
                profile_data={"age": 36}
            )

    @pytest.mark.standalone()
    def test_update_patient_profile_wrong_patient(self, initialized_mock_pat):
        """Test profile update fails when profile belongs to different patient."""
        # Create a profile for patient-123
        profile_data = {"age": 35, "gender": "female"}
        created_profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data=profile_data
        )

        profile_id = created_profile["profile_id"]

        # Try to update it with a different patient ID
        with pytest.raises(AuthorizationError):
            initialized_mock_pat.update_patient_profile(
                patient_id="patient-456",  # Different patient
                profile_data={"age": 36}
            )

    @pytest.mark.standalone()
    def test_update_patient_profile_empty_data(self, initialized_mock_pat):
        """Test profile update fails with empty profile data."""
        # First create a profile
        profile_data = {"age": 35, "gender": "female"}
        created_profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data=profile_data
        )

        profile_id = created_profile["profile_id"]

        # Try to update with empty data
        with pytest.raises(ValidationError):
            initialized_mock_pat.update_patient_profile(
                patient_id="patient-123",
                profile_data={}
            )


class TestMockPATIntegration:
    """Tests for MockPATService integration functionality."""

    @pytest.mark.standalone()
    def test_integrate_with_digital_twin_success(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test successful integration with digital twin."""
        # First create an analysis
        analysis = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types,
        )

        analysis_id = analysis["analysis_id"]

        # Create a profile
        profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data={"age": 35, "gender": "female"}
        )

        profile_id = profile["profile_id"]

        # Now integrate with digital twin
        result = initialized_mock_pat.integrate_with_digital_twin(
            patient_id="patient-123",
            analysis_id=analysis_id,
        )

        # Verify result structure
        assert "integration_id" in result
        assert "patient_id" in result
        assert "timestamp" in result
        assert "digital_twin_updates" in result
        assert "metadata" in result

        # Verify patient ID is preserved
        assert result["patient_id"] == "patient-123"

        # Verify digital twin updates contain expected fields
        assert "neurotransmitter_levels" in result["digital_twin_updates"]
        assert "brain_regions" in result["digital_twin_updates"]
        assert "insights" in result["digital_twin_updates"]

        # Verify metadata contains references to input data
        assert "profile_id" in result["metadata"]
        assert "analysis_id" in result["metadata"]
        assert result["metadata"]["profile_id"] == profile_id
        assert result["metadata"]["analysis_id"] == analysis_id

    @pytest.mark.standalone()
    def test_integrate_with_digital_twin_not_initialized(self, mock_pat):
        """Test integration fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.integrate_with_digital_twin(
                patient_id="patient-123",
                analysis_id="analysis-xyz",
            )

    @pytest.mark.standalone()
    def test_integrate_with_digital_twin_missing_patient_id(self, initialized_mock_pat):
        """Test integration fails with missing patient ID."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.integrate_with_digital_twin(
                patient_id=None,
                analysis_id="analysis-xyz",
            )

    @pytest.mark.standalone()
    def test_integrate_with_digital_twin_profile_not_found(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test integration fails when profile doesn't exist."""
        # First create an analysis
        analysis = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types,
        )

        analysis_id = analysis["analysis_id"]

        # Attempt integration with non-existent profile
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.integrate_with_digital_twin(
                patient_id="non-existent-profile",
                analysis_id=analysis_id,
            )

    @pytest.mark.standalone()
    def test_integrate_with_digital_twin_analysis_not_found(
        self,
        initialized_mock_pat
    ):
        """Test integration fails when analysis doesn't exist."""
        # Create a profile
        profile = initialized_mock_pat.create_patient_profile(
            patient_id="patient-123",
            profile_data={"age": 35, "gender": "female"}
        )

        profile_id = profile["profile_id"]

        # Attempt integration with non-existent analysis
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.integrate_with_digital_twin(
                patient_id="patient-123",
                analysis_id="non-existent-analysis",
            )

    @pytest.mark.standalone()
    def test_integrate_with_digital_twin_wrong_patient(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types
    ):
        """Test integration fails when analysis does not belong to patient."""
        # Create analysis for patient-123
        analysis = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types,
        )

        analysis_id = analysis["analysis_id"]

        # Attempt integration with a different patient ID
        with pytest.raises(AuthorizationError):
            initialized_mock_pat.integrate_with_digital_twin(
                patient_id="patient-456",  # Different patient
                analysis_id=analysis_id,
            )