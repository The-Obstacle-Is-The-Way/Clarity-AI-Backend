"""
Unit tests for the mock implementation of the PAT service.

This module contains unit tests for the MockPAT class, ensuring all methods
work correctly and handle edge cases properly.
"""

# Corrected import alias syntax
from datetime import datetime, timedelta, timezone

import pytest

from app.core.exceptions.base_exceptions import (
    AuthorizationError,
    InitializationError,
    ResourceNotFoundError,
    ValidationError,
)

# Import the PAT-specific one for testing the theory
# from app.core.services.ml.pat.exceptions import AuthorizationError as PatAuthorizationError
from app.core.services.ml.pat.mock import MockPATService as MockPAT


@pytest.fixture
def mock_pat():
    """Create a MockPAT instance for testing."""
    pat = MockPAT()
    pat.initialize({})
    return pat


@pytest.fixture
def sample_readings():
    """Create sample accelerometer readings for testing."""
    readings = []
    # Use a fixed base time for reproducibility if needed, or keep dynamic
    base_timestamp = datetime.now().isoformat()

    for i in range(100):
        # Correctly append the dictionary without extra parentheses
        readings.append(
            {
                "timestamp": f"{base_timestamp[:-7]}{i:02d}Z",
                "x": float(i) / 50.0,
                "y": float(i + 10) / 50.0,
                "z": float(i + 20) / 50.0,
            }
        )

    # Correct return statement
    return readings


@pytest.fixture
def sample_device_info():
    """Create sample device info for testing."""
    return {
        "device_type": "smartwatch",
        "model": "Model X",
        "firmware_version": "1.2.3",
        "manufacturer": "TestMaker",
        "sampling_capabilities": {
            "max_sampling_rate_hz": 50.0,
            "battery_life_hours": 48,
        },
        "sensors": ["accelerometer", "gyroscope", "heart_rate"],
    }


class TestMockPAT:
    """Tests for the MockPAT implementation."""

    def test_initialization_success(self) -> None:
        """Test successful initialization of MockPAT."""
        pat = MockPAT()
        pat.initialize({})

        assert pat.configured is True
        assert pat.delay_ms == 0

    def test_initialization_with_delay(self) -> None:
        """Test initialization with delay parameter."""
        pat = MockPAT()
        pat.initialize({"delay_ms": 100})

        assert pat.configured is True
        assert pat.delay_ms == 100

    def test_analyze_actigraphy_success(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test successful actigraphy analysis."""
        result = mock_pat.analyze_actigraphy(
            patient_id="test-patient",
            readings=sample_readings,
            start_time="2025-03-28T00:00:00Z",
            end_time="2025-03-28T08:00:00Z",
            sampling_rate_hz=10.0,
            device_info=sample_device_info,
            analysis_types=["sleep", "activity"],
        )

        assert isinstance(result, dict)
        assert "results" in result
        assert "sleep" in result["results"]
        assert "activity" in result["results"]
        assert "metrics" in result
        assert "general" in result["metrics"]

    def test_analyze_actigraphy_with_all_types(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test actigraphy analysis with all analysis types."""
        result = mock_pat.analyze_actigraphy(
            patient_id="test-patient",
            readings=sample_readings,
            start_time="2025-03-28T00:00:00Z",
            end_time="2025-03-28T08:00:00Z",
            sampling_rate_hz=10.0,
            device_info=sample_device_info,
            analysis_types=[
                "sleep",
                "activity",
                "circadian_rhythm",
                "behavioral_patterns",
                "mood_indicators",
            ],
        )

        assert isinstance(result, dict)
        assert "results" in result
        for analysis_type in [
            "sleep",
            "activity",
            "circadian_rhythm",
            "behavioral_patterns",
            "mood_indicators",
        ]:
            assert analysis_type in result["results"]
        assert "metrics" in result
        assert "general" in result["metrics"]

    def test_analyze_actigraphy_missing_patient_id(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test actigraphy analysis with missing patient ID."""
        with pytest.raises(ValidationError) as excinfo:
            mock_pat.analyze_actigraphy(
                patient_id="",  # Empty patient ID
                readings=sample_readings,
                start_time="2025-03-28T00:00:00Z",
                end_time="2025-03-28T08:00:00Z",
                sampling_rate_hz=10.0,
                device_info=sample_device_info,
                analysis_types=["sleep"],
            )

        excinfo.match(r"^Patient ID is required")

    def test_analyze_actigraphy_invalid_sampling_rate(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test actigraphy analysis with invalid sampling rate."""
        with pytest.raises(ValidationError) as excinfo:
            mock_pat.analyze_actigraphy(
                patient_id="test-patient",
                readings=sample_readings,
                start_time="2025-03-28T00:00:00Z",
                end_time="2025-03-28T08:00:00Z",
                sampling_rate_hz=-1.0,  # Negative sampling rate
                device_info=sample_device_info,
                analysis_types=["sleep"],
            )

        excinfo.match(r"^Sampling rate must be positive")

    def test_analyze_actigraphy_insufficient_readings(self, mock_pat, sample_device_info) -> None:
        """Test actigraphy analysis with insufficient readings."""
        # Create a list with only 5 readings
        readings = []
        base_timestamp = datetime.now().isoformat()

        for i in range(5):
            readings.append(
                {
                    "timestamp": f"{base_timestamp[:-7]}{i:02d}Z",
                    "x": float(i) / 50.0,
                    "y": float(i + 10) / 50.0,
                    "z": float(i + 20) / 50.0,
                }
            )

        with pytest.raises(ValidationError) as excinfo:
            mock_pat.analyze_actigraphy(
                patient_id="test-patient",
                readings=readings,  # Only 5 readings
                start_time="2025-03-28T00:00:00Z",
                end_time="2025-03-28T08:00:00Z",
                sampling_rate_hz=10.0,
                device_info=sample_device_info,
                analysis_types=["sleep"],
            )

        excinfo.match(r"^At least 10 readings are required")

    def test_analyze_actigraphy_invalid_reading_format(self, mock_pat, sample_device_info) -> None:
        """Test analysis with invalid reading format. Ensure enough readings are provided first."""
        # Create 10 readings, with the first one malformed (missing timestamp)
        malformed_readings = [{"x": 0.1, "y": 0.2, "z": 0.9}]  # Malformed first reading
        for i in range(1, 10):  # Add 9 more valid readings
            malformed_readings.append(
                {
                    "timestamp": (datetime.now(timezone.utc) - timedelta(seconds=i)).isoformat(),
                    "x": 0.1 + i * 0.01,
                    "y": 0.2 + i * 0.01,
                    "z": 0.9 - i * 0.01,
                }
            )

        with pytest.raises(ValidationError) as excinfo:
            mock_pat.analyze_actigraphy(
                patient_id="patient-invalid-reading-fmt",
                readings=malformed_readings,  # Use the list with 10 readings, 1st malformed
                start_time="2023-01-01T00:00:00Z",
                end_time="2023-01-01T01:00:00Z",
                sampling_rate_hz=30.0,
                device_info=sample_device_info,
                analysis_types=["sleep"],  # Keep a valid analysis type
            )
        # The mock service's _validate_actigraphy_inputs checks for missing keys dynamically.
        # For the first reading {"x": 0.1, "y": 0.2, "z": 0.9}, 'timestamp' is missing.
        excinfo.match(
            r"Invalid reading format at index 0: missing required keys \('timestamp',\)\."
        )

    def test_analyze_actigraphy_unsupported_analysis_type(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test actigraphy analysis with unsupported analysis type."""
        with pytest.raises(ValidationError) as excinfo:
            mock_pat.analyze_actigraphy(
                patient_id="test-patient",
                readings=sample_readings,
                start_time="2025-03-28T00:00:00Z",
                end_time="2025-03-28T08:00:00Z",
                sampling_rate_hz=10.0,
                device_info=sample_device_info,
                analysis_types=["unsupported_type"],  # Unsupported type
            )

        excinfo.match(r"Invalid analysis type: unsupported_type")

    def test_get_actigraphy_embeddings_success(self, mock_pat, sample_readings) -> None:
        """Test successful embeddings generation."""
        result = mock_pat.get_actigraphy_embeddings(
            patient_id="test-patient",
            readings=sample_readings,
            start_time="2025-03-28T00:00:00Z",
            end_time="2025-03-28T08:00:00Z",
            sampling_rate_hz=10.0,
        )

        # Verify response structure
        assert "embedding_id" in result
        assert result["patient_id"] == "test-patient"
        assert "timestamp" in result
        assert "embedding_vector" in result
        # Fixed size in mock implementation
        assert len(result["embedding_vector"]) == 128
        assert result["embedding_dimensions"] == 128

        # Verify that the embedding was stored
        embedding_id = result["embedding_id"]
        assert embedding_id in mock_pat.embeddings

        # Verify that the vector is normalized
        vector = result["embedding_vector"]
        magnitude = sum(x**2 for x in vector) ** 0.5
        assert abs(magnitude - 1.0) < 1e-6  # Should be very close to 1.0

    def test_get_analysis_by_id_success(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test successful retrieval of analysis by ID."""
        # First, create an analysis
        result = mock_pat.analyze_actigraphy(
            patient_id="test-patient",
            readings=sample_readings,
            start_time="2025-03-28T00:00:00Z",
            end_time="2025-03-28T08:00:00Z",
            sampling_rate_hz=10.0,
            device_info=sample_device_info,
            analysis_types=["sleep", "activity"],
        )

        analysis_id = result["analysis_id"]

        # Now, retrieve the analysis
        retrieved = mock_pat.get_analysis_by_id(analysis_id)

        assert isinstance(retrieved, dict)
        assert "results" in retrieved
        assert "sleep" in retrieved["results"]
        assert "activity" in retrieved["results"]
        assert "metrics" in retrieved
        assert "general" in retrieved["metrics"]

    def test_get_analysis_by_id_not_found(self, mock_pat) -> None:
        """Test retrieval of analysis by ID when not found."""
        with pytest.raises(ResourceNotFoundError) as excinfo:
            mock_pat.get_analysis_by_id("non-existent-id")

        excinfo.match(r"^Analysis not found")

    def test_get_patient_analyses_success(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test successful retrieval of patient analyses."""
        # Create multiple analyses for the same patient
        for i in range(3):
            mock_pat.analyze_actigraphy(
                patient_id="test-patient",
                readings=sample_readings,
                start_time=f"2025-03-{28 - i}T00:00:00Z",
                end_time=f"2025-03-{28 - i}T08:00:00Z",
                sampling_rate_hz=10.0,
                device_info=sample_device_info,
                analysis_types=["sleep"],
            )

        # Retrieve analyses for the patient
        result = mock_pat.get_patient_analyses("test-patient")

        # Verify clean interface - returns list directly (Interface Segregation Principle)
        assert isinstance(result, list)
        assert len(result) == 3

        # Verify that the analyses are sorted by timestamp (newest first)
        timestamps = [analysis["timestamp"] for analysis in result]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_get_patient_analyses_with_pagination(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test retrieval of patient analyses with pagination."""
        # Create multiple analyses for the same patient
        for i in range(5):
            mock_pat.analyze_actigraphy(
                patient_id="test-patient",
                readings=sample_readings,
                start_time=f"2025-03-{28 - i}T00:00:00Z",
                end_time=f"2025-03-{28 - i}T08:00:00Z",
                sampling_rate_hz=10.0,
                device_info=sample_device_info,
                analysis_types=["sleep"],
            )

        # Retrieve analyses with pagination - clean interface returns list directly
        result = mock_pat.get_patient_analyses("test-patient", limit=2, offset=1)

        # Verify clean interface with pagination applied
        assert isinstance(result, list)
        assert len(result) == 2  # Pagination limit applied

    def test_get_patient_analyses_empty(self, mock_pat) -> None:
        """Test retrieval of patient analyses when none exist."""
        result = mock_pat.get_patient_analyses("non-existent-patient")

        # Clean interface returns empty list directly
        assert isinstance(result, list)
        assert len(result) == 0

    def test_get_model_info(self, mock_pat) -> None:
        """Test getting model information."""
        info = mock_pat.get_model_info()

        assert info["model_name"] == "MockPAT"
        assert "version" in info
        assert "description" in info
        assert "capabilities" in info
        assert info["provider"] == "mock"
        assert len(info["capabilities"]) > 0

    def test_integrate_with_digital_twin_success(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test successful integration with digital twin."""
        # First, create an analysis
        result = mock_pat.analyze_actigraphy(
            patient_id="test-patient",
            readings=sample_readings,
            start_time="2025-03-28T00:00:00Z",
            end_time="2025-03-28T08:00:00Z",
            sampling_rate_hz=10.0,
            device_info=sample_device_info,
            analysis_types=[
                "sleep",
                "activity",
                "circadian_rhythm",
                "behavioral_patterns",
                "mood_indicators",
            ],
        )

        analysis_id = result["analysis_id"]

        # Now, integrate with a digital twin profile
        integration = mock_pat.integrate_with_digital_twin(
            patient_id="test-patient",
            profile_id="test-profile",
            analysis_id=analysis_id,
        )

        # Verify response structure
        assert integration["patient_id"] == "test-patient"
        assert integration["profile_id"] == "test-profile"
        assert integration["integration_status"] == "success"
        assert "timestamp" in integration
        assert "integrated_profile" in integration

        # Verify that the profile was stored
        profile_id = integration["profile_id"]
        assert profile_id in mock_pat.profiles

        # Verify integrated profile structure
        profile = integration["integrated_profile"]
        assert profile["id"] == "test-profile"
        assert profile["patient_id"] == "test-patient"
        assert profile["actigraphy_analysis_id"] == analysis_id

        # Verify that all analysis components were integrated
        assert "activity_summary" in profile
        assert "sleep_summary" in profile
        assert "circadian_rhythm" in profile
        assert "behavioral_insights" in profile
        assert "mood_assessment" in profile

    def test_integrate_with_digital_twin_analysis_not_found(self, mock_pat) -> None:
        """Test integration with digital twin when analysis not found."""
        with pytest.raises(ResourceNotFoundError) as excinfo:
            mock_pat.integrate_with_digital_twin(
                patient_id="test-patient",
                profile_id="test-profile",
                analysis_id="non-existent-id",
            )

        excinfo.match(r"Analysis .* not found")

    def test_integrate_with_digital_twin_wrong_patient(
        self, mock_pat, sample_readings, sample_device_info
    ) -> None:
        """Test integration with digital twin when analysis belongs to different patient."""
        # First, create an analysis for patient1
        result = mock_pat.analyze_actigraphy(
            patient_id="patient1",
            readings=sample_readings,
            start_time="2025-03-28T00:00:00Z",
            end_time="2025-03-28T08:00:00Z",
            sampling_rate_hz=10.0,
            device_info=sample_device_info,
            analysis_types=["sleep"],
        )

        analysis_id = result["analysis_id"]

        # Now, try to integrate with a profile for patient2
        with pytest.raises(AuthorizationError) as excinfo:
            mock_pat.integrate_with_digital_twin(
                patient_id="patient2",  # Different patient
                profile_id="test-profile",
                analysis_id=analysis_id,
            )

        assert "does not belong to patient" in str(excinfo.value)

    def test_uninitialized_error(self) -> None:
        """Test calling methods before initialization."""
        # Create a fresh instance of MockPATService that's guaranteed to be uninitialized
        uninitialized_service = MockPAT()  # Corrected: Use MockPAT as defined by `as MockPAT`
        with pytest.raises(InitializationError):  # InitializationError is from base_exceptions
            uninitialized_service.get_model_info()
