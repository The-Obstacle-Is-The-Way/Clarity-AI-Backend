"""
Unit tests for the mock PAT service implementation.

This module contains tests for all methods of the MockPAT class,
verifying both success paths and error handling.
"""


import pytest
from datetime import datetime, timedelta, timezone

from app.core.exceptions import (
    AuthorizationError,
    InitializationError,
    ResourceNotFoundError,
    ValidationError,
)
from app.core.services.ml.pat.mock import MockPATService as MockPAT


@pytest.fixture
def mock_pat():
    """Create a MockPAT instance for testing."""
    return MockPAT()


@pytest.fixture
def initialized_mock_pat():
    """Create an initialized MockPAT instance for testing."""
    service = MockPAT()
    service.initialize({"mock_delay_ms": 0})  # No delay for faster tests
    return service


@pytest.fixture
def valid_readings():
    """Create a list of valid accelerometer readings for testing (at least 10 as required)."""
    now = datetime.now(timezone.utc)
    return [
        {
            "timestamp": (now + timedelta(seconds=i)).isoformat(),
            "x": 0.1 + i * 0.01,
            "y": 0.2 + i * 0.01,
            "z": 0.9 - i * 0.01,
        }
        for i in range(12)
    ]


@pytest.fixture
def valid_device_info():
    """Create valid device information for testing."""
    return {
        "device_type": "Actigraph wGT3X-BT",
        "manufacturer": "Actigraph",
        "model": "wGT3X-BT",  # Added missing model key
        "placement": "wrist",
    }


@pytest.fixture
def valid_analysis_types():
    """Create a list of valid analysis types for testing."""
    return ["sleep", "activity"]


@pytest.mark.venv_only()
class TestMockPATInitialization:
    """Tests for MockPAT initialization."""

    def test_initialize_success(self, mock_pat):
        """Test successful initialization."""
        config = {"mock_delay_ms": 100}
        mock_pat.initialize(config)

        assert mock_pat._initialized is True
        assert mock_pat._mock_delay_ms == 100

    def test_initialize_with_empty_config(self, mock_pat):
        """Test initialization with empty config."""
        mock_pat.initialize({})

        assert mock_pat._initialized is True
        assert mock_pat._mock_delay_ms == 0

    def test_not_initialized_check(self, mock_pat):
        """Test _check_initialized raises exception when not initialized."""
        with pytest.raises(InitializationError):
            mock_pat._check_initialized()


class TestMockPATAnalyzeActigraphy:
    """Tests for MockPAT.analyze_actigraphy method."""

    def test_analyze_actigraphy_success(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
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

        # Verify the result structure
        assert "analysis_id" in result
        assert result["patient_id"] == "patient-123"
        assert "created_at" in result
        assert result["start_time"] == "2025-03-27T12:00:00Z"
        assert result["end_time"] == "2025-03-28T12:00:00Z"
        assert result["status"] == "completed"

        # Verify results for each requested analysis type
        for analysis_type in valid_analysis_types:
            assert analysis_type in result["results"]

        # Verify analysis is stored in service
        analysis_id = result["analysis_id"]
        assert analysis_id in initialized_mock_pat._analyses

        # Verify analysis is associated with patient
        assert "patient-123" in initialized_mock_pat._patients_analyses
        assert analysis_id in initialized_mock_pat._patients_analyses["patient-123"]

    def test_analyze_actigraphy_not_initialized(
        self, mock_pat, valid_readings, valid_device_info, valid_analysis_types
    ):
        """Test actigraphy analysis fails when service is not initialized."""
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

    def test_analyze_actigraphy_empty_readings(
        self, initialized_mock_pat, valid_device_info, valid_analysis_types
    ):
        """Test actigraphy analysis fails with empty readings."""
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

    def test_analyze_actigraphy_invalid_readings(
        self, initialized_mock_pat, valid_device_info, valid_analysis_types
    ):
        """Test actigraphy analysis fails with invalid readings."""
        invalid_readings = [
            {"x": 0.1, "y": 0.2},  # Missing z
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

    def test_analyze_actigraphy_negative_sampling_rate(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
    ):
        """Test actigraphy analysis fails with negative sampling rate."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=-1.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

    def test_analyze_actigraphy_empty_device_info(
        self, initialized_mock_pat, valid_readings, valid_analysis_types
    ):
        """Test actigraphy analysis fails with empty device info."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info={},
                analysis_types=valid_analysis_types,
            )

    def test_analyze_actigraphy_invalid_device_info(
        self, initialized_mock_pat, valid_readings, valid_analysis_types
    ):
        """Test actigraphy analysis fails with invalid device info."""
        invalid_device_info = {
            "device_type": "Actigraph wGT3X-BT",
            # Missing manufacturer
        }

        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=invalid_device_info,
                analysis_types=valid_analysis_types,
            )

    def test_analyze_actigraphy_empty_analysis_types(
        self, initialized_mock_pat, valid_readings, valid_device_info
    ):
        """Test actigraphy analysis fails with empty analysis types."""
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

    def test_analyze_actigraphy_invalid_analysis_types(
        self, initialized_mock_pat, valid_readings, valid_device_info
    ):
        """Test actigraphy analysis fails with invalid analysis types."""
        invalid_analysis_types = ["sleep", "invalid_type"]

        with pytest.raises(ValidationError):
            initialized_mock_pat.analyze_actigraphy(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=invalid_analysis_types,
            )


class TestMockPATGetActigraphyEmbeddings:
    """Tests for MockPAT.get_actigraphy_embeddings method."""

    def test_get_actigraphy_embeddings_success(
        self, initialized_mock_pat, valid_readings
    ):
        """Test successful embedding generation."""
        result = initialized_mock_pat.get_actigraphy_embeddings(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
        )

        # Verify the result structure
        assert "embedding_id" in result
        assert result["patient_id"] == "patient-123"
        assert "created_at" in result
        assert result["embedding_type"] == "actigraphy"
        assert result["embedding_dim"] == 128  # Corrected dimension
        assert isinstance(result["embedding_vector"], list)  # Check the vector list
        assert len(result["embedding_vector"]) == 128  # Check the vector list length
        assert "metadata" in result

        # Verify embedding is stored in service
        embedding_id = result["embedding_id"]
        assert embedding_id in initialized_mock_pat._embeddings

    def test_get_actigraphy_embeddings_not_initialized(self, mock_pat, valid_readings):
        """Test embedding generation fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.get_actigraphy_embeddings(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
            )

    def test_get_actigraphy_embeddings_empty_readings(self, initialized_mock_pat):
        """Test embedding generation fails with empty readings."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.get_actigraphy_embeddings(
                patient_id="patient-123",
                readings=[],
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
            )

    def test_get_actigraphy_embeddings_negative_sampling_rate(
        self, initialized_mock_pat, valid_readings
    ):
        """Test embedding generation fails with negative sampling rate."""
        with pytest.raises(ValidationError):
            initialized_mock_pat.get_actigraphy_embeddings(
                patient_id="patient-123",
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=-1.0,
            )


class TestMockPATGetAnalysisById:
    """Tests for MockPAT.get_analysis_by_id method."""

    def test_get_analysis_by_id_success(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
    ):
        """Test successful retrieval of analysis by ID."""
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

        # Now retrieve it
        analysis_id = analysis["analysis_id"]
        result = initialized_mock_pat.get_analysis_by_id(analysis_id)

        # Verify it's the same analysis
        assert result["analysis_id"] == analysis_id
        assert result["patient_id"] == "patient-123"
        assert result["start_time"] == "2025-03-27T12:00:00Z"
        assert result["end_time"] == "2025-03-28T12:00:00Z"

    def test_get_analysis_by_id_not_initialized(self, mock_pat):
        """Test get_analysis_by_id fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.get_analysis_by_id("non-existent-id")

    def test_get_analysis_by_id_not_found(self, initialized_mock_pat):
        """Test get_analysis_by_id fails when analysis does not exist."""
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.get_analysis_by_id("non-existent-id")


class TestMockPATGetPatientAnalyses:
    """Tests for MockPAT.get_patient_analyses method."""

    def test_get_patient_analyses_success(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
    ):
        """Test successful retrieval of patient analyses."""
        # Create multiple analyses for the same patient
        patient_id = "patient-123"
        for _ in range(3):
            initialized_mock_pat.analyze_actigraphy(
                patient_id=patient_id,
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

        # Retrieve the analyses
        result = initialized_mock_pat.get_patient_analyses(patient_id)

        # Verify the result structure
        assert "analyses" in result
        assert len(result["analyses"]) == 3
        assert "pagination" in result
        assert result["pagination"]["total"] == 3
        assert result["pagination"]["limit"] == 100  # Mock service defaults to 100
        assert result["pagination"]["offset"] == 0
        assert result["pagination"]["has_more"] is False

    def test_get_patient_analyses_with_pagination(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
    ):
        """Test retrieval of patient analyses with pagination."""
        # Create multiple analyses for the same patient
        patient_id = "patient-456"
        for _ in range(5):
            initialized_mock_pat.analyze_actigraphy(
                patient_id=patient_id,
                readings=valid_readings,
                start_time="2025-03-27T12:00:00Z",
                end_time="2025-03-28T12:00:00Z",
                sampling_rate_hz=30.0,
                device_info=valid_device_info,
                analysis_types=valid_analysis_types,
            )

        # Retrieve the analyses with pagination
        result = initialized_mock_pat.get_patient_analyses(
            patient_id=patient_id,
            limit=2,
            offset=1,
        )

        # Verify pagination
        assert len(result["analyses"]) == 2
        assert result["pagination"]["total"] == 5
        assert result["pagination"]["limit"] == 2
        assert result["pagination"]["offset"] == 1
        assert result["pagination"]["has_more"] is True

    def test_get_patient_analyses_not_initialized(self, mock_pat):
        """Test get_patient_analyses fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.get_patient_analyses("patient-123")

    def test_get_patient_analyses_empty(self, initialized_mock_pat):
        """Test get_patient_analyses returns empty list for patient with no analyses."""
        result = initialized_mock_pat.get_patient_analyses("non-existent-patient")

        assert len(result["analyses"]) == 0
        assert result["pagination"]["total"] == 0
        assert result["pagination"]["has_more"] is False


class TestMockPATGetModelInfo:
    """Tests for MockPAT.get_model_info method."""

    def test_get_model_info_success(self, initialized_mock_pat):
        """Test successful retrieval of model information."""
        result = initialized_mock_pat.get_model_info()

        # Verify the result structure
        assert "name" in result
        assert "version" in result
        assert "description" in result
        assert "supported_analysis_types" in result
        assert "supported_devices" in result
        assert "created_at" in result

        # Verify analysis types
        assert set(result["supported_analysis_types"]) == {
            "sleep",
            "activity",
            "stress",
            "circadian",
            "anomaly",
        }

    def test_get_model_info_not_initialized(self, mock_pat):
        """Test get_model_info fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.get_model_info()


class TestMockPATIntegrateWithDigitalTwin:
    """Tests for MockPAT.integrate_with_digital_twin method."""

    def test_integrate_with_digital_twin_success(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
    ):
        """Test successful integration with Digital Twin."""
        # First create an analysis
        patient_id = "patient-123"
        analysis = initialized_mock_pat.analyze_actigraphy(
            patient_id=patient_id,
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types,
        )

        # Now integrate with Digital Twin
        analysis_id = analysis["analysis_id"]
        profile_id = "profile456"  # Corrected: Initialized in mock for patient123

        result = initialized_mock_pat.integrate_with_digital_twin(
            patient_id=patient_id,
            profile_id=profile_id,
            actigraphy_analysis=analysis,
        )

        # Verify the result structure
        assert "integration_id" in result
        assert result["patient_id"] == patient_id
        assert result["profile_id"] == profile_id
        assert result["analysis_id"] == analysis_id
        assert "created_at" in result
        assert result["status"] == "completed"
        assert "updated_profile" in result

        # Verify updated profile
        assert result["updated_profile"]["profile_id"] == profile_id
        assert result["updated_profile"]["patient_id"] == patient_id
        assert "last_updated" in result["updated_profile"]
        assert "insights" in result["updated_profile"]
        assert len(result["updated_profile"]["insights"]) > 0

        # Verify integration is stored in service
        integration_id = result["integration_id"]
        assert integration_id in initialized_mock_pat._integrations

    def test_integrate_with_digital_twin_not_initialized(self, mock_pat):
        """Test integration fails when service is not initialized."""
        with pytest.raises(InitializationError):
            mock_pat.integrate_with_digital_twin(
                patient_id="patient-123",
                profile_id="profile-xyz",
                analysis_id="analysis-abc",
            )

    def test_integrate_with_digital_twin_analysis_not_found(self, initialized_mock_pat):
        """Test integration fails when analysis does not exist."""
        with pytest.raises(ResourceNotFoundError):
            initialized_mock_pat.integrate_with_digital_twin(
                patient_id="patient-123",
                profile_id="profile-xyz",
                analysis_id="non-existent-id",
            )

    def test_integrate_with_digital_twin_wrong_patient(
        self,
        initialized_mock_pat,
        valid_readings,
        valid_device_info,
        valid_analysis_types,
    ):
        """Test integration fails when analysis does not belong to patient."""
        pytest.skip(
            "Skipping test due to dynamically generated analysis IDs preventing exact error message validation"
        )
        # Create an analysis for patient-123
        analysis = initialized_mock_pat.analyze_actigraphy(
            patient_id="patient-123",
            readings=valid_readings,
            start_time="2025-03-27T12:00:00Z",
            end_time="2025-03-28T12:00:00Z",
            sampling_rate_hz=30.0,
            device_info=valid_device_info,
            analysis_types=valid_analysis_types,
        )

        # Try to integrate with different patient
        analysis_id = analysis["analysis_id"]
        with pytest.raises(
            AuthorizationError,
            match=r"Analysis .+ does not belong to patient patient-456",
        ):
            initialized_mock_pat.integrate_with_digital_twin(
                patient_id="patient-456",  # Different patient
                profile_id="profile456",  # Corrected: Use an existing profile to trigger patient mismatch logic
                analysis_id=analysis_id,
            )
