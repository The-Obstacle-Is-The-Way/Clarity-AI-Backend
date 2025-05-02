from __future__ import annotations

# Standard library imports
import logging
import uuid
from datetime import datetime
from typing import Any

# Local application/library specific imports
from app.core.config import settings  # noqa: F401
from app.core.services.ml.pat.exceptions import (
    AuthorizationError,
    InitializationError,
    ResourceNotFoundError,
    ValidationError,
)
from app.domain.utils.datetime_utils import UTC

# --- Mock Service Class ---


class MockPATService:
    """Mock implementation of the PAT service for standalone tests."""

    _initialized: bool = False
    _mock_delay_ms: int = 0
    _logger = logging.getLogger(__name__)

    def __init__(self) -> None:
        self._mock_profiles: dict[str, dict[str, Any]] = {}
        self._mock_analyses: dict[str, dict[str, Any]] = {}

    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the PAT service.

        Args:
            config: Configuration settings for the service
        """
        # Check for re-initialization
        if self._initialized:
            raise InitializationError("MockPATService is already initialized.")

        # Validate configuration
        if config is None or not isinstance(config, dict):
            raise ValidationError("Configuration must be a dictionary.")
        
        mock_delay_ms = config.get("mock_delay_ms", 0) # Default to 0 if not provided
        if not isinstance(mock_delay_ms, int) or mock_delay_ms < 0:
            raise ValidationError("'mock_delay_ms' must be a non-negative integer.")
        
        self._mock_delay_ms = mock_delay_ms
        self._initialized = True
        self._logger.info(
            f"Mock PAT service initialized with config: {config}"
        )

    def shutdown(self) -> None:
        """(Mock) Shutdown the service and clear state."""
        self._initialized = False
        self._mock_analyses = {}
        self._mock_profiles = {}
        self._logger.info("Mock PAT service shut down.")

    def is_healthy(self) -> bool:
        """(Mock) Check if the service is initialized and healthy."""
        return self._initialized

    def _check_initialized(self) -> None:
        """
        Check if the service is initialized.

        Raises:
            InitializationError: If the service is not initialized
        """
        if not self._initialized:
            raise InitializationError("Mock PAT service not initialized")

    def _simulate_delay(self) -> None:
        """Simulate processing delay if configured."""
        if self._mock_delay_ms > 0:
            self._logger.debug(f"PAT Mock: Simulating delay of {self._mock_delay_ms} ms")
            # time.sleep(self._mock_delay_ms / 1000.0) # Remove blocking sleep
            pass # Keep block structure valid

    def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, float]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, Any],
        analysis_types: list[str],
    ) -> dict[str, Any]:
        """
        Analyze actigraphy data for a patient.

        Args:
            patient_id: Unique identifier for the patient
            readings: List of accelerometer readings (x, y, z)
            start_time: ISO-8601 formatted start time
            end_time: ISO-8601 formatted end time
            sampling_rate_hz: Sampling rate in Hz
            device_info: Information about the recording device
            analysis_types: Types of analysis to perform

        Returns:
            Dict with analysis results

        Raises:
            InitializationError: If the service is not initialized
            ValidationError: If input validation fails
        """
        self._check_initialized()
        self._validate_inputs(
            patient_id=patient_id,
            readings=readings,
            start_time_str=start_time,
            end_time_str=end_time,
            sampling_rate_hz=sampling_rate_hz,
            device_info=device_info,
            analysis_types=analysis_types,
        )

        # Simulate analysis delay
        if self._mock_delay_ms > 0:
            self._logger.debug(f"PAT Mock: Simulating delay of {self._mock_delay_ms} ms")
            # time.sleep(self._mock_delay_ms / 1000.0) # Remove blocking sleep
            pass # Keep block structure valid

        analysis_id = str(uuid.uuid4())
        creation_timestamp = datetime.now(UTC).isoformat()

        # Mock results based on analysis_types
        results: dict[str, Any] = {}
        for analysis_type in analysis_types:
            if analysis_type == "sleep":
                results["sleep"] = {
                    "efficiency": 87.5,
                    "duration_hours": 7.2,
                    "deep_sleep_percentage": 22.3,
                    "rem_sleep_percentage": 18.7,
                    "light_sleep_percentage": 59.0,
                    "sleep_onset_minutes": 15,
                    "wakeups": 2,
                }
            elif analysis_type == "activity":
                results["activity"] = {
                    "active_minutes": 245,
                    "sedentary_minutes": 720,
                    "calories_burned": 2150,
                    "step_count": 8500,
                    "intensity_scores": {
                        "light": 120,
                        "moderate": 85,
                        "vigorous": 40
                    },
                }
            elif analysis_type == "stress":
                results["stress"] = {
                    "average_level": 3.2,
                    "peak_level": 7.8,
                    "low_periods": 2,
                    "high_periods": 3,
                    "recovery_time_minutes": 45,
                }
            else:
                # Generic data for other analysis types
                results[analysis_type] = {
                    "score": 75.0, 
                    "confidence": 0.85, 
                    "metrics": {
                        "metric1": 0.6, 
                        "metric2": 0.8, 
                        "metric3": 0.4, 
                    }, 
                }

        # Store the analysis
        self._mock_analyses[analysis_id] = {
            "analysis_id": analysis_id,
            "patient_id": patient_id,
            "timestamp": creation_timestamp,
            "results": results,
            "metadata": {
                "device_info": device_info,
                "start_time": start_time,
                "end_time": end_time,
                "sampling_rate_hz": sampling_rate_hz,
                "readings_count": len(readings),
                "analysis_types": analysis_types,
            },
        }

        return self._mock_analyses[analysis_id]

    def _validate_inputs(
        self,
        patient_id: str | None,
        readings: list[dict[str, float]] | None,
        start_time_str: str | None,
        end_time_str: str | None,
        sampling_rate_hz: float | None,
        device_info: dict[str, Any] | None,
        analysis_types: list[str] | None,
    ) -> None:
        """Validate all inputs for the analyze_actigraphy method."""
        if not patient_id:
            raise ValidationError("Patient ID must be provided.")
        self._validate_readings(readings)
        start_time, end_time = self._validate_time_range(
            start_time_str, end_time_str
        )
        if sampling_rate_hz is None or sampling_rate_hz <= 0:
            raise ValidationError("Sampling rate must be a positive number.")
        self._validate_device_info(device_info)
        if not analysis_types:
            raise ValidationError("At least one analysis type must be specified.")

    def _validate_readings(
        self, readings: list[dict[str, float]] | None
    ) -> None:
        """(Mock) Validate actigraphy readings format and content."""
        if not readings or not isinstance(readings, list):
            raise ValidationError("Readings must be a non-empty list.")
        
        for i, reading in enumerate(readings):
            if not isinstance(reading, dict):
                raise ValidationError(f"Reading at index {i} is not a dictionary.")
            required_keys = {'x', 'y', 'z'}
            if not required_keys.issubset(reading.keys()):
                missing = required_keys - reading.keys()
                raise ValidationError(f"Reading at index {i} missing keys: {missing}")
            for axis in required_keys:
                if not isinstance(reading[axis], int | float):
                    raise ValidationError(
                        f"Value for '{axis}' at index {i} is not a number."
                    )

        self._logger.debug(f"Validated {len(readings)} readings.")

    def _validate_time_range(
        self, start_time_str: str | None, end_time_str: str | None
    ) -> tuple[datetime, datetime]:
        """Validate start and end time strings and their order."""
        if not start_time_str or not end_time_str:
             raise ValidationError("Start time and end time must be provided.")
        try:
            start_time = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            end_time = datetime.fromisoformat(end_time_str.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValidationError(f"Invalid ISO 8601 timestamp format: {e}") from e

        if end_time <= start_time:
            raise ValidationError("End time must be after start time.")
        return start_time, end_time

    def _validate_device_info(self, device_info: dict[str, Any] | None) -> None:
        """(Mock) Validate device information structure."""
        # This is likely called internally in a real implementation.
        # Added here mainly to satisfy test_device_info_validation.
        if not device_info or not isinstance(device_info, dict):
            raise ValidationError("Device info must be a dictionary.")

        required_keys = ["device_type", "manufacturer", "model", "placement"]
        missing_keys = [key for key in required_keys if key not in device_info]
        if missing_keys:
            raise ValidationError(f"Missing required device info keys: {', '.join(missing_keys)}")

        # Add specific type checks if needed (e.g., manufacturer is string)
        if not isinstance(device_info.get("manufacturer"), str):
            raise ValidationError("'manufacturer' must be a string.")
        if not isinstance(device_info.get("model"), str):
             raise ValidationError("'model' must be a string.")

        self._logger.debug(f"Device info validated: {device_info}")

    def create_patient_profile(
        self, patient_id: str, profile_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a patient profile (mock)."""
        self._check_initialized()
        if not patient_id:
            raise ValidationError("Patient ID must be provided for profile creation.")
        if not profile_data or not isinstance(profile_data, dict):
            raise ValidationError("Profile data must be a non-empty dictionary.")

        # In a real system, check if patient_id already has a profile
        # For mock, we can just create it. Generate a unique profile ID.
        profile_id = f"prof_{uuid.uuid4()}"
        
        # Store profile keyed by profile_id, including patient_id inside
        self._mock_profiles[profile_id] = {
            "profile_id": profile_id,
            "patient_id": patient_id,
            "timestamp": datetime.now(UTC).isoformat(), # Renamed from created_at
            **profile_data,
        }
        self._logger.info(f"Created profile {profile_id} for patient {patient_id}")
        return self._mock_profiles[profile_id]

    def get_patient_profile(self, patient_id: str) -> dict[str, Any]:
        """(Mock) Retrieves an existing patient profile by patient_id.
        
        Note: Mock searches linearly. Real system uses indexed lookup.
        """
        self._check_initialized()
        if not patient_id:
            raise ValidationError("Patient ID must be provided.")

        # Find the profile associated with the patient_id
        found_profile = None
        for profile in self._mock_profiles.values():
            if profile.get("patient_id") == patient_id:
                found_profile = profile
                break
                
        if not found_profile:
            raise ResourceNotFoundError(f"Profile for patient {patient_id} not found.")
            
        self._logger.debug(
            f"Retrieved profile {found_profile['profile_id']} for patient {patient_id}"
        )
        return found_profile

    def update_patient_profile(
        self, patient_id: str, profile_data: dict[str, Any]
    ) -> dict[str, Any]:
        """(Mock) Updates an existing patient profile by patient_id.
        
        Note: Mock searches linearly. Real system uses indexed lookup.
        """
        self._check_initialized()
        if not patient_id:
            raise ValidationError("Patient ID must be provided for update.")
        if not profile_data or not isinstance(profile_data, dict):
            raise ValidationError("Profile data must be a non-empty dictionary for update.")

        # Find the profile associated with the patient_id
        target_profile_id = None
        for prof_id, profile in self._mock_profiles.items():
            if profile.get("patient_id") == patient_id:
                target_profile_id = prof_id
                break

        if not target_profile_id:
            raise ResourceNotFoundError(f"Profile for patient {patient_id} not found for update.")

        # Update the found profile
        self._mock_profiles[target_profile_id].update(profile_data)
        # Keep updated_at distinct if needed, or unify later
        self._mock_profiles[target_profile_id]["updated_at"] = datetime.now(UTC).isoformat()
        self._logger.info(f"Updated profile {target_profile_id} for patient {patient_id}")
        return self._mock_profiles[target_profile_id]

    def get_analysis_by_id(self, analysis_id: str) -> dict[str, Any]:
        """(Mock) Retrieves analysis results by ID."""
        self._check_initialized()
        if not analysis_id:
            raise ValidationError("Analysis ID must be provided.")

        if analysis_id not in self._mock_analyses:
            raise ResourceNotFoundError(f"Analysis {analysis_id} not found")
            
        self._logger.info(f"Retrieved analysis {analysis_id}")
        return self._mock_analyses[analysis_id]

    def integrate_with_digital_twin(
        self,
        patient_id: str,
        analysis_id: str,
        twin_id: str | None = None,
    ) -> dict[str, Any]:
        """Integrate PAT analysis with digital twin (mock)."""
        self._check_initialized()
        if not patient_id:
            raise ValidationError("Patient ID must be provided for integration.")
        if not analysis_id:
            raise ValidationError("Analysis ID must be provided for integration.")

        # Verify analysis exists
        if analysis_id not in self._mock_analyses:
            raise ResourceNotFoundError(f"Analysis {analysis_id} not found.")
            
        analysis_data = self._mock_analyses[analysis_id]
        analysis_patient_id = analysis_data.get("patient_id")

        # Verify analysis belongs to the correct patient
        if analysis_patient_id != patient_id:
            # Use AuthorizationError or a specific MismatchError if defined
            raise AuthorizationError(
                f"Analysis {analysis_id} does not belong to patient {patient_id}."
            )

        # Verify patient profile exists (implicitly checked by get_patient_profile)
        try:
            self.get_patient_profile(patient_id)
        except ResourceNotFoundError as err:
             raise ResourceNotFoundError(
                 f"Patient profile for {patient_id} not found for integration."
             ) from err

        # Simulate integration
        integration_status = "success"
        integration_id = str(uuid.uuid4())
        integration_record = {
            "integration_id": integration_id,
            "patient_id": patient_id,
            "analysis_id": analysis_id,
            "twin_id": twin_id or f"mock_twin_{patient_id}",
            "status": integration_status,
            "timestamp": datetime.now(UTC).isoformat()
        }
        self._logger.info(
            f"Integrated analysis {analysis_id} for patient {patient_id} "
            f"with twin {integration_record['twin_id']}"
        )
        return integration_record

    def get_actigraphy_embeddings(
        self,
        patient_id: str,
        readings: list[dict[str, float]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        embedding_dim: int = 384,
    ) -> dict[str, Any]:
        """
        Generate embeddings from actigraphy data.

        Args:
            patient_id: Unique identifier for the patient
            readings: List of accelerometer readings (x, y, z)
            start_time: ISO-8601 formatted start time
            end_time: ISO-8601 formatted end time
            sampling_rate_hz: Sampling rate in Hz
            embedding_dim: Dimension of the embedding vector

        Returns:
            Dict with embedding results

        Raises:
            InitializationError: If the service is not initialized
            ValidationError: If input validation fails
        """
        self._check_initialized()

        # Validate inputs
        if not readings:
            raise ValidationError("Readings must be a non-empty list")
        if sampling_rate_hz <= 0:
            raise ValidationError("Sampling rate must be positive")

        # Simulate processing delay
        if self._mock_delay_ms > 0:
            self._logger.debug(f"PAT Mock: Simulating delay of {self._mock_delay_ms} ms")
            # time.sleep(self._mock_delay_ms / 1000.0) # Remove blocking sleep
            pass # Keep block structure valid

        # Generate embedding
        embedding_id = str(uuid.uuid4())

        # Create a deterministic embedding based on inputs
        embedding = []
        for i in range(embedding_dim):
            # Simple deterministic pattern based on i
            value = 0.1 * ((i % 10) - 5)
            if i % 2 == 0:
                value = -value
            embedding.append(value)

        # Create result
        result = {
            "embedding_id": embedding_id,
            "patient_id": patient_id,
            "created_at": datetime.now(UTC).isoformat(),
            "embedding_type": "actigraphy",
            "embedding_dim": embedding_dim,
            "embedding": embedding,
            "metadata": {
                "start_time": start_time,
                "end_time": end_time,
                "sampling_rate_hz": sampling_rate_hz,
                "readings_count": len(readings),
            },
        }

        self._logger.info(
            f"Generated embedding {embedding_id} for patient {patient_id} "
            f"using model {result['metadata']['model_name']}"
        )

        return result

    def get_patient_analyses(
        self,
        patient_id: str,
        page: int = 1,
        limit: int = 10
    ) -> dict[str, Any]:
        """
        Get paginated list of analyses for a patient.

        Args:
            patient_id: The ID of the patient
            page: Page number for pagination
            limit: Maximum number of analyses to return

        Returns:
            Dict containing the analyses and pagination info

        Raises:
            InitializationError: If the service is not initialized
        """
        self._check_initialized()

        # Get all analysis IDs for this patient (reformatted comprehension)
        analysis_ids = [
            aid for aid, analysis in self._mock_analyses.items()
            if analysis.get("patient_id") == patient_id
        ]
        total = len(analysis_ids)

        # Apply pagination
        offset = (page - 1) * limit
        paginated_ids = analysis_ids[offset: offset + limit]
        total_pages = -(-total // limit)  # Ceiling division

        analyses = [self._mock_analyses[aid] for aid in paginated_ids]

        return {
            "analyses": analyses,
            "pagination": {
                "page": page,
                "limit": limit,
                "total_items": total,
                "total_pages": total_pages,
            },
        }

    def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the PAT model.

        Returns:
            Dict with model information

        Raises:
            InitializationError: If the service is not initialized
        """
        self._check_initialized()
        return {
            "name": "MockPATModel",
            "version": "1.0.0",
            "description": "Mock implementation of the PAT model for testing",
            "capabilities": [
                "actigraphy_analysis",
                "sleep_detection",
                "activity_classification",
                "stress_assessment",
                "anomaly_detection",
            ],
            "supported_analysis_types": [
                "sleep",
                "activity",
                "stress",
                "circadian",
                "anomaly"
            ],
            "supported_devices": [
                "Actigraph wGT3X-BT",
                "Apple Watch",
                "Fitbit Sense",
                "Garmin Vivosmart",
                "Generic Accelerometer",
            ],
            "created_at": "2025-01-01T00:00:00Z",
            "last_updated": "2025-03-15T00:00:00Z",
            "accuracy_metrics": {
                "sleep_detection": 0.92,
                "activity_classification": 0.89,
                "stress_assessment": 0.85,
                "anomaly_detection": 0.78,
            },
        }

    def get_system_capabilities(self) -> dict[str, Any]:
        """
        Get system capabilities.

        Returns:
            Dict with system capabilities
        """
        self._check_initialized()
        return {
            "service_status": "operational" if self._initialized else "offline",
            "version": "mock-1.0.0",
            "supported_endpoints": [
                "/analyze",
                "/analysis/{analysis_id}",
                "/profiles",
                "/profiles/{patient_id}",
                "/integrate",
                "/embeddings",
                "/capabilities",
                "/health",
            ],
            "supported_analysis_types": [
                "sleep",
                "activity",
                "stress",
                "circadian",
                "anomaly",
            ],
            "supported_devices": [
                "Actigraph wGT3X-BT",
                "Apple Watch",
                "Fitbit Sense",
                "Garmin Vivosmart",
                "Generic Accelerometer", 
            ],
        }
