"""
Standalone mock implementation of the PAT (Patient Actigraphy Tracking)
service.

This module provides a self-contained mock that can be used for testing
PAT functionality without requiring actual AWS or external service connections.
"""

import json
import logging
import uuid
import time
from datetime import datetime
from app.domain.utils.datetime_utils import UTC
from typing import Dict, List, Any, Optional

from app.core.exceptions.base_exceptions import (
    InitializationError,
    ResourceNotFoundError,
)
from app.core.services.ml.pat.exceptions import ValidationError


class MockPATService:
    """Mock implementation of the PAT service for standalone tests."""

    def __init__(self):
        """Initialize the Mock PAT service."""
        self._initialized = False
        self._mock_delay_ms = 0
        self._analyses = {}
        self._embeddings = {}
        self._patients_analyses = {}
        self._integrations = {}
        self._logger = logging.getLogger(__name__)

        # Supported analysis types
        self._supported_types = [
            "sleep",
            "activity",
            "stress",
            "circadian",
            "anomaly"
        ]

    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the PAT service.

        Args:
            config: Configuration settings for the service
        """
        self._initialized = True
        self._mock_delay_ms = config.get("mock_delay_ms", 0)
        self._logger.info("Mock PAT service initialized")

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
        readings: List[Dict[str, float]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: Dict[str, str],
        analysis_types: List[str],
    ) -> Dict[str, Any]:
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

        # Validate inputs
        if not readings:
            raise ValidationError("Readings must be a non-empty list")
        for reading in readings:
            if "x" not in reading or "y" not in reading or "z" not in reading:
                raise ValidationError(
                    "Each reading must contain x, y, z values")
        if sampling_rate_hz <= 0:
            raise ValidationError("Sampling rate must be positive")
        if (
            not device_info
            or "device_type" not in device_info
            or "manufacturer" not in device_info
        ):
            raise ValidationError(
                "Device info must include device_type and manufacturer"
            )
        if not analysis_types:
            raise ValidationError("Analysis types must be a non-empty list")
        for analysis_type in analysis_types:
            if analysis_type not in self._supported_types:
                raise ValidationError(
                    f"Unsupported analysis type: {analysis_type}")

        # Simulate processing delay
        self._simulate_delay()

        # Generate analysis results
        analysis_id = str(uuid.uuid4())

        # Create mock result data based on input
        result = {
            "analysis_id": analysis_id,
            "patient_id": patient_id,
            "created_at": datetime.now(UTC).isoformat(),
            "start_time": start_time,
            "end_time": end_time,
            "device_info": device_info,
            "analysis_types": analysis_types,
            "status": "completed",
            "results": {},
        }

        # Generate mock results for each analysis type
        for analysis_type in analysis_types:
            if analysis_type == "sleep":
                result["results"]["sleep"] = {
                    "efficiency": 87.5,
                    "duration_hours": 7.2,
                    "deep_sleep_percentage": 22.3,
                    "rem_sleep_percentage": 18.7,
                    "light_sleep_percentage": 59.0,
                    "sleep_onset_minutes": 15,
                    "wakeups": 2,
                }
            elif analysis_type == "activity":
                result["results"]["activity"] = {
                    "active_minutes": 245,
                    "sedentary_minutes": 720,
                    "calories_burned": 2150,
                    "step_count": 8500,
                    "intensity_scores": {
                        "light": 120,
                        "moderate": 85,
                        "vigorous": 40},
                }
            elif analysis_type == "stress":
                result["results"]["stress"] = {
                    "average_level": 3.2,
                    "peak_level": 7.8,
                    "low_periods": 2,
                    "high_periods": 3,
                    "recovery_time_minutes": 45,
                }
            else:
                # Generic data for other analysis types
                result["results"][analysis_type] = {
                    "score": 75.0, "confidence": 0.85, "metrics": {
                        "metric1": 0.6, "metric2": 0.8, "metric3": 0.4, }, }

        # Store the analysis
        self._analyses[analysis_id] = result

        # Associate with patient
        if patient_id not in self._patients_analyses:
            self._patients_analyses[patient_id] = []
        self._patients_analyses[patient_id].append(analysis_id)
        return result

    def get_actigraphy_embeddings(
        self,
        patient_id: str,
        readings: List[Dict[str, float]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        embedding_dim: int = 384,
    ) -> Dict[str, Any]:
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
        self._simulate_delay()

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

        # Store the embedding
        self._embeddings[embedding_id] = result

        return result

    def get_analysis_by_id(self, analysis_id: str) -> Dict[str, Any]:
        """
        Retrieve an analysis by its ID.

        Args:
            analysis_id: The ID of the analysis to retrieve

        Returns:
            Dict containing the analysis data

        Raises:
            InitializationError: If the service is not initialized
            ResourceNotFoundError: If the analysis is not found
        """
        self._check_initialized()
        if analysis_id not in self._analyses:
            raise ResourceNotFoundError(f"Analysis not found: {analysis_id}")
        return self._analyses[analysis_id]

    def get_patient_analyses(
        self, patient_id: str, limit: int = 10, offset: int = 0
    ) -> Dict[str, Any]:
        """
        Retrieve all analyses for a patient with pagination.

        Args:
            patient_id: The ID of the patient
            limit: Maximum number of analyses to return
            offset: Number of analyses to skip

        Returns:
            Dict containing the analyses and pagination info

        Raises:
            InitializationError: If the service is not initialized
        """
        self._check_initialized()

        # Get all analysis IDs for this patient
        analysis_ids = self._patients_analyses.get(patient_id, [])
        total = len(analysis_ids)

        # Apply pagination
        paginated_ids = analysis_ids[offset: offset + limit]

        # Get full analysis data for each ID
        analyses = [self._analyses[aid] for aid in paginated_ids]

        return {
            "analyses": analyses,
            "pagination": {
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total,
            },
        }

    def get_model_info(self) -> Dict[str, Any]:
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
            "supported_analysis_types": self._supported_types,
            "supported_devices": [
                "Actigraph wGT3X-BT",
                "Apple Watch",
                "Fitbit Sense",
                "Oura Ring",
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

    def integrate_with_digital_twin(
        self, patient_id: str, profile_id: str, analysis_id: str
    ) -> Dict[str, Any]:
        """
        Integrate analysis results with a digital twin profile.

        Args:
            patient_id: The ID of the patient
            profile_id: The ID of the digital twin profile
            analysis_id: The ID of the analysis to integrate

        Returns:
            Dict with integration results

        Raises:
            InitializationError: If the service is not initialized
            ResourceNotFoundError: If the analysis is not found
        """
        self._check_initialized()

        # Verify the analysis exists
        if analysis_id not in self._analyses:
            raise ResourceNotFoundError(f"Analysis not found: {analysis_id}")

        # Verify the analysis belongs to the patient
        analysis = self._analyses[analysis_id]
        if analysis["patient_id"] != patient_id:
            raise ValidationError(
                f"Analysis {analysis_id} does not belong to patient {patient_id}")

        # Simulate processing delay
        self._simulate_delay()

        # Generate a unique ID for this integration
        integration_id = str(uuid.uuid4())

        # Create mock integration result
        result = {
            "integration_id": integration_id,
            "patient_id": patient_id,
            "profile_id": profile_id,
            "analysis_id": analysis_id,
            "created_at": datetime.now(UTC).isoformat(),
            "status": "completed",
            "updated_profile": {
                "profile_id": profile_id,
                "patient_id": patient_id,
                "last_updated": datetime.now(UTC).isoformat(),
                "insights": [],
            },
        }

        # Generate insights based on the analysis types
        analysis_types = analysis["analysis_types"]

        if "sleep" in analysis_types:
            result["updated_profile"]["insights"].append(
                {
                    "type": "sleep",
                    "title": "Sleep Quality Insight",
                    "description": "Sleep quality has been moderate with occasional disruptions.",
                    "confidence": 0.85,
                    "recommendations": [
                        "Maintain consistent sleep schedule",
                        "Reduce screen time before bed",
                    ],
                })
        if "activity" in analysis_types:
            result["updated_profile"]["insights"].append(
                {
                    "type": "activity",
                    "title": "Activity Pattern Insight",
                    "description": "Activity levels have been below recommended guidelines.",
                    "confidence": 0.78,
                    "recommendations": [
                        "Increase daily steps to 10,000",
                        "Add 30 minutes of moderate exercise",
                    ],
                })

        # Store the integration
        self._integrations[integration_id] = result

        return result
