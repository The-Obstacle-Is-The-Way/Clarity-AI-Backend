"""
Biometric Integration Service for the Digital Twin Psychiatry Platform.

This service manages the integration of biometric data from various sources
into the patient's digital twin, enabling advanced analysis and personalized
treatment recommendations based on physiological and neurological patterns.
"""

import logging  # For actual logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID  # Ensure uuid4 is imported if used for default IDs

from app.domain.entities.biometric_twin_enhanced import (
    BiometricDataPoint,
    BiometricSource,
    BiometricTwin,
    BiometricType,
)
from app.domain.exceptions import DomainError
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository
from app.domain.utils.datetime_utils import UTC

logger = logging.getLogger(__name__)


class BiometricIntegrationService:
    """
    Service for integrating biometric data into patient digital twins.

    This service provides methods for collecting, processing, and analyzing
    biometric data from various sources (wearables, medical devices, etc.)
    and integrating it into the patient's digital twin for comprehensive
    psychiatric care.
    """

    def __init__(self, biometric_twin_repository: BiometricTwinRepository) -> None:
        """
        Initialize the BiometricIntegrationService.

        Args:
            biometric_twin_repository: Repository for storing and retrieving biometric twins
        """
        self.biometric_twin_repository = biometric_twin_repository

    def get_or_create_biometric_twin(self, patient_id: UUID) -> BiometricTwin:
        """
        Get an existing biometric twin or create a new one if it doesn't exist.

        Args:
            patient_id: ID of the patient

        Returns:
            The patient's biometric twin

        Raises:
            DomainError: If there's an error retrieving or creating the twin
        """
        try:
            str_patient_id = str(patient_id)  # EnhancedBiometricTwin.create expects str

            twin = self.biometric_twin_repository.get_by_patient_id(patient_id)
            if twin:
                return twin

            logger.info(f"Creating new BiometricTwin for patient_id: {str_patient_id}")
            new_twin = BiometricTwin.create(patient_id=str_patient_id)
            self.biometric_twin_repository.save(new_twin)
            logger.info(
                f"Successfully created and saved new BiometricTwin for patient_id: {str_patient_id}"
            )
            return new_twin
        except Exception as e:
            logger.error(
                f"Failed to get or create biometric twin for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            raise DomainError(
                f"Failed to get or create biometric twin for patient {patient_id}: {e!s}"
            )

    def add_biometric_data(
        self,
        patient_id: UUID,
        data_type: str,
        value: float | int | str | dict,
        source: str,
        timestamp: datetime | None = None,
        metadata: dict | None = None,
        confidence: float = 1.0,
    ) -> BiometricDataPoint:
        """
        Add a new biometric data point to a patient's digital twin.

        Args:
            patient_id: ID of the patient
            data_type: Type of biometric data (string, will be mapped to BiometricType)
            value: The measured value
            source: Device or system that provided the measurement (string, will be mapped to BiometricSource)
            timestamp: When the measurement was taken (defaults to now)
            metadata: Additional contextual information
            confidence: Confidence level (Note: EnhancedBiometricDataPoint does not take confidence in __init__, stored in metadata)

        Returns:
            The created biometric data point (EnhancedBiometricDataPoint)

        Raises:
            DomainError: If there's an error adding the data
            ValueError: If data_type or source are invalid
        """
        try:
            twin = self.get_or_create_biometric_twin(patient_id)

            try:
                biometric_type_enum = BiometricType(data_type.lower())
            except ValueError:
                err_msg = f"Invalid data_type: '{data_type}'. Must be one of {[t.value for t in BiometricType]}"
                logger.warning(err_msg)
                raise ValueError(err_msg)

            try:
                biometric_source_enum = BiometricSource(source.lower())
            except ValueError:
                err_msg = f"Invalid source: '{source}'. Must be one of {[s.value for s in BiometricSource]}"
                logger.warning(err_msg)
                raise ValueError(err_msg)

            data_point_timestamp = timestamp or datetime.now(UTC)

            current_metadata = metadata.copy() if metadata else {}
            current_metadata["confidence"] = confidence  # Corrected string literal

            data_point = BiometricDataPoint(
                timestamp=data_point_timestamp,
                value=value,
                source=biometric_source_enum,
                metadata=current_metadata,
            )

            twin.add_data_point(
                biometric_type=biometric_type_enum, data_point=data_point
            )

            self.biometric_twin_repository.save(twin)
            logger.info(
                f"Added biometric data ({biometric_type_enum.value}) for patient {patient_id}"
            )
            return data_point
        except ValueError as ve:
            logger.error(
                f"ValueError in add_biometric_data for patient {patient_id}: {ve!s}",
                exc_info=True,
            )
            raise ve
        except Exception as e:
            logger.error(
                f"Failed to add biometric data for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            raise DomainError(
                f"Failed to add biometric data for patient {patient_id}: {e!s}"
            )

    def batch_add_biometric_data(
        self, patient_id: UUID, data_points_dicts: list[dict]
    ) -> list[BiometricDataPoint]:
        """
        Add multiple biometric data points in a single batch operation.

        Args:
            patient_id: ID of the patient
            data_points_dicts: List of data point dictionaries. Each dict should contain:
                                 'data_type', 'value', 'source', and optionally
                                 'timestamp', 'metadata', 'confidence'.

        Returns:
            List of created biometric data points (EnhancedBiometricDataPoint)

        Raises:
            DomainError: If there's an error adding the data
            ValueError: If any data_type or source is invalid, or dict format is wrong
        """
        try:
            twin = self.get_or_create_biometric_twin(patient_id)
            created_points = []

            for i, point_data in enumerate(data_points_dicts):
                data_type_str = point_data.get("data_type")
                value = point_data.get("value")
                source_str = point_data.get("source")

                if not all(
                    [
                        isinstance(data_type_str, str),
                        value is not None,
                        isinstance(source_str, str),
                    ]
                ):
                    err_msg = f"Batch item {i}: Each data point must have string 'data_type', non-null 'value', and string 'source'."
                    logger.warning(err_msg)
                    raise ValueError(err_msg)

                try:
                    biometric_type_enum = BiometricType(data_type_str.lower())
                except ValueError:
                    err_msg = f"Batch item {i}: Invalid data_type '{data_type_str}'."
                    logger.warning(err_msg)
                    raise ValueError(err_msg)

                try:
                    biometric_source_enum = BiometricSource(source_str.lower())
                except ValueError:
                    err_msg = f"Batch item {i}: Invalid source '{source_str}'."
                    logger.warning(err_msg)
                    raise ValueError(err_msg)

                point_timestamp_input = point_data.get("timestamp", datetime.now(UTC))
                if isinstance(point_timestamp_input, str):
                    try:
                        point_timestamp = datetime.fromisoformat(
                            point_timestamp_input.replace("Z", "+00:00")
                        )
                    except ValueError:
                        err_msg = f"Batch item {i}: Invalid timestamp format '{point_timestamp_input}'."
                        logger.warning(err_msg)
                        raise ValueError(err_msg)
                elif isinstance(point_timestamp_input, datetime):
                    point_timestamp = point_timestamp_input
                else:
                    err_msg = f"Batch item {i}: Timestamp must be datetime object or ISO string."
                    logger.warning(err_msg)
                    raise ValueError(err_msg)

                point_metadata = point_data.get("metadata", {})
                if not isinstance(point_metadata, dict):
                    err_msg = f"Batch item {i}: Metadata must be a dictionary."
                    logger.warning(err_msg)
                    raise ValueError(err_msg)

                point_confidence = point_data.get("confidence", 1.0)
                point_metadata[
                    "confidence"
                ] = point_confidence  # Corrected string literal

                data_point = BiometricDataPoint(
                    timestamp=point_timestamp,
                    value=value,
                    source=biometric_source_enum,
                    metadata=point_metadata,
                )

                twin.add_data_point(
                    biometric_type=biometric_type_enum, data_point=data_point
                )
                created_points.append(data_point)

            if created_points:
                self.biometric_twin_repository.save(twin)
            logger.info(
                f"Batch added {len(created_points)} biometric data points for patient {patient_id}"
            )
            return created_points
        except ValueError as ve:
            logger.error(
                f"ValueError in batch_add_biometric_data for patient {patient_id}: {ve!s}",
                exc_info=True,
            )
            raise ve
        except Exception as e:
            logger.error(
                f"Failed to batch add biometric data for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            raise DomainError(
                f"Failed to batch add biometric data for patient {patient_id}: {e!s}"
            )

    def get_biometric_data(
        self,
        patient_id: UUID,
        data_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        source: str | None = None,
    ) -> list[BiometricDataPoint]:
        """
        Retrieve biometric data for a patient with optional filtering.
        """
        try:
            twin = self.biometric_twin_repository.get_by_patient_id(patient_id)
            if not twin:
                logger.info(
                    f"No BiometricTwin found for patient {patient_id} in get_biometric_data."
                )
                return []

            biometric_type_filter: BiometricType | None = None
            if data_type:
                try:
                    biometric_type_filter = BiometricType(data_type.lower())
                except ValueError:
                    logger.warning(
                        f"Invalid data_type filter '{data_type}' in get_biometric_data. Returning empty list."
                    )
                    return []

            biometric_source_filter: BiometricSource | None = None
            if source:
                try:
                    biometric_source_filter = BiometricSource(source.lower())
                except ValueError:
                    logger.warning(
                        f"Invalid source filter '{source}' in get_biometric_data. Returning empty list."
                    )
                    return []

            all_points: list[BiometricDataPoint] = []
            if biometric_type_filter:
                timeseries = twin.get_biometric_data(biometric_type_filter)
                if timeseries:
                    all_points.extend(timeseries.data_points)
            else:
                if hasattr(twin, "timeseries_data") and isinstance(
                    twin.timeseries_data, dict
                ):
                    for ts_type, timeseries_obj in twin.timeseries_data.items():
                        if hasattr(timeseries_obj, "data_points"):
                            all_points.extend(timeseries_obj.data_points)
                else:
                    logger.warning(
                        f"BiometricTwin for patient {patient_id} missing or has malformed timeseries_data attribute."
                    )

            filtered_points = all_points

            if start_time:
                filtered_points = [
                    dp for dp in filtered_points if dp.timestamp >= start_time
                ]

            if end_time:
                filtered_points = [
                    dp for dp in filtered_points if dp.timestamp <= end_time
                ]

            if biometric_source_filter:
                filtered_points = [
                    dp for dp in filtered_points if dp.source == biometric_source_filter
                ]

            return sorted(filtered_points, key=lambda dp: dp.timestamp)
        except Exception as e:
            logger.error(
                f"Failed to retrieve biometric data for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            raise DomainError(
                f"Failed to retrieve biometric data for patient {patient_id}: {e!s}"
            )

    def analyze_trends(
        self,
        patient_id: UUID,
        data_type: str,
        window_days: int = 30,
        interval: str = "day",
    ) -> dict[str, Any]:
        """
        Analyze trends in a specific type of biometric data over time.
        (Simplified placeholder implementation)
        """
        logger.info(f"Analyzing trends for patient {patient_id}, data_type {data_type}")
        try:
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=window_days)

            data_points = self.get_biometric_data(
                patient_id=patient_id,
                data_type=data_type,
                start_time=start_time,
                end_time=end_time,
            )

            if not data_points:
                return {
                    "status": "insufficient_data",
                    "message": f"No {data_type} data available for the specified time period",
                }

            values = []
            for dp in data_points:
                if isinstance(dp.value, (int, float)):
                    values.append(float(dp.value))
                elif (
                    isinstance(dp.value, dict)
                    and "value" in dp.value
                    and isinstance(dp.value["value"], (int, float))
                ):
                    values.append(float(dp.value["value"]))

            if not values:
                return {
                    "status": "invalid_data_format",
                    "message": f"Could not extract numeric values for {data_type} for trend analysis.",
                }

            avg_val = sum(values) / len(values)
            min_val = min(values)
            max_val = max(values)
            trend_direction = "stable"
            if len(values) >= 2:
                if values[-1] > values[0]:
                    trend_direction = "increasing"
                elif values[-1] < values[0]:
                    trend_direction = "decreasing"

            return {
                "status": "success",
                "data_type": data_type,
                "period": f"{window_days} days",
                "count": len(values),
                "average": avg_val,
                "minimum": min_val,
                "maximum": max_val,
                "trend": trend_direction,
                "last_value": values[-1] if values else None,
                "last_timestamp": data_points[-1].timestamp.isoformat()
                if data_points
                else None,
            }
        except Exception as e:
            logger.error(
                f"Failed to analyze trends for patient {patient_id}, data_type {data_type}: {e!s}",
                exc_info=True,
            )
            raise DomainError(f"Failed to analyze trends: {e!s}")

    def detect_correlations(
        self,
        patient_id: UUID,
        primary_data_type: str,
        secondary_data_types: list[str],
        window_days: int = 30,
    ) -> dict[str, float]:
        """
        Detect correlations between different types of biometric data.
        (Simplified placeholder implementation)
        """
        logger.info(
            f"Detecting correlations for patient {patient_id}, primary_data_type {primary_data_type}"
        )
        correlations = {}
        for sec_type in secondary_data_types:
            import random

            correlations[sec_type] = round(random.uniform(-0.8, 0.8), 2)

        if not correlations and secondary_data_types:
            correlations = dict.fromkeys(secondary_data_types, 0.0)

        return correlations

    def connect_device(
        self,
        patient_id: UUID,
        device_id: str,
        device_type: str,
        connection_metadata: dict | None = None,
    ) -> bool:
        """
        Connect a biometric monitoring device to a patient's digital twin.
        (Functionality related to twin.connect_device is commented out as method does not exist on EnhancedBiometricTwin)
        """
        logger.info(
            f"Attempting to connect device {device_id} ({device_type}) for patient {patient_id}"
        )
        try:
            twin = self.get_or_create_biometric_twin(patient_id)

            event_metadata = connection_metadata or {}
            event_metadata.update(
                {
                    "device_type": device_type,
                    "device_id": device_id,
                    "connection_status": "connected",
                    "connected_at": datetime.now(UTC).isoformat(),
                }
            )

            self.add_biometric_data(
                patient_id=patient_id,
                data_type="system_event",
                value={
                    "event": "device_connected",
                    "device_id": device_id,
                    "device_type": device_type,
                },
                source="system_service",
                metadata=event_metadata,
            )

            logger.info(
                f"Device connection event recorded for device {device_id}, patient {patient_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Failed to connect device {device_id} for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            raise DomainError(f"Failed to connect device: {e!s}")

    async def disconnect_device(
        self, patient_id: UUID, device_id: str, reason: str | None = None
    ) -> bool:
        """
        Disconnect a biometric monitoring device from a patient's digital twin.
        (Functionality related to twin.disconnect_device is commented out as method does not exist on EnhancedBiometricTwin)
        Calls to repository are synchronous. add_biometric_data is synchronous.
        """
        logger.info(
            f"Attempting to disconnect device {device_id} for patient {patient_id}"
        )
        try:
            twin = self.biometric_twin_repository.get_by_patient_id(
                patient_id
            )  # Synchronous
            if not twin:
                logger.warning(
                    f"BiometricTwin not found for patient {patient_id} during disconnect_device."
                )
                return False

            event_metadata = {
                "reason": reason or "user_initiated",
                "device_id": device_id,
                "disconnection_status": "disconnected",
                "disconnected_at": datetime.now(UTC).isoformat(),
            }

            self.add_biometric_data(  # Synchronous
                patient_id=patient_id,
                data_type="system_event",
                value={"event": "device_disconnected", "device_id": device_id},
                source="system_service",
                metadata=event_metadata,
            )

            logger.info(
                f"Device disconnection event recorded for device {device_id}, patient {patient_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Failed to disconnect device {device_id} for patient {patient_id}: {e!s}",
                exc_info=True,
            )
            raise DomainError(f"Failed to disconnect device: {e!s}")
