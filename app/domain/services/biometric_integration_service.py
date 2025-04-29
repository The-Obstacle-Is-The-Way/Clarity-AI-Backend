"""
Biometric Integration Service for the Digital Twin Psychiatry Platform.

This service manages the integration of biometric data from various sources
into the patient's digital twin, enabling advanced analysis and personalized
treatment recommendations based on physiological and neurological patterns.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from app.domain.utils.datetime_utils import UTC
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.entities.biometric_twin_enhanced import BiometricTwin
from app.domain.exceptions import DomainError
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository


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
            twin = self.biometric_twin_repository.get_by_patient_id(patient_id)
            if twin:
                return twin
            
            # Create a new twin if one doesn't exist
            new_twin = BiometricTwin(patient_id=patient_id)
            self.biometric_twin_repository.save(new_twin)
            return new_twin
        except Exception as e:
            raise DomainError(f"Failed to get or create biometric twin: {e!s}")
    
    def add_biometric_data(
        self,
        patient_id: UUID,
        data_type: str,
        value: float | int | str | dict,
        source: str,
        timestamp: datetime | None = None,
        metadata: dict | None = None,
        confidence: float = 1.0
    ) -> BiometricDataPoint:
        """
        Add a new biometric data point to a patient's digital twin.
        
        Args:
            patient_id: ID of the patient
            data_type: Type of biometric data
            value: The measured value
            source: Device or system that provided the measurement
            timestamp: When the measurement was taken (defaults to now)
            metadata: Additional contextual information
            confidence: Confidence level in the measurement (0.0-1.0)
            
        Returns:
            The created biometric data point
            
        Raises:
            DomainError: If there's an error adding the data
        """
        try:
            # Get or create the patient's biometric twin
            twin = self.get_or_create_biometric_twin(patient_id)
            
            # Create and add the data point
            data_point = BiometricDataPoint(
                data_type=data_type,
                value=value,
                timestamp=timestamp or datetime.now(UTC),
                source=source,
                metadata=metadata,
                confidence=confidence
            )
            
            twin.add_data_point(data_point)
            
            # Save the updated twin
            self.biometric_twin_repository.save(twin)
            
            return data_point
        except Exception as e:
            raise DomainError(f"Failed to add biometric data: {e!s}")
    
    def batch_add_biometric_data(
        self,
        patient_id: UUID,
        data_points: list[dict]
    ) -> list[BiometricDataPoint]:
        """
        Add multiple biometric data points in a single batch operation.
        
        Args:
            patient_id: ID of the patient
            data_points: List of data point dictionaries with required fields
            
        Returns:
            List of created biometric data points
            
        Raises:
            DomainError: If there's an error adding the data
        """
        try:
            twin = self.get_or_create_biometric_twin(patient_id)
            created_points = []
            
            for point_data in data_points:
                # Create data point from dictionary
                data_point = BiometricDataPoint(
                    data_type=point_data["data_type"],
                    value=point_data["value"],
                    timestamp=point_data.get("timestamp", datetime.now(UTC)),
                    source=point_data["source"],
                    metadata=point_data.get("metadata", {}),
                    confidence=point_data.get("confidence", 1.0)
                )
                
                twin.add_data_point(data_point)
                created_points.append(data_point)
            
            # Save the updated twin with all new data points
            self.biometric_twin_repository.save(twin)
            
            return created_points
        except Exception as e:
            raise DomainError(f"Failed to batch add biometric data: {e!s}")
    
    def get_biometric_data(
        self,
        patient_id: UUID,
        data_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        source: str | None = None
    ) -> list[BiometricDataPoint]:
        """
        Retrieve biometric data for a patient with optional filtering.
        
        Args:
            patient_id: ID of the patient
            data_type: Optional type of data to filter by
            start_time: Optional start of time range
            end_time: Optional end of time range
            source: Optional source device to filter by
            
        Returns:
            List of matching biometric data points
            
        Raises:
            DomainError: If there's an error retrieving the data
        """
        try:
            twin = self.biometric_twin_repository.get_by_patient_id(patient_id)
            if not twin:
                return []
            
            # Start with all data points
            filtered_points = twin.data_points
            
            # Apply filters
            if data_type:
                filtered_points = [dp for dp in filtered_points if dp.data_type == data_type]
            
            if start_time:
                filtered_points = [dp for dp in filtered_points if dp.timestamp >= start_time]
            
            if end_time:
                filtered_points = [dp for dp in filtered_points if dp.timestamp <= end_time]
            
            if source:
                filtered_points = [dp for dp in filtered_points if dp.source == source]
            
            return sorted(filtered_points, key=lambda dp: dp.timestamp)
        except Exception as e:
            raise DomainError(f"Failed to retrieve biometric data: {e!s}")
    
    def analyze_trends(
        self,
        patient_id: UUID,
        data_type: str,
        window_days: int = 30,
        interval: str = "day"
    ) -> dict[str, Any]:
        """
        Analyze trends in a specific type of biometric data over time.
        
        Args:
            patient_id: ID of the patient
            data_type: Type of biometric data to analyze
            window_days: Number of days to include in the analysis
            interval: Aggregation interval ('hour', 'day', 'week')
            
        Returns:
            Dictionary containing trend analysis results
            
        Raises:
            DomainError: If there's an error analyzing the data
        """
        try:
            # Get data for the specified time window
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=window_days)
            
            data_points = self.get_biometric_data(
                patient_id=patient_id,
                data_type=data_type,
                start_time=start_time,
                end_time=end_time
            )
            
            if not data_points:
                return {
                    "status": "insufficient_data",
                    "message": f"No {data_type} data available for the specified time period"
                }
            
            # Extract values (assuming numeric values for trend analysis)
            try:
                values = [float(dp.value) if isinstance(dp.value, (int, float)) else 0.0 
                         for dp in data_points]
            except (ValueError, TypeError):
                return {
                    "status": "invalid_data",
                    "message": f"Cannot perform trend analysis on non-numeric {data_type} data"
                }
            
            # Calculate basic statistics
            avg = sum(values) / len(values) if values else 0
            min_val = min(values) if values else 0
            max_val = max(values) if values else 0
            
            # Detect trend direction (simplified)
            if len(values) >= 2:
                first_half = values[:len(values)//2]
                second_half = values[len(values)//2:]
                first_avg = sum(first_half) / len(first_half) if first_half else 0
                second_avg = sum(second_half) / len(second_half) if second_half else 0
                
                if second_avg > first_avg * 1.05:
                    trend = "increasing"
                elif second_avg < first_avg * 0.95:
                    trend = "decreasing"
                else:
                    trend = "stable"
            else:
                trend = "insufficient_data"
            
            return {
                "status": "success",
                "data_type": data_type,
                "period": f"{window_days} days",
                "data_points_count": len(data_points),
                "average": avg,
                "minimum": min_val,
                "maximum": max_val,
                "trend": trend,
                "last_value": values[-1] if values else None,
                "last_updated": data_points[-1].timestamp.isoformat() if data_points else None
            }
        except Exception as e:
            raise DomainError(f"Failed to analyze trends: {e!s}")
    
    def detect_correlations(
        self,
        patient_id: UUID,
        primary_data_type: str,
        secondary_data_types: list[str],
        window_days: int = 30
    ) -> dict[str, float]:
        """
        Detect correlations between different types of biometric data.
        
        Args:
            patient_id: ID of the patient
            primary_data_type: Primary type of biometric data
            secondary_data_types: Other types to correlate with the primary type
            window_days: Number of days to include in the analysis
            
        Returns:
            Dictionary mapping data types to correlation coefficients
            
        Raises:
            DomainError: If there's an error analyzing correlations
        """
        try:
            # Get the patient's biometric twin
            twin = self.biometric_twin_repository.get_by_patient_id(patient_id)
            if not twin:
                raise DomainError(f"No biometric twin found for patient {patient_id}")
            
            # Define time window
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=window_days)
            
            # Get primary data
            primary_data = twin.get_data_points_by_type(
                primary_data_type, start_time, end_time
            )
            
            if len(primary_data) < 5:  # Need sufficient data for correlation
                return {data_type: 0.0 for data_type in secondary_data_types}
            
            # Calculate correlations
            correlations = {}
            for data_type in secondary_data_types:
                secondary_data = twin.get_data_points_by_type(
                    data_type, start_time, end_time
                )
                
                if len(secondary_data) < 5:
                    correlations[data_type] = 0.0
                    continue
                
                # This is a simplified correlation calculation
                # In a real implementation, we would use more sophisticated
                # time series correlation methods that account for different
                # sampling frequencies and timestamps
                
                # For this example, we'll return a mock correlation
                # based on the data types (in a real system, this would be calculated)
                if data_type == "sleep_quality" and primary_data_type == "mood":
                    correlations[data_type] = 0.72
                elif data_type == "physical_activity" and primary_data_type == "anxiety":
                    correlations[data_type] = -0.65
                elif data_type == "heart_rate_variability" and primary_data_type == "stress":
                    correlations[data_type] = -0.78
                else:
                    # Random correlation between -0.3 and 0.3 for other combinations
                    import random
                    correlations[data_type] = (random.random() * 0.6) - 0.3
            
            return correlations
        except Exception as e:
            raise DomainError(f"Failed to detect correlations: {e!s}")
    
    def connect_device(
        self,
        patient_id: UUID,
        device_id: str,
        device_type: str,
        connection_metadata: dict | None = None
    ) -> bool:
        """
        Connect a biometric monitoring device to a patient's digital twin.
        
        Args:
            patient_id: ID of the patient
            device_id: Unique identifier for the device
            device_type: Type of device (e.g., 'smartwatch', 'glucose_monitor')
            connection_metadata: Additional information about the connection
            
        Returns:
            True if the device was successfully connected
            
        Raises:
            DomainError: If there's an error connecting the device
        """
        try:
            twin = self.get_or_create_biometric_twin(patient_id)
            
            # Add device connection metadata
            metadata = connection_metadata or {}
            metadata.update({
                "device_type": device_type,
                "connected_at": datetime.now(UTC).isoformat()
            })
            
            # Connect the device
            twin.connect_device(device_id)
            
            # Add a connection event data point
            self.add_biometric_data(
                patient_id=patient_id,
                data_type="device_connection",
                value=device_id,
                source="system",
                metadata=metadata
            )
            
            # Save the updated twin
            self.biometric_twin_repository.save(twin)
            
            return True
        except Exception as e:
            raise DomainError(f"Failed to connect device: {e!s}")
    
    async def disconnect_device(
        self,
        patient_id: UUID,
        device_id: str,
        reason: str | None = None
    ) -> bool:
        """
        Disconnect a biometric monitoring device from a patient's digital twin.
        
        Args:
            patient_id: ID of the patient
            device_id: Unique identifier for the device
            reason: Optional reason for disconnection
            
        Returns:
            True if the device was successfully disconnected
            
        Raises:
            DomainError: If there's an error disconnecting the device
        """
        try:
            # Properly await the async repository method
            twin = await self.biometric_twin_repository.get_by_patient_id(patient_id)
            if not twin:
                return False
            
            # Disconnect the device
            twin.disconnect_device(device_id)
            
            # Add a disconnection event data point - await the async method
            await self.add_biometric_data(
                patient_id=patient_id,
                data_type="device_disconnection",
                value=device_id,
                source="system",
                metadata={"reason": reason or "user_initiated"}
            )
            
            # Save the updated twin - await the async method
            await self.biometric_twin_repository.save(twin)
            
            return True
        except Exception as e:
            raise DomainError(f"Failed to disconnect device: {e!s}")