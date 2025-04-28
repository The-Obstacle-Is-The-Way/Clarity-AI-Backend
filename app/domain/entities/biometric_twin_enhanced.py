"""
Enhanced Biometric Twin domain entity module.

This module defines the core domain entities for the biometric digital twin system,
which is responsible for tracking and analyzing patient biometric data.
"""

from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from uuid import uuid4

from app.domain.value_objects.physiological_ranges import PhysiologicalRange


class BiometricSource(str, Enum):
    """Sources of biometric data."""
    
    WEARABLE = "wearable"
    CLINICAL = "clinical"
    PATIENT_REPORTED = "patient_reported"
    MOBILE_APP = "mobile_app"
    ENVIRONMENTAL = "environmental"
    RESEARCH_DEVICE = "research_device"


class BiometricType(str, Enum):
    """Types of biometric measurements."""
    
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    TEMPERATURE = "temperature"
    RESPIRATORY_RATE = "respiratory_rate"
    BLOOD_GLUCOSE = "blood_glucose"
    OXYGEN_SATURATION = "oxygen_saturation"
    SLEEP = "sleep"
    ACTIVITY = "activity"
    STRESS = "stress"
    MOOD = "mood"
    WEIGHT = "weight"
    HRV = "hrv"  # Heart Rate Variability


class BiometricDataPoint:
    """
    A single biometric measurement data point.
    
    Attributes:
        timestamp: When the measurement was taken
        value: Measurement value (can be numeric or structured data)
        source: Source of the measurement
        metadata: Additional contextual information
    """
    
    def __init__(
        self,
        timestamp: datetime,
        value: Any,
        source: BiometricSource,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a BiometricDataPoint.
        
        Args:
            timestamp: When the measurement was taken
            value: Measurement value (can be numeric or structured data)
            source: Source of the measurement
            metadata: Additional contextual information
        """
        self.timestamp = timestamp
        self.value = value
        self.source = source
        self.metadata = metadata or {}
    
    def add_metadata(self, data: Dict[str, Any]) -> None:
        """
        Add additional metadata to the data point.
        
        Args:
            data: Metadata to add
        """
        self.metadata.update(data)
    
    def get_normalized_value(self) -> float:
        """
        Get a normalized numeric value for comparison.
        
        For complex values like blood pressure, returns the primary value
        (e.g., systolic pressure).
        
        Returns:
            Normalized numeric value or 0.0 if not convertible
        """
        try:
            if isinstance(self.value, (int, float)):
                return float(self.value)
            
            if isinstance(self.value, dict):
                # For blood pressure, return systolic
                if "systolic" in self.value:
                    return float(self.value["systolic"])
                
                # For other structured data, return primary value
                if "value" in self.value:
                    return float(self.value["value"])
            
            # Try to convert to float if possible
            return float(self.value)
        
        except (ValueError, TypeError):
            # Return default value for non-numeric data
            return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.
        
        Returns:
            Dictionary with data point values
        """
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": self.value,
            "source": self.source.value,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BiometricDataPoint":
        """
        Create a BiometricDataPoint from a dictionary.
        
        Args:
            data: Dictionary with data point values
            
        Returns:
            New BiometricDataPoint instance
        """
        timestamp = (
            datetime.fromisoformat(data["timestamp"])
            if isinstance(data["timestamp"], str)
            else data["timestamp"]
        )
        
        source = (
            BiometricSource(data["source"])
            if isinstance(data["source"], str)
            else data["source"]
        )
        
        return cls(
            timestamp=timestamp,
            value=data["value"],
            source=source,
            metadata=data.get("metadata", {})
        )
    
    def __lt__(self, other: "BiometricDataPoint") -> bool:
        """
        Compare data points by timestamp.
        
        Args:
            other: Another data point to compare with
            
        Returns:
            True if this data point is earlier
        """
        return self.timestamp < other.timestamp


class BiometricTimeseriesData:
    """
    A time series of biometric measurements.
    
    Attributes:
        biometric_type: Type of biometric data
        unit: Unit of measurement
        data_points: Collection of data points in chronological order
        physiological_range: Normal and critical ranges for this biometric
    """
    
    def __init__(
        self,
        biometric_type: BiometricType,
        unit: str,
        data_points: List[BiometricDataPoint],
        physiological_range: Optional[PhysiologicalRange] = None
    ):
        """
        Initialize a BiometricTimeseriesData.
        
        Args:
            biometric_type: Type of biometric data
            unit: Unit of measurement
            data_points: Collection of data points
            physiological_range: Normal and critical ranges
        """
        self.biometric_type = biometric_type
        self.unit = unit
        self.data_points = sorted(data_points)  # Sort by timestamp
        
        # Use provided range or get default for this type
        self.physiological_range = physiological_range or PhysiologicalRange.get_default_range(biometric_type.value)
        
        # If no range exists, create a default one based on data
        if not self.physiological_range and data_points:
            values = [dp.get_normalized_value() for dp in data_points]
            if values:
                mean = sum(values) / len(values)
                std_dev = (sum((x - mean) ** 2 for x in values) / len(values)) ** 0.5
                self.physiological_range = PhysiologicalRange(
                    min=mean - std_dev,
                    max=mean + std_dev,
                    critical_min=mean - 3 * std_dev,
                    critical_max=mean + 3 * std_dev
                )
    
    def add_data_point(self, data_point: BiometricDataPoint) -> None:
        """
        Add a new data point to the timeseries.
        
        Args:
            data_point: Data point to add
        """
        self.data_points.append(data_point)
        self.data_points.sort()  # Re-sort to maintain chronological order
    
    def get_latest_value(self) -> Optional[BiometricDataPoint]:
        """
        Get the most recent data point.
        
        Returns:
            Latest data point or None if empty
        """
        return self.data_points[-1] if self.data_points else None
    
    def get_values_in_range(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> List[BiometricDataPoint]:
        """
        Get data points within a time range.
        
        Args:
            start_time: Range start time
            end_time: Range end time
            
        Returns:
            List of data points in the specified range
        """
        return [
            dp for dp in self.data_points
            if start_time <= dp.timestamp <= end_time
        ]
    
    def get_abnormal_values(self) -> List[BiometricDataPoint]:
        """
        Get data points with values outside normal range but not critical.
        
        Returns:
            List of data points with abnormal values
        """
        if not self.physiological_range:
            return []
            
        return [
            dp for dp in self.data_points
            if self.physiological_range.is_abnormal(dp.get_normalized_value())
        ]
    
    def get_critical_values(self) -> List[BiometricDataPoint]:
        """
        Get data points with values in critical range.
        
        Returns:
            List of data points with critical values
        """
        if not self.physiological_range:
            return []
            
        return [
            dp for dp in self.data_points
            if self.physiological_range.is_critical(dp.get_normalized_value())
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.
        
        Returns:
            Dictionary with timeseries data
        """
        return {
            "biometric_type": self.biometric_type.value,
            "unit": self.unit,
            "data_points": [dp.to_dict() for dp in self.data_points],
            "physiological_range": self.physiological_range.to_dict() if self.physiological_range else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BiometricTimeseriesData":
        """
        Create a BiometricTimeseriesData from a dictionary.
        
        Args:
            data: Dictionary with timeseries data
            
        Returns:
            New BiometricTimeseriesData instance
        """
        biometric_type = (
            BiometricType(data["biometric_type"])
            if isinstance(data["biometric_type"], str)
            else data["biometric_type"]
        )
        
        data_points = [
            BiometricDataPoint.from_dict(dp_data)
            for dp_data in data["data_points"]
        ]
        
        physiological_range = (
            PhysiologicalRange.from_dict(data["physiological_range"])
            if data.get("physiological_range")
            else None
        )
        
        return cls(
            biometric_type=biometric_type,
            unit=data["unit"],
            data_points=data_points,
            physiological_range=physiological_range
        )


class BiometricTwin:
    """
    Biometric digital twin for a patient.
    
    Represents all the biometric data collected for a patient,
    organized by measurement type.
    
    Attributes:
        id: Unique identifier for the twin
        patient_id: ID of the associated patient
        timeseries_data: Collection of biometric timeseries
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """
    
    def __init__(
        self,
        patient_id: str,
        timeseries_data: Dict[BiometricType, BiometricTimeseriesData],
        id: Optional[str] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None
    ):
        """
        Initialize a BiometricTwin.

        Args:
            patient_id: ID of the associated patient
            timeseries_data: Collection of biometric timeseries
            id: Unique identifier for the twin (auto-generated if None)
            created_at: Creation timestamp (auto-generated if None)
            updated_at: Last update timestamp (auto-generated if None)
        """
        now = datetime.now()
        self.id = id or str(uuid4())
        self.patient_id = patient_id
        self.timeseries_data = timeseries_data
        self.created_at = created_at or now
        self.updated_at = updated_at or now
    
    @classmethod
    def create(cls, patient_id: str) -> "BiometricTwin":
        """
        Create a new BiometricTwin for a patient.
        
        Args:
            patient_id: ID of the patient
            
        Returns:
            New BiometricTwin instance
        """
        now = datetime.now()
        return cls(
            id=str(uuid4()),
            patient_id=patient_id,
            timeseries_data={},
            created_at=now,
            updated_at=now
        )
    
    def add_biometric_data(self, timeseries: BiometricTimeseriesData) -> None:
        """
        Add a new biometric timeseries.
        
        Args:
            timeseries: Biometric timeseries to add
        """
        self.timeseries_data[timeseries.biometric_type] = timeseries
        self.updated_at = datetime.now()
    
    def add_data_point(
        self,
        biometric_type: BiometricType,
        data_point: BiometricDataPoint,
        unit: Optional[str] = None
    ) -> None:
        """
        Add a data point to a specific biometric timeseries.
        
        If the biometric type doesn't exist yet, it will be created.
        
        Args:
            biometric_type: Type of biometric data
            data_point: Data point to add
            unit: Unit of measurement (required for new timeseries)
        """
        # If this biometric type already exists, just add the data point
        if biometric_type in self.timeseries_data:
            self.timeseries_data[biometric_type].add_data_point(data_point)
        
        # Otherwise, create a new timeseries
        else:
            if not unit:
                # Get default unit for this type if not provided
                unit_map = {
                    BiometricType.HEART_RATE: "bpm",
                    BiometricType.BLOOD_PRESSURE: "mmHg",
                    BiometricType.TEMPERATURE: "°C",
                    BiometricType.RESPIRATORY_RATE: "breaths/min",
                    BiometricType.BLOOD_GLUCOSE: "mg/dL",
                    BiometricType.OXYGEN_SATURATION: "%",
                    BiometricType.WEIGHT: "kg",
                    BiometricType.HRV: "ms"
                }
                unit = unit_map.get(biometric_type, "")
            
            self.timeseries_data[biometric_type] = BiometricTimeseriesData(
                biometric_type=biometric_type,
                unit=unit,
                data_points=[data_point]
            )
        
        self.updated_at = datetime.now()
    
    def get_biometric_data(self, biometric_type: BiometricType) -> Optional[BiometricTimeseriesData]:
        """
        Get timeseries data for a specific biometric type.
        
        Args:
            biometric_type: Type of biometric data
            
        Returns:
            Biometric timeseries or None if not found
        """
        return self.timeseries_data.get(biometric_type)
    
    def get_latest_values(self) -> Dict[BiometricType, BiometricDataPoint]:
        """
        Get latest values for all biometric types.
        
        Returns:
            Dictionary mapping biometric types to their latest data points
        """
        return {
            biometric_type: timeseries.get_latest_value()
            for biometric_type, timeseries in self.timeseries_data.items()
            if timeseries.get_latest_value() is not None
        }
    
    def get_abnormal_values(self) -> Dict[BiometricType, List[BiometricDataPoint]]:
        """
        Get abnormal values for all biometric types.
        
        Returns:
            Dictionary mapping biometric types to lists of abnormal data points
        """
        return {
            biometric_type: timeseries.get_abnormal_values()
            for biometric_type, timeseries in self.timeseries_data.items()
            if timeseries.get_abnormal_values()
        }
    
    def get_critical_values(self) -> Dict[BiometricType, List[BiometricDataPoint]]:
        """
        Get critical values for all biometric types.
        
        Returns:
            Dictionary mapping biometric types to lists of critical data points
        """
        return {
            biometric_type: timeseries.get_critical_values()
            for biometric_type, timeseries in self.timeseries_data.items()
            if timeseries.get_critical_values()
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.
        
        Returns:
            Dictionary with BiometricTwin data
        """
        return {
            "id": self.id,
            "patient_id": self.patient_id,
            "timeseries_data": {
                biometric_type.value: timeseries.to_dict()
                for biometric_type, timeseries in self.timeseries_data.items()
            },
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BiometricTwin":
        """
        Create a BiometricTwin from a dictionary.
        
        Args:
            data: Dictionary with BiometricTwin data
            
        Returns:
            New BiometricTwin instance
        """
        # Convert string timestamps to datetime objects
        created_at = (
            datetime.fromisoformat(data["created_at"])
            if isinstance(data["created_at"], str)
            else data["created_at"]
        )
        
        updated_at = (
            datetime.fromisoformat(data["updated_at"])
            if isinstance(data["updated_at"], str)
            else data["updated_at"]
        )
        
        # Convert timeseries data
        timeseries_data = {}
        for type_str, ts_data in data["timeseries_data"].items():
            biometric_type = BiometricType(type_str)
            timeseries_data[biometric_type] = BiometricTimeseriesData.from_dict(ts_data)
        
        return cls(
            id=data["id"],
            patient_id=data["patient_id"],
            timeseries_data=timeseries_data,
            created_at=created_at,
            updated_at=updated_at
        )