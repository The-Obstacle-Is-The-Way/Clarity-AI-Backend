"""
Temporal neurotransmitter sequence model for the Enhanced Digital Twin.

This module defines the class for representing time series data specifically for
neurotransmitter levels across different brain regions.
"""
import uuid
from datetime import datetime, timedelta
from typing import Any, cast
from uuid import UUID

from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    Neurotransmitter,
    TemporalResolution,
)
from app.domain.entities.temporal_sequence import TemporalSequence


class TemporalNeurotransmitterSequence(TemporalSequence):
    """
    A specialized temporal sequence for tracking neurotransmitter levels over time.

    This class extends the base TemporalSequence to provide specific functionality
    for neurotransmitter data, including methods for adding data points for specific
    neurotransmitters in specific brain regions.
    """

    def __init__(
        self,
        patient_id: UUID,
        start_time: datetime,
        end_time: datetime,
        resolution_hours: float = 24.0,
        sequence_id: UUID | None = None,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize a new temporal neurotransmitter sequence.

        Args:
            patient_id: UUID of the associated patient
            start_time: Start time of the sequence
            end_time: End time of the sequence
            resolution_hours: Time resolution in hours
            sequence_id: Optional UUID for the sequence (auto-generated if None)
            name: Optional name for the sequence
            metadata: Optional additional metadata
        """
        # Calculate number of time points based on resolution
        total_hours = (end_time - start_time).total_seconds() / 3600
        num_points = max(1, int(total_hours / resolution_hours)) + 1

        # Generate timestamps
        timestamps = [start_time + timedelta(hours=i * resolution_hours) for i in range(num_points)]

        # Determine temporal resolution enum value
        if resolution_hours <= 1:
            temp_resolution = TemporalResolution.HOURLY
        elif resolution_hours <= 24:
            temp_resolution = TemporalResolution.DAILY
        else:
            temp_resolution = TemporalResolution.WEEKLY

        # Calculate feature names based on all neurotransmitters and brain regions
        feature_names = []
        for nt in Neurotransmitter:
            for region in BrainRegion:
                feature_names.append(f"{nt.value}_{region.value}")

        # Initialize with empty values (all zeros)
        values = [[0.0 for _ in range(len(feature_names))] for _ in range(len(timestamps))]

        # Generate sequence ID if not provided
        if sequence_id is None:
            sequence_id = uuid.uuid4()

        # Set up metadata
        meta = metadata or {}
        meta.update(
            {
                "resolution_hours": resolution_hours,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            }
        )

        # Initialize base class
        super().__init__(
            sequence_id=sequence_id,
            feature_names=feature_names,
            timestamps=timestamps,
            values=values,
            patient_id=patient_id,
            metadata=meta,
            name=name or f"NT-Sequence-{str(sequence_id)[:8]}",
            temporal_resolution=temp_resolution,
        )

        # Additional properties specific to neurotransmitter sequences
        self.start_time = start_time
        self.end_time = end_time
        self.resolution_hours = resolution_hours

        # Cache for feature indices
        self._feature_indices = {feature: idx for idx, feature in enumerate(feature_names)}

    def add_data_point(
        self,
        timestamp: datetime,
        neurotransmitter: Neurotransmitter,
        brain_region: BrainRegion,
        value: float,
    ) -> bool:
        """
        Add a data point for a specific neurotransmitter and brain region.

        Args:
            timestamp: Timestamp for the data point
            neurotransmitter: The neurotransmitter being measured
            brain_region: The brain region being measured
            value: The measured value (normalized 0.0-1.0)

        Returns:
            Boolean indicating success
        """
        # Find the closest timestamp in our sequence
        closest_idx = None
        min_diff = timedelta.max

        for idx, ts in enumerate(self.timestamps):
            diff = abs(ts - timestamp)
            if diff < min_diff:
                min_diff = diff
                closest_idx = idx

        # If closest timestamp is too far away, return False
        if min_diff > timedelta(hours=self.resolution_hours):
            return False

        # Get feature index
        feature_name = f"{neurotransmitter.value}_{brain_region.value}"
        if feature_name not in self._feature_indices:
            return False

        feature_idx = self._feature_indices[feature_name]

        # Update the value
        self._values[closest_idx][feature_idx] = max(0.0, min(1.0, value))
        self.updated_at = datetime.now()

        return True

    def get_neurotransmitter_levels(
        self, neurotransmitter: Neurotransmitter, brain_region: BrainRegion = None
    ) -> list[tuple[datetime, float]]:
        """
        Get the time series for a specific neurotransmitter.

        Args:
            neurotransmitter: The neurotransmitter to retrieve
            brain_region: Optional brain region filter

        Returns:
            List of (timestamp, value) tuples
        """
        result = []

        if brain_region:
            # Get data for specific region
            feature_name = f"{neurotransmitter.value}_{brain_region.value}"
            if feature_name not in self._feature_indices:
                return []

            feature_idx = self._feature_indices[feature_name]

            for idx, ts in enumerate(self.timestamps):
                result.append((ts, self._values[idx][feature_idx]))

        else:
            # Get average across all regions
            region_feature_idxs = []
            for feature, idx in self._feature_indices.items():
                if feature.startswith(f"{neurotransmitter.value}_"):
                    region_feature_idxs.append(idx)

            if not region_feature_idxs:
                return []

            for idx, ts in enumerate(self.timestamps):
                avg_value = sum(self._values[idx][f_idx] for f_idx in region_feature_idxs) / len(
                    region_feature_idxs
                )
                result.append((ts, avg_value))

        return result

    def get_brain_region_levels(
        self, brain_region: BrainRegion, neurotransmitter: Neurotransmitter = None
    ) -> list[tuple[datetime, float]]:
        """
        Get the time series for a specific brain region.

        Args:
            brain_region: The brain region to retrieve
            neurotransmitter: Optional neurotransmitter filter

        Returns:
            List of (timestamp, value) tuples
        """
        result = []

        if neurotransmitter:
            # Get data for specific neurotransmitter
            feature_name = f"{neurotransmitter.value}_{brain_region.value}"
            if feature_name not in self._feature_indices:
                return []

            feature_idx = self._feature_indices[feature_name]

            for idx, ts in enumerate(self.timestamps):
                result.append((ts, self._values[idx][feature_idx]))

        else:
            # Get average across all neurotransmitters
            nt_feature_idxs = []
            for feature, idx in self._feature_indices.items():
                if feature.endswith(f"_{brain_region.value}"):
                    nt_feature_idxs.append(idx)

            if not nt_feature_idxs:
                return []

            for idx, ts in enumerate(self.timestamps):
                avg_value = sum(self._values[idx][f_idx] for f_idx in nt_feature_idxs) / len(
                    nt_feature_idxs
                )
                result.append((ts, avg_value))

        return result

    def analyze_trend(
        self,
        neurotransmitter: Neurotransmitter,
        brain_region: BrainRegion,
        window_size: int = 3,
    ) -> dict[str, Any]:
        """
        Analyze the trend for a specific neurotransmitter and brain region.

        Args:
            neurotransmitter: The neurotransmitter to analyze
            brain_region: The brain region to analyze
            window_size: Moving average window size

        Returns:
            Dictionary with trend analysis
        """
        feature_name = f"{neurotransmitter.value}_{brain_region.value}"
        if feature_name not in self._feature_indices:
            return {"trend": "unknown", "significance": "low", "correlation": {}}

        feature_idx = self._feature_indices[feature_name]

        # Get the values
        values = [self._values[idx][feature_idx] for idx in range(len(self.timestamps))]

        # Skip if not enough data points
        if len(values) < 3:
            return {
                "trend": "insufficient_data",
                "significance": "low",
                "correlation": {},
            }

        # Calculate moving average
        ma_values = []
        for i in range(len(values)):
            window_start = max(0, i - window_size + 1)
            window = values[window_start : i + 1]
            ma_values.append(sum(window) / len(window))

        # Calculate trend
        start_ma = ma_values[0]
        end_ma = ma_values[-1]

        trend = "stable"
        if end_ma > start_ma + 0.1:
            trend = "increasing"
        elif end_ma < start_ma - 0.1:
            trend = "decreasing"

        # Calculate significance
        significance = "low"
        change = abs(end_ma - start_ma)
        if change > 0.3:
            significance = "high"
        elif change > 0.15:
            significance = "medium"

        # Calculate correlations with other features
        correlations = {}
        for other_feature, other_idx in self._feature_indices.items():
            if other_feature == feature_name:
                continue

            other_values = [self._values[idx][other_idx] for idx in range(len(self.timestamps))]

            # Calculate Pearson correlation
            corr = self._calculate_correlation(values, other_values)

            if abs(corr) > 0.7:
                correlations[other_feature] = corr

        return {
            "trend": trend,
            "significance": significance,
            "correlation": correlations,
        }

    def _calculate_correlation(self, x: list[float], y: list[float]) -> float:
        """
        Calculate Pearson correlation coefficient between two sequences.

        Args:
            x: First sequence of values
            y: Second sequence of values

        Returns:
            Correlation coefficient (-1.0 to 1.0)
        """
        n = len(x)
        if n != len(y) or n < 2:
            return 0.0

        # Calculate means
        x_mean = sum(x) / n
        y_mean = sum(y) / n

        # Calculate covariance and variances
        cov = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        var_x = sum((val - x_mean) ** 2 for val in x)
        var_y = sum((val - y_mean) ** 2 for val in y)

        # Calculate correlation
        if var_x == 0 or var_y == 0:
            return 0.0

        return cast(float, cov / ((var_x * var_y) ** 0.5))
