"""Unit tests for BiometricTwin entity."""
import uuid
from datetime import datetime, timedelta

import pytest

from app.domain.entities.biometric_twin_enhanced import (
    BiometricDataPoint,
    BiometricSource,
    BiometricTimeseriesData,
    BiometricTwin,
    BiometricType,
)
from app.domain.value_objects.physiological_ranges import PhysiologicalRange


@pytest.fixture
def sample_data_points():
    """Create sample biometric data points for testing."""
    timestamp = datetime.now()
    return [
        BiometricDataPoint(
            timestamp=timestamp - timedelta(days=2),
            value=72.5,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        ),
        BiometricDataPoint(
            timestamp=timestamp - timedelta(days=1),
            value=75.0,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        ),
        BiometricDataPoint(
            timestamp=timestamp,
            value=70.5,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        ),
    ]


@pytest.fixture
def sample_physiological_range():
    """Create a sample physiological range for testing."""
    return PhysiologicalRange(min=60.0, max=100.0, critical_min=40.0, critical_max=140.0)


@pytest.fixture
def sample_timeseries(sample_data_points, sample_physiological_range):
    """Create a sample biometric timeseries for testing."""
    return BiometricTimeseriesData(
        biometric_type=BiometricType.HEART_RATE,
        unit="bpm",
        data_points=sample_data_points,
        physiological_range=sample_physiological_range,
    )


@pytest.fixture
def sample_biometric_twin(sample_timeseries):
    """Create a sample biometric twin for testing."""
    twin = BiometricTwin(
        patient_id="patient-123",
        timeseries_data={BiometricType.HEART_RATE: sample_timeseries},
    )
    return twin


class TestBiometricDataPoint:
    """Tests for the BiometricDataPoint class."""

    def test_init(self) -> None:
        """Test initialization of BiometricDataPoint."""
        timestamp = datetime.now()
        point = BiometricDataPoint(
            timestamp=timestamp,
            value=72.5,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        )

        assert point.timestamp == timestamp
        assert point.value == 72.5
        assert point.source == BiometricSource.WEARABLE
        assert point.metadata == {"device": "fitbit"}

    def test_to_dict(self) -> None:
        """Test converting data point to a dictionary."""
        timestamp = datetime.now()
        point = BiometricDataPoint(
            timestamp=timestamp,
            value=72.5,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        )

        result = point.to_dict()

        assert result["timestamp"] == timestamp.isoformat()
        assert result["value"] == 72.5
        assert result["source"] == "wearable"
        assert result["metadata"] == {"device": "fitbit"}

    def test_from_dict(self) -> None:
        """Test creating a data point from a dictionary."""
        timestamp = datetime.now()
        data = {
            "timestamp": timestamp.isoformat(),
            "value": 72.5,
            "source": "wearable",
            "metadata": {"device": "fitbit"},
        }

        point = BiometricDataPoint.from_dict(data)

        assert point.value == 72.5
        assert point.source == BiometricSource.WEARABLE
        assert point.metadata == {"device": "fitbit"}


class TestBiometricTimeseriesData:
    """Tests for the BiometricTimeseriesData class."""

    def test_init(self, sample_data_points, sample_physiological_range) -> None:
        """Test initialization of BiometricTimeseriesData."""
        timeseries = BiometricTimeseriesData(
            biometric_type=BiometricType.HEART_RATE,
            unit="bpm",
            data_points=sample_data_points,
            physiological_range=sample_physiological_range,
        )

        assert timeseries.biometric_type == BiometricType.HEART_RATE
        assert timeseries.unit == "bpm"
        assert len(timeseries.data_points) == 3
        assert timeseries.physiological_range == sample_physiological_range

    def test_add_data_point(self, sample_timeseries) -> None:
        """Test adding a data point to timeseries."""
        new_point = BiometricDataPoint(
            timestamp=datetime.now() + timedelta(hours=1),
            value=68.0,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        )

        initial_count = len(sample_timeseries.data_points)
        sample_timeseries.add_data_point(new_point)

        assert len(sample_timeseries.data_points) == initial_count + 1
        assert sample_timeseries.data_points[-1] == new_point

    def test_get_latest_value(self, sample_timeseries) -> None:
        """Test getting the latest data point."""
        latest = sample_timeseries.get_latest_value()

        assert latest.value == 70.5  # The latest value from the fixture

    def test_to_dict(self, sample_timeseries) -> None:
        """Test converting timeseries to dictionary."""
        result = sample_timeseries.to_dict()

        assert result["biometric_type"] == "heart_rate"
        assert result["unit"] == "bpm"
        assert len(result["data_points"]) == 3
        assert "physiological_range" in result
        assert result["physiological_range"]["min"] == 60.0

    def test_from_dict(self) -> None:
        """Test creating timeseries from dictionary."""
        now = datetime.now()
        data = {
            "biometric_type": "heart_rate",
            "unit": "bpm",
            "data_points": [
                {
                    "timestamp": now.isoformat(),
                    "value": 72.5,
                    "source": "wearable",
                    "metadata": {"device": "fitbit"},
                }
            ],
            "physiological_range": {
                "min": 60.0,
                "max": 100.0,
                "critical_min": 40.0,
                "critical_max": 140.0,
            },
        }

        timeseries = BiometricTimeseriesData.from_dict(data)

        assert timeseries.biometric_type == BiometricType.HEART_RATE
        assert timeseries.unit == "bpm"
        assert len(timeseries.data_points) == 1
        assert timeseries.data_points[0].value == 72.5
        assert timeseries.physiological_range.min == 60.0


class TestBiometricTwin:
    """Tests for the BiometricTwin class."""

    def test_init(self, sample_biometric_twin, sample_timeseries) -> None:
        """Test initialization of BiometricTwin."""
        assert sample_biometric_twin.patient_id == "patient-123"
        assert sample_biometric_twin.timeseries_data[BiometricType.HEART_RATE] == sample_timeseries

    def test_add_biometric_data(self, sample_biometric_twin) -> None:
        """Test adding a new biometric timeseries."""
        # Create a new timeseries
        bp_data_point = BiometricDataPoint(
            timestamp=datetime.now(),
            value={"systolic": 120, "diastolic": 80},
            source=BiometricSource.CLINICAL,
            metadata={"position": "sitting"},
        )

        bp_timeseries = BiometricTimeseriesData(
            biometric_type=BiometricType.BLOOD_PRESSURE,
            unit="mmHg",
            data_points=[bp_data_point],
        )

        # Add to twin
        sample_biometric_twin.add_biometric_data(bp_timeseries)

        assert BiometricType.BLOOD_PRESSURE in sample_biometric_twin.timeseries_data
        assert sample_biometric_twin.timeseries_data[BiometricType.BLOOD_PRESSURE] == bp_timeseries

    def test_add_data_point(self, sample_biometric_twin) -> None:
        """Test adding a data point to an existing timeseries."""
        new_point = BiometricDataPoint(
            timestamp=datetime.now() + timedelta(hours=1),
            value=68.0,
            source=BiometricSource.WEARABLE,
            metadata={"device": "fitbit"},
        )

        initial_count = len(
            sample_biometric_twin.timeseries_data[BiometricType.HEART_RATE].data_points
        )

        sample_biometric_twin.add_data_point(BiometricType.HEART_RATE, new_point)

        assert (
            len(sample_biometric_twin.timeseries_data[BiometricType.HEART_RATE].data_points)
            == initial_count + 1
        )

    def test_add_data_point_new_type(self, sample_biometric_twin) -> None:
        """Test adding a data point for a new biometric type."""
        new_point = BiometricDataPoint(
            timestamp=datetime.now(),
            value=98.6,
            source=BiometricSource.CLINICAL,
            metadata={"method": "oral"},
        )

        sample_biometric_twin.add_data_point(BiometricType.TEMPERATURE, new_point, "°C")

        assert BiometricType.TEMPERATURE in sample_biometric_twin.timeseries_data
        assert (
            len(sample_biometric_twin.timeseries_data[BiometricType.TEMPERATURE].data_points) == 1
        )
        assert sample_biometric_twin.timeseries_data[BiometricType.TEMPERATURE].unit == "°C"

    def test_get_biometric_data(self, sample_biometric_twin, sample_timeseries) -> None:
        """Test getting biometric data for a specific type."""
        result = sample_biometric_twin.get_biometric_data(BiometricType.HEART_RATE)

        assert result == sample_timeseries
        assert result.get_latest_value().value == 70.5

    def test_get_latest_values(self, sample_biometric_twin) -> None:
        """Test getting latest values for all biometric types."""
        # Add another biometric type
        bp_data_point = BiometricDataPoint(
            timestamp=datetime.now(),
            value={"systolic": 120, "diastolic": 80},
            source=BiometricSource.CLINICAL,
            metadata={"position": "sitting"},
        )

        sample_biometric_twin.add_data_point(BiometricType.BLOOD_PRESSURE, bp_data_point, "mmHg")

        latest_values = sample_biometric_twin.get_latest_values()

        assert len(latest_values) == 2
        assert BiometricType.HEART_RATE in latest_values
        assert BiometricType.BLOOD_PRESSURE in latest_values
        assert latest_values[BiometricType.HEART_RATE].value == 70.5
        assert latest_values[BiometricType.BLOOD_PRESSURE].value == {
            "systolic": 120,
            "diastolic": 80,
        }

    def test_to_dict(self, sample_biometric_twin) -> None:
        """Test converting a biometric twin to dictionary."""
        result = sample_biometric_twin.to_dict()

        assert result["id"] == sample_biometric_twin.id
        assert result["patient_id"] == "patient-123"
        assert "heart_rate" in result["timeseries_data"]
        assert result["timeseries_data"]["heart_rate"]["unit"] == "bpm"
        assert len(result["timeseries_data"]["heart_rate"]["data_points"]) == 3

    def test_from_dict(self) -> None:
        """Test creating a biometric twin from dictionary."""
        now = datetime.now()
        twin_id = str(uuid.uuid4())

        data = {
            "id": twin_id,
            "patient_id": "patient-456",
            "timeseries_data": {
                "heart_rate": {
                    "biometric_type": "heart_rate",
                    "unit": "bpm",
                    "data_points": [
                        {
                            "timestamp": now.isoformat(),
                            "value": 72.5,
                            "source": "wearable",
                            "metadata": {"device": "fitbit"},
                        }
                    ],
                    "physiological_range": {
                        "min": 60.0,
                        "max": 100.0,
                        "critical_min": 40.0,
                        "critical_max": 140.0,
                    },
                }
            },
            "created_at": (now - timedelta(days=30)).isoformat(),
            "updated_at": now.isoformat(),
        }

        twin = BiometricTwin.from_dict(data)

        assert twin.id == twin_id
        assert twin.patient_id == "patient-456"
        assert BiometricType.HEART_RATE in twin.timeseries_data
        assert twin.timeseries_data[BiometricType.HEART_RATE].unit == "bpm"
        assert len(twin.timeseries_data[BiometricType.HEART_RATE].data_points) == 1
        assert twin.timeseries_data[BiometricType.HEART_RATE].data_points[0].value == 72.5
