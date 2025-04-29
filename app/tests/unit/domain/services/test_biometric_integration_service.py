# -*- coding: utf-8 -*-
"""
Unit tests for the BiometricIntegrationService.

This module contains tests for the BiometricIntegrationService, ensuring it
correctly integrates biometric data into patient digital twins.
"""

import pytest
from datetime import datetime, timedelta
from app.domain.utils.datetime_utils import UTC
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from uuid import UUID, uuid4
from typing import Any

# Correct import for BiometricTwin
from app.domain.entities.digital_twin.digital_twin import DigitalTwin
from app.domain.entities.patient import Patient
from app.domain.entities.provider import Provider
# Correct import path for BiometricTwin
from app.domain.entities.biometric_twin_enhanced import BiometricTwin
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository
from app.domain.services.biometric_integration_service import BiometricIntegrationService
from app.domain.exceptions import DomainError
from app.domain.services.digital_twin_service import DigitalTwinService
# from app.infrastructure.external.devices.interface import WearableDevice  # Commented out: Path seems incorrect and usage unclear
# Keep existing BiometricDataPoint import if needed by tests
from app.domain.entities.biometric_twin import BiometricDataPoint


@pytest.mark.db_required()  # Assuming db_required is a valid marker
class TestBiometricIntegrationService:
    """Tests for the BiometricIntegrationService class."""
    
    @pytest.fixture
    def mock_repository(self):
        """Create a mock repository for testing."""
        repo = AsyncMock()  # Use AsyncMock for async methods
        repo.get_by_patient_id = AsyncMock()
        repo.save = AsyncMock()
        return repo
        
    @pytest.fixture
    def service(self, mock_repository):
        """Create a BiometricIntegrationService instance for testing."""
        return BiometricIntegrationService(
            biometric_twin_repository=mock_repository
        )

    @pytest.mark.asyncio
    async def test_get_or_create_biometric_twin_existing(self, service, mock_repository):
        """Test retrieving an existing biometric twin."""
        # Arrange
        patient_id = uuid4()
        mock_twin = BiometricTwin(patient_id=patient_id)
        mock_repository.get_by_patient_id.return_value = mock_twin

        # Act
        result = await service.get_or_create_biometric_twin(patient_id)

        # Assert
        assert result == mock_twin
        mock_repository.get_by_patient_id.assert_called_once_with(patient_id)
        mock_repository.save.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_or_create_biometric_twin_new(self, service, mock_repository):
        """Test creating a new biometric twin when one doesn't exist."""
        # Arrange
        patient_id = uuid4()
        mock_repository.get_by_patient_id.return_value = None
        # Make save return the object passed to it
        
        async def save_side_effect(twin):
            return twin
        mock_repository.save.side_effect = save_side_effect

        # Act
        result = await service.get_or_create_biometric_twin(patient_id)

        # Assert
        assert isinstance(result, BiometricTwin)
        assert result.patient_id == patient_id
        mock_repository.get_by_patient_id.assert_called_once_with(patient_id)
        mock_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_create_biometric_twin_error(self, service, mock_repository):
        """Test error handling when repository operations fail."""
        # Arrange
        patient_id = uuid4()
        mock_repository.get_by_patient_id.side_effect = Exception("Database error")

        # Act & Assert
        with pytest.raises(DomainError) as exc_info:
            await service.get_or_create_biometric_twin(patient_id)
            
        assert "Failed to get or create biometric twin" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_add_biometric_data(self, service, mock_repository):
        """Test adding a biometric data point."""
        # Arrange
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_twin.patient_id = patient_id
        mock_twin.add_data_point = MagicMock()  # Mock the method
        
        # Mock the get_or_create_biometric_twin method to return our mock twin
        service.get_or_create_biometric_twin = AsyncMock(return_value=mock_twin)
        
        # Act
        data_point = await service.add_biometric_data(
            patient_id=patient_id,
            data_type="heart_rate",
            value=75,
            source="smartwatch",
            metadata={"activity": "resting"},
            confidence=0.95
        )

        # Assert
        assert data_point.data_type == "heart_rate"
        assert data_point.value == 75
        assert data_point.source == "smartwatch"
        assert data_point.metadata == {"activity": "resting"}
        assert data_point.confidence == 0.95
        
        mock_twin.add_data_point.assert_called_once()
        # Check the argument passed to add_data_point
        call_args, _ = mock_twin.add_data_point.call_args
        added_dp = call_args[0]
        assert isinstance(added_dp, BiometricTwin)
        assert added_dp.data_type == "heart_rate"
        
        mock_repository.save.assert_called_once_with(mock_twin)

    @pytest.mark.asyncio
    async def test_add_biometric_data_with_error(self, service, mock_repository):
        """Test error handling when adding biometric data fails."""
        # Arrange
        patient_id = uuid4()
        service.get_or_create_biometric_twin = AsyncMock(side_effect=Exception("Repository error"))
        
        # Act & Assert
        with pytest.raises(DomainError) as exc_info:
            await service.add_biometric_data(
                patient_id=patient_id,
                data_type="heart_rate",
                value=75,
                source="smartwatch"
            )
            
        assert "Failed to add biometric data" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_batch_add_biometric_data(self, service, mock_repository):
        """Test adding multiple biometric data points in a batch."""
        # Arrange
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_twin.patient_id = patient_id
        mock_twin.add_data_point = MagicMock()  # Mock the method
        
        # Mock the get_or_create_biometric_twin method
        service.get_or_create_biometric_twin = AsyncMock(return_value=mock_twin)
        
        # Prepare batch data
        batch_data = [
            {
                "data_type": "heart_rate",
                "value": 75,
                "source": "smartwatch",
                "timestamp": datetime.now(UTC)
            },
            {
                "data_type": "blood_pressure",
                "value": "120/80",
                "source": "blood_pressure_monitor",
                "timestamp": datetime.now(UTC)
            }
        ]
        
        # Act
        result = await service.batch_add_biometric_data(patient_id, batch_data)
        
        # Assert
        assert len(result) == 2
        assert result[0].data_type == "heart_rate"
        assert result[1].data_type == "blood_pressure"
        
        assert mock_twin.add_data_point.call_count == 2
        mock_repository.save.assert_called_once_with(mock_twin)

    @pytest.mark.asyncio
    async def test_get_biometric_data(self, service, mock_repository):
        """Test retrieving biometric data with filtering."""
        # Arrange
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)

        # Create some test data points
        now = datetime.now(UTC)
        data_points = [
            BiometricTwin(
                data_type="heart_rate",
                value=75,
                timestamp=now,
                source="smartwatch",
                patient_id=patient_id
            ),
            BiometricTwin(
                data_type="heart_rate",
                value=80,
                timestamp=now - timedelta(hours=1),
                source="smartwatch",
                patient_id=patient_id
            ),
            BiometricTwin(
                data_type="blood_pressure",
                value="120/80",
                timestamp=now,
                source="blood_pressure_monitor",
                patient_id=patient_id
            )
        ]
        
        # Set up the mock twin's data points retrieval
        # Assume get_data_points exists
        mock_twin.get_data_points.return_value = data_points
        mock_repository.get_by_patient_id.return_value = mock_twin

        # Act - Get all heart rate data
        result = await service.get_biometric_data(
            patient_id=patient_id,
            data_type="heart_rate"
        )

        # Assert
        assert len(result) == 2
        assert all(dp.data_type == "heart_rate" for dp in result)
        mock_twin.get_data_points.assert_called_with(
            data_type="heart_rate", start_time=None, end_time=None, source=None
        )

        # Act - Get data from a specific source
        result = await service.get_biometric_data(
            patient_id=patient_id,
            source="blood_pressure_monitor"
        )

        # Assert
        assert len(result) == 1
        assert result[0].data_type == "blood_pressure"
        mock_twin.get_data_points.assert_called_with(
            data_type=None,
            start_time=None,
            end_time=None,
            source="blood_pressure_monitor"
        )

    @pytest.mark.asyncio
    async def test_get_biometric_data_no_twin(self, service, mock_repository):
        """Test retrieving biometric data when no twin exists."""
        # Arrange
        patient_id = uuid4()
        mock_repository.get_by_patient_id.return_value = None

        # Act
        result = await service.get_biometric_data(patient_id=patient_id)

        # Assert
        assert result == []

    @pytest.mark.asyncio
    async def test_analyze_trends(self, service, mock_repository):
        """Test analyzing trends in biometric data."""
        # Arrange
        patient_id = uuid4()

        # Mock the get_biometric_data method to return test data
        now = datetime.now(UTC)
        test_data = [
            BiometricTwin(
                data_type="heart_rate",
                value=70,
                timestamp=now - timedelta(days=3),
                source="smartwatch",
                patient_id=patient_id
            ),
            BiometricTwin(
                data_type="heart_rate",
                value=75,
                timestamp=now - timedelta(days=2),
                source="smartwatch",
                patient_id=patient_id
            ),
            BiometricTwin(
                data_type="heart_rate",
                value=80,
                timestamp=now - timedelta(days=1),
                source="smartwatch",
                patient_id=patient_id
            ),
            BiometricTwin(
                data_type="heart_rate",
                value=85,
                timestamp=now,
                source="smartwatch",
                patient_id=patient_id
            )
        ]
        
        service.get_biometric_data = AsyncMock(return_value=test_data)
        
        # Act
        result = await service.analyze_trends(
            patient_id=patient_id,
            data_type="heart_rate",
            window_days=7
        )

        # Assert
        assert result["status"] == "success"
        assert result["data_type"] == "heart_rate"
        assert result["data_points_count"] == 4
        assert result["trend"] == "increasing"  # Values are increasing
        assert result["average"] == 77.5  # (70+75+80+85)/4
        assert result["minimum"] == 70
        assert result["maximum"] == 85

    @pytest.mark.asyncio
    async def test_analyze_trends_insufficient_data(self, service, mock_repository):
        """Test analyzing trends with insufficient data."""
        # Arrange
        patient_id = uuid4()
        service.get_biometric_data = AsyncMock(return_value=[])

        # Act
        result = await service.analyze_trends(
            patient_id=patient_id,
            data_type="heart_rate"
        )

        # Assert
        await service.get_biometric_data.assert_awaited_once()
        assert result["status"] == "insufficient_data"
        assert result["data_type"] == "heart_rate"
        assert result["message"] == "Not enough data points to analyze trends"

    @pytest.mark.asyncio
    async def test_detect_correlations(self, service, mock_repository):
        """Test detecting correlations between different biometric data types."""
        # Arrange
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_repository.get_by_patient_id.return_value = mock_twin

        # Mock the get_data_points_by_type method to return sufficient data
        now = datetime.now(UTC)
        heart_rate_data = [
            BiometricTwin(
                data_type="heart_rate",
                value=70 + i,
                timestamp=now - timedelta(hours=i),
                source="smartwatch",
                patient_id=patient_id
            ) for i in range(10)
        ]
        
        sleep_data = [
            BiometricTwin(
                data_type="sleep_quality",
                value=0.8 - (i * 0.05),
                timestamp=now - timedelta(hours=i),
                source="sleep_tracker",
                patient_id=patient_id
            ) for i in range(10)
        ]
        
        # Configure the mock to return different data based on the data_type argument
        async def get_data_points_side_effect(data_type: str, *args: Any, **kwargs: Any) -> list:
            if data_type == "heart_rate":
                return heart_rate_data
            elif data_type == "sleep_quality":
                return sleep_data
            else:
                return []

        # Assume BiometricTwin has get_data_points method
        mock_twin.get_data_points = AsyncMock(side_effect=get_data_points_side_effect)

        # Act
        result = await service.detect_correlations(
            patient_id=patient_id,
            primary_data_type="heart_rate",
            secondary_data_types=["sleep_quality", "activity_level"]
        )

        # Assert
        assert "sleep_quality" in result
        assert isinstance(result["sleep_quality"], float)
        assert "activity_level" in result
        # Should be float or None if no data
        assert isinstance(result["activity_level"], float)

    @pytest.mark.asyncio
    async def test_connect_device(self, service, mock_repository):
        """Test connecting a device to a biometric twin."""
        # Arrange
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_twin.connect_device = MagicMock()  # Mock the method

        # Mock the get_or_create_biometric_twin method
        service.get_or_create_biometric_twin = AsyncMock(return_value=mock_twin)

        # Mock the add_biometric_data method
        service.add_biometric_data = AsyncMock()

        # Act
        result = await service.connect_device(
            patient_id=patient_id,
            device_id="smartwatch-123",
            device_type="smartwatch",
            connection_metadata={"model": "Apple Watch Series 7"}
        )

        # Assert
        assert result is True
        mock_twin.connect_device.assert_called_once_with("smartwatch-123")
        service.add_biometric_data.assert_called_once()  # Check if event was logged
        mock_repository.save.assert_called_once_with(mock_twin)

    @pytest.mark.asyncio
    async def test_disconnect_device(self, service, mock_repository):
        """Test disconnecting a device from a biometric twin."""
        # Arrange
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_twin.disconnect_device = MagicMock()  # Mock the method
        mock_repository.get_by_patient_id.return_value = mock_twin

        # Mock the add_biometric_data method as AsyncMock since it's an async method
        service.add_biometric_data = AsyncMock(return_value=None)

        # Act
        result = await service.disconnect_device(
            patient_id=patient_id,
            device_id="smartwatch-123",
            reason="user_requested"
        )

        # Assert
        assert result is True
        mock_twin.disconnect_device.assert_called_once_with("smartwatch-123")
        await service.add_biometric_data.assert_awaited_once()  # Use assert_awaited for async mocks
        mock_repository.save.assert_called_once_with(mock_twin)

    @pytest.mark.asyncio
    async def test_disconnect_device_no_twin(self, service, mock_repository):
        """Test disconnecting a device when no twin exists."""
        # Arrange
        patient_id = uuid4()
        mock_repository.get_by_patient_id.return_value = None

        # Act
        result = await service.disconnect_device(
            patient_id=patient_id,
            device_id="smartwatch-123"
        )

        # Assert
        assert result is False
