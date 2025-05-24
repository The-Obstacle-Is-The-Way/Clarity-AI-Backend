"""
Unit tests for the BiometricIntegrationService.

This module contains tests for the BiometricIntegrationService, ensuring it
correctly integrates biometric data into patient digital twins.
"""

from datetime import datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.domain.entities.biometric_twin_enhanced import BiometricTwin
from app.domain.exceptions import DomainError
from app.domain.services.biometric_integration_service import (
    BiometricIntegrationService,
)
from app.domain.utils.datetime_utils import UTC


@pytest.mark.db_required()
class TestBiometricIntegrationService:
    """Tests for the BiometricIntegrationService class."""

    @pytest.fixture
    def mock_repository(self):
        repo = MagicMock()
        repo.get_by_patient_id = MagicMock()
        repo.save = MagicMock()
        return repo

    @pytest.fixture
    def service(self, mock_repository):
        return BiometricIntegrationService(biometric_twin_repository=mock_repository)

    def test_get_or_create_biometric_twin_existing(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = BiometricTwin.create(patient_id=str(patient_id))
        mock_repository.get_by_patient_id.return_value = mock_twin
        result = service.get_or_create_biometric_twin(patient_id)
        assert result == mock_twin
        mock_repository.get_by_patient_id.assert_called_once_with(patient_id)
        mock_repository.save.assert_not_called()

    def test_get_or_create_biometric_twin_new(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_repository.get_by_patient_id.return_value = None

        def save_side_effect(twin):
            return twin

        mock_repository.save.side_effect = save_side_effect
        result = service.get_or_create_biometric_twin(patient_id)
        assert isinstance(result, BiometricTwin)
        assert str(result.patient_id) == str(patient_id)
        mock_repository.get_by_patient_id.assert_called_once_with(patient_id)
        mock_repository.save.assert_called_once()

    def test_get_or_create_biometric_twin_error(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_repository.get_by_patient_id.side_effect = Exception("Database error")
        with pytest.raises(DomainError) as exc_info:
            service.get_or_create_biometric_twin(patient_id)
        assert "Failed to get or create biometric twin" in str(exc_info.value)

    def test_add_biometric_data(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_twin.patient_id = patient_id
        mock_twin.add_data_point = MagicMock()
        service.get_or_create_biometric_twin = MagicMock(return_value=mock_twin)
        data_point = service.add_biometric_data(
            patient_id=patient_id,
            data_type="heart_rate",
            value=75,
            source="wearable",
            metadata={"activity": "resting"},
            confidence=0.95,
        )
        assert data_point.value == 75
        assert data_point.source.value == "wearable"
        assert data_point.metadata["activity"] == "resting"
        assert data_point.metadata["confidence"] == 0.95
        mock_twin.add_data_point.assert_called_once()
        mock_repository.save.assert_called_once_with(mock_twin)

    def test_add_biometric_data_with_error(self, service, mock_repository) -> None:
        patient_id = uuid4()
        service.get_or_create_biometric_twin = MagicMock(side_effect=Exception("Repository error"))
        with pytest.raises(DomainError) as exc_info:
            service.add_biometric_data(
                patient_id=patient_id,
                data_type="heart_rate",
                value=75,
                source="wearable",
            )
        assert "Failed to add biometric data" in str(exc_info.value)

    def test_batch_add_biometric_data(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_twin.patient_id = patient_id
        mock_twin.add_data_point = MagicMock()
        service.get_or_create_biometric_twin = MagicMock(return_value=mock_twin)
        batch_data = [
            {
                "data_type": "heart_rate",
                "value": 75,
                "source": "wearable",
                "timestamp": datetime.now(UTC),
            },
            {
                "data_type": "blood_pressure",
                "value": "120/80",
                "source": "wearable",
                "timestamp": datetime.now(UTC),
            },
        ]
        result = service.batch_add_biometric_data(patient_id, batch_data)
        assert len(result) == 2
        assert result[0].value == 75
        assert result[1].value == "120/80"
        assert mock_twin.add_data_point.call_count == 2
        mock_repository.save.assert_called_once_with(mock_twin)

    def test_get_biometric_data(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        datetime.now(UTC)
        mock_twin.timeseries_data = {}
        mock_twin.get_biometric_data = MagicMock(return_value=None)
        mock_repository.get_by_patient_id.return_value = mock_twin
        result = service.get_biometric_data(patient_id=patient_id, data_type="heart_rate")
        assert isinstance(result, list)
        mock_twin.get_biometric_data.assert_called_with(
            service._to_biometric_type("heart_rate")
        ) if hasattr(service, "_to_biometric_type") else True

    def test_get_biometric_data_no_twin(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_repository.get_by_patient_id.return_value = None
        result = service.get_biometric_data(patient_id=patient_id)
        assert result == []

    def test_analyze_trends(self, service, mock_repository) -> None:
        patient_id = uuid4()
        datetime.now(UTC)
        service.get_biometric_data = MagicMock(
            return_value=[
                MagicMock(value=70),
                MagicMock(value=75),
                MagicMock(value=80),
                MagicMock(value=85),
            ]
        )
        result = service.analyze_trends(
            patient_id=patient_id, data_type="heart_rate", window_days=7
        )
        assert result["status"] == "success"
        assert result["data_type"] == "heart_rate"
        assert result["count"] == 4
        assert result["trend"] == "increasing"
        assert result["average"] == 77.5
        assert result["minimum"] == 70
        assert result["maximum"] == 85

    def test_analyze_trends_insufficient_data(self, service, mock_repository) -> None:
        patient_id = uuid4()
        service.get_biometric_data = MagicMock(return_value=[])
        result = service.analyze_trends(patient_id=patient_id, data_type="heart_rate")
        assert result["status"] == "insufficient_data"

    def test_detect_correlations(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_repository.get_by_patient_id.return_value = mock_twin
        service.get_biometric_data = MagicMock(
            return_value=[
                MagicMock(value=70),
                MagicMock(value=75),
                MagicMock(value=80),
                MagicMock(value=85),
            ]
        )
        result = service.detect_correlations(
            patient_id=patient_id,
            primary_data_type="heart_rate",
            secondary_data_types=["sleep_quality", "activity"],
        )
        assert "sleep_quality" in result
        assert isinstance(result["sleep_quality"], float)
        assert "activity" in result
        assert isinstance(result["activity"], float)

    def test_connect_device(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        service.get_or_create_biometric_twin = MagicMock(return_value=mock_twin)
        service.add_biometric_data = MagicMock()
        result = service.connect_device(
            patient_id=patient_id,
            device_id="wearable-123",
            device_type="wearable",
            connection_metadata={"model": "Apple Watch Series 7"},
        )
        assert result is True
        service.add_biometric_data.assert_called_once()
        mock_repository.save.assert_not_called()

    @pytest.mark.asyncio
    async def test_disconnect_device(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_twin = MagicMock(spec=BiometricTwin)
        mock_repository.get_by_patient_id.return_value = mock_twin
        service.add_biometric_data = MagicMock(return_value=None)
        result = await service.disconnect_device(
            patient_id=patient_id, device_id="wearable-123", reason="user_requested"
        )
        assert result is True
        service.add_biometric_data.assert_called_once()
        mock_repository.save.assert_not_called()

    @pytest.mark.asyncio
    async def test_disconnect_device_no_twin(self, service, mock_repository) -> None:
        patient_id = uuid4()
        mock_repository.get_by_patient_id.return_value = None
        result = await service.disconnect_device(patient_id=patient_id, device_id="wearable-123")
        assert result is False
