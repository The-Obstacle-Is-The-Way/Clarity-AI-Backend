from unittest.mock import AsyncMock

import pytest

from app.application.use_cases.patient.get_patient_by_id import GetPatientByIdUseCase
from app.domain.entities.patient import Patient
from app.domain.exceptions.patient_exceptions import PatientNotFoundError


@pytest.mark.asyncio
async def test_execute_returns_patient():
    # Arrange
    mock_service = AsyncMock()
    dummy_patient = Patient(id="123", date_of_birth="1990-01-01", gender="M")
    mock_service.get_by_id.return_value = dummy_patient
    use_case = GetPatientByIdUseCase(mock_service)

    # Act
    result = await use_case.execute("123")

    # Assert
    mock_service.get_by_id.assert_awaited_once_with("123")
    assert result is dummy_patient


@pytest.mark.asyncio
async def test_execute_propagates_not_found_error():
    # Arrange
    mock_service = AsyncMock()
    mock_service.get_by_id.side_effect = PatientNotFoundError("123")
    use_case = GetPatientByIdUseCase(mock_service)

    # Act & Assert
    with pytest.raises(PatientNotFoundError):
        await use_case.execute("123")
    mock_service.get_by_id.assert_awaited_once_with("123")
