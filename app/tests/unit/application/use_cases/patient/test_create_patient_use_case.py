from unittest.mock import AsyncMock

import pytest

from app.application.use_cases.patient.create_patient import CreatePatientUseCase
from app.domain.entities.patient import Patient


@pytest.mark.asyncio
async def test_execute_creates_patient_and_returns_result():
    # Arrange
    mock_repo = AsyncMock()
    dummy_patient = Patient(id="123", date_of_birth="1990-01-01", gender="F")
    mock_repo.create.return_value = dummy_patient
    use_case = CreatePatientUseCase(mock_repo)
    patient_data = {"id": "123", "date_of_birth": "1990-01-01", "gender": "F"}

    # Act
    result = await use_case.execute(patient_data)

    # Assert
    mock_repo.create.assert_awaited_once()
    created_arg = mock_repo.create.call_args.args[0]
    assert isinstance(created_arg, Patient)
    assert created_arg.id == patient_data["id"]
    assert created_arg.gender == patient_data["gender"]
    assert result is dummy_patient


@pytest.mark.asyncio
async def test_execute_raises_value_error_for_invalid_data():
    # Arrange
    mock_repo = AsyncMock()
    use_case = CreatePatientUseCase(mock_repo)
    invalid_data = {"id": "123"}  # Missing date_of_birth and gender

    # Act & Assert
    with pytest.raises(ValueError):
        await use_case.execute(invalid_data)
    mock_repo.create.assert_not_called()
