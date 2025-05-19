from unittest.mock import AsyncMock

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

from app.application.use_cases.patient.update_patient import UpdatePatientUseCase
from app.domain.entities.patient import Patient


@pytest.mark.asyncio
async def test_execute_calls_update_and_returns_patient():
    # Arrange
    mock_service = AsyncMock()
    dummy_patient = Patient(id="123", date_of_birth="1990-01-01", gender="M")
    mock_service.update.return_value = dummy_patient
    use_case = UpdatePatientUseCase(mock_service)
    updated_data = {"gender": "F"}

    # Act
    result = await use_case.execute("123", updated_data)

    # Assert
    mock_service.update.assert_awaited_once_with("123", updated_data)
    assert result is dummy_patient
