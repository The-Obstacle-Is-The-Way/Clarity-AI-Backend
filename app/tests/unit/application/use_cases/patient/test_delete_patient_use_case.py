from unittest.mock import AsyncMock

import pytest

from app.application.use_cases.patient.delete_patient import DeletePatientUseCase


@pytest.mark.asyncio
async def test_execute_calls_delete_and_returns_true():
    # Arrange
    mock_service = AsyncMock()
    mock_service.delete.return_value = True
    use_case = DeletePatientUseCase(mock_service)

    # Act
    result = await use_case.execute("123")

    # Assert
    mock_service.delete.assert_awaited_once_with("123")
    assert result is True
