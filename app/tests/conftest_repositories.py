"""
Pytest fixtures for repositories and database dependency injection.

This module provides fixtures for creating repository instances in tests,
enabling proper testing with SOLID principles and clean architecture.
"""
import pytest
from typing import AsyncGenerator, Any, Dict, Type, TypeVar
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock

from app.tests.utils.repository_factory import (
    create_repository,
    MockUnitOfWork,
    MockPatientRepository,
    MockBiometricRuleRepository,
    MockBiometricAlertRepository,
    MockBiometricTwinRepository
)

# Repository interfaces
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.repositories.biometric_rule_repository import BiometricRuleRepository
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository

# Import the domain Unit of Work interface
from app.domain.interfaces.unit_of_work import UnitOfWork

# Import the core IUserRepository interface
from app.core.interfaces.repositories.user_repository import IUserRepository

T = TypeVar('T')

@pytest.fixture
def mock_session() -> AsyncSession:
    """
    Create a mock AsyncSession for testing.
    
    Returns:
        AsyncMock instance that simulates an AsyncSession
    """
    mock = AsyncMock(spec=AsyncSession)
    # Add common session methods
    mock.execute = AsyncMock()
    mock.commit = AsyncMock()
    mock.rollback = AsyncMock()
    mock.close = AsyncMock()
    mock.refresh = AsyncMock()
    return mock

@pytest.fixture
def mock_unit_of_work(mock_session: AsyncSession) -> MockUnitOfWork:
    """
    Create a MockUnitOfWork for testing.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        MockUnitOfWork instance with the mock session
    """
    return MockUnitOfWork(mock_session)

@pytest.fixture
def user_repository(mock_session: AsyncSession) -> IUserRepository:
    """
    Create a mock UserRepository for testing.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        MockUserRepository instance
    """
    return MockUserRepository(mock_session)

@pytest.fixture
def patient_repository(mock_session: AsyncSession) -> PatientRepository:
    """
    Create a mock PatientRepository for testing.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        MockPatientRepository instance
    """
    return MockPatientRepository(mock_session)

@pytest.fixture
def biometric_rule_repository(mock_session: AsyncSession) -> BiometricRuleRepository:
    """
    Create a mock BiometricRuleRepository for testing.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        MockBiometricRuleRepository instance
    """
    return MockBiometricRuleRepository(mock_session)

@pytest.fixture
def biometric_alert_repository(mock_session: AsyncSession) -> BiometricAlertRepository:
    """
    Create a mock BiometricAlertRepository for testing.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        MockBiometricAlertRepository instance
    """
    return MockBiometricAlertRepository(mock_session)

@pytest.fixture
def biometric_twin_repository(mock_session: AsyncSession) -> BiometricTwinRepository:
    """
    Create a mock BiometricTwinRepository for testing.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        MockBiometricTwinRepository instance
    """
    return MockBiometricTwinRepository(mock_session)

@pytest.fixture
def repository_factory(mock_session: AsyncSession):
    """
    Create a factory function to generate repositories.
    
    Args:
        mock_session: Mock AsyncSession to use
        
    Returns:
        Function that creates repository instances
    """
    def _factory(repo_type: Type[T]) -> T:
        return create_repository(repo_type, mock_session)
    
    return _factory
