import logging
from typing import TypeVar
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

# Application Core Interfaces
from app.core.interfaces.repositories.biometric_alert_repository import IBiometricAlertRepository
from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.core.interfaces.repositories.biometric_twin_repository import IBiometricTwinRepository
from app.core.interfaces.repositories.digital_twin_repository import IDigitalTwinRepository
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.user_repository import IUserRepository
from app.core.interfaces.unit_of_work import IUnitOfWork

# Application Test Utilities (Mock Implementations)
from app.tests.utils.repository_factory import (
    MockBiometricAlertRepository,
    MockBiometricRuleRepository,
    MockBiometricTwinRepository,
    MockDigitalTwinRepository,
    MockPatientRepository,
    MockUnitOfWork,
    MockUserRepository,
    REPOSITORY_MAP,
    RepositoryFactory
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


@pytest.fixture
def mock_session() -> AsyncSession:
    """Provides a mock AsyncSession."""
    session = AsyncMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    session.refresh = AsyncMock()
    logger.debug("Mock AsyncSession created.")
    return session


@pytest.fixture
def mock_unit_of_work(mock_session: AsyncSession) -> IUnitOfWork:
    """
    Provides a mock UnitOfWork with a mock session.

    Args:
        mock_session: The mock AsyncSession fixture.

    Returns:
        An instance of MockUnitOfWork.
    """
    uow = MockUnitOfWork(mock_session)
    logger.debug("Mock UnitOfWork created.")
    return uow


@pytest.fixture
def user_repository(mock_session: AsyncSession) -> IUserRepository:
    """
    Create a mock UserRepository for testing.

    Args:
        mock_session: Mock async session.

    Returns:
        MockUserRepository instance implementing IUserRepository.
    """
    repo = MockUserRepository(mock_session)
    logger.debug("MockUserRepository fixture created.")
    return repo


@pytest.fixture
def patient_repository(mock_session: AsyncSession) -> IPatientRepository:
    """
    Create a mock PatientRepository for testing.

    Args:
        mock_session: Mock async session.

    Returns:
        MockPatientRepository instance.
    """
    repo = MockPatientRepository(mock_session)
    logger.debug("MockPatientRepository fixture created.")
    return repo


@pytest.fixture
def digital_twin_repository(mock_session: AsyncSession) -> IDigitalTwinRepository:
    """Create a mock DigitalTwinRepository for testing."""
    repo = MockDigitalTwinRepository(mock_session)
    logger.debug("MockDigitalTwinRepository fixture created.")
    return repo


@pytest.fixture
def biometric_rule_repository(mock_session: AsyncSession) -> IBiometricRuleRepository:
    """Create a mock BiometricRuleRepository for testing."""
    repo = MockBiometricRuleRepository(mock_session)
    logger.debug("MockBiometricRuleRepository fixture created.")
    return repo


@pytest.fixture
def biometric_alert_repository(mock_session: AsyncSession) -> IBiometricAlertRepository:
    """Create a mock BiometricAlertRepository for testing."""
    repo = MockBiometricAlertRepository(mock_session)
    logger.debug("MockBiometricAlertRepository fixture created.")
    return repo


@pytest.fixture
def biometric_twin_repository(mock_session: AsyncSession) -> IBiometricTwinRepository:
    """Create a mock BiometricTwinRepository for testing."""
    repo = MockBiometricTwinRepository(mock_session)
    logger.debug("MockBiometricTwinRepository fixture created.")
    return repo


@pytest.fixture
def repository_factory(mock_session: AsyncSession) -> RepositoryFactory:
    """
    Provides a RepositoryFactory configured with mock repositories.

    Args:
        mock_session: The mock AsyncSession fixture.

    Returns:
        An instance of RepositoryFactory.
    """
    factory = RepositoryFactory(db_session=mock_session, repository_map=REPOSITORY_MAP)
    logger.debug("RepositoryFactory fixture created with mock map.")
    return factory
