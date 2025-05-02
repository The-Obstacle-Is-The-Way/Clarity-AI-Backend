"""
Repository factory for tests.

This module provides utilities for creating repository instances in test environments
without requiring a full database connection, enabling proper unit testing
with clean architecture principles.
"""

import logging
import types
from enum import Enum
from typing import Generic, TypeVar
from unittest.mock import AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession

# Import interfaces first (dependency layers)
from app.core.interfaces.repositories.base import IRepository
from app.core.interfaces.repositories.biometric_alert_repository import IBiometricAlertRepository
from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.core.interfaces.repositories.biometric_twin_repository import IBiometricTwinRepository
from app.core.interfaces.repositories.digital_twin_repository import IDigitalTwinRepository
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.user_repository import IUserRepository
from app.core.interfaces.unit_of_work import IUnitOfWork

# Import entities
from app.domain.entities.biometric_alert import BiometricAlert
from app.domain.entities.biometric_rule import BiometricRule
from app.domain.entities.biometric_twin import BiometricTwinState
from app.domain.entities.digital_twin import DigitalTwin
from app.domain.entities.patient import Patient
from app.domain.entities.user import User

logger = logging.getLogger(__name__)

T = TypeVar('T')  # Generic type for entities
RepoInterface = TypeVar('RepoInterface', bound=IRepository)
MockRepoImpl = TypeVar('MockRepoImpl', bound='MockRepository')


# Base Mock Repository
class MockRepository(Generic[T]):
    """Generic base class for mock repositories."""
    def __init__(self, session: AsyncSession | None = None):
        self._session = session or AsyncMock(spec=AsyncSession)
        self._setup_mocks()
        logger.debug(f"Initialized {self.__class__.__name__} mock.")

    def _setup_mocks(self) -> None:
        """Set up common async mock methods. Override in subclasses if needed."""
        # Default mocks for common repository methods
        self.get_by_id = AsyncMock(return_value=None)
        self.list_all = AsyncMock(return_value=[])
        self.add = AsyncMock()
        self.update = AsyncMock()
        self.delete = AsyncMock(return_value=True)
        self.exists = AsyncMock(return_value=False)


# Mock Implementations
class MockUserRepository(MockRepository[User], IUserRepository):
    """Mock implementation of UserRepository for testing."""
    def __init__(self, session: AsyncSession | None = None):
        super().__init__(session)
        # Add specific mock methods for UserRepository if needed
        self.get_by_email = AsyncMock(return_value=None)
        self.get_by_username = AsyncMock(return_value=None)


class MockPatientRepository(MockRepository[Patient], IPatientRepository):
    """Mock implementation of PatientRepository for testing."""
    def __init__(self, session: AsyncSession | None = None):
        super().__init__(session)
        # Add specific mock methods if needed
        self.get_by_provider_id = AsyncMock(return_value=[])


class MockDigitalTwinRepository(MockRepository[DigitalTwin], IDigitalTwinRepository):
    """Mock implementation of DigitalTwinRepository for testing."""
    def __init__(self, session: AsyncSession | None = None):
        super().__init__(session)
        # Add specific mock methods if needed
        self.get_by_patient_id = AsyncMock(return_value=None)


class MockBiometricRuleRepository(MockRepository[BiometricRule], IBiometricRuleRepository):
    """Mock implementation of BiometricRuleRepository for testing."""
    def __init__(self, session: AsyncSession | None = None):
        super().__init__(session)
        # Add specific mock methods if needed
        self.get_active_rules = AsyncMock(return_value=[])


class MockBiometricAlertRepository(MockRepository[BiometricAlert], IBiometricAlertRepository):
    """Mock implementation of BiometricAlertRepository for testing."""
    def __init__(self, session: AsyncSession | None = None):
        super().__init__(session)
        # Add specific mock methods if needed
        self.get_unacknowledged = AsyncMock(return_value=[])
        self.acknowledge = AsyncMock(return_value=True)


class MockBiometricTwinRepository(MockRepository[BiometricTwinState], IBiometricTwinRepository):
    """Mock implementation of BiometricTwinRepository for testing."""
    def __init__(self, session: AsyncSession | None = None):
        super().__init__(session)
        # Add specific mock methods if needed
        self.get_latest_data = AsyncMock(return_value=None)


# Mapping from repository interfaces to mock implementations
REPOSITORY_MAP: dict[type[IRepository], type[MockRepository]] = {
    IUserRepository: MockUserRepository,
    IPatientRepository: MockPatientRepository,
    IDigitalTwinRepository: MockDigitalTwinRepository,
    IBiometricRuleRepository: MockBiometricRuleRepository,
    IBiometricAlertRepository: MockBiometricAlertRepository,
    IBiometricTwinRepository: MockBiometricTwinRepository,
}


# Enum for identifying repository types (optional but can be helpful)
class RepositoryType(Enum):
    USER = IUserRepository
    PATIENT = IPatientRepository
    DIGITAL_TWIN = IDigitalTwinRepository
    BIOMETRIC_RULE = IBiometricRuleRepository
    BIOMETRIC_ALERT = IBiometricAlertRepository
    BIOMETRIC_TWIN = IBiometricTwinRepository


# Factory Function (Simplified - consider if factory class is better)
def create_repository(repo_type: type[RepoInterface], session: AsyncSession | None = None) -> RepoInterface:
    """
    Creates a mock repository instance based on the provided interface type.

    Args:
        repo_type: The interface type of the repository to create.
        session: An optional AsyncSession mock.

    Returns:
        An instance of the corresponding mock repository.

    Raises:
        ValueError: If the repository type is not registered in REPOSITORY_MAP.
    """
    mock_class = REPOSITORY_MAP.get(repo_type)
    if not mock_class:
        msg = f"Mock repository not found for {repo_type.__name__}"
        logger.error(f"No mock repository registered for type: {repo_type.__name__}")
        raise ValueError(msg)

    logger.debug(
        f"Creating mock repository for {repo_type.__name__} using {mock_class.__name__}"
    )
    # Ignore type checker error for dynamic creation
    return mock_class(session) # type: ignore[return-value]


# Repository Factory Class (More structured approach)
class RepositoryFactory:
    """Factory for creating repository instances, configured with mocks for testing."""

    def __init__(
        self,
        db_session: AsyncSession,
        repository_map: dict[type[IRepository], type[MockRepository]],
    ):
        self._session = db_session
        self._repository_map = repository_map
        logger.debug(
            f"RepositoryFactory initialized with {len(repository_map)} mock mappings."
        )

    def get_repository(self, repo_interface: type[RepoInterface]) -> RepoInterface:
        """Gets an instance of the requested repository interface."""
        mock_class = self._repository_map.get(repo_interface)
        if not mock_class:
            msg = f"Mock repository not found for {repo_interface.__name__}"
            logger.error(
                f"No mock repository registered for interface: {repo_interface.__name__}"
            )
            raise ValueError(msg)

        logger.debug(
            f"Providing mock instance of {mock_class.__name__} "
            f"for {repo_interface.__name__}"
        )
        # Instantiate the mock repository with the session
        return mock_class(self._session) # type: ignore[return-value]


# Mock Unit of Work
class MockUnitOfWork(IUnitOfWork):
    """Mock implementation of the Unit of Work pattern for testing."""
    def __init__(self, session: AsyncSession):
        self.session = session
        self.committed = False
        self.rolled_back = False
        self.users = MockUserRepository(session)
        self.patients = MockPatientRepository(session)
        self.digital_twins = MockDigitalTwinRepository(session)
        self.biometric_rules = MockBiometricRuleRepository(session)
        self.biometric_alerts = MockBiometricAlertRepository(session)
        self.biometric_twins = MockBiometricTwinRepository(session)
        logger.debug("MockUnitOfWork initialized with mock repositories.")

    async def __aenter__(self) -> 'MockUnitOfWork':
        self.committed = False
        self.rolled_back = False
        logger.debug("MockUnitOfWork entered context.")
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: types.TracebackType | None) -> None:
        if exc_type:
            await self.rollback()
            logger.warning(
                f"MockUnitOfWork exiting with exception: {exc_type.__name__}, "
                f"rolling back."
            )
        else:
            await self.commit()
            logger.debug("MockUnitOfWork exiting normally, committing.")

    async def commit(self) -> None:
        self.committed = True
        self.rolled_back = False
        logger.debug("MockUnitOfWork commit called.")
        await self.session.commit()  # Mock commit

    async def rollback(self) -> None:
        self.rolled_back = True
        self.committed = False
        logger.debug("MockUnitOfWork rollback called.")
        await self.session.rollback()  # Mock rollback
