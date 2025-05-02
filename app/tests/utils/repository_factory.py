"""
Repository factory for tests.

This module provides utilities for creating repository instances in test environments
without requiring a full database connection, enabling proper unit testing
with clean architecture principles.
"""

from typing import Any, Dict, Optional, Type, TypeVar
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy.ext.asyncio import AsyncSession

# Import interfaces
from app.domain.repositories.user_repository import UserRepository
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.repositories.biometric_rule_repository import BiometricRuleRepository
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository

# Import from app.tests.utils.async_test_helpers when available
from app.tests.utils.async_test_helpers import create_async_mock

T = TypeVar('T')

class MockRepository:
    """
    Base class for mock repositories that implements common repository methods.
    
    This class provides basic mock implementations of standard repository methods
    to simplify test setup for any repository type.
    """
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """
        Initialize the mock repository.
        
        Args:
            session: Optional session instance, can be None for tests
        """
        self.session = session
        self._setup_mocks()
        
    def _setup_mocks(self):
        """Setup standard mock methods that all repositories typically have."""
        self.get_by_id = create_async_mock()
        self.list_all = create_async_mock(return_value=[])
        self.create = create_async_mock()
        self.update = create_async_mock()
        self.delete = create_async_mock(return_value=True)
        self.save = create_async_mock()


class MockUserRepository(MockRepository, UserRepository):
    """Mock implementation of UserRepository for testing."""
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize with session parameter matching the real implementation."""
        super().__init__(session)
        self.get_by_email = create_async_mock()
        self.get_by_username = create_async_mock()
        self.get_by_role = create_async_mock(return_value=[])
        

class MockPatientRepository(MockRepository, PatientRepository):
    """Mock implementation of PatientRepository for testing."""
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize with session parameter matching the real implementation."""
        super().__init__(session)
        self.get_by_medical_record_number = create_async_mock()
        self.get_by_user_id = create_async_mock()
        self.search = create_async_mock(return_value=[])


class MockBiometricRuleRepository(MockRepository, BiometricRuleRepository):
    """Mock implementation of BiometricRuleRepository for testing."""
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize with session parameter matching the real implementation."""
        super().__init__(session)
        self.get_rules_for_patient = create_async_mock(return_value=[])
        self.get_active_rules = create_async_mock(return_value=[])
        self.get_rule_templates = create_async_mock(return_value=[])


class MockBiometricAlertRepository(MockRepository, BiometricAlertRepository):
    """Mock implementation of BiometricAlertRepository for testing."""
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize with session parameter matching the real implementation."""
        super().__init__(session)
        self.get_alerts_for_patient = create_async_mock(return_value=[])
        self.get_unacknowledged_alerts = create_async_mock(return_value=[])
        self.get_patient_alert_summary = create_async_mock()


class MockBiometricTwinRepository(MockRepository, BiometricTwinRepository):
    """Mock implementation of BiometricTwinRepository for testing."""
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize with session parameter matching the real implementation."""
        super().__init__(session)
        self.get_by_patient_id = create_async_mock()


# Mapping from repository interfaces to mock implementations
REPOSITORY_MOCKS: Dict[Type, Type] = {
    UserRepository: MockUserRepository,
    PatientRepository: MockPatientRepository,
    BiometricRuleRepository: MockBiometricRuleRepository,
    BiometricAlertRepository: MockBiometricAlertRepository,
    BiometricTwinRepository: MockBiometricTwinRepository,
}


def create_repository(repo_type: Type[T], session: Optional[AsyncSession] = None) -> T:
    """
    Create a mock repository instance for testing.
    
    Args:
        repo_type: Repository interface type to create
        session: Optional session to pass to the repository
        
    Returns:
        Mock repository instance that implements the specified interface
    """
    mock_class = REPOSITORY_MOCKS.get(repo_type)
    
    if mock_class:
        return mock_class(session)
    
    # If no specific mock class is defined, create a generic mock
    mock = MockRepository(session)
    # Make it look like the requested type
    mock.__class__ = type(f"Mock{repo_type.__name__}", (MockRepository, repo_type), {})
    return mock  # type: ignore


class MockUnitOfWork:
    """
    Mock implementation of UnitOfWork for testing.
    
    This class provides a test double for the UnitOfWork pattern that doesn't
    require a real database connection, simplifying unit tests.
    """
    
    def __init__(self, session: Optional[AsyncSession] = None):
        """
        Initialize the mock unit of work.
        
        Args:
            session: Optional session to use for repositories
        """
        self.session = session or AsyncMock()
        self._repositories = {}
        self.commit = create_async_mock()
        self.rollback = create_async_mock()
        
    def __getitem__(self, repo_type: Type[T]) -> T:
        """
        Get a repository instance of the specified type.
        
        Args:
            repo_type: Repository interface type
            
        Returns:
            Mock repository instance
        """
        if repo_type not in self._repositories:
            self._repositories[repo_type] = create_repository(repo_type, self.session)
        return self._repositories[repo_type]
        
    async def __aenter__(self):
        """Support async context manager protocol."""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Support async context manager protocol."""
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()
