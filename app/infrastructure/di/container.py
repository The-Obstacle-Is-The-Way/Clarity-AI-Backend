"""
Dependency Injection Container.

This module implements a dependency injection container following
the SOLID principles, particularly Dependency Inversion Principle.
The container manages service registration and resolution, enabling
loose coupling between components and facilitating testing.
"""

import logging
from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Global container instance
_container = None

# Generic type variable for interfaces
T = TypeVar("T")


class DIContainer:
    """
    Dependency Injection Container for managing application services.

    This container implements the Service Locator pattern responsibly,
    allowing for centralized management of service dependencies while
    maintaining testability and loose coupling between components.
    """

    def __init__(self, is_mock: bool = False):
        """
        Initialize the DI container.

        Args:
            is_mock: Whether this container should use mock implementations
        """
        self._services: dict[type, Any] = {}
        self._singletons: dict[type, type] = {}
        self._factories: dict[type, Callable] = {}
        self._repository_factories: dict[type, Callable[[AsyncSession], Any]] = {}
        self._is_mock = is_mock
        logger.info(
            f"Initializing {'MOCK' if is_mock else 'REAL'} DI container and registering services."
        )

    def register(self, interface: type[T], implementation: T) -> None:
        """
        Register an implementation for an interface.

        Args:
            interface: The interface type to register
            implementation: The implementation instance
        """
        self._services[interface] = implementation

        register_msg = (
            f"Registered {'MOCK' if self._is_mock else ''} {interface.__name__} in DI container."
        )
        if self._is_mock:
            logger.info(register_msg)
        else:
            logger.debug(register_msg)

    def register_instance(self, interface: type[T], instance: T) -> None:
        """
        Register a specific instance for an interface.

        This is an alias for register() to maintain a consistent naming convention.

        Args:
            interface: The interface type to register
            instance: The instance to register
        """
        self.register(interface, instance)

    def register_singleton(self, interface: type[T], implementation_type: type[T]) -> None:
        """
        Register a singleton implementation for an interface.

        This registers a type that will be instantiated once when first requested.

        Args:
            interface: The interface type to register
            implementation_type: The implementation type
        """
        self._singletons[interface] = implementation_type

    def register_factory(self, interface: type[T], factory: Callable[[], T]) -> None:
        """
        Register a factory function for creating service instances.

        Args:
            interface: The interface type
            factory: Factory function that creates instances of the interface
        """
        self._factories[interface] = factory

    def register_repository_factory(
        self, interface: type[T], factory: Callable[[AsyncSession], T]
    ) -> None:
        """
        Register a factory function for creating repository instances with session injection.

        Args:
            interface: The repository interface type
            factory: Factory function that creates instances of the repository
        """
        self._repository_factories[interface] = factory

    def get(self, interface: type[T]) -> T:
        """
        Resolve an implementation for the specified interface.

        Args:
            interface: The interface type to resolve

        Returns:
            An instance implementing the interface

        Raises:
            KeyError: If no implementation is registered for the interface
        """
        # First check for direct instance registrations
        if interface in self._services:
            return self._services[interface]

        # Then check for registered singletons
        if interface in self._singletons:
            implementation_type = self._singletons[interface]
            instance = implementation_type()
            # Cache the instance for future requests
            self._services[interface] = instance
            return instance

        # Then check for registered factories
        if interface in self._factories:
            # Create instance using factory
            instance = self._factories[interface]()
            # Cache the instance for future use
            self._services[interface] = instance
            return instance

        # Not found
        raise KeyError(f"No implementation registered for {interface.__name__}")

    def get_repository_factory(self, interface: type[T]) -> Callable[[AsyncSession], T]:
        """
        Get a factory function for creating repository instances.

        Args:
            interface: The repository interface type

        Returns:
            A factory function that creates repository instances

        Raises:
            KeyError: If no factory is registered for the interface
        """
        if interface in self._repository_factories:
            return self._repository_factories[interface]

        raise KeyError(f"No repository factory registered for {interface.__name__}")

    def register_services(self) -> None:
        """
        Register all services based on configuration.

        This method is responsible for registering all application services
        with their appropriate implementations, whether real or mocked.
        """
        try:
            if self._is_mock:
                self._register_mock_services()
            else:
                self._register_real_services()

            logger.info(
                f"DI Container initialized with {'MOCK' if self._is_mock else 'REAL'} service registrations."
            )
        except Exception as e:
            logger.error(
                f"Error registering {'mock' if self._is_mock else 'real'} services in DI container: {e!s}"
            )
            logger.exception(e)

    def _register_mock_services(self) -> None:
        """Register mock implementations for testing."""
        from unittest.mock import MagicMock

        # Import core interfaces
        from app.core.interfaces.repositories.base_repository import (
            BaseRepositoryInterface,
        )

        # Create and register generic mocks for all repository types
        # Event repository
        mock_event_repo = MagicMock(spec=BaseRepositoryInterface)
        self.register(BaseRepositoryInterface, mock_event_repo)
        logger.info("Registered MOCK EventRepository in DI container.")

        # For test collection, register some common repository types

        # Appointment repository
        mock_appointment_repo = MagicMock(spec=BaseRepositoryInterface)
        self.register(BaseRepositoryInterface, mock_appointment_repo)
        logger.info("Registered MOCK IAppointmentRepository in DI container.")

        # Clinical note repository
        mock_note_repo = MagicMock(spec=BaseRepositoryInterface)
        self.register(BaseRepositoryInterface, mock_note_repo)
        logger.info("Registered MOCK ClinicalNoteRepository in DI container.")

        # Medication repository
        mock_medication_repo = MagicMock(spec=BaseRepositoryInterface)
        self.register(BaseRepositoryInterface, mock_medication_repo)
        logger.info("Registered MOCK MedicationRepository in DI container.")

        # Patient repository
        mock_patient_repo = MagicMock(spec=BaseRepositoryInterface)
        self.register(BaseRepositoryInterface, mock_patient_repo)
        logger.info("Registered MOCK PatientRepository in DI container.")

        # Digital twin repository
        mock_twin_repo = MagicMock(spec=BaseRepositoryInterface)
        self.register(BaseRepositoryInterface, mock_twin_repo)
        logger.info("Registered MOCK DigitalTwinRepository in DI container.")

        # Register service mocks as needed

        # Analytics service
        from app.core.interfaces.services.analytics_service_interface import (
            AnalyticsServiceInterface,
        )

        mock_analytics_service = MagicMock(spec=AnalyticsServiceInterface)
        self.register(AnalyticsServiceInterface, mock_analytics_service)
        logger.info("Registered AnalyticsService in DI container.")

    def _register_real_services(self) -> None:
        """Register real implementations for production."""
        # Import repositories and their interfaces
        # Import biometric rule repository
        from app.core.interfaces.repositories.biometric_rule_repository import (
            IBiometricRuleRepository,
        )
        from app.core.interfaces.repositories.user_repository_interface import (
            IUserRepository,
        )
        from app.infrastructure.persistence.sqlalchemy.repositories.biometric_rule_repository import (
            get_biometric_rule_repository,
        )
        from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
            get_user_repository,
        )

        # Register repository factories
        self.register_repository_factory(IUserRepository, get_user_repository)
        self.register_repository_factory(IBiometricRuleRepository, get_biometric_rule_repository)

        # Import services and their interfaces
        from app.application.services.biometric_alert_service import (
            BiometricAlertService,
        )

        # Import AlertServiceInterface and its implementation
        from app.core.interfaces.services.alert_service_interface import (
            AlertServiceInterface,
        )
        from app.core.interfaces.services.auth_service_interface import (
            AuthServiceInterface,
        )
        from app.core.interfaces.services.jwt_service_interface import (
            JWTServiceInterface,
        )
        from app.infrastructure.security.auth.auth_service import get_auth_service
        from app.infrastructure.security.jwt.jwt_service import get_jwt_service

        # Register services directly or via factories
        self.register_factory(AuthServiceInterface, get_auth_service)
        self.register_factory(JWTServiceInterface, get_jwt_service)

        # Register AlertServiceInterface with BiometricAlertService implementation
        self.register_singleton(AlertServiceInterface, BiometricAlertService)
        logger.info(
            "Registered BiometricAlertService as AlertServiceInterface implementation in DI container."
        )

        # Import and register Biometric Event Processor
        try:
            from app.core.interfaces.services.biometric_event_processor_interface import (
                IBiometricEventProcessor,
            )
            from app.core.services.biometric_event_processor import (
                get_biometric_event_processor,
            )

            self.register_factory(IBiometricEventProcessor, get_biometric_event_processor)
            logger.info("Registered BiometricEventProcessor factory in DI container.")
        except ImportError:
            logger.warning("Could not register BiometricEventProcessor (missing files?)")

        # Register additional services
        try:
            from app.core.interfaces.services.analytics_service_interface import (
                AnalyticsServiceInterface,
            )
            from app.core.services.analytics_service import AnalyticsService

            # Create and register analytics service
            analytics_service = AnalyticsService()
            self.register(AnalyticsServiceInterface, analytics_service)
            logger.info("Registered AnalyticsService in DI container.")
        except ImportError:
            logger.warning("Could not register AnalyticsService (missing implementation)")


def get_container(use_mock: bool = False) -> DIContainer:
    """
    Get the global DI container instance.

    This function follows the Singleton pattern, ensuring only one
    container exists throughout the application lifecycle.

    Args:
        use_mock: Whether to use mock implementations

    Returns:
        The global DI container instance
    """
    global _container

    if _container is None:
        _container = DIContainer(is_mock=use_mock)
        _container.register_services()
    elif use_mock and not _container._is_mock:
        # If we requested a mock container but have a real one, recreate it
        _container = DIContainer(is_mock=True)
        _container.register_services()

    return _container


def reset_container() -> None:
    """
    Reset the global DI container instance.

    This function is useful for testing when we need to reset
    the container between tests.
    """
    global _container
    _container = None


def get_service(interface_type: type[T]) -> T:
    """
    Get a service instance by its interface type.

    This is a convenience function that delegates to the container's get method.
    It maintains backward compatibility with existing code.

    Args:
        interface_type: The interface type to resolve

    Returns:
        An instance implementing the interface
    """
    container = get_container()
    return container.get(interface_type)


# Expose container singleton directly for backward compatibility
container = get_container()


def configure_container() -> DIContainer:
    """Configure and return the dependency injection container."""
    container = DIContainer()

    # Register interface implementations
    container.register_instance(JWTConfig, JWTConfig())
    container.register_singleton(AuthServiceInterface, AuthService)
    container.register_singleton(JWTServiceInterface, JWTService)
    container.register_singleton(TokenEncryptionServiceInterface, TokenEncryptionService)
    container.register_singleton(PasswordHashingServiceInterface, BcryptPasswordHashingService)
    container.register_singleton(UserRepositoryInterface, UserRepository)
    container.register_singleton(
        TokenBlacklistRepositoryInterface, InMemoryTokenBlacklistRepository
    )
    container.register_singleton(
        AlertServiceInterface, BiometricAlertService
    )  # Register BiometricAlertService

    # Register factory methods for database-dependent services
    container.register_factory(AsyncSessionLocal, get_session_factory)

    return container
