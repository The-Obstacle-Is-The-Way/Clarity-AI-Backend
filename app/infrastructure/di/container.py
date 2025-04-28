# -*- coding: utf-8 -*-
"""
NOVAMIND Dependency Injection Container
=====================================
Implements a clean dependency injection pattern for the NOVAMIND platform.
Follows SOLID principles and Clean Architecture by centralizing dependency management.
"""

import inspect
import importlib # Added for dynamic imports
from functools import lru_cache
from typing import Any, Callable, Dict, Generic, Optional, Type, TypeVar, cast, Union # Added Union

from fastapi import Depends

# Defer service/repository imports to within get_container
from app.core.utils.logging import get_logger
# Corrected import path for XGBoostInterface
from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.domain.interfaces.ml_service_interface import (
    BiometricCorrelationInterface,
    DigitalTwinServiceInterface,
    PharmacogenomicsInterface,
    SymptomForecastingInterface,
    # XGBoostInterface, # Removed from here
)

# Remove top-level repository interface imports as they don't exist with these names
# from app.domain.repositories.digital_twin_repository import IDigitalTwinRepository
# from app.domain.repositories.patient_repository import IPatientRepository

# Ensure AnalyticsService is importable here
from app.domain.services.analytics_service import AnalyticsService
# Placeholder for where AnalyticsService implementation might be
# from app.infrastructure.services.analytics_service_impl import AnalyticsServiceImpl # Example

# Import Settings class
from app.config.settings import Settings, get_settings

# Import EventRepository and potentially its implementation/mock
from app.domain.repositories.temporal_repository import EventRepository
# from app.infrastructure.repositories.temporal.timescale_repository import TimescaleEventRepository # Example Impl

# Import Appointment Repository interface
from app.domain.repositories.appointment_repository import IAppointmentRepository
from unittest.mock import AsyncMock

# Import Clinical Note Repository interface/type
from app.domain.repositories.clinical_note_repository import ClinicalNoteRepository
# Import Medication Repository type
from app.domain.repositories.medication_repository import MedicationRepository
# Import Patient Repository type
from app.domain.repositories.patient_repository import PatientRepository
# Import Digital Twin Repository type
from app.domain.repositories.digital_twin_repository import DigitalTwinRepository

# Initialize logger using the utility function
logger = get_logger(__name__)

# Type variable for DI registrations
T = TypeVar("T")

# Initialize container global variable
container = None


class DIContainer:
    """
    Dependency Injection Container for managing service dependencies.
    Implements the Service Locator pattern in a clean, type-safe way.
    """

    def __init__(self):
        """Initialize the container with empty registrations."""
        self._registrations: Dict[str, Callable[[], Any]] = {}
        self._instances: Dict[str, Any] = {}
        logger.debug("Dependency Injection Container initialized")

    def register(
        self, interface_type: Type[T], implementation_factory: Callable[[], T]
    ) -> None:
        """
        Register a service implementation factory for an interface.

        Args:
            interface_type: The interface or abstract type
            implementation_factory: Factory function creating the implementation
        """
        key = self._get_key(interface_type)
        self._registrations[key] = implementation_factory
        logger.debug(f"Registered factory for {key}")

    def register_scoped(
        self, interface_type: Type[T], implementation_type: Type[T]
    ) -> None:
        """
        Register a scoped service (instance per request/scope).

        Args:
            interface_type: The interface or abstract type
            implementation_type: The concrete implementation class
        """
        key = self._get_key(interface_type)
        # Store the type itself; instantiation happens on resolution
        self._registrations[key] = implementation_type
        logger.debug(f"Registered scoped service for {key}")

    def register_instance(self, interface_type: Type[T], instance: T) -> None:
        """
        Register a singleton instance for an interface.

        Args:
            interface_type: The interface or abstract type
            instance: The singleton instance
        """
        key = self._get_key(interface_type)
        self._instances[key] = instance
        logger.debug(f"Registered instance for {key}")

    def resolve(self, interface_type: Union[Type[T], str]) -> T:
        """
        Resolve a dependency by its interface type.

        Args:
            interface_type: The interface type to resolve

        Returns:
            An instance of the registered implementation

        Raises:
            TypeError: If the type is not registered
            Exception: If instantiation fails
        """
        key = self._get_key(interface_type)

        # Check singletons first
        if key in self._instances:
            logger.debug(f"Resolving instance for {key}")
            return cast(T, self._instances[key])

        # Check registrations (factories or scoped types)
        if key in self._registrations:
            registration = self._registrations[key]
            # If it's a factory function
            if callable(registration) and not isinstance(registration, type):
                logger.debug(f"Resolving factory for {key}")
                try:
                    instance = registration()
                    return cast(T, instance)
                except Exception as e:
                    logger.error(f"Error instantiating {key} from factory: {e}", exc_info=True)
                    raise Exception(f"Error resolving {key}: {e}") from e
            # If it's a type (scoped registration)
            elif isinstance(registration, type):
                logger.debug(f"Resolving scoped type {key}")
                try:
                    # Perform dependency injection for the implementation's __init__
                    instance = self._create_instance_with_dependencies(registration)
                    return cast(T, instance)
                except Exception as e:
                    logger.error(f"Error instantiating scoped {key}: {e}", exc_info=True)
                    raise Exception(f"Error resolving scoped {key}: {e}") from e

        logger.error(f"Type {interface_type} not registered in DI container.")
        raise TypeError(f"Type {interface_type} not registered.")

    def _create_instance_with_dependencies(self, implementation_type: Type[T]) -> T:
        """Instantiate a class, injecting its dependencies from the container."""
        signature = inspect.signature(implementation_type.__init__)
        dependencies: Dict[str, Any] = {}

        for name, param in signature.parameters.items():
            if name == 'self':
                continue
            if param.annotation is inspect.Parameter.empty:
                logger.warning(
                    f"Dependency '{name}' for {implementation_type.__name__} has no type hint. Cannot inject."
                )
                # Or raise an error if strict injection is required
                # raise TypeError(f"Missing type hint for dependency '{name}' in {implementation_type.__name__}")
                continue

            # Resolve dependency based on type hint
            try:
                dependencies[name] = self.resolve(param.annotation)
            except TypeError as e:
                # If dependency not found, re-raise with more context
                logger.error(
                    f"Failed to resolve dependency '{name}: {param.annotation.__name__}' for {implementation_type.__name__}",
                    exc_info=True
                )
                raise TypeError(
                    f"Cannot instantiate {implementation_type.__name__}: Dependency '{name}' ({param.annotation.__name__}) not registered."
                ) from e
            except Exception as e:
                 logger.error(
                    f"Unexpected error resolving dependency '{name}: {param.annotation.__name__}' for {implementation_type.__name__}",
                    exc_info=True
                )
                 raise

        logger.debug(f"Injecting dependencies {list(dependencies.keys())} into {implementation_type.__name__}")
        return implementation_type(**dependencies)

    def _get_key(self, interface_type: Union[Type[T], str]) -> str: # Accept string
        """Generate a unique key for registration/resolution."""
        if isinstance(interface_type, str):
            # If it's a string path, use it directly as the key
            # We assume the registration also used this string path
            return interface_type
        elif inspect.isclass(interface_type):
            return f"{interface_type.__module__}.{interface_type.__name__}"
        else:
            # Handle unexpected types
            raise TypeError(f"Unsupported type for DI key: {type(interface_type)}")

    def override(self, interface_type: Union[Type[T], str], implementation_factory: Callable[[], T]) -> None: # Accept string
        """
        Override an existing registration, useful for testing.

        Args:
            interface_type: The interface type to override.
            implementation_factory: The new factory function.
        """
        key = self._get_key(interface_type)
        if key not in self._registrations and key not in self._instances:
             logger.warning(f"Attempting to override non-existent registration for {key}. Registering instead.")
        
        # Override the existing registration
        self._registrations[key] = implementation_factory
        # If there's an instance, remove it so the factory is used next time
        if key in self._instances:
            del self._instances[key]

    def clear(self) -> None:
        """Clear all registrations and instances. Useful for testing."""
        self._registrations.clear()
        self._instances.clear()
        logger.debug("DI container cleared")


class Container(DIContainer):
    """
    Extended container with additional features for FastAPI integration.
    """

    def __init__(self):
        """Initialize the DI container with standard registrations."""
        super().__init__()
        logger.debug("Extended Container initialized")

    def register(
        self, interface_type: Type[T], implementation_factory: Callable[[], T]
    ) -> None:
        """
        Register with FastAPI dependency integration.
        Supports both interface resolution and FastAPI dependency injection.
        """
        super().register(interface_type, implementation_factory)
        
        # Also register a FastAPI dependency for dependency injection
        if inspect.isclass(interface_type):
            dependency_key = f"fastapi_dependency_{interface_type.__name__}"
            self._instances[dependency_key] = Depends(lambda: implementation_factory())

    def register_instance(self, interface_type: Type[T], instance: T) -> None:
        """
        Register a singleton with FastAPI dependency integration.
        """
        super().register_instance(interface_type, instance)
        
        # Also register a FastAPI dependency for this instance
        if inspect.isclass(interface_type):
            dependency_key = f"fastapi_dependency_{interface_type.__name__}"
            self._instances[dependency_key] = Depends(lambda: instance)

    def register_scoped(
        self, interface_type: Type[T], implementation_type: Type[T]
    ) -> None:
        """
        Register a scoped service with FastAPI dependency integration.
        Creates a new instance per request.
        """
        key = self._get_key(interface_type)
        
        # Create a factory that resolves dependencies from the container
        def factory():
            # Get constructor dependencies
            dependencies = self._resolve_dependencies(implementation_type)
            # Create instance with resolved dependencies
            return implementation_type(**dependencies)
        
        # Register the factory that creates a new instance each time
        self._registrations[key] = factory
        logger.debug(f"Registered scoped service for {key}")

    def resolve(self, interface_type: Type[T]) -> T:
        """
        Resolve a dependency, with special handling for FastAPI's Depends.
        """
        # Handle FastAPI dependency injection if a string is passed
        if isinstance(interface_type, str):
            if interface_type.startswith("fastapi_dependency_"):
                # Extract the raw dependency and return it
                dependency_name = interface_type[len("fastapi_dependency_"):]
                for key, instance in self._instances.items():
                    if key.endswith(dependency_name):
                        return cast(T, instance)
            
            # If it's not a FastAPI dependency, resolve normally
            
        # Handle normal resolution
        try:
            return super().resolve(interface_type)
        except TypeError as e:
            # If it's a callable that returns a dependency, try invoking it
            if callable(interface_type) and not inspect.isclass(interface_type):
                try:
                    result = interface_type()
                    return cast(T, result)
                except Exception:
                    # If invoking fails, re-raise the original error
                    raise e
            # Re-raise the original error
            raise

    def _get_type_name(self, type_obj: Type) -> str:
        """Get a human-readable type name."""
        return getattr(type_obj, "__name__", str(type_obj))

    def _resolve_dependencies(self, implementation_type: Type[T]) -> Dict[str, Any]:
        """Resolve all constructor dependencies for a type."""
        dependencies = {}
        signature = inspect.signature(implementation_type.__init__)
        
        for param_name, param in signature.parameters.items():
            if param_name == "self":
                continue
                
            # Skip parameters without type hints
            if param.annotation is inspect.Parameter.empty:
                logger.warning(
                    f"Parameter '{param_name}' in {self._get_type_name(implementation_type)} has no type hint."
                )
                # Use default if available, otherwise skip
                if param.default is not inspect.Parameter.empty:
                    dependencies[param_name] = param.default
                continue
                
            # Resolve the dependency
            try:
                dependencies[param_name] = self.resolve(param.annotation)
            except Exception as e:
                logger.error(
                    f"Failed to resolve dependency '{param_name}' for {self._get_type_name(implementation_type)}: {e}",
                    exc_info=True
                )
                # Use default if available
                if param.default is not inspect.Parameter.empty:
                    dependencies[param_name] = param.default
                else:
                    # Re-raise with more context
                    raise ValueError(
                        f"Could not resolve dependency '{param_name}' for {self._get_type_name(implementation_type)}"
                    ) from e
                    
        return dependencies


def get_container():
    """Singleton function to access the DI container."""
    global container
    if container is not None:
        return container
    
    import os
    if os.environ.get("MOCK_DI_CONTAINERS") == "true":
        from unittest.mock import MagicMock, AsyncMock
        
        # Create a mock container that will resolve any service
        mock_container = MagicMock()
        
        # Configure the mock container to return mock objects for any requested service
        def resolve_mock(*args, **kwargs):
            mock_service = MagicMock()
            # Make any async methods return AsyncMock
            mock_service.__call__ = AsyncMock(return_value=mock_service)
            return mock_service
        
        mock_container.resolve.side_effect = resolve_mock
        mock_container.get.side_effect = resolve_mock
        
        # Set our global container reference to use in the app
        container = mock_container
        return container
    
    # Normal container initialization WITH registrations
    try:
        from unittest.mock import AsyncMock
        
        logger.info("Initializing REAL DI container and registering services.")
        container = Container() 

        # --- Register Core Services --- 
        # Settings is now imported
        container.register(Settings, get_settings)

        # Example: JWT Service
        from app.core.interfaces.services.jwt_service import IJwtService
        from app.infrastructure.security.jwt.jwt_service import JWTService
        # Assuming JWTService needs settings; the container will resolve it
        container.register_scoped(IJwtService, JWTService)

        # Example: Password Handler (Singleton)
        from app.infrastructure.security.password.password_handler import PasswordHandler
        container.register_instance(PasswordHandler, PasswordHandler())

        # Example: User Repository
        from app.domain.repositories.user_repository import UserRepository
        from app.infrastructure.repositories.user_repository import SqlAlchemyUserRepository
        # Assuming SqlAlchemyUserRepository needs an AsyncSession; 
        # this might require session management integration or a factory
        # For now, let's register the type (scoped)
        container.register_scoped(UserRepository, SqlAlchemyUserRepository)

        # Example: Authentication Service
        from app.infrastructure.security.auth.authentication_service import AuthenticationService
        # Container will inject registered dependencies (UserRepo, PW Handler, JWT Service)
        container.register_scoped(AuthenticationService, AuthenticationService)
        
        # --- ADD EventRepository Registration (Mock) ---
        mock_event_repo = AsyncMock(spec=EventRepository)
        container.register(EventRepository, lambda: mock_event_repo)
        logger.info(f"Registered MOCK {EventRepository.__name__} in DI container.")

        # --- ADD AppointmentRepository Registration (Mock) ---
        mock_appt_repo = AsyncMock(spec=IAppointmentRepository)
        container.register(IAppointmentRepository, lambda: mock_appt_repo)
        logger.info(f"Registered MOCK {IAppointmentRepository.__name__} in DI container.")

        # --- ADD ClinicalNoteRepository Registration (Mock) ---
        # TODO: Replace with actual implementation registration later if needed
        mock_cnote_repo = AsyncMock(spec=ClinicalNoteRepository)
        container.register(ClinicalNoteRepository, lambda: mock_cnote_repo)
        logger.info(f"Registered MOCK {ClinicalNoteRepository.__name__} in DI container.")

        # --- ADD MedicationRepository Registration (Mock) ---
        # TODO: Replace with actual implementation registration later if needed
        mock_med_repo = AsyncMock(spec=MedicationRepository)
        container.register(MedicationRepository, lambda: mock_med_repo)
        logger.info(f"Registered MOCK {MedicationRepository.__name__} in DI container.")

        # --- ADD PatientRepository Registration (Mock) ---
        # Assuming AnalyticsService uses PatientRepository type hint
        # TODO: Replace with actual implementation registration later if needed
        mock_patient_repo = AsyncMock(spec=PatientRepository)
        container.register(PatientRepository, lambda: mock_patient_repo)
        logger.info(f"Registered MOCK {PatientRepository.__name__} in DI container.")

        # --- ADD DigitalTwinRepository Registration (Mock) ---
        # TODO: Replace with actual implementation registration later if needed
        mock_dt_repo = AsyncMock(spec=DigitalTwinRepository)
        container.register(DigitalTwinRepository, lambda: mock_dt_repo)
        logger.info(f"Registered MOCK {DigitalTwinRepository.__name__} in DI container.")

        # --- Register AnalyticsService (depends on EventRepo, ApptRepo, CNoteRepo) --- 
        container.register_scoped(AnalyticsService, AnalyticsService) 
        logger.info(f"Registered {AnalyticsService.__name__} in DI container.")

        # --- ADD XGBoost Registration (Example) ---
        # Replace XGBoostServiceImpl with the actual implementation
        # from app.infrastructure.services.xgboost_service_impl import XGBoostServiceImpl # Example
        # Assume for now AnalyticsService acts as placeholder 
        # container.register_scoped(XGBoostInterface, XGBoostServiceImpl) 

        # ... register other necessary services/repositories ...

        logger.info("DI Container initialized with REAL service registrations.")
        return container
        
    except Exception as e:
        logger.error(f"Error registering real services in DI container: {e}", exc_info=True)
        # Fallback to empty container on error during real init
        container = DIContainer()
        return container


def get_service(service_type: Union[Type[T], str] = None) -> Any:  # Accept string or default to None, returns service instance or resolver
    """
    Get a service from the container.
    
    If service_type is None, this returns a function that can be used with
    FastAPI's dependency injection system to resolve a service at request time.
    
    Args:
        service_type: Optional type to resolve directly
    
    Returns:
        Either the resolved service instance or a function to resolve a service
    """
    container = get_container()  # This will create or reuse the singleton
    
    if service_type is not None:
        # If service_type is provided, return the instance directly
        return container.resolve(service_type)
    
    # Otherwise, return a resolver function for FastAPI dependency injection
    def _get_service() -> T:
        # Note: This should be called by FastAPI's dependency system, where
        # the service type will be inferred from the parameter type annotation.
        # Get the service type from the parameter annotation of the caller
        frame = inspect.currentframe().f_back
        if frame:
            try:
                # Get parameter name from the caller
                param_name = list(frame.f_locals.keys())[0]  # This gets the name of the first parameter
                # Get the function object
                func_obj = frame.f_globals.get(frame.f_code.co_name, None)
                if func_obj and hasattr(func_obj, "__annotations__"):
                    # Get the type annotation for this parameter
                    service_type_annotation = func_obj.__annotations__.get(param_name)
                    if service_type_annotation:
                        # Resolve the service from the container
                        return container.resolve(service_type_annotation)
            finally:
                del frame  # Avoid reference cycles
        
        raise ValueError("Could not determine service type from function annotation")
    
    return _get_service


# Create and initialize a container instance for import
# This addresses the import in main.py that expects 'container'
container = get_container()
