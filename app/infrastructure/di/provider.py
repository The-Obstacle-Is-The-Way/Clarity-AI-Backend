"""
Dependency Injection Provider.

This module provides a clean dependency injection mechanism following
SOLID principles, particularly the Dependency Inversion Principle.
It decouples high-level modules from low-level modules by abstracting
the creation of dependencies behind a standard interface.
"""

from typing import TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.di.container import get_container

# Generic type variable for interfaces
T = TypeVar("T")


def get_service_instance(interface_type: type[T]) -> T:
    """
    Get an instance of a service that implements the specified interface.

    This function uses the dependency injection container to resolve
    the concrete implementation of the requested interface type,
    following the Dependency Inversion Principle.

    Args:
        interface_type: The interface type to resolve

    Returns:
        An instance of a class that implements the interface

    Raises:
        KeyError: If no implementation is registered for the interface
    """
    container = get_container()
    return container.get(interface_type)


def get_repository_instance(repository_type: type[T], session: AsyncSession) -> T:
    """
    Get an instance of a repository that implements the specified interface.

    This function uses the dependency injection container to resolve
    the concrete implementation of the requested repository interface type
    and injects the provided database session.

    Args:
        repository_type: The repository interface type to resolve
        session: The database session to inject into the repository

    Returns:
        An instance of a repository that implements the interface

    Raises:
        KeyError: If no repository implementation is registered for the interface
    """
    container = get_container()
    factory = container.get_repository_factory(repository_type)
    return factory(session)
