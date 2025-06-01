"""
FastAPI-Safe Dependency Adapters Module.

This module provides adapter patterns for clean architecture interfaces to work with FastAPI's
dependency injection system, which doesn't support abstract interfaces for type annotations.

These adapters preserve the clean architecture pattern internally while exposing concrete
types that FastAPI can work with for parameter annotations and response models.
"""

from collections.abc import Callable
from typing import Any, TypeVar, cast

from fastapi import Request

# Core layer interfaces
from app.core.interfaces.services.audit_logger_interface import IAuditLogger

# Infrastructure layer implementations for casting
from app.infrastructure.repositories.memory_token_blacklist_repository import (
    MemoryTokenBlacklistRepository,
)
from app.infrastructure.repositories.sqla.user_repository import SQLAlchemyUserRepository
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl

T = TypeVar("T")
ConcreteT = TypeVar("ConcreteT", bound=Any)


def adapt_interface_dependency(
    interface_dependency: Callable[..., Any], concrete_type: type[ConcreteT]
) -> Callable[..., ConcreteT]:
    """
    Adapts an interface-returning dependency to a concrete type for FastAPI compatibility.

    This preserves clean architecture internally while exposing concrete types that
    FastAPI can work with for parameter annotations and response models.

    Args:
        interface_dependency: The original dependency that returns an interface
        concrete_type: The concrete type to cast the dependency result to

    Returns:
        A dependency function that returns a concrete type
    """

    def adapted_dependency(*args: Any, **kwargs: Any) -> ConcreteT:  # type: ignore[override]
        impl = interface_dependency(*args, **kwargs)
        # No runtime conversion; cast solely for type checking.
        return cast(ConcreteT, impl)

    return adapted_dependency


# FastAPI-safe versions of core dependencies
def get_token_blacklist_repository_safe() -> MemoryTokenBlacklistRepository:
    """
    Provides a concrete token blacklist repository for FastAPI compatibility.

    Returns:
        A concrete MemoryTokenBlacklistRepository instance
    """
    from app.presentation.api.dependencies.token_blacklist import get_token_blacklist_repository

    repo = get_token_blacklist_repository()
    return cast(MemoryTokenBlacklistRepository, repo)


def get_audit_logger_safe() -> IAuditLogger:  # Return as IAuditLogger for proper typing
    """
    Provides an audit logger interface implementation for FastAPI compatibility.

    Returns:
        An implementation of IAuditLogger adapted for FastAPI
    """
    from app.presentation.api.dependencies.logging import get_audit_logger

    # Get the interface implementation through the proper dependency provider
    logger = get_audit_logger()
    # Return the interface implementation directly, using Any return type for FastAPI compatibility
    return logger


def get_user_repository_safe() -> SQLAlchemyUserRepository:
    """
    Provides a concrete user repository for FastAPI compatibility.

    Returns:
        A concrete SQLAlchemyUserRepository instance
    """
    from app.presentation.api.dependencies.user_repository import get_user_repository

    repo = get_user_repository()
    return cast(SQLAlchemyUserRepository, repo)


def get_jwt_service_safe(request: Request) -> JWTServiceImpl:
    """
    Provides a concrete JWT service for FastAPI compatibility.

    Returns:
        A concrete JWTServiceImpl instance
    """
    from app.presentation.api.dependencies.jwt import get_jwt_service_from_request

    jwt_service = get_jwt_service_from_request(request)
    return cast(JWTServiceImpl, jwt_service)
