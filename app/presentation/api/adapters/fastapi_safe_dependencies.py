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

from app.infrastructure.logging.audit_logger import AuditLogger
from app.infrastructure.repositories.memory_token_blacklist_repository import (
    MemoryTokenBlacklistRepository,
)
from app.infrastructure.repositories.sqla.user_repository import SQLAlchemyUserRepository
from app.infrastructure.security.jwt.jwt_service_impl import JWTServiceImpl

T = TypeVar("T")
ConcreteT = TypeVar("ConcreteT")


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

    def adapted_dependency(*args: Any, **kwargs: Any) -> ConcreteT:
        impl = interface_dependency(*args, **kwargs)
        # No actual conversion happens here - it's just type hints for FastAPI
        return cast(concrete_type, impl)

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


def get_audit_logger_safe() -> AuditLogger:
    """
    Provides a concrete audit logger for FastAPI compatibility.

    Returns:
        A concrete AuditLogger instance
    """
    from app.presentation.api.dependencies.audit_logger import get_audit_logger

    logger = get_audit_logger()
    return cast(AuditLogger, logger)


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
