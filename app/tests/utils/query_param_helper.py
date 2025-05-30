"""
Helper module for handling FastAPI dependency query parameters.

This module provides utilities to help tests bypass issues with unexpected
query parameters in FastAPI routes.
"""

import inspect
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

T = TypeVar("T")


def with_query_params(
    dependency_fn: Callable[..., T | Awaitable[T]],
) -> Callable[..., T | Awaitable[T]]:
    """
    Wraps a dependency function to handle unexpected query parameters.

    This decorator makes the dependency function accept arbitrary **kwargs,
    allowing it to be used in FastAPI route handlers that have query parameters
    that aren't part of the dependencies' signatures.

    Args:
        dependency_fn: The original dependency function to wrap

    Returns:
        A wrapped dependency function that accepts arbitrary kwargs
    """

    async def wrapper(*args: Any, **kwargs: Any) -> T:
        """
        Wrapper function that strips unknown kwargs before calling the dependency.
        """
        # Get the parameter names from the original function
        sig = inspect.signature(dependency_fn)
        param_names = sig.parameters.keys()

        # Filter kwargs to only include those that match the function's parameters
        filtered_kwargs = {k: v for k, v in kwargs.items() if k in param_names}

        # Call the dependency function with filtered kwargs
        result = dependency_fn(*args, **filtered_kwargs)

        # Handle awaitable results
        if inspect.isawaitable(result):
            awaited_result = await result
            return cast(T, awaited_result)
        return cast(T, result)

    return wrapper


def create_query_param_wrapper(
    params: dict[str, Any] | None = None,
) -> Callable[[Callable[..., T | Awaitable[T]]], Callable[..., T | Awaitable[T]]]:
    """
    Creates a wrapper for route handlers that adds required query parameters.

    This is useful for testing routes that expect query parameters but are
    being called directly in tests without those parameters being provided.

    Args:
        params: Dictionary of parameter names and default values

    Returns:
        A decorator that adds the specified query parameters to a route handler
    """
    params = params or {"args": None, "kwargs": None}

    def decorator(handler: Callable[..., T | Awaitable[T]]) -> Callable[..., T | Awaitable[T]]:
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            # Add the specified query parameters if they're not already present
            for name, value in params.items():
                if name not in kwargs:
                    kwargs[name] = value

            # Call the original handler
            result = handler(*args, **kwargs)

            # Handle awaitable results
            if inspect.isawaitable(result):
                awaited_result = await result
                return cast(T, awaited_result)
            return cast(T, result)

        return wrapper

    return decorator
