"""
Async test helpers for properly working with AsyncMock objects.

This module provides utilities that make it easier to work with AsyncMock objects
in pytest tests, preventing "coroutine was never awaited" warnings.
"""

from typing import Any, TypeVar
from unittest.mock import AsyncMock as _AsyncMock

# Define a type variable for return types
T = TypeVar("T")


class SafeAsyncMock(_AsyncMock):
    """
    Enhanced AsyncMock that enables proper assertion handling for async tests.

    This class extends AsyncMock to add async-specific assertion methods,
    preventing "coroutine was never awaited" warnings that happen when
    using standard assertion methods directly on AsyncMock objects.
    
    Note: We use different method names to avoid overriding synchronous methods.
    """

    async def async_assert_called_with(self, *args: Any, **kwargs: Any) -> None:
        """
        Async-safe version of assert_called_with.

        Args:
            *args: Positional arguments to check
            **kwargs: Keyword arguments to check
        """
        super().assert_called_with(*args, **kwargs)

    async def async_assert_called_once_with(self, *args: Any, **kwargs: Any) -> None:
        """
        Async-safe version of assert_called_once_with.

        Args:
            *args: Positional arguments to check
            **kwargs: Keyword arguments to check
        """
        super().assert_called_once_with(*args, **kwargs)

    async def async_assert_called(self) -> None:
        """
        Async-safe version of assert_called.
        """
        super().assert_called()

    async def async_assert_called_once(self) -> None:
        """
        Async-safe version of assert_called_once.
        """
        super().assert_called_once()

    async def async_assert_not_called(self) -> None:
        """
        Async-safe version of assert_not_called.
        """
        super().assert_not_called()

    async def async_assert_awaited(self) -> None:
        """
        Async-safe version of assert_awaited.
        """
        super().assert_awaited()

    async def async_assert_awaited_once(self) -> None:
        """
        Async-safe version of assert_awaited_once.
        """
        super().assert_awaited_once()

    async def async_assert_awaited_with(self, *args: Any, **kwargs: Any) -> None:
        """
        Async-safe version of assert_awaited_with.

        Args:
            *args: Positional arguments to check
            **kwargs: Keyword arguments to check
        """
        super().assert_awaited_with(*args, **kwargs)

    async def async_assert_awaited_once_with(self, *args: Any, **kwargs: Any) -> None:
        """
        Async-safe version of assert_awaited_once_with.

        Args:
            *args: Positional arguments to check
            **kwargs: Keyword arguments to check
        """
        super().assert_awaited_once_with(*args, **kwargs)

    async def async_assert_any_call(self, *args: Any, **kwargs: Any) -> None:
        """
        Async-safe version of assert_any_call.

        Args:
            *args: Positional arguments to check
            **kwargs: Keyword arguments to check
        """
        super().assert_any_call(*args, **kwargs)


def create_async_mock(*args: Any, **kwargs: Any) -> SafeAsyncMock:
    """
    Create a SafeAsyncMock instance that supports awaitable assertions.

    Args:
        *args: Positional arguments to pass to AsyncMock
        **kwargs: Keyword arguments to pass to AsyncMock

    Returns:
        SafeAsyncMock: An enhanced AsyncMock with awaitable assertion methods
    """
    from unittest.mock import AsyncMock

    # Create an AsyncMock with the provided args and kwargs
    mock = AsyncMock(*args, **kwargs)

    # Make it a SafeAsyncMock
    mock.__class__ = SafeAsyncMock

    return mock
