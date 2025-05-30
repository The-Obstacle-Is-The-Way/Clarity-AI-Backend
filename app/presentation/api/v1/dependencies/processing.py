"""
Dependency provider for the biometric-event processor (v1 API).

This module intentionally contains *no* FastAPI imports; it can therefore be
type-checked in isolation without requiring the full web stack.  We rely on the
DI container's ``get()`` method instead of the legacy ``resolve()`` to avoid
`Any` leakage and satisfy mypy.
"""

from typing import Protocol, TypeVar

from app.core.interfaces.services.biometric_event_processor_interface import (
    IBiometricEventProcessor,
)
from app.infrastructure.di.container import get_container

T = TypeVar("T")


class _SupportsGet(Protocol):
    """Minimal protocol for DI containers that expose ``get``."""

    def get(self, interface: type[T]) -> T:
        ...


def get_event_processor() -> IBiometricEventProcessor:
    """Return the concrete biometric-event processor from the DI container."""

    container: _SupportsGet = get_container()
    return container.get(IBiometricEventProcessor)
