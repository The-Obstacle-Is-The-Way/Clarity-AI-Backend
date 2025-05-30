# Placeholder for domain authentication entities
from typing import Any


class UnauthenticatedUser:
    """Represents an unauthenticated user."""

    # This class might be expanded later if needed, for example, to conform to an interface
    # or carry specific unauthenticated state, but for now, it serves as a marker.
    def __init__(self) -> None:
        self.is_authenticated: bool = False
        self.roles: list[Any] = []
        self.id: Any | None = None  # Or a specific sentinel value

    def __str__(self) -> str:
        return "UnauthenticatedUser"

    def __repr__(self) -> str:
        return "<UnauthenticatedUser>"
