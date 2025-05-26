# Placeholder for domain authentication entities
from typing import List, Optional, Any


class UnauthenticatedUser:
    """Represents an unauthenticated user."""

    # This class might be expanded later if needed, for example, to conform to an interface
    # or carry specific unauthenticated state, but for now, it serves as a marker.
    def __init__(self) -> None:
        self.is_authenticated: bool = False
        self.roles: List[Any] = []
        self.id: Optional[Any] = None  # Or a specific sentinel value

    def __str__(self) -> str:
        return "UnauthenticatedUser"

    def __repr__(self) -> str:
        return "<UnauthenticatedUser>"
