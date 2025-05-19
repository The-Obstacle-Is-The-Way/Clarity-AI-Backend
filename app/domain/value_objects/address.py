# app/domain/value_objects/address.py
"""Address value object."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Address:
    """
    Immutable value object representing a physical address.

    Follows HIPAA best practices for storing address information.
    """

    street: str
    city: str
    state: str
    zip_code: str
    country: str | None = "USA"

    def __init__(
        self,
        *,
        street: str | None = None,
        line1: str | None = None,
        line2: str | None = None,
        city: str,
        state: str,
        zip_code: str | None = None,
        postal_code: str | None = None,
        country: str | None = "USA",
    ):
        """
        Initialize Address, allowing either 'street' or 'line1', and 'zip_code' or 'postal_code'.
        'line2' is optional and stored on the instance but not included in to_dict.
        """
        s = street if street is not None else line1
        if not s:
            raise ValueError("Street (street or line1) is required")
        z = zip_code if zip_code is not None else postal_code
        if not z:
            raise ValueError("ZIP code (zip_code or postal_code) is required")
        # Store street and alias line1 for compatibility
        object.__setattr__(self, "street", s)
        object.__setattr__(self, "line1", s)
        object.__setattr__(self, "city", city)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "zip_code", z)
        object.__setattr__(self, "country", country)
        object.__setattr__(self, "line2", line2)
        self.__post_init__()

    def __post_init__(self) -> None:
        """Validate address after initialization."""
        if not self.street:
            raise ValueError("Street is required")

        if not self.city:
            raise ValueError("City is required")

        if not self.state:
            raise ValueError("State is required")

        if not self.zip_code:
            raise ValueError("ZIP code is required")

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "street": self.street,
            "city": self.city,
            "state": self.state,
            "zip_code": self.zip_code,
            "country": self.country,
        }

    def dict(self) -> dict:
        """
        Alias for to_dict() - for Pydantic v1 compatibility.

        Returns:
            Dictionary representation of the address
        """
        return self.to_dict()

    def model_dump(self) -> dict:
        """
        Alias for to_dict() - for Pydantic v2 compatibility.

        Returns:
            Dictionary representation of the address
        """
        return self.to_dict()

    def __str__(self) -> str:
        """Get string representation."""
        return f"{self.street}, {self.city}, {self.state} {self.zip_code}"
