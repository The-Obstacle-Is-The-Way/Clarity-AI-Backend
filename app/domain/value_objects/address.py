"""Address value object for HIPAA-compliant patient information."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Address:
    """
    Immutable value object representing a physical address.

    Contains PHI that must be handled according to HIPAA regulations.
    Follows Domain-Driven Design principles for value objects.
    """

    street: str
    city: str
    state: str
    zip_code: str
    country: str = "US"

    def __init__(self, street: str | None = None, city: str | None = None, state: str | None = None, 
                 zip_code: str | None = None, country: str = "US", line1: str | None = None, **kwargs):
        """Initialize Address with backward compatibility for 'line1' parameter."""
        # Handle legacy 'line1' parameter
        if line1 is not None and street is None:
            street = line1
        
        # Convert None values to empty strings to satisfy type requirements
        # Validation will happen in __post_init__
        street = street or ""
        city = city or ""
        state = state or ""
        zip_code = zip_code or ""
        
        # Use object.__setattr__ because dataclass is frozen
        object.__setattr__(self, 'street', street)
        object.__setattr__(self, 'city', city)
        object.__setattr__(self, 'state', state)
        object.__setattr__(self, 'zip_code', zip_code)
        object.__setattr__(self, 'country', country)
        
        # Call post_init manually since we're overriding __init__
        self.__post_init__()

    def __post_init__(self) -> None:
        """Validate address components with proper null safety."""
        # Check for empty values (including None converted to empty strings)
        if not self.street.strip():
            raise ValueError("Street address cannot be empty")
        if not self.city.strip():
            raise ValueError("City cannot be empty")
        if not self.state.strip():
            raise ValueError("State cannot be empty")
        if not self.zip_code.strip():
            raise ValueError("ZIP code cannot be empty")

        # Basic ZIP code validation (US format)
        if self.country == "US":
            zip_digits = "".join(filter(str.isdigit, self.zip_code))
            if len(zip_digits) not in [5, 9]:  # 12345 or 123456789
                raise ValueError("Invalid US ZIP code format")

    def to_dict(self) -> dict[str, Any]:
        """Convert address to dictionary representation."""
        return {
            "street": self.street,
            "city": self.city,
            "state": self.state,
            "zip_code": self.zip_code,
            "country": self.country,
        }

    def __str__(self) -> str:
        """Return formatted address string."""
        if self.country == "US":
            return f"{self.street}, {self.city}, {self.state} {self.zip_code}"
        else:
            return f"{self.street}, {self.city}, {self.state} {self.zip_code}, {self.country}"

    def get_display_format(self) -> str:
        """Get display-friendly formatted address."""
        return str(self)

    def get_single_line(self) -> str:
        """Get single-line address format."""
        return str(self)

    def is_us_address(self) -> bool:
        """Check if this is a US address."""
        return self.country.upper() == "US"

    def get_state_abbreviation(self) -> str:
        """Get state abbreviation (assumes already abbreviated for US addresses)."""
        return self.state.upper()

    def get_zip_code_base(self) -> str:
        """Get base ZIP code (first 5 digits for US addresses)."""
        if self.is_us_address():
            digits = "".join(filter(str.isdigit, self.zip_code))
            return digits[:5] if len(digits) >= 5 else digits
        return self.zip_code

    def get_zip_code_extension(self) -> str | None:
        """Get ZIP+4 extension if available."""
        if self.is_us_address():
            digits = "".join(filter(str.isdigit, self.zip_code))
            return digits[5:9] if len(digits) == 9 else None
        return None

    @classmethod
    def create_from_dict(cls, data: dict[str, Any]) -> "Address":
        """Create Address from dictionary data with backward compatibility."""
        # Handle backward compatibility: 'line1' -> 'street'
        street = data.get("street") or data.get("line1", "")

        return cls(
            street=street,
            city=data["city"],
            state=data["state"],
            zip_code=data["zip_code"],
            country=data.get("country", "US"),
        )

    @classmethod
    def create(cls, **kwargs: Any) -> "Address":
        """Factory method with backward compatibility for legacy 'line1' parameter."""
        # Handle legacy 'line1' parameter
        if "line1" in kwargs and "street" not in kwargs:
            kwargs["street"] = kwargs.pop("line1")

        return cls(
            street=kwargs["street"],
            city=kwargs["city"],
            state=kwargs["state"],
            zip_code=kwargs["zip_code"],
            country=kwargs.get("country", "US"),
        )

    def validate_completeness(self) -> bool:
        """Validate that all required fields are present and non-empty."""
        required_fields = [self.street, self.city, self.state, self.zip_code]
        return all(field and field.strip() for field in required_fields)

    def is_same_location(self, other: object) -> bool:
        """Check if two addresses represent the same location."""
        if not isinstance(other, Address):
            return False

        # Normalize for comparison
        return (
            self.street.lower().strip() == other.street.lower().strip()
            and self.city.lower().strip() == other.city.lower().strip()
            and self.state.lower().strip() == other.state.lower().strip()
            and self.zip_code.strip() == other.zip_code.strip()
            and self.country.lower().strip() == other.country.lower().strip()
        )
