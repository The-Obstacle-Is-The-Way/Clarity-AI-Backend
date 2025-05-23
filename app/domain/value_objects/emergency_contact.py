"""Emergency contact value object."""

from dataclasses import dataclass
from typing import Any

from app.domain.value_objects.address import Address


@dataclass(frozen=True)
class EmergencyContact:
    """
    Immutable value object for a patient's emergency contact.

    Contains PHI that must be handled according to HIPAA regulations.
    Follows Domain-Driven Design principles for value objects.
    """

    name: str
    relationship: str
    phone: str
    email: str | None = None
    address: Address | None = None

    def __post_init__(self) -> None:
        """Validate emergency contact data."""
        if not self.name.strip():
            raise ValueError("Name cannot be empty")

        if not self.relationship.strip():
            raise ValueError("Relationship cannot be empty")

        if not self.phone.strip():
            raise ValueError("Phone number cannot be empty")

        # Basic phone validation
        digits = "".join(filter(str.isdigit, self.phone))
        if len(digits) < 10:
            raise ValueError("Invalid phone number format")

        # Basic email validation if provided
        if self.email and "@" not in self.email:
            raise ValueError("Invalid email format")

    @classmethod
    def create(
        cls,
        name: str,
        relationship: str,
        phone: str,
        email: str | None = None,
        address: Address | dict[str, Any] | None = None,
    ) -> "EmergencyContact":
        """
        Factory method for creating EmergencyContact with dict address support.

        This method handles the conversion of dict address to Address object
        before dataclass initialization.
        """
        address_obj: Address | None = None
        if address:
            if isinstance(address, dict):
                address_obj = Address.create_from_dict(address)
            elif isinstance(address, Address):
                address_obj = address
            else:
                raise ValueError("Address must be a dict or Address object")

        return cls(
            name=name,
            relationship=relationship,
            phone=phone,
            email=email,
            address=address_obj,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        # Handle address which could be Address object or None
        address_dict: dict[str, Any] | None = None
        if self.address:
            address_dict = self.address.to_dict()

        return {
            "name": self.name,
            "relationship": self.relationship,
            "phone": self.phone,
            "email": self.email,
            "address": address_dict,
        }

    def model_dump(self) -> dict[str, Any]:
        """
        Pydantic v2 compatibility method.

        Returns:
            Dictionary representation of the emergency contact
        """
        return self.to_dict()

    def get_display_name(self) -> str:
        """Get formatted display name with relationship."""
        return f"{self.name} ({self.relationship})"

    def has_complete_contact_info(self) -> bool:
        """Check if contact has both phone and email."""
        return bool(self.phone and self.email)

    def get_primary_contact_method(self) -> str:
        """Get the primary contact method (phone always available, email optional)."""
        return "phone"  # Phone is required, so always primary

    def get_all_contact_methods(self) -> list[str]:
        """Get list of available contact methods."""
        methods = ["phone"]  # Phone is always available
        if self.email:
            methods.append("email")
        return methods

    def has_address(self) -> bool:
        """Check if emergency contact has an address."""
        return self.address is not None

    def get_formatted_address(self) -> str | None:
        """Get formatted address string, if available."""
        if self.address:
            return str(self.address)
        return None

    def get_contact_summary(self) -> str:
        """Get a summary of contact information."""
        summary = f"{self.get_display_name()}: {self.phone}"
        if self.email:
            summary += f", {self.email}"
        if self.address:
            summary += f", {self.address.get_single_line()}"
        return summary

    def is_same_person(self, other: object) -> bool:
        """Check if two emergency contacts represent the same person."""
        if not isinstance(other, EmergencyContact):
            return False

        # Compare normalized names and relationships
        return (
            self.name.lower().strip() == other.name.lower().strip()
            and self.relationship.lower().strip() == other.relationship.lower().strip()
        )

    def validate_completeness(self) -> bool:
        """Validate that all required fields are present and non-empty."""
        return bool(
            self.name
            and self.name.strip()
            and self.relationship
            and self.relationship.strip()
            and self.phone
            and self.phone.strip()
        )

    @classmethod
    def create_from_dict(cls, data: dict[str, Any]) -> "EmergencyContact":
        """Create EmergencyContact from dictionary data."""
        return cls.create(
            name=data["name"],
            relationship=data["relationship"],
            phone=data["phone"],
            email=data.get("email"),
            address=data.get("address"),
        )
