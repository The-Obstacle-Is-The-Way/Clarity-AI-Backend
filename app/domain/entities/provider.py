"""
Provider Entity

This module defines the Provider entity for the domain layer,
representing a healthcare provider in the system.
"""

from datetime import datetime, time
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.domain.exceptions import ValidationError


class ProviderType(Enum):
    """Type of provider."""

    PSYCHIATRIST = "psychiatrist"
    PSYCHOLOGIST = "psychologist"
    THERAPIST = "therapist"
    NURSE_PRACTITIONER = "nurse_practitioner"
    SOCIAL_WORKER = "social_worker"
    COUNSELOR = "counselor"
    OTHER = "other"


class ProviderStatus(Enum):
    """Status of a provider."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ON_LEAVE = "on_leave"
    PENDING = "pending"


class ProviderRole(Enum):
    """Role of a provider - alias for ProviderType for backward compatibility."""

    PSYCHIATRIST = "psychiatrist"
    PSYCHOLOGIST = "psychologist"
    THERAPIST = "therapist"
    NURSE_PRACTITIONER = "nurse_practitioner"
    SOCIAL_WORKER = "social_worker"
    COUNSELOR = "counselor"
    OTHER = "other"


class ProviderSpecialty(Enum):
    """Specialty areas for providers."""

    GENERAL_PSYCHIATRY = "general_psychiatry"
    CHILD_ADOLESCENT_PSYCHIATRY = "child_adolescent_psychiatry"
    ADDICTION_PSYCHIATRY = "addiction_psychiatry"
    GERIATRIC_PSYCHIATRY = "geriatric_psychiatry"
    FORENSIC_PSYCHIATRY = "forensic_psychiatry"
    CONSULTATION_LIAISON_PSYCHIATRY = "consultation_liaison_psychiatry"
    COGNITIVE_BEHAVIORAL_THERAPY = "cognitive_behavioral_therapy"
    DIALECTICAL_BEHAVIOR_THERAPY = "dialectical_behavior_therapy"
    PSYCHODYNAMIC_THERAPY = "psychodynamic_therapy"
    FAMILY_THERAPY = "family_therapy"
    GROUP_THERAPY = "group_therapy"
    TRAUMA_THERAPY = "trauma_therapy"
    ANXIETY_DISORDERS = "anxiety_disorders"
    MOOD_DISORDERS = "mood_disorders"
    PSYCHOTIC_DISORDERS = "psychotic_disorders"
    PERSONALITY_DISORDERS = "personality_disorders"
    EATING_DISORDERS = "eating_disorders"
    SUBSTANCE_USE_DISORDERS = "substance_use_disorders"
    ADHD = "adhd"
    AUTISM_SPECTRUM_DISORDERS = "autism_spectrum_disorders"


class Credential:
    """Represents a professional credential for a provider."""

    def __init__(
        self,
        type: str,
        issuer: str,
        issue_date: datetime,
        expiration_date: datetime | None = None,
        identifier: str | None = None,
        verification_url: str | None = None,
    ):
        """
        Initialize a credential.

        Args:
            type: Type of credential (e.g., "MD", "PhD", "License")
            issuer: Institution that issued the credential
            issue_date: Date the credential was issued
            expiration_date: Optional expiration date
            identifier: Optional identifier (e.g., license number)
            verification_url: Optional URL for verification
        """
        self.type = type
        self.issuer = issuer
        self.issue_date = issue_date
        self.expiration_date = expiration_date
        self.identifier = identifier
        self.verification_url = verification_url

    @property
    def is_expired(self) -> bool:
        """Check if the credential is expired."""
        if self.expiration_date is None:
            return False
        return datetime.now() > self.expiration_date

    @property
    def expires_soon(self) -> bool:
        """Check if the credential expires within 30 days."""
        if self.expiration_date is None:
            return False
        days_until_expiry = (self.expiration_date - datetime.now()).days
        return 0 < days_until_expiry <= 30


class AvailabilitySlot:
    """Represents an availability slot for a provider."""

    def __init__(
        self,
        day_of_week: int,
        start_time: time,
        end_time: time,
        is_telehealth: bool = True,
        is_in_person: bool = True,
    ):
        """
        Initialize an availability slot.

        Args:
            day_of_week: Day of the week (0 = Monday, 6 = Sunday)
            start_time: Start time of availability
            end_time: End time of availability
            is_telehealth: Whether telehealth appointments are supported
            is_in_person: Whether in-person appointments are supported
        """
        if not (0 <= day_of_week <= 6):
            raise ValidationError("Day of week must be between 0 (Monday) and 6 (Sunday)")
        if start_time >= end_time:
            raise ValidationError("Start time must be before end time")

        self.day_of_week = day_of_week
        self.start_time = start_time
        self.end_time = end_time
        self.is_telehealth = is_telehealth
        self.is_in_person = is_in_person


class Provider:
    """
    Provider entity representing a healthcare provider in the system.

    This entity encapsulates all the business logic related to providers,
    including personal information, credentials, and availability.
    """

    # Type annotations for instance attributes
    id: UUID
    first_name: str | None
    last_name: str | None
    provider_type: ProviderType | None
    specialties: list[str]
    license_number: str | None
    npi_number: str | None
    email: str | None
    phone: str | None
    address: dict[str, Any]
    bio: str | None
    education: list[dict[str, Any]]
    certifications: list[dict[str, Any]]
    languages: list[str]
    status: ProviderStatus
    availability: dict[str, list[dict[str, Any]]]
    max_patients: int | None
    current_patient_count: int
    accepts_new_patients: bool
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, Any]

    def __init__(
        self,
        id: UUID | str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        provider_type: ProviderType | str | None = None,
        specialties: list[str] | None = None,
        license_number: str | None = None,
        npi_number: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        address: dict[str, Any] | None = None,
        bio: str | None = None,
        education: list[dict[str, Any]] | None = None,
        certifications: list[dict[str, Any]] | None = None,
        languages: list[str] | None = None,
        status: ProviderStatus | str = ProviderStatus.ACTIVE,
        availability: dict[str, list[dict[str, Any]]] | None = None,
        max_patients: int | None = None,
        current_patient_count: int = 0,
        accepts_new_patients: bool = True,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize a provider.

        Args:
            id: Unique identifier for the provider
            first_name: First name of the provider
            last_name: Last name of the provider
            provider_type: Type of provider
            specialties: Specialties of the provider
            license_number: License number of the provider
            npi_number: NPI number of the provider
            email: Email address of the provider
            phone: Phone number of the provider
            address: Address of the provider
            bio: Biography of the provider
            education: Education history of the provider
            certifications: Certifications of the provider
            languages: Languages spoken by the provider
            status: Status of the provider
            availability: Availability schedule of the provider
            max_patients: Maximum number of patients the provider can have
            current_patient_count: Current number of patients
            accepts_new_patients: Whether the provider accepts new patients
            created_at: Time the provider was created
            updated_at: Time the provider was last updated
            metadata: Additional metadata
        """
        self.id = UUID(id) if isinstance(id, str) else (id if id else uuid4())
        self.first_name = first_name
        self.last_name = last_name

        # Convert string to enum if necessary
        if isinstance(provider_type, str):
            self.provider_type = ProviderType(provider_type)
        else:
            self.provider_type = provider_type

        self.specialties = specialties or []
        self.license_number = license_number
        self.npi_number = npi_number
        self.email = email
        self.phone = phone
        self.address = address or {}
        self.bio = bio
        self.education = education or []
        self.certifications = certifications or []
        self.languages = languages or []

        # Convert string to enum if necessary
        if isinstance(status, str):
            self.status = ProviderStatus(status)
        else:
            self.status = status

        self.availability = availability or {}
        self.max_patients = max_patients
        self.current_patient_count = current_patient_count
        self.accepts_new_patients = accepts_new_patients
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.metadata = metadata or {}

        # Validate the provider
        self._validate()

    def _validate(self) -> None:
        """
        Validate the provider.

        Raises:
            ValidationException: If the provider is invalid
        """
        # Check required fields
        if not self.first_name:
            raise ValidationError("First name is required")

        if not self.last_name:
            raise ValidationError("Last name is required")

        if not self.provider_type:
            raise ValidationError("Provider type is required")

        # Check that at least one contact method is provided
        if not self.email and not self.phone:
            raise ValidationError("At least one contact method (email or phone) is required")

        # Validate email format if provided
        if self.email and not self._is_valid_email(self.email):
            raise ValidationError(f"Invalid email format: {self.email}")

        # Validate phone format if provided
        if self.phone and not self._is_valid_phone(self.phone):
            raise ValidationError(f"Invalid phone format: {self.phone}")

        # Validate license number if provider is a psychiatrist
        if self.provider_type == ProviderType.PSYCHIATRIST and not self.license_number:
            raise ValidationError("License number is required for psychiatrists")

    def _is_valid_email(self, email: str) -> bool:
        """
        Check if an email is valid.

        Args:
            email: Email to check

        Returns:
            True if valid, False otherwise
        """
        # Simple email validation
        return "@" in email and "." in email.split("@")[1]

    def _is_valid_phone(self, phone: str) -> bool:
        """
        Check if a phone number is valid.

        Args:
            phone: Phone number to check

        Returns:
            True if valid, False otherwise
        """
        # Simple phone validation (digits, spaces, dashes, parentheses)
        return all(c.isdigit() or c in " -.()" for c in phone)

    def update_personal_info(
        self,
        first_name: str | None = None,
        last_name: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        address: dict[str, Any] | None = None,
        bio: str | None = None,
    ) -> None:
        """
        Update personal information.

        Args:
            first_name: New first name
            last_name: New last name
            email: New email
            phone: New phone
            address: New address
            bio: New biography

        Raises:
            ValidationException: If the updated information is invalid
        """
        # Update fields if provided
        if first_name is not None:
            self.first_name = first_name

        if last_name is not None:
            self.last_name = last_name

        if email is not None:
            self.email = email

        if phone is not None:
            self.phone = phone

        if address is not None:
            self.address = address

        if bio is not None:
            self.bio = bio

        # Update timestamp
        self.updated_at = datetime.now()

        # Validate the updated provider
        self._validate()

    def update_professional_info(
        self,
        provider_type: ProviderType | str | None = None,
        specialties: list[str] | None = None,
        license_number: str | None = None,
        npi_number: str | None = None,
        education: list[dict[str, Any]] | None = None,
        certifications: list[dict[str, Any]] | None = None,
        languages: list[str] | None = None,
    ) -> None:
        """
        Update professional information.

        Args:
            provider_type: New provider type
            specialties: New specialties
            license_number: New license number
            npi_number: New NPI number
            education: New education history
            certifications: New certifications
            languages: New languages

        Raises:
            ValidationException: If the updated information is invalid
        """
        # Update fields if provided
        if provider_type is not None:
            if isinstance(provider_type, str):
                self.provider_type = ProviderType(provider_type)
            else:
                self.provider_type = provider_type

        if specialties is not None:
            self.specialties = specialties

        if license_number is not None:
            self.license_number = license_number

        if npi_number is not None:
            self.npi_number = npi_number

        if education is not None:
            self.education = education

        if certifications is not None:
            self.certifications = certifications

        if languages is not None:
            self.languages = languages

        # Update timestamp
        self.updated_at = datetime.now()

        # Validate the updated provider
        self._validate()

    def update_status(self, status: ProviderStatus | str) -> None:
        """
        Update the provider's status.

        Args:
            status: New status
        """
        if isinstance(status, str):
            self.status = ProviderStatus(status)
        else:
            self.status = status

        # Update timestamp
        self.updated_at = datetime.now()

    @property
    def is_active(self) -> bool:
        """
        Check if the provider is active.

        Returns:
            True if the provider is active, False otherwise
        """
        return self.status == ProviderStatus.ACTIVE

    @property
    def full_name(self) -> str:
        """
        Get the provider's full name.

        Returns:
            Full name combining first and last name
        """
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return "Unknown Provider"

    def set_accepts_new_patients(self, accepts: bool) -> None:
        """
        Set whether the provider accepts new patients.

        Args:
            accepts: Whether to accept new patients
        """
        self.accepts_new_patients = accepts
        self.updated_at = datetime.now()

    def add_specialty(self, specialty: str) -> None:
        """
        Add a specialty.

        Args:
            specialty: Specialty to add
        """
        if specialty not in self.specialties:
            self.specialties.append(specialty)

            # Update timestamp
            self.updated_at = datetime.now()

    def remove_specialty(self, specialty: str) -> None:
        """
        Remove a specialty.

        Args:
            specialty: Specialty to remove
        """
        if specialty in self.specialties:
            self.specialties.remove(specialty)

            # Update timestamp
            self.updated_at = datetime.now()

    def add_language(self, language: str) -> None:
        """
        Add a language.

        Args:
            language: Language to add
        """
        if language not in self.languages:
            self.languages.append(language)

            # Update timestamp
            self.updated_at = datetime.now()

    def remove_language(self, language: str) -> None:
        """
        Remove a language.

        Args:
            language: Language to remove
        """
        if language in self.languages:
            self.languages.remove(language)

            # Update timestamp
            self.updated_at = datetime.now()

    def add_education(self, education: dict[str, Any]) -> None:
        """
        Add an education entry.

        Args:
            education: Education entry to add

        Raises:
            ValidationException: If the education entry is invalid
        """
        # Validate education entry
        if not education.get("institution"):
            raise ValidationError("Education institution is required")

        if not education.get("degree"):
            raise ValidationError("Education degree is required")

        # Add education entry
        self.education.append(education)

        # Update timestamp
        self.updated_at = datetime.now()

    def add_certification(self, certification: dict[str, Any]) -> None:
        """
        Add a certification.

        Args:
            certification: Certification to add

        Raises:
            ValidationException: If the certification is invalid
        """
        # Validate certification
        if not certification.get("name"):
            raise ValidationError("Certification name is required")

        # Add certification
        self.certifications.append(certification)

        # Update timestamp
        self.updated_at = datetime.now()

    def set_availability(self, availability: dict[str, list[dict[str, Any]]]) -> None:
        """
        Set availability schedule.

        Args:
            availability: Availability schedule

        Raises:
            ValidationException: If the availability is invalid
        """
        # Validate availability
        for day, slots in availability.items():
            for slot in slots:
                if "start" not in slot or "end" not in slot:
                    raise ValidationError(f"Invalid availability slot for {day}: {slot}")

        self.availability = availability

        # Update timestamp
        self.updated_at = datetime.now()

    def add_availability_slot(self, day: str, start: time | str, end: time | str) -> None:
        """
        Add an availability slot.

        Args:
            day: Day of the week (e.g., "monday")
            start: Start time
            end: End time

        Raises:
            ValidationException: If the slot is invalid
        """
        # Convert string to time if necessary
        if isinstance(start, str):
            start_parts = start.split(":")
            start = time(int(start_parts[0]), int(start_parts[1]))

        if isinstance(end, str):
            end_parts = end.split(":")
            end = time(int(end_parts[0]), int(end_parts[1]))

        # Validate slot
        if start >= end:
            raise ValidationError("Start time must be before end time")

        # Initialize day if not present
        if day not in self.availability:
            self.availability[day] = []

        # Add slot
        self.availability[day].append(
            {"start": start.strftime("%H:%M"), "end": end.strftime("%H:%M")}
        )

        # Update timestamp
        self.updated_at = datetime.now()

    def remove_availability_slot(self, day: str, index: int) -> None:
        """
        Remove an availability slot.

        Args:
            day: Day of the week
            index: Index of the slot to remove

        Raises:
            KeyError: If the day is not found
            IndexError: If the index is out of range
        """
        if day not in self.availability:
            raise KeyError(f"Day not found: {day}")

        if index < 0 or index >= len(self.availability[day]):
            raise IndexError(f"Slot index out of range for {day}: {index}")

        # Remove slot
        self.availability[day].pop(index)

        # Update timestamp
        self.updated_at = datetime.now()

    def is_available(self, day: str, start: time, end: time) -> bool:
        """
        Check if the provider is available during a time slot.

        Args:
            day: Day of the week
            start: Start time
            end: End time

        Returns:
            True if available, False otherwise
        """
        # Check if the provider is active
        if self.status != ProviderStatus.ACTIVE:
            return False

        # Check if the day exists in availability
        if day not in self.availability:
            return False

        # Check if any slot overlaps with the requested time
        for slot in self.availability[day]:
            slot_start = self._parse_time(slot["start"])
            slot_end = self._parse_time(slot["end"])

            # Check for overlap
            # If the requested time falls within the provider's available slot
            if start >= slot_start and start < slot_end and end > slot_start and end <= slot_end:
                return True

        return False

    def _parse_time(self, time_str: str) -> time:
        """
        Parse a time string.

        Args:
            time_str: Time string in format "HH:MM"

        Returns:
            Time object
        """
        hours, minutes = map(int, time_str.split(":"))
        return time(hours, minutes)

    def update_patient_count(self, count: int) -> None:
        """
        Update the current patient count.

        Args:
            count: New patient count

        Raises:
            ValidationException: If the count is negative
        """
        if count < 0:
            raise ValidationError("Patient count cannot be negative")

        self.current_patient_count = count

        # Update timestamp
        self.updated_at = datetime.now()

    def increment_patient_count(self) -> None:
        """
        Increment the current patient count.

        Raises:
            ValidationException: If the maximum patient count is reached
        """
        if self.max_patients is not None and self.current_patient_count >= self.max_patients:
            raise ValidationError("Maximum patient count reached")

        self.current_patient_count += 1

        # Update timestamp
        self.updated_at = datetime.now()

    def decrement_patient_count(self) -> None:
        """
        Decrement the current patient count.

        Raises:
            ValidationException: If the count is already zero
        """
        if self.current_patient_count <= 0:
            raise ValidationError("Patient count is already zero")

        self.current_patient_count -= 1

        # Update timestamp
        self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the provider to a dictionary.

        Returns:
            Dictionary representation of the provider
        """
        return {
            "id": str(self.id),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "provider_type": self.provider_type.value if self.provider_type else None,
            "specialties": self.specialties,
            "license_number": self.license_number,
            "npi_number": self.npi_number,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "bio": self.bio,
            "education": self.education,
            "certifications": self.certifications,
            "languages": self.languages,
            "status": self.status.value if self.status else None,
            "availability": self.availability,
            "max_patients": self.max_patients,
            "current_patient_count": self.current_patient_count,
            "accepts_new_patients": self.accepts_new_patients,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Provider":
        """
        Create a provider from a dictionary.

        Args:
            data: Dictionary representation of a provider

        Returns:
            Provider instance
        """
        # Convert ISO format strings to datetime objects
        for field in ["created_at", "updated_at"]:
            if data.get(field):
                data[field] = datetime.fromisoformat(data[field])

        return cls(**data)

    def __eq__(self, other: object) -> bool:
        """
        Check if two providers are equal.

        Args:
            other: Other object to compare with

        Returns:
            True if equal, False otherwise
        """
        if not isinstance(other, Provider):
            return False

        return str(self.id) == str(other.id)

    def __hash__(self) -> int:
        """
        Get the hash of the provider.

        Returns:
            Hash value
        """
        return hash(str(self.id))

    def __str__(self) -> str:
        """
        Get a string representation of the provider.

        Returns:
            String representation
        """
        return f"Provider(id={self.id}, name={self.first_name} {self.last_name}, type={self.provider_type.value if self.provider_type else None})"
