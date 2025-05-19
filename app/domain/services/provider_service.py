"""
Provider service module for the NOVAMIND backend.

This module contains the ProviderService, which encapsulates complex business logic
related to provider management in the concierge psychiatry practice.
"""

from datetime import datetime
from uuid import UUID

from app.domain.entities.provider import (
    AvailabilitySlot,
    Credential,
    Provider,
    ProviderRole,
    ProviderSpecialty,
)
from app.domain.exceptions import (
    PatientLimitExceededError,
    ValidationError,
)
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.repositories.provider_repository import ProviderRepository
from app.domain.utils.datetime_utils import UTC


class ProviderService:
    """
    Service for managing providers in the concierge psychiatry practice.

    This service encapsulates complex business logic related to provider
    management, credential verification, and availability.
    """

    def __init__(
        self,
        provider_repository: ProviderRepository,
        patient_repository: PatientRepository,
    ):
        """
        Initialize the provider service

        Args:
            provider_repository: Repository for provider data access
            patient_repository: Repository for patient data access
        """
        self._provider_repo = provider_repository
        self._patient_repo = patient_repository

    async def register_provider(
        self,
        first_name: str,
        last_name: str,
        role: ProviderRole,
        email: str,
        specialties: set[ProviderSpecialty] | None = None,
        npi_number: str | None = None,
        dea_number: str | None = None,
        phone: str | None = None,
        bio: str | None = None,
        max_patients: int | None = None,
    ) -> Provider:
        """
        Register a new provider

        Args:
            first_name: Provider's first name
            last_name: Provider's last name
            role: Provider's role
            email: Provider's email address
            specialties: Optional set of provider specialties
            npi_number: Optional National Provider Identifier
            dea_number: Optional DEA number for prescribers
            phone: Optional phone number
            bio: Optional professional biography
            max_patients: Optional maximum number of patients

        Returns:
            The created provider entity

        Raises:
            ValidationError: If the provider data is invalid
        """
        # Check if provider with email already exists
        existing_provider = await self._provider_repo.get_by_email(email)
        if existing_provider:
            raise ValidationError(f"Provider with email {email} already exists")

        # Check if provider with NPI already exists (if provided)
        if npi_number:
            existing_provider = await self._provider_repo.get_by_npi(npi_number)
            if existing_provider:
                raise ValidationError(f"Provider with NPI {npi_number} already exists")

        # Create provider entity
        provider = Provider(
            first_name=first_name,
            last_name=last_name,
            role=role,
            email=email,
            specialties=specialties or set(),
            npi_number=npi_number,
            dea_number=dea_number,
            phone=phone,
            bio=bio,
            max_patients=max_patients,
            is_active=True,
            accepts_new_patients=True,
        )

        # Save to repository
        return await self._provider_repo.create(provider)

    async def add_credential(
        self,
        provider_id: UUID,
        credential_type: str,
        issuer: str,
        issue_date: datetime,
        expiration_date: datetime | None = None,
        identifier: str | None = None,
        verification_url: str | None = None,
    ) -> Provider:
        """
        Add a credential to a provider

        Args:
            provider_id: UUID of the provider
            credential_type: Type of credential (e.g., "MD", "PhD")
            issuer: Issuing institution
            issue_date: Date credential was issued
            expiration_date: Optional expiration date
            identifier: Optional identifier (e.g., license number)
            verification_url: Optional URL for verification

        Returns:
            The updated provider entity

        Raises:
            ValidationError: If the credential data is invalid
        """
        # Retrieve the provider
        provider = await self._provider_repo.get_by_id(provider_id)
        if not provider:
            raise ValidationError(f"Provider with ID {provider_id} does not exist")

        # Validate credential data
        if expiration_date and expiration_date < datetime.now(UTC):
            raise ValidationError("Credential expiration date cannot be in the past")

        # Create credential
        credential = Credential(
            type=credential_type,
            issuer=issuer,
            issue_date=issue_date,
            expiration_date=expiration_date,
            identifier=identifier,
            verification_url=verification_url,
        )

        # Add to provider
        provider.add_credential(credential)

        # Save to repository
        return await self._provider_repo.update(provider)

    async def add_availability(
        self,
        provider_id: UUID,
        day_of_week: int,
        start_time: datetime,
        end_time: datetime,
        is_telehealth: bool = True,
        is_in_person: bool = True,
    ) -> Provider:
        """
        Add an availability slot to a provider

        Args:
            provider_id: UUID of the provider
            day_of_week: Day of the week (0 = Monday, 6 = Sunday)
            start_time: Start time of availability
            end_time: End time of availability
            is_telehealth: Whether telehealth appointments are supported
            is_in_person: Whether in-person appointments are supported

        Returns:
            The updated provider entity

        Raises:
            ValidationError: If the availability data is invalid
        """
        # Retrieve the provider
        provider = await self._provider_repo.get_by_id(provider_id)
        if not provider:
            raise ValidationError(f"Provider with ID {provider_id} does not exist")

        # Create availability slot
        availability = AvailabilitySlot(
            day_of_week=day_of_week,
            start_time=start_time.time(),
            end_time=end_time.time(),
            is_telehealth=is_telehealth,
            is_in_person=is_in_person,
        )

        # Add to provider
        provider.add_availability(availability)

        # Save to repository
        return await self._provider_repo.update(provider)

    async def verify_credentials(self, provider_id: UUID) -> tuple[bool, list[str]]:
        """
        Verify that a provider's credentials are valid and not expired

        Args:
            provider_id: UUID of the provider

        Returns:
            Tuple containing (is_valid, list_of_issues)

        Raises:
            ValidationError: If the provider doesn't exist
        """
        # Retrieve the provider
        provider = await self._provider_repo.get_by_id(provider_id)
        if not provider:
            raise ValidationError(f"Provider with ID {provider_id} does not exist")

        # Check credentials
        issues = []

        # Check for expired credentials
        for i, credential in enumerate(provider.credentials):
            if credential.is_expired:
                issues.append(f"Credential {credential.type} from {credential.issuer} is expired")
            elif credential.expires_soon:
                days_left = (credential.expiration_date - datetime.now(UTC)).days
                issues.append(
                    f"Credential {credential.type} from {credential.issuer} expires in {days_left} days"
                )

        # Check if prescriber role has DEA number
        if provider.is_prescriber and not provider.dea_number:
            issues.append(
                f"Provider with role {provider.role.name} requires a DEA number for prescribing"
            )

        # Check if provider has any credentials
        if not provider.credentials:
            issues.append("Provider has no credentials")

        return (len(issues) == 0, issues)

    async def get_available_providers(
        self,
        day_of_week: int,
        specialty: ProviderSpecialty | None = None,
        is_telehealth: bool = False,
    ) -> list[Provider]:
        """
        Get providers available on a specific day, optionally filtered by specialty and appointment type

        Args:
            day_of_week: Day of the week (0 = Monday, 6 = Sunday)
            specialty: Optional specialty to filter by
            is_telehealth: Whether to filter for telehealth availability

        Returns:
            List of available provider entities
        """
        # Get providers available on the specified day
        providers = await self._provider_repo.get_available_on_day(day_of_week)

        # Filter by specialty if specified
        if specialty:
            providers = [p for p in providers if specialty in p.specialties]

        # Filter by telehealth if specified
        if is_telehealth:
            providers = [
                p
                for p in providers
                if any(
                    slot.is_telehealth and slot.day_of_week == day_of_week
                    for slot in p.availability
                )
            ]

        # Filter out inactive providers
        providers = [p for p in providers if p.is_active]

        return providers

    async def get_prescribers(self) -> list[Provider]:
        """
        Get all providers who can prescribe medications

        Returns:
            List of provider entities who can prescribe
        """
        # Get all prescribers
        prescribers = await self._provider_repo.get_prescribers()

        # Filter out inactive providers
        prescribers = [p for p in prescribers if p.is_active]

        return prescribers

    async def check_patient_capacity(self, provider_id: UUID) -> tuple[bool, int | None]:
        """
        Check if a provider has capacity for new patients

        Args:
            provider_id: UUID of the provider

        Returns:
            Tuple containing (has_capacity, remaining_slots)

        Raises:
            ValidationError: If the provider doesn't exist
        """
        # Retrieve the provider
        provider = await self._provider_repo.get_by_id(provider_id)
        if not provider:
            raise ValidationError(f"Provider with ID {provider_id} does not exist")

        # If provider is not accepting patients, return False
        if not provider.accepts_new_patients or not provider.is_active:
            return (False, 0)

        # If provider has no max_patients, they have unlimited capacity
        if provider.max_patients is None:
            return (True, None)

        # Count current patients
        patient_count = await self._count_provider_patients(provider_id)

        # Calculate remaining capacity
        remaining = provider.max_patients - patient_count
        has_capacity = remaining > 0

        return (has_capacity, remaining)

    async def assign_patient_to_provider(self, patient_id: UUID, provider_id: UUID) -> bool:
        """
        Assign a patient to a provider

        Args:
            patient_id: UUID of the patient
            provider_id: UUID of the provider

        Returns:
            True if assignment was successful

        Raises:
            ValidationError: If the patient or provider doesn't exist
            PatientLimitExceededError: If the provider has reached their patient limit
        """
        # Verify patient exists
        patient = await self._patient_repo.get_by_id(patient_id)
        if not patient:
            raise ValidationError(f"Patient with ID {patient_id} does not exist")

        # Verify provider exists
        provider = await self._provider_repo.get_by_id(provider_id)
        if not provider:
            raise ValidationError(f"Provider with ID {provider_id} does not exist")

        # Check if provider is accepting patients
        if not provider.accepts_new_patients or not provider.is_active:
            raise ValidationError(f"Provider {provider.full_name} is not accepting new patients")

        # Check provider capacity
        has_capacity, remaining = await self.check_patient_capacity(provider_id)
        if not has_capacity:
            raise PatientLimitExceededError(
                f"Provider {provider.full_name} has reached their patient limit"
            )

        # In a real implementation, this would update a patient-provider relationship
        # For now, we'll just return True to indicate success
        return True

    async def _count_provider_patients(self, provider_id: UUID) -> int:
        """
        Count the number of patients assigned to a provider

        Args:
            provider_id: UUID of the provider

        Returns:
            Number of patients assigned to the provider
        """
        # In a real implementation, this would query a patient-provider relationship
        # For now, we'll just return a placeholder value
        return 0
