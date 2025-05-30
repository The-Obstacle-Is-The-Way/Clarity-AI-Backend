"""
Provider Repository Interface

This module defines the interface for provider repositories.
"""

from abc import ABC, abstractmethod
from datetime import date, datetime
from typing import Any
from uuid import UUID

from app.domain.entities.provider import Provider


class ProviderRepository(ABC):
    """
    Interface for provider repositories.

    This abstract class defines the contract that all provider repositories
    must implement, ensuring consistent access to provider data regardless
    of the underlying storage mechanism.
    """

    @abstractmethod
    async def get_by_id(
        self, provider_id: UUID, context: dict[str, Any] | None = None
    ) -> Provider | None:
        """
        Get a provider by ID.

        Args:
            provider_id: ID of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_email(
        self, email: str, context: dict[str, Any] | None = None
    ) -> Provider | None:
        """
        Get a provider by email.

        Args:
            email: Email of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_license_number(
        self, license_number: str, context: dict[str, Any] | None = None
    ) -> Provider | None:
        """
        Get a provider by license number.

        Args:
            license_number: License number of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_by_npi(self, npi: str, context: dict[str, Any] | None = None) -> Provider | None:
        """
        Get a provider by NPI (National Provider Identifier).

        Args:
            npi: NPI number of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    async def create(self, provider: Provider, context: dict[str, Any] | None = None) -> Provider:
        """
        Create a new provider record.

        Args:
            provider: Provider entity to create
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Created provider entity with populated ID and timestamps
        """
        pass

    @abstractmethod
    async def update(
        self, provider: Provider, context: dict[str, Any] | None = None
    ) -> Provider | None:
        """
        Update an existing provider record.

        Args:
            provider: Provider entity with updated data
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Updated provider entity if successful, None if provider not found
        """
        pass

    @abstractmethod
    async def delete(self, provider_id: UUID, context: dict[str, Any] | None = None) -> bool:
        """
        Delete a provider.

        Args:
            provider_id: ID of the provider to delete
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            True if deleted, False otherwise
        """
        pass

    @abstractmethod
    async def search(
        self, query: str, limit: int = 10, offset: int = 0, context: dict[str, Any] | None = None
    ) -> list[Provider]:
        """
        Search for providers.

        Args:
            query: Search query
            limit: Maximum number of results
            offset: Offset for pagination
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            List of matching providers
        """
        pass

    @abstractmethod
    async def list_all(
        self,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "last_name",
        sort_order: str = "asc",
        context: dict[str, Any] | None = None,
    ) -> list[Provider]:
        """
        Get all providers with pagination.

        Args:
            limit: Maximum number of results
            offset: Offset for pagination
            sort_by: Field to sort by
            sort_order: Sort order (asc or desc)
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            List of providers
        """
        pass

    @abstractmethod
    async def count(self, context: dict[str, Any] | None = None) -> int:
        """
        Count all providers.

        Args:
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Number of providers
        """
        pass

    @abstractmethod
    async def exists(self, provider_id: UUID, context: dict[str, Any] | None = None) -> bool:
        """
        Check if a provider exists.

        Args:
            provider_id: ID of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_email(self, email: str, context: dict[str, Any] | None = None) -> bool:
        """
        Check if a provider exists by email.

        Args:
            email: Email of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_license_number(
        self, license_number: str, context: dict[str, Any] | None = None
    ) -> bool:
        """
        Check if a provider exists by license number.

        Args:
            license_number: License number of the provider
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    async def get_available_providers(
        self,
        start_time: datetime,
        end_time: datetime,
        specialties: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> list[Provider]:
        """
        Get providers available during a time range.

        Args:
            start_time: Start time
            end_time: End time
            specialties: Optional list of specialties to filter by
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            List of available providers
        """
        pass

    @abstractmethod
    async def get_providers_by_specialty(
        self,
        specialty: str,
        limit: int = 100,
        offset: int = 0,
        context: dict[str, Any] | None = None,
    ) -> list[Provider]:
        """
        Get providers by specialty.

        Args:
            specialty: Specialty to filter by
            limit: Maximum number of results
            offset: Offset for pagination
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            List of providers with the specified specialty
        """
        pass

    @abstractmethod
    async def get_provider_availability(
        self,
        provider_id: UUID,
        start_date: datetime,
        end_date: datetime,
        context: dict[str, Any] | None = None,
    ) -> dict[str, list[dict[str, datetime]]]:
        """
        Get a provider's availability.

        Args:
            provider_id: ID of the provider
            start_date: Start date
            end_date: End date
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Dictionary mapping dates to lists of available time slots
        """
        pass

    @abstractmethod
    async def get_available_on_day(
        self, day: date, context: dict[str, Any] | None = None
    ) -> list[Provider]:
        """
        Get providers available on a specific day.

        Args:
            day: The specific day to check availability for
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            List of providers available on the specified day
        """
        pass

    @abstractmethod
    async def get_prescribers(self, context: dict[str, Any] | None = None) -> list[Provider]:
        """
        Get providers who can prescribe medications.

        Args:
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            List of providers who are authorized to prescribe medications
        """
        pass

    # Convenience method for backward compatibility
    @abstractmethod
    async def save(self, provider: Provider, context: dict[str, Any] | None = None) -> Provider:
        """
        Save a provider (create if new, update if existing).

        Args:
            provider: Provider to save
            context: Optional context for HIPAA audit logging (user_id, action, etc.)

        Returns:
            Saved provider
        """
        pass
