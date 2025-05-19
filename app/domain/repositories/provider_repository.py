"""
Provider Repository Interface

This module defines the interface for provider repositories.
"""

from abc import ABC, abstractmethod
from datetime import datetime
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
    def get_by_id(self, provider_id: UUID | str) -> Provider | None:
        """
        Get a provider by ID.

        Args:
            provider_id: ID of the provider

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    def get_by_email(self, email: str) -> Provider | None:
        """
        Get a provider by email.

        Args:
            email: Email of the provider

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    def get_by_license_number(self, license_number: str) -> Provider | None:
        """
        Get a provider by license number.

        Args:
            license_number: License number of the provider

        Returns:
            Provider if found, None otherwise
        """
        pass

    @abstractmethod
    def save(self, provider: Provider) -> Provider:
        """
        Save a provider.

        Args:
            provider: Provider to save

        Returns:
            Saved provider
        """
        pass

    @abstractmethod
    def delete(self, provider_id: UUID | str) -> bool:
        """
        Delete a provider.

        Args:
            provider_id: ID of the provider to delete

        Returns:
            True if deleted, False otherwise
        """
        pass

    @abstractmethod
    def search(self, query: str, limit: int = 10, offset: int = 0) -> list[Provider]:
        """
        Search for providers.

        Args:
            query: Search query
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of matching providers
        """
        pass

    @abstractmethod
    def get_all(
        self,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "last_name",
        sort_order: str = "asc",
    ) -> list[Provider]:
        """
        Get all providers with pagination.

        Args:
            limit: Maximum number of results
            offset: Offset for pagination
            sort_by: Field to sort by
            sort_order: Sort order (asc or desc)

        Returns:
            List of providers
        """
        pass

    @abstractmethod
    def count(self) -> int:
        """
        Count all providers.

        Returns:
            Number of providers
        """
        pass

    @abstractmethod
    def exists(self, provider_id: UUID | str) -> bool:
        """
        Check if a provider exists.

        Args:
            provider_id: ID of the provider

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    def exists_by_email(self, email: str) -> bool:
        """
        Check if a provider exists by email.

        Args:
            email: Email of the provider

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    def exists_by_license_number(self, license_number: str) -> bool:
        """
        Check if a provider exists by license number.

        Args:
            license_number: License number of the provider

        Returns:
            True if exists, False otherwise
        """
        pass

    @abstractmethod
    def get_available_providers(
        self,
        start_time: datetime,
        end_time: datetime,
        specialties: list[str] | None = None,
    ) -> list[Provider]:
        """
        Get providers available during a time range.

        Args:
            start_time: Start time
            end_time: End time
            specialties: Optional list of specialties to filter by

        Returns:
            List of available providers
        """
        pass

    @abstractmethod
    def get_providers_by_specialty(
        self, specialty: str, limit: int = 100, offset: int = 0
    ) -> list[Provider]:
        """
        Get providers by specialty.

        Args:
            specialty: Specialty to filter by
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of providers with the specified specialty
        """
        pass

    @abstractmethod
    def get_provider_availability(
        self, provider_id: UUID | str, start_date: datetime, end_date: datetime
    ) -> dict[str, list[dict[str, datetime]]]:
        """
        Get a provider's availability.

        Args:
            provider_id: ID of the provider
            start_date: Start date
            end_date: End date

        Returns:
            Dictionary mapping dates to lists of available time slots
        """
        pass
