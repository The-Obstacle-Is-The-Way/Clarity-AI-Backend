"""
Repository interface for BiometricTwin entities.

This module defines the interface for storing and retrieving BiometricTwin
entities, following the Repository pattern to abstract data access operations.
"""

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.biometric_twin_enhanced import BiometricTwin


class BiometricTwinRepository(ABC):
    """
    Repository interface for BiometricTwin entities.

    This abstract class defines the contract for repositories that handle
    BiometricTwin entities, ensuring consistent data access patterns across
    different storage implementations.
    """

    @abstractmethod
    def get_by_id(self, twin_id: UUID) -> BiometricTwin | None:
        """
        Retrieve a BiometricTwin by its ID.

        Args:
            twin_id: The unique identifier of the BiometricTwin

        Returns:
            The BiometricTwin if found, None otherwise
        """
        pass

    @abstractmethod
    def get_by_patient_id(self, patient_id: UUID) -> BiometricTwin | None:
        """
        Retrieve a BiometricTwin by the associated patient ID.

        Args:
            patient_id: The unique identifier of the patient

        Returns:
            The BiometricTwin if found, None otherwise
        """
        pass

    @abstractmethod
    def save(self, biometric_twin: BiometricTwin) -> BiometricTwin:
        """
        Save a BiometricTwin entity.

        This method handles both creation of new entities and updates to existing ones.

        Args:
            biometric_twin: The BiometricTwin entity to save

        Returns:
            The saved BiometricTwin with any repository-generated fields updated
        """
        pass

    @abstractmethod
    def delete(self, twin_id: UUID) -> bool:
        """
        Delete a BiometricTwin by its ID.

        Args:
            twin_id: The unique identifier of the BiometricTwin to delete

        Returns:
            True if the entity was successfully deleted, False otherwise
        """
        pass

    @abstractmethod
    def list_by_connected_device(self, device_id: str) -> list[BiometricTwin]:
        """
        List all BiometricTwin entities connected to a specific device.

        Args:
            device_id: The unique identifier of the connected device

        Returns:
            List of BiometricTwin entities connected to the specified device
        """
        pass

    @abstractmethod
    def list_all(self, limit: int = 100, offset: int = 0) -> list[BiometricTwin]:
        """
        List all BiometricTwin entities with pagination.

        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip

        Returns:
            List of BiometricTwin entities
        """
        pass

    @abstractmethod
    def count(self) -> int:
        """
        Count the total number of BiometricTwin entities.

        Returns:
            The total count of BiometricTwin entities
        """
        pass
