"""
Digital Twin Repository Interface - Core Domain Interface

This module defines the interface for Digital Twin repository implementations,
following the principles of clean architecture with hexagonal ports and adapters.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IDigitalTwinRepository(ABC):
    """
    Interface for Digital Twin repository implementations.
    Defines the contract for storage and retrieval of Digital Twin data.
    """

    @abstractmethod
    async def create_digital_twin(self, twin_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new digital twin.

        Args:
            twin_data: Data for the digital twin

        Returns:
            The created digital twin with ID
        """
        pass

    @abstractmethod
    async def get_digital_twin(self, twin_id: str | UUID) -> dict[str, Any] | None:
        """
        Get a digital twin by ID.

        Args:
            twin_id: Digital twin ID

        Returns:
            Digital twin data if found, None otherwise
        """
        pass

    @abstractmethod
    async def update_digital_twin(
        self, twin_id: str | UUID, twin_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Update a digital twin.

        Args:
            twin_id: Digital twin ID
            twin_data: Updated data

        Returns:
            Updated digital twin if found, None otherwise
        """
        pass

    @abstractmethod
    async def delete_digital_twin(self, twin_id: str | UUID) -> bool:
        """
        Delete a digital twin.

        Args:
            twin_id: Digital twin ID

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    async def list_digital_twins(self, user_id: str | UUID | None = None) -> list[dict[str, Any]]:
        """
        List all digital twins, optionally filtered by user ID.

        Args:
            user_id: Optional user ID to filter by

        Returns:
            List of digital twins
        """
        pass

    @abstractmethod
    async def create_session(
        self, twin_id: str | UUID, session_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a new session for a digital twin.

        Args:
            twin_id: Digital twin ID
            session_data: Session data

        Returns:
            Created session with ID
        """
        pass

    @abstractmethod
    async def get_session(self, session_id: str | UUID) -> dict[str, Any] | None:
        """
        Get a session by ID.

        Args:
            session_id: Session ID

        Returns:
            Session data if found, None otherwise
        """
        pass

    @abstractmethod
    async def update_session(
        self, session_id: str | UUID, session_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Update a session.

        Args:
            session_id: Session ID
            session_data: Updated data

        Returns:
            Updated session if found, None otherwise
        """
        pass

    @abstractmethod
    async def add_message_to_session(
        self, session_id: str | UUID, message: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Add a message to a session.

        Args:
            session_id: Session ID
            message: Message data

        Returns:
            Updated session with the new message
        """
        pass

    @abstractmethod
    async def end_session(self, session_id: str | UUID) -> dict[str, Any] | None:
        """
        End a session.

        Args:
            session_id: Session ID

        Returns:
            Updated session if found, None otherwise
        """
        pass
