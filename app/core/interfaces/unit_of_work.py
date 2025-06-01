"""Unit of Work interface definition.

This module defines the Unit of Work pattern interface which provides
a transactional boundary for database operations across multiple repositories,
ensuring HIPAA-compliant data consistency in the application's persistence layer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any


class IUnitOfWork(ABC):
    """
    Unit of Work interface defining a transaction boundary for domain operations.

    The Unit of Work pattern maintains a list of objects affected by a business transaction
    and coordinates the writing out of changes. This interface ensures all concrete
    implementations provide the necessary methods for transaction management.
    """

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork:
        """
        Enter the context manager, beginning a new transaction.

        Returns:
            The UnitOfWork instance for method chaining
        """
        pass

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Exit the context manager, handling commit or rollback based on exceptions.

        Args:
            exc_type: The exception type if an exception was raised
            exc_val: The exception value if an exception was raised
            exc_tb: The traceback if an exception was raised
        """
        pass

    @abstractmethod
    async def commit(self) -> None:
        """
        Commit all changes made within the transaction.

        This method persists all changes made through repositories within this
        unit of work to the underlying database or storage mechanism.
        """
        pass

    @abstractmethod
    async def rollback(self) -> None:
        """
        Rollback all changes made within the transaction.

        This method discards all changes made through repositories within this
        unit of work, leaving the database or storage mechanism unchanged.
        """
        pass

    # Repository property protocols
    @property
    @abstractmethod
    def users(self) -> Any:
        """Access to the user repository within this transaction."""
        pass

    @property
    @abstractmethod
    def patients(self) -> Any:
        """Access to the patient repository within this transaction."""
        pass

    @property
    @abstractmethod
    def digital_twins(self) -> Any:
        """Access to the digital twin repository within this transaction."""
        pass

    @property
    @abstractmethod
    def biometric_rules(self) -> Any:
        """Access to the biometric rule repository within this transaction."""
        pass

    @property
    @abstractmethod
    def biometric_alerts(self) -> Any:
        """Access to the biometric alert repository within this transaction."""
        pass

    @property
    @abstractmethod
    def biometric_twins(self) -> Any:
        """Access to the biometric twin repository within this transaction."""
        pass
