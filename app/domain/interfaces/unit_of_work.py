"""
Unit of Work interface for the Novamind Digital Twin Platform.

This module defines the interface for the Unit of Work pattern, which provides
transactional boundaries for all operations on PHI data in accordance with HIPAA
security requirements.
"""

import abc
from typing import Any, ContextManager


class UnitOfWork(abc.ABC):
    """
    Abstract interface for the Unit of Work pattern.
    
    This pattern provides a way to group operations into a single transaction,
    ensuring that either all operations complete successfully, or none of them do.
    This is critical for maintaining data integrity in a HIPAA-compliant system.
    """
    
    @abc.abstractmethod
    def __enter__(self) -> "UnitOfWork":
        """
        Enter the unit of work context, beginning a new transaction.
        
        Returns:
            The Unit of Work instance
        """
        pass
    
    @abc.abstractmethod
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit the unit of work context, committing or rolling back the transaction.
        
        Args:
            exc_type: Exception type if an exception was raised, None otherwise
            exc_val: Exception value if an exception was raised, None otherwise
            exc_tb: Exception traceback if an exception was raised, None otherwise
        """
        pass
    
    @abc.abstractmethod
    def commit(self) -> None:
        """
        Commit the current transaction.
        
        This makes all changes permanent within the current transaction.
        """
        pass
    
    @abc.abstractmethod
    def rollback(self) -> None:
        """
        Roll back the current transaction.
        
        This cancels all changes made within the current transaction.
        """
        pass
    
    @abc.abstractmethod
    def nested(self) -> ContextManager["UnitOfWork"]:
        """
        Create a nested transaction.
        
        This allows for partial commits/rollbacks within a larger transaction.
        
        Returns:
            A context manager for the nested transaction
        """
        pass
    
    @abc.abstractmethod
    def read_only(self) -> ContextManager["UnitOfWork"]:
        """
        Create a read-only transaction.
        
        This ensures that no changes can be committed, protecting PHI data from
        accidental modifications during read operations.
        
        Returns:
            A context manager for the read-only transaction
        """
        pass
    
    @abc.abstractmethod
    def set_metadata(self, metadata: dict[str, Any]) -> None:
        """
        Set metadata for the current transaction.
        
        This metadata is used for audit logging of PHI access and modifications,
        ensuring HIPAA compliance for all data operations.
        
        Args:
            metadata: Dictionary of metadata for the transaction
        """
        pass