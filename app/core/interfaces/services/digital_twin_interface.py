"""
Digital Twin Interface Module.

This module defines the interface for Digital Twin services in the core domain,
following the Dependency Inversion Principle of SOLID.
"""

from abc import ABC, abstractmethod
from typing import Any


class DigitalTwinInterface(ABC):
    """
    Interface for Digital Twin service implementations.
    
    This interface defines the contract that all Digital Twin service
    implementations must adhere to, allowing for dependency injection
    and better testability.
    """
    
    @abstractmethod
    async def create_digital_twin(self, patient_id: str, initial_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new digital twin for a patient.
        
        Args:
            patient_id: The ID of the patient
            initial_data: Initial data to populate the twin
            
        Returns:
            A dictionary containing the status or details of the created twin
        """
        pass
    
    @abstractmethod
    async def get_twin_status(self, twin_id: str) -> dict[str, Any]:
        """
        Get the current status of a digital twin.
        
        Args:
            twin_id: The ID of the digital twin
            
        Returns:
            A dictionary containing the status information
        """
        pass
    
    @abstractmethod
    async def update_twin_data(self, twin_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        Update the data associated with a digital twin.
        
        Args:
            twin_id: The ID of the digital twin
            data: The data to update
            
        Returns:
            A dictionary confirming the update status
        """
        pass
    
    @abstractmethod
    async def get_insights(self, twin_id: str, insight_types: list[str]) -> dict[str, Any]:
        """
        Generate insights from the digital twin's data.
        
        Args:
            twin_id: The ID of the digital twin
            insight_types: A list of specific insight types to generate
            
        Returns:
            A dictionary containing the requested insights
        """
        pass
    
    @abstractmethod
    async def interact(self, twin_id: str, query: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Interact with the digital twin, potentially asking questions or running simulations.
        
        Args:
            twin_id: The ID of the digital twin
            query: The interaction query or command
            context: Optional context for the interaction
            
        Returns:
            A dictionary containing the result of the interaction
        """
        pass
    
    @abstractmethod
    def is_healthy(self) -> bool:
        """
        Check if the Digital Twin service is healthy and available.
        
        Returns:
            Boolean indicating service health
        """
        pass
