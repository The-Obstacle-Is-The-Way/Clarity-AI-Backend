"""
Interface definition for the PAT service.

This module defines the interface for the Physical Activity Tracking (PAT) service,
which provides actigraphy analysis and embedding generation capabilities.
"""

import abc
from typing import Any


class PATInterface(abc.ABC):
    """Interface for the PAT service.
    
    This interface defines the contract that all PAT service implementations
    must follow, providing methods for analyzing actigraphy data, generating
    embeddings, and integrating with digital twin profiles.
    """
    
    @abc.abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the PAT service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InitializationError: If initialization fails
        """
        pass
    
    @abc.abstractmethod
    def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, Any],
        analysis_types: list[str]
    ) -> dict[str, Any]:
        """Analyze actigraphy data and return insights.
        
        Args:
            patient_id: Unique identifier for the patient
            readings: List of accelerometer readings
            start_time: ISO-8601 formatted start time
            end_time: ISO-8601 formatted end time
            sampling_rate_hz: Sampling rate in Hz
            device_info: Information about the device
            analysis_types: List of analysis types to perform
        
        Returns:
            Dictionary containing analysis results
            
        Raises:
            ValidationError: If input validation fails
            AnalysisError: If analysis fails
            InitializationError: If service is not initialized
        """
        pass
    
    @abc.abstractmethod
    def get_actigraphy_embeddings(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float
    ) -> dict[str, Any]:
        """Generate embeddings from actigraphy data.
        
        Args:
            patient_id: Unique identifier for the patient
            readings: List of accelerometer readings
            start_time: ISO-8601 formatted start time
            end_time: ISO-8601 formatted end time
            sampling_rate_hz: Sampling rate in Hz
        
        Returns:
            Dictionary containing embedding vector and metadata
            
        Raises:
            ValidationError: If input validation fails
            EmbeddingError: If embedding generation fails
            InitializationError: If service is not initialized
        """
        pass
    
    @abc.abstractmethod
    def get_analysis_by_id(self, analysis_id: str) -> dict[str, Any]:
        """Retrieve an analysis by its ID.
        
        Args:
            analysis_id: Unique identifier for the analysis
        
        Returns:
            Dictionary containing the analysis
            
        Raises:
            ResourceNotFoundError: If the analysis is not found
            InitializationError: If service is not initialized
        """
        pass
    
    @abc.abstractmethod
    def get_patient_analyses(
        self,
        patient_id: str,
        limit: int = 10,
        offset: int = 0
    ) -> dict[str, Any]:
        """Retrieve analyses for a patient.
        
        Args:
            patient_id: Unique identifier for the patient
            limit: Maximum number of analyses to return
            offset: Offset for pagination
        
        Returns:
            Dictionary containing the analyses and pagination information
            
        Raises:
            InitializationError: If service is not initialized
        """
        pass
    
    @abc.abstractmethod
    def get_model_info(self) -> dict[str, Any]:
        """Get information about the PAT model.
        
        Returns:
            Dictionary containing model information
            
        Raises:
            InitializationError: If service is not initialized
        """
        pass
    
    @abc.abstractmethod
    def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        analysis_id: str
    ) -> dict[str, Any]:
        """Integrate actigraphy analysis with a digital twin profile.
        
        Args:
            patient_id: Unique identifier for the patient
            profile_id: Unique identifier for the digital twin profile
            analysis_id: Unique identifier for the analysis to integrate
        
        Returns:
            Dictionary containing the integration status and updated profile
            
        Raises:
            ResourceNotFoundError: If the analysis or profile is not found
            AuthorizationError: If the analysis does not belong to the patient
            IntegrationError: If integration fails
            InitializationError: If service is not initialized
        """
        pass
