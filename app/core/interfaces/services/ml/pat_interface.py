"""
Psychiatric Assessment Tool (PAT) Interface.

This module defines the interface for psychiatric assessment tools 
that analyze patient data to provide clinical insights and predictions.
"""

from abc import ABC, abstractmethod
from typing import Any

from app.core.domain.entities.digital_twin import DigitalTwin
from app.core.domain.entities.patient import Patient


class PATInterface(ABC):
    """
    Interface for psychiatric assessment tool services.
    
    PAT services analyze patient data and provide clinical insights,
    predictions, and digital twin modeling capabilities.
    """
    
    @abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize the PAT service with required models and configurations.
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def analyze_patient(
        self, 
        patient_id: str, 
        data: dict[str, Any],
        include_risk_factors: bool = True,
        include_recommendations: bool = True
    ) -> dict[str, Any]:
        """
        Analyze patient data to extract clinical insights.
        
        Args:
            patient_id: Patient identifier
            data: Patient data for analysis
            include_risk_factors: Whether to include risk factors in the analysis
            include_recommendations: Whether to include treatment recommendations
            
        Returns:
            Analysis results with clinical insights
        """
        pass
    
    @abstractmethod
    async def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        timeframe_days: int,
        data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Predict specific risk factors for a patient.
        
        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict (e.g., "suicide", "hospitalization")
            timeframe_days: Prediction timeframe in days
            data: Additional data for prediction, if None uses stored patient data
            
        Returns:
            Risk prediction results with confidence scores
        """
        pass
    
    @abstractmethod
    async def create_digital_twin(
        self, 
        patient: Patient,
        include_features: list[str] = None
    ) -> DigitalTwin:
        """
        Create a digital twin model for a patient.
        
        Args:
            patient: Patient entity
            include_features: Optional list of specific features to include
            
        Returns:
            Digital twin entity representing the patient
        """
        pass
    
    @abstractmethod
    async def update_digital_twin(
        self,
        digital_twin_id: str,
        new_data: dict[str, Any]
    ) -> DigitalTwin:
        """
        Update an existing digital twin with new patient data.
        
        Args:
            digital_twin_id: Digital twin identifier
            new_data: New patient data to incorporate
            
        Returns:
            Updated digital twin entity
        """
        pass
    
    @abstractmethod
    async def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the underlying models used by the PAT service.
        
        Returns:
            Model information including version, training data, and capabilities
        """
        pass
