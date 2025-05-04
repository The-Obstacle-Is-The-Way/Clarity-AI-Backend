"""
XGBoost interface definition.

This module defines the domain interface for XGBoost services,
following clean architecture principles and the dependency inversion principle.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class XGBoostInterface(ABC):
    """
    Abstract interface for XGBoost ML services.
    
    This interface defines the contract that any XGBoost implementation must fulfill,
    following the Interface Segregation Principle from SOLID. It serves as a port
    in the hexagonal architecture pattern.
    """
    
    @abstractmethod
    async def predict_risk(self, patient_id: UUID, features: dict[str, Any]) -> dict[str, Any]:
        """
        Predict risk factors for a patient using XGBoost models.
        
        Args:
            patient_id: Unique identifier for the patient
            features: Dictionary of features for prediction
            
        Returns:
            Risk assessment results
        """
        pass
    
    @abstractmethod
    async def predict_treatment_response(
        self, 
        patient_id: UUID, 
        medication_id: str,
        features: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Predict patient response to a specific treatment using XGBoost models.
        
        Args:
            patient_id: Unique identifier for the patient
            medication_id: Identifier for the medication
            features: Dictionary of features for prediction
            
        Returns:
            Treatment response prediction results
        """
        pass
    
    @abstractmethod
    async def get_feature_importance(self, model_id: str) -> list[dict[str, Any]]:
        """
        Get feature importance for a specific XGBoost model.
        
        Args:
            model_id: Identifier for the specific model
            
        Returns:
            List of feature importance scores
        """
        pass
