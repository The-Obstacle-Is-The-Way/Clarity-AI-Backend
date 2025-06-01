"""
ML Service Interface Module.

This module defines the interface for ML services in the core domain,
following the Dependency Inversion Principle of SOLID.
"""

from abc import ABC, abstractmethod
from typing import Any, TypeVar

T = TypeVar('T')


class MLServiceInterface(ABC):
    """
    Interface for ML service implementations.
    
    This interface defines the contract that all ML service
    implementations must adhere to, allowing for dependency injection
    and better testability.
    """
    
    @abstractmethod
    async def predict(
        self, model_id: str, features: dict[str, Any], options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Make a prediction using the specified ML model.
        
        Args:
            model_id: Identifier for the ML model to use
            features: Input features for the prediction
            options: Additional options for the prediction
            
        Returns:
            Prediction results including prediction, confidence, and metadata
        """
        pass
    
    @abstractmethod
    async def batch_predict(
        self, model_id: str, batch_features: list[dict[str, Any]], options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Make batch predictions using the specified ML model.
        
        Args:
            model_id: Identifier for the ML model to use
            batch_features: List of feature sets for batch prediction
            options: Additional options for the prediction
            
        Returns:
            Batch prediction results
        """
        pass
    
    @abstractmethod
    async def get_model_info(self, model_id: str) -> dict[str, Any]:
        """
        Get information about a specific ML model.
        
        Args:
            model_id: Identifier for the ML model
            
        Returns:
            Model information including features, performance metrics, etc.
        """
        pass
    
    @abstractmethod
    async def list_models(self) -> dict[str, Any]:
        """
        List all available ML models.
        
        Returns:
            List of available models with basic info
        """
        pass
    
    @abstractmethod
    async def get_feature_importance(
        self, model_id: str, features: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Calculate feature importance for a prediction.
        
        Args:
            model_id: Identifier for the ML model
            features: Input features for which to calculate importance
            
        Returns:
            Feature importance scores and related metadata
        """
        pass
    
    @abstractmethod
    def is_healthy(self) -> bool:
        """
        Check if the ML service is healthy and available.
        
        Returns:
            Boolean indicating service health
        """
        pass
    
    @abstractmethod
    def get_health_info(self) -> dict[str, Any]:
        """
        Get detailed health information about the ML service.
        
        Returns:
            Health information including uptime, available models, etc.
        """
        pass
