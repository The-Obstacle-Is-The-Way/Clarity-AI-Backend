"""
Base Machine Learning Model Interface.

This module defines the base interface for all machine learning models
in the Novamind Digital Twin system, ensuring consistent API and behavior
across different model implementations.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Union


class BaseMLModel(ABC):
    """
    Abstract base class for all machine learning models in the system.
    
    This interface defines the contract that all ML models must adhere to,
    ensuring consistent behavior and interoperability across the system.
    """
    
    @property
    @abstractmethod
    def is_initialized(self) -> bool:
        """
        Check if the model is initialized and ready for inference.
        
        Returns:
            bool: True if the model is initialized, False otherwise
        """
        pass
    
    @abstractmethod
    async def initialize(self, **kwargs) -> bool:
        """
        Initialize the model with the given parameters.
        
        Args:
            **kwargs: Model-specific initialization parameters
            
        Returns:
            bool: True if initialization was successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def predict(self, input_data: Any) -> Dict[str, Any]:
        """
        Make predictions using the model.
        
        Args:
            input_data: Input data for prediction
            
        Returns:
            Dict[str, Any]: Prediction results
            
        Raises:
            ModelInferenceError: If prediction fails
        """
        pass
    
    @abstractmethod
    async def evaluate(self, test_data: Any) -> Dict[str, float]:
        """
        Evaluate the model on test data.
        
        Args:
            test_data: Test data for evaluation
            
        Returns:
            Dict[str, float]: Evaluation metrics
        """
        pass
    
    @abstractmethod
    async def save(self, path: str) -> bool:
        """
        Save the model to the specified path.
        
        Args:
            path: Path to save the model
            
        Returns:
            bool: True if saving was successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def load(self, path: str) -> bool:
        """
        Load the model from the specified path.
        
        Args:
            path: Path to load the model from
            
        Returns:
            bool: True if loading was successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about the model.
        
        Returns:
            Dict[str, Any]: Model metadata including version, training date, etc.
        """
        pass