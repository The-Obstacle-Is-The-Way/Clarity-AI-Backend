"""
Mock MentaLLaMA Service Implementation.

This module provides a mock implementation of the MentaLLaMA service
for development and testing purposes.
"""

import logging
import random
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.core.interfaces.services.mentallama_service_interface import MentaLLaMAInterface

logger = logging.getLogger(__name__)

class MockMentaLLaMAService(MentaLLaMAInterface):
    """
    Mock implementation of the MentaLLaMA service.
    
    This implementation simulates responses for testing purposes.
    """
    
    def __init__(self) -> None:
        """Initialize the mock service."""
        self._initialized = False
        self._config: Dict[str, Any] = {}
        self._available_models = ["mentallama-7b", "mentallama-33b"]
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the mock service with configuration parameters.
        
        Args:
            config: Configuration dictionary
        """
        logger.info("Initializing MockMentaLLaMAService")
        self._config = config
        self._initialized = True
    
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if the service is initialized
        """
        return self._initialized
    
    async def process(
        self,
        prompt: str,
        user_id: str,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Process a text prompt and generate a mock response.
        
        Args:
            prompt: The text prompt to process
            user_id: User ID for logging and personalization
            model: Model identifier to use
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
            **kwargs: Additional parameters
            
        Returns:
            Dictionary containing mock processing results
        """
        if not self._initialized:
            logger.warning("MockMentaLLaMAService used before initialization")
            self.initialize({})
        
        logger.info(f"Processing prompt for user {user_id} with model {model or 'default'}")
        
        # Default response
        mock_response = {
            "model": model or "mock_model",
            "prompt": prompt,
            "response": "mock process response",
            "provider": "mock_provider"
        }
        
        # Special handling for specialized endpoints based on model parameter
        if model == "risk":
            # For suicide risk assessment
            mock_response.update({
                "risk_level": "low",
                "risk_factors": ["mention of hopelessness"],
                "protective_factors": ["social support"],
                "recommendations": ["Continue therapy"],
                "immediate_action_required": False
            })
        elif model == "conditions":
            # For condition detection
            mock_response.update({
                "conditions": [
                    {"condition": "anxiety", "confidence": 0.8},
                    {"condition": "depression", "confidence": 0.6}
                ]
            })
        elif model == "wellness":
            # For wellness assessment
            dimensions = kwargs.get("dimensions", ["physical", "mental", "social"])
            mock_response.update({
                "dimensions": {dim: {"score": round(random.uniform(0.3, 0.9), 2)} for dim in dimensions}
            })
        elif model == "therapeutic":
            # For therapeutic responses
            mock_response.update({
                "therapeutic_approach": "cognitive-behavioral",
                "techniques": ["validation", "reframing"]
            })
        
        return mock_response
    
    async def detect_depression(
        self,
        text: str,
        user_id: str,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Detect signs of depression in text.
        
        Args:
            text: Text to analyze
            user_id: User ID for logging and personalization
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with detection results and confidence scores
        """
        if not self._initialized:
            logger.warning("MockMentaLLaMAService used before initialization")
            self.initialize({})
        
        logger.info(f"Detecting depression in text for user {user_id}")
        
        # Generate a mock detection result
        mock_result = {
            "depression_detected": True,
            "score": 0.9,
            "evidence": ["mentions of sadness", "sleep issues", "lack of motivation"],
            "confidence": 0.85,
            "severity": "moderate",
            "recommendation": "Consider clinical assessment"
        }
        
        return mock_result
    
    def shutdown(self) -> None:
        """Shut down the mock service."""
        logger.info("Shutting down MockMentaLLaMAService")
        self._initialized = False
