"""
Mock MentaLLaMA Service Implementation.

This module provides a mock implementation of the MentaLLaMA service
for development and testing purposes.
"""

import logging
import random
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.core.services.ml.interface import MentaLLaMAInterface

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
        text: str,
        model_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Process a text prompt and generate a mock response.
        
        Args:
            text: The text prompt to process
            model_type: Model type to use
            options: Additional options
            
        Returns:
            Dictionary containing mock processing results
        """
        if not self._initialized:
            logger.warning("MockMentaLLaMAService used before initialization")
            self.initialize({})
        
        user_id = options.get("user_id", "default_user") if options else "default_user"
        logger.info(f"Processing text for user {user_id} with model {model_type or 'default'}")
        
        # Default response
        mock_response = {
            "model": model_type or "mock_model",
            "prompt": text,
            "response": "mock process response",
            "provider": "mock_provider"
        }
        
        # Special handling for specialized endpoints based on model parameter
        if model_type == "risk":
            # For suicide risk assessment
            mock_response.update({
                "risk_level": "low",
                "risk_factors": ["mention of hopelessness"],
                "protective_factors": ["social support"],
                "recommendations": ["Continue therapy"],
                "immediate_action_required": False
            })
        elif model_type == "conditions":
            # For condition detection
            mock_response.update({
                "conditions": [
                    {"condition": "anxiety", "confidence": 0.8},
                    {"condition": "depression", "confidence": 0.6}
                ]
            })
        elif model_type == "wellness":
            # For wellness assessment
            dimensions = options.get("dimensions", ["physical", "mental", "social"]) if options else ["physical", "mental", "social"]
            mock_response.update({
                "dimensions": {dim: {"score": round(random.uniform(0.3, 0.9), 2)} for dim in dimensions}
            })
        elif model_type == "therapeutic":
            # For therapeutic responses
            mock_response.update({
                "therapeutic_approach": "cognitive-behavioral",
                "techniques": ["validation", "reframing"]
            })
        
        return mock_response
    
    async def detect_depression(
        self,
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Detect signs of depression in text.
        
        Args:
            text: Text to analyze
            options: Additional options
            
        Returns:
            Dictionary with detection results and confidence scores
        """
        if not self._initialized:
            logger.warning("MockMentaLLaMAService used before initialization")
            self.initialize({})
        
        logger.info(f"Detecting depression in text")
        
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
