# -*- coding: utf-8 -*-
"""
Text Generation Service Implementation.

This module implements HIPAA-compliant specialized text generation
services for clinical documentation, patient education, and more.
"""

import time
import uuid
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from app.core.services.ml.interface import TextGenerationInterface
from app.core.exceptions import ServiceUnavailableError, ModelNotFoundError, ExternalServiceException, InvalidRequestError
from app.infrastructure.security.phi.phi_service import PHIService
from app.core.services.ml.base import BaseMLService

logger = logging.getLogger(__name__)

# Instantiate sanitizer for use
sanitizer = PHIService()

class TextGenerationService(TextGenerationInterface):
    """
    Implementation of the text generation service for clinical use cases.
    
    This service provides specialized text generation for clinical
    documentation, summaries, and patient education materials.
    """

    def __init__(self):
        """Initialize the text generation service."""
        self._initialized = False
        self._mentalllama_service = None
        self._config = {}
        self._model_configs = {}

    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the text generation service with configuration.
        
        Args:
            config: Service configuration including API keys and model settings
        
        Raises:
            ServiceUnavailableError: If initialization fails
        """
        try:
            self._config = config
            
            # Configure model types and their parameters
            self._setup_model_configs()
            
            # Set up the MentaLLaMA service for backend processing
            # In a real implementation, this would be injected via DI
            from app.core.services.ml.mentalllama import MentaLLaMAService
            self._mentalllama_service = MentaLLaMAService()
            self._mentalllama_service.initialize(config.get("mentalllama", {}))
            
            self._initialized = True
            logger.info("Text generation service initialized")
        except Exception as e:
            self._initialized = False
            logger.error("Failed to initialize text generation service: %s", str(e))
            raise ServiceUnavailableError(
                "Text generation service initialization failed"
            ) from e

    def _setup_model_configs(self) -> None:
        """
        Set up configuration for different model types.
        
        This method configures settings for each specialized model type
        including which MentaLLaMA model to use, default parameters, etc.
        """
        # Default configurations for different text generation model types
        self._model_configs = {
            "clinical_summary": {
                "mentalllama_model": "clinical-medium",
                "mentalllama_task": "summarize",
                "max_tokens": 500,
                "temperature": 0.7,
                "system_prompt": "You are a clinical assistant helping summarize patient information."
            },
            "therapy_notes": {
                "mentalllama_model": "therapy-medium",
                "mentalllama_task": "generate",
                "max_tokens": 800,
                "temperature": 0.5,
                "system_prompt": "You are a therapy notes assistant providing structured documentation."
            },
            "patient_education": {
                "mentalllama_model": "clinical-small",
                "mentalllama_task": "generate",
                "max_tokens": 1000,
                "temperature": 0.6,
                "system_prompt": "You are creating patient education materials that are clear and accessible."
            },
            "diagnostic_assistance": {
                "mentalllama_model": "clinical-large",
                "mentalllama_task": "analyze",
                "max_tokens": 600,
                "temperature": 0.3,
                "system_prompt": "You are providing diagnostic assistance based on clinical information."
            },
            "treatment_planning": {
                "mentalllama_model": "clinical-large",
                "mentalllama_task": "recommend",
                "max_tokens": 700,
                "temperature": 0.4,
                "system_prompt": "You are assisting with evidence-based treatment planning options."
            }
        }
        
        # Override with any configurations from the config
        config_overrides = self._config.get("model_configs", {})
        for model_type, overrides in config_overrides.items():
            if model_type in self._model_configs:
                self._model_configs[model_type].update(overrides)

    def is_healthy(self) -> bool:
        """
        Check if the service is operational.
        
        Returns:
            bool: True if service is operational, False otherwise
        """
        return (self._initialized and 
                self._mentalllama_service is not None and 
                self._mentalllama_service.is_healthy())

    def shutdown(self) -> None:
        """Clean up resources when shutting down the service."""
        if self._mentalllama_service:
            self._mentalllama_service.shutdown()
        self._initialized = False
        logger.info("Text generation service shut down")

    def generate_text(
        self,
        prompt: str,
        context: Optional[str] = None,
        max_tokens: int = 500,
        temperature: float = 0.7,
        model_type: str = "clinical_summary",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate text using the specified model type.
        
        Args:
            prompt: The input prompt for text generation
            context: Additional context to inform generation
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0.0-1.0)
            model_type: The type of model to use for generation
            **kwargs: Additional model-specific parameters
            
        Returns:
            Dict containing the generated text and metadata
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            ModelNotFoundError: If requested model type is not available
        """
        if not self._initialized:
            raise ServiceUnavailableError("Text generation service not initialized")
        
        if model_type not in self._model_configs:
            raise ModelNotFoundError(f"Model type not found: {model_type}")
        
        # Get model configuration
        model_config = self._model_configs[model_type]
        
        # Sanitize inputs for PHI
        sanitized_prompt = sanitizer.sanitize(prompt, sensitivity="high")
        sanitized_context = sanitizer.sanitize(context) if context else None
        
        # Prepare MentaLLaMA context
        llama_context = self._prepare_context(
            sanitized_prompt, 
            sanitized_context,
            model_config.get("system_prompt", "")
        )
        
        # Record processing start time
        start_time = time.time()
        
        # Use MentaLLaMA service for generation
        mentalllama_response = self._mentalllama_service.process(
            prompt=sanitized_prompt,
            model=model_config.get("mentalllama_model", "clinical-medium"),
            task=model_config.get("mentalllama_task", "generate"),
            context=llama_context,
            max_tokens=kwargs.get("max_tokens", model_config.get("max_tokens", max_tokens)),
            temperature=kwargs.get("temperature", model_config.get("temperature", temperature)),
            **kwargs
        )
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Build response
        response = {
            "text": mentalllama_response["text"],
            "model_type": model_type,
            "tokens_used": mentalllama_response["tokens_used"],
            "created_at": datetime.now().isoformat(),
            "metadata": {
                "processing_time": processing_time,
                "model": mentalllama_response["model"],
                "task": mentalllama_response["task"]
            }
        }
        
        # Add custom metadata from kwargs if provided
        if "metadata" in kwargs and isinstance(kwargs["metadata"], dict):
            response["metadata"].update(kwargs["metadata"])
        
        return response

    def _prepare_context(
        self, 
        prompt: str, 
        context: Optional[str], 
        system_prompt: str
    ) -> Dict[str, Any]:
        """
        Prepare context for MentaLLaMA processing.
        
        Args:
            prompt: Sanitized prompt
            context: Sanitized additional context
            system_prompt: System prompt for the model
            
        Returns:
            Dict: Structured context for MentaLLaMA
        """
        # Structure the context for MentaLLaMA in a chat-like format
        messages = []
        
        # Add system prompt if provided
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        
        # Add context as user message if provided
        if context:
            messages.append({
                "role": "user",
                "content": context
            })
        
        # Return structured context
        return {
            "messages": messages,
            "format": "chat"
        }