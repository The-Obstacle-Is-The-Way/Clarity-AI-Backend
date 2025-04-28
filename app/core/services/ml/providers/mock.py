# -*- coding: utf-8 -*-
"""
Mock Provider for MentaLLaMA.

This module provides a mock implementation for the MentaLLaMA service
to use in development and testing environments.
"""

import json
import time
from typing import Any, Dict, List, Optional, Union

from app.core.exceptions import (
    InvalidConfigurationError, 
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
# Import the proper interface
from app.core.services.ml.interface import MentaLLaMAInterface
from app.core.utils.logging import get_logger

# Create logger (no PHI logging)
logger = get_logger(__name__)


class MockMentaLLaMA(MentaLLaMAInterface):
    """
    Mock implementation for MentaLLaMA service.
    
    This class provides a mocked version of MentaLLaMA service
    for use in development and testing environments.
    """
    
    def __init__(self):
        """Initialize the mock MentaLLaMA service."""
        self._initialized = False
        self._config = None
        self._available_models = {}
        self._model_mappings = {}
        
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            if "provider" not in config:
                raise InvalidConfigurationError("Missing required configuration parameter: provider")
                
            if config["provider"] != "mock":
                raise InvalidConfigurationError(f"Invalid provider: {config['provider']}. Expected: mock")
                
            self._config = config
            self._initialized = True
            
            # Initialize provider-specific components
            self._initialize_provider()
            
            logger.info("MockMentaLLaMA service initialized successfully")
            
        except InvalidConfigurationError as e:
            logger.error(f"Failed to initialize MockMentaLLaMA service: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during initialization: {str(e)}")
            raise InvalidConfigurationError(f"Failed to initialize: {str(e)}")
            
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        return self._initialized
        
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        self._available_models = {}
        
    def process(
        self, 
        prompt: str,
        model_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process text using the MentaLLaMA model.
        
        Args:
            prompt: Text to process
            model_type: Type of model to use
            options: Additional processing options
            
        Returns:
            Processing results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
            ModelNotFoundError: If model type is not found
        """
        if not self._initialized:
            raise ServiceUnavailableError("Service not initialized")
            
        if not prompt or not isinstance(prompt, str):
            raise InvalidRequestError("Invalid prompt")
            
        # Determine model to use
        model = self._model_mappings.get(model_type, self._model_mappings["default"])
        
        # Process the prompt
        start_time = time.time()
        
        # Generate mock response
        response = self._generate(prompt=prompt, model=model)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Create response ID
        response_id = f"mock-{int(time.time())}-{hash(prompt) % 10000}"
        
        return {
            "response_id": response_id,
            "text": response["text"],
            "model": model,
            "provider": "mock",
            "processing_time": processing_time,
            "tokens_used": response["tokens_used"],
            "created_at": time.time(),
            "confidence": response["metadata"].get("confidence", 0.85),
            "metadata": response["metadata"]
        }
        
    def detect_depression(
        self, 
        text: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Detect depression signals in text.
        
        Args:
            text: Text to analyze
            options: Additional options for depression detection
            
        Returns:
            Depression detection results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("Service not initialized")
            
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Invalid text input")
            
        # Generate mock response based on text content
        depression_indicators = ["depressed", "depression", "sad", "hopeless", "worthless"]
        text_lower = text.lower()
        
        # Check for strong depression indicators that should trigger positive result
        if "very depressed" in text_lower or "don't enjoy anything" in text_lower or \
           ("depressed" in text_lower and "hopeless" in text_lower):
            return self._depression_detection_responses["positive"]
        elif any(indicator in text_lower for indicator in depression_indicators):
            if "severe" in text_lower or "suicide" in text_lower:
                result = self._depression_detection_responses["positive"]
            elif "mild" in text_lower or "sometimes" in text_lower:
                result = self._depression_detection_responses["mild"]
            else:
                # Default to mild for any depression indicator
                result = self._depression_detection_responses["mild"]
        else:
            result = self._depression_detection_responses["negative"]
            
        return result
    
    def depression_detection(self, text: str) -> Dict[str, Any]:
        """
        Detect depression signals in text (alias for detect_depression).
        
        Args:
            text: Text to analyze
            
        Returns:
            Depression detection results
        """
        return self.detect_depression(text)
        
    def risk_assessment(self, text: str) -> Dict[str, Any]:
        """
        Assess risk level based on text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Risk assessment results
        """
        if not self._initialized:
            raise ServiceUnavailableError("Service not initialized")
            
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Invalid text input")
            
        # Generate mock response based on text content
        risk_indicators = ["suicide", "harm", "hurt myself", "end my life", "kill"]
        text_lower = text.lower()
        
        if any(indicator in text_lower for indicator in risk_indicators):
            if "plan" in text_lower or "decided" in text_lower:
                return self._risk_assessment_responses["high_risk"]
            elif "thought about" in text_lower or "considered" in text_lower:
                return self._risk_assessment_responses["moderate_risk"]
            else:
                return self._risk_assessment_responses["low_risk"]
        else:
            return self._risk_assessment_responses["low_risk"]
            
    def sentiment_analysis(self, text: str) -> Dict[str, Any]:
        """
        Analyze sentiment in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Sentiment analysis results
        """
        if not self._initialized:
            raise ServiceUnavailableError("Service not initialized")
            
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Invalid text input")
            
        # Generate mock response based on text content
        positive_indicators = ["happy", "joy", "excited", "grateful", "good"]
        negative_indicators = ["unhappy", "angry", "frustrated", "anxious", "bad"]
        text_lower = text.lower()
        
        positive_count = sum(1 for indicator in positive_indicators if indicator in text_lower)
        negative_count = sum(1 for indicator in negative_indicators if indicator in text_lower)
        
        if positive_count > negative_count:
            return self._sentiment_analysis_responses["positive"]
        elif negative_count > positive_count:
            return self._sentiment_analysis_responses["negative"]
        else:
            return self._sentiment_analysis_responses["neutral"]
            
    def wellness_dimensions(self, text: str) -> Dict[str, Any]:
        """
        Analyze wellness dimensions in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Wellness dimensions analysis results
        """
        if not self._initialized:
            raise ServiceUnavailableError("Service not initialized")
            
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Invalid text input")
            
        # Generate mock response based on text content
        balanced_indicators = ["balance", "wellness", "healthy", "exercise", "good sleep"]
        unbalanced_indicators = ["imbalance", "struggle", "tired", "stress", "overwhelmed"]
        text_lower = text.lower()
        
        balanced_count = sum(1 for indicator in balanced_indicators if indicator in text_lower)
        unbalanced_count = sum(1 for indicator in unbalanced_indicators if indicator in text_lower)
        
        if balanced_count > unbalanced_count:
            return self._wellness_dimensions_responses["balanced"]
        else:
            return self._wellness_dimensions_responses["unbalanced"]
            
    def _parse_depression_detection_result(self, response_text: str) -> Dict[str, Any]:
        """
        Parse depression detection result from response text.
        
        Args:
            response_text: Response text to parse
            
        Returns:
            Parsed depression detection result
        """
        try:
            if isinstance(response_text, dict):
                return response_text
                
            # Try to parse as JSON
            return json.loads(response_text)
        except json.JSONDecodeError:
            # If not JSON, return a basic result
            return {
                "depression_indicated": False,
                "key_indicators": [],
                "severity": "unknown",
                "rationale": "Could not parse response",
                "confidence": 0.5
            }
    
    def _initialize_provider(self) -> None:
        """
        Initialize mock provider.
        
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            # Set available models
            self._available_models = {
                "mock-basic": {"provider": "mock", "capabilities": ["general"]},
                "mock-clinical": {"provider": "mock", "capabilities": ["clinical", "depression_detection"]},
                "mock-risk": {"provider": "mock", "capabilities": ["clinical", "risk_assessment"]},
                "mock-advanced": {"provider": "mock", "capabilities": ["clinical", "depression_detection", "risk_assessment", "sentiment_analysis"]},
            }
            
            # Set up model mappings
            self._model_mappings = {
                "default": "mock-advanced",
                "depression_detection": "mock-clinical",
                "risk_assessment": "mock-risk",
                "sentiment_analysis": "mock-advanced",
                "wellness_dimensions": "mock-advanced",
            }
            
            # Set up mock responses
            self._setup_mock_responses()
            
            logger.info("Mock MentaLLaMA service initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Mock MentaLLaMA service: {str(e)}")
            raise InvalidConfigurationError(f"Failed to initialize Mock MentaLLaMA service: {str(e)}")
    
    def _setup_mock_responses(self) -> None:
        """Set up mock responses for different tasks."""
        # Depression detection responses
        self._depression_detection_responses = {
            "positive": {
                "depression_indicated": True,
                "key_indicators": [
                    "persistent sadness", 
                    "loss of interest", 
                    "difficulty concentrating",
                    "sleep disturbances"
                ],
                "severity": "moderate",
                "rationale": "The text contains multiple indicators of depression including persistent sadness, loss of interest in activities, difficulty concentrating, and sleep disturbances. These symptoms appear to be of moderate severity based on their frequency and impact on daily functioning.",
                "confidence": 0.85
            },
            "negative": {
                "depression_indicated": False,
                "key_indicators": [],
                "severity": "none",
                "rationale": "The text does not contain significant indicators of depression. The mood described appears to be within normal range with appropriate emotional responses to situations.",
                "confidence": 0.92
            },
            "mild": {
                "depression_indicated": True,
                "key_indicators": [
                    "occasional sadness", 
                    "mild fatigue"
                ],
                "severity": "mild",
                "rationale": "The text contains some mild indicators of depression, including occasional sadness and fatigue. These symptoms appear to be mild and may not significantly impact daily functioning.",
                "confidence": 0.78
            }
        }
        
        # Risk assessment responses
        self._risk_assessment_responses = {
            "high_risk": {
                "risk_level": "high",
                "key_indicators": [
                    "suicidal ideation", 
                    "specific plan",
                    "access to means"
                ],
                "suggested_actions": [
                    "Immediate clinical assessment",
                    "Safety planning",
                    "Consider emergency services"
                ],
                "rationale": "The text contains explicit mentions of suicidal thoughts with a specific plan and access to means. This represents a high and immediate risk requiring prompt intervention.",
                "confidence": 0.92
            },
            "moderate_risk": {
                "risk_level": "moderate",
                "key_indicators": [
                    "passive suicidal thoughts", 
                    "increased alcohol use",
                    "social withdrawal"
                ],
                "suggested_actions": [
                    "Follow-up clinical assessment within 24-48 hours",
                    "Safety planning",
                    "Increase support and monitoring"
                ],
                "rationale": "The text contains mentions of passive suicidal thoughts without a specific plan, combined with risk factors like increased substance use and social isolation.",
                "confidence": 0.85
            },
            "low_risk": {
                "risk_level": "low",
                "key_indicators": [
                    "occasional hopelessness", 
                    "mild distress"
                ],
                "suggested_actions": [
                    "Routine follow-up",
                    "Monitoring of symptoms",
                    "Self-care recommendations"
                ],
                "rationale": "The text contains some mild distress but no indications of suicidal thoughts or intent. The individual appears to have adequate coping mechanisms and support systems.",
                "confidence": 0.88
            }
        }
        
        # Sentiment analysis responses
        self._sentiment_analysis_responses = {
            "positive": {
                "overall_sentiment": "positive",
                "sentiment_score": 0.72,
                "key_phrases": [
                    "feeling great", 
                    "excited about progress", 
                    "grateful for support"
                ],
                "emotion_distribution": {
                    "joy": 0.65,
                    "sadness": 0.05,
                    "anger": 0.02,
                    "fear": 0.08,
                    "surprise": 0.12,
                    "disgust": 0.01
                },
                "confidence": 0.85
            },
            "negative": {
                "overall_sentiment": "negative",
                "sentiment_score": -0.68,
                "key_phrases": [
                    "feeling overwhelmed", 
                    "struggling to cope", 
                    "constant worry"
                ],
                "emotion_distribution": {
                    "joy": 0.05,
                    "sadness": 0.45,
                    "anger": 0.15,
                    "fear": 0.25,
                    "surprise": 0.03,
                    "disgust": 0.07
                },
                "confidence": 0.82
            },
            "neutral": {
                "overall_sentiment": "neutral",
                "sentiment_score": 0.05,
                "key_phrases": [
                    "routine activities", 
                    "daily patterns", 
                    "normal schedule"
                ],
                "emotion_distribution": {
                    "joy": 0.18,
                    "sadness": 0.20,
                    "anger": 0.10,
                    "fear": 0.12,
                    "surprise": 0.20,
                    "disgust": 0.05
                },
                "confidence": 0.75
            }
        }
        
        # Wellness dimensions responses
        self._wellness_dimensions_responses = {
            "balanced": {
                "dimension_scores": {
                    "emotional": 0.75,
                    "physical": 0.80,
                    "social": 0.70,
                    "spiritual": 0.65,
                    "intellectual": 0.85,
                    "occupational": 0.75,
                    "environmental": 0.70
                },
                "areas_of_strength": [
                    "intellectual", 
                    "physical", 
                    "emotional"
                ],
                "areas_for_improvement": [
                    "spiritual", 
                    "social"
                ],
                "recommendations": [
                    "Regular meditation practice to enhance spiritual wellness",
                    "Increase social connections through group activities",
                    "Maintain current physical exercise routine"
                ],
                "confidence": 0.88
            },
            "unbalanced": {
                "dimension_scores": {
                    "emotional": 0.30,
                    "physical": 0.45,
                    "social": 0.25,
                    "spiritual": 0.40,
                    "intellectual": 0.75,
                    "occupational": 0.85,
                    "environmental": 0.50
                },
                "areas_of_strength": [
                    "occupational", 
                    "intellectual"
                ],
                "areas_for_improvement": [
                    "emotional", 
                    "social", 
                    "physical"
                ],
                "recommendations": [
                    "Prioritize emotional self-care through daily mindfulness",
                    "Improve social connections by scheduling regular social activities",
                    "Develop a consistent physical exercise routine",
                    "Consider better work-life balance despite occupational success"
                ],
                "confidence": 0.82
            }
        }
        
        # General responses
        self._general_responses = {
            "default": "This is a mock response from the MentaLLaMA service. In a real environment, this would contain generated content from a mental health-focused language model.",
            "help": "The MentaLLaMA service provides mental health analysis capabilities including depression detection, risk assessment, sentiment analysis, and wellness dimensions analysis.",
            "error": "Sorry, I couldn't process that request. Please try again with a different input."
        }
    
    def _generate(
        self,
        prompt: str,
        model: str = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate mock text response.
        
        Args:
            prompt: Input prompt
            model: Model to use
            max_tokens: Maximum tokens to generate (ignored in mock)
            temperature: Sampling temperature (ignored in mock)
            **kwargs: Additional parameters
            
        Returns:
            Dict containing generated text and metadata
            
        Raises:
            ModelNotFoundError: If model is not available
        """
        try:
            # Start generation time for realistic simulation
            start_time = time.time()
            
            # Add a small delay to simulate processing
            time.sleep(0.2)
            
            # Determine response based on prompt content
            text = self._determine_response(prompt)
            
            # End generation time
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Calculate tokens (simulated)
            input_tokens = len(prompt.split()) * 1.3  # rough estimate
            output_tokens = len(text.split()) * 1.3  # rough estimate
            tokens_used = int(input_tokens + output_tokens)
            
            # Create result
            result = {
                "text": text,
                "processing_time": processing_time,
                "tokens_used": tokens_used,
                "metadata": {
                    "model": model or self._model_mappings["default"],
                    "provider": "mock",
                    "confidence": 0.85
                }
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Mock generation failed: {str(e)}")
            # Even in mock, return a proper error response
            return {
                "text": self._general_responses["error"],
                "processing_time": 0.1,
                "tokens_used": 20,
                "metadata": {
                    "model": model or self._model_mappings["default"],
                    "provider": "mock",
                    "confidence": 0.5,
                    "error": str(e)
                }
            }
    
    def _determine_response(self, prompt: str) -> str:
        """
        Determine appropriate response based on prompt content.
        
        Args:
            prompt: Input prompt
            
        Returns:
            Generated mock text
        """
        prompt_lower = prompt.lower()
        
        # Check for depression indicators in the prompt
        depression_indicators = ["depressed", "depression", "sad", "hopeless", "worthless"]
        if any(indicator in prompt_lower for indicator in depression_indicators):
            if "severe" in prompt_lower or "suicide" in prompt_lower:
                return json.dumps(self._depression_detection_responses["positive"], indent=2)
            elif "mild" in prompt_lower or "sometimes" in prompt_lower:
                return json.dumps(self._depression_detection_responses["mild"], indent=2)
            else:
                return json.dumps(self._depression_detection_responses["negative"], indent=2)
        
        # Check for risk indicators in the prompt
        risk_indicators = ["suicide", "harm", "hurt myself", "end my life", "kill"]
        if any(indicator in prompt_lower for indicator in risk_indicators):
            if "plan" in prompt_lower or "decided" in prompt_lower:
                return json.dumps(self._risk_assessment_responses["high_risk"], indent=2)
            elif "thought about" in prompt_lower or "considered" in prompt_lower:
                return json.dumps(self._risk_assessment_responses["moderate_risk"], indent=2)
            else:
                return json.dumps(self._risk_assessment_responses["low_risk"], indent=2)
        
        # Check for sentiment indicators in the prompt
        positive_indicators = ["happy", "joy", "excited", "grateful", "good"]
        negative_indicators = ["unhappy", "angry", "frustrated", "anxious", "bad"]
        
        positive_count = sum(1 for indicator in positive_indicators if indicator in prompt_lower)
        negative_count = sum(1 for indicator in negative_indicators if indicator in prompt_lower)
        
        if positive_count > negative_count:
            return json.dumps(self._sentiment_analysis_responses["positive"], indent=2)
        elif negative_count > positive_count:
            return json.dumps(self._sentiment_analysis_responses["negative"], indent=2)
        else:
            return json.dumps(self._sentiment_analysis_responses["neutral"], indent=2)
        
        # Default response
        return self._general_responses["default"]
