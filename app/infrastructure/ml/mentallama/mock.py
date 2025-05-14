"""
MentaLLaMA Mock Module - Test Adapter

This module provides a complete implementation of the MentaLLaMA interface expected
by test code while following clean architecture principles. It serves as an adapter
to the domain-driven MentaLLaMAServiceInterface.
"""
import random
import uuid
from datetime import datetime
from typing import Any, Optional

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
from app.domain.entities.clinical_insight import ClinicalInsight, InsightCategory, InsightSeverity
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import MockMentalLLaMAService


class MockMentaLLaMA:
    """
    Mock implementation of the MentaLLaMA API for testing.
    
    This adapter implements the interface expected by tests while
    delegating to the canonical implementation in MockMentalLLaMAService.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_endpoint: str = "https://api.mockmentallama.com/v1",
        model_name: str = "mock-mentallama-1",
        temperature: float = 0.7
    ):
        """
        Initialize the MentaLLaMA mock adapter.
        
        Args:
            api_key: API key for MentaLLaMA (not used in mock)
            api_endpoint: API endpoint (not used in mock)
            model_name: Model to use for analysis
            temperature: Temperature parameter for model
        """
        self._api_key = api_key
        self._api_endpoint = api_endpoint
        self._model_name = model_name
        self._temperature = temperature
        self._initialized = False
        self._mock_responses = {}
        
        # Create the actual implementation that follows clean architecture
        self._service = MockMentalLLaMAService(error_simulation_mode=False)
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the mock service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            # Update configuration if provided
            mock_responses = config.get("mock_responses", {})
            if not isinstance(mock_responses, dict) and mock_responses is not None:
                raise InvalidConfigurationError("mock_responses must be a dictionary")
                
            # Store configuration
            self._mock_responses = mock_responses
            self._initialized = True
        except Exception as e:
            raise InvalidConfigurationError(f"Failed to initialize MentaLLaMA mock: {str(e)}")
    
    def is_healthy(self) -> bool:
        """Check if the mock service is initialized and healthy."""
        return self._initialized
    
    def shutdown(self) -> None:
        """Shutdown the mock service."""
        self._initialized = False
        
    def _ensure_initialized(self) -> None:
        """Ensure the service is initialized before use."""
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service not initialized")
            
    def _validate_text(self, text: str) -> None:
        """Validate text input."""
        if not isinstance(text, str):
            raise InvalidRequestError("Text must be a string")
        if not text:
            raise InvalidRequestError("Text cannot be empty")
    
    def process(
        self, 
        text: str, 
        model_type: Optional[str] = None,
        options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Process text using the MentaLLaMA service.
        
        Args:
            text: Text to analyze
            model_type: Type of model/analysis to run
            options: Additional options
            
        Returns:
            Analysis results
            
        Raises:
            InvalidRequestError: If input is invalid
            ModelNotFoundError: If model type is invalid
            ServiceUnavailableError: If service not initialized
        """
        self._ensure_initialized()
        self._validate_text(text)
        
        # Use configured mock responses if available
        if model_type and model_type in self._mock_responses:
            return self._mock_responses[model_type]
        elif "general" in self._mock_responses:
            return self._mock_responses["general"]
            
        # If model type is specified but not supported
        if model_type and model_type not in ["general", "clinical", "risk", "sentiment", "wellness"]:
            raise ModelNotFoundError(f"Model type '{model_type}' not found")
        
        # Default to using the adapter implementation
        patient_id = uuid.uuid4()
        
        # Create mock insights directly for synchronous test compatibility
        # Since we can't await the async method in a sync context
        # Determine appropriate category and severity based on text content
        has_depression = any(word in text.lower() for word in ["sad", "down", "depressed", "hopeless"])
        
        # Use proper enum values
        category = InsightCategory.DIAGNOSTIC
        severity = InsightSeverity.MODERATE if has_depression else InsightSeverity.LOW
        
        insights = [
            ClinicalInsight(
                text="Mock insight from text: " + text[:30] + "...",
                category=category,
                severity=severity,
                confidence=0.85,
                evidence="Evidence from text",
                timestamp=datetime.now(),
                metadata={"source": "mock", "model_type": model_type or "general"}
            )
        ]
        
        # Map to expected response format
        result = {
            "text": text,
            "content": text,  # This field is also expected by the test
            "model_type": model_type or "general",
            "timestamp": datetime.now().isoformat(),
            "model": self._model_name,
            "insights": [self._insight_to_dict(insight) for insight in insights],
            "metadata": {
                "patient_id": str(patient_id),
                "confidence": 0.85,
                "processing_time_ms": random.randint(100, 500)
            }
        }
        
        return result
    
    def _insight_to_dict(self, insight: ClinicalInsight) -> dict[str, Any]:
        """Convert a ClinicalInsight to dictionary representation."""
        # Serialize enum values to strings instead of integers for test compatibility
        return {
            "text": insight.text,
            "category": insight.category.name,  # Use name instead of value to get string
            "severity": insight.severity.name, # Use name instead of value to get string
            "confidence": insight.confidence,
            "evidence": insight.evidence,
            "timestamp": insight.timestamp.isoformat() if insight.timestamp else None,
            "metadata": insight.metadata or {}
        }
        
    def detect_depression(
        self, 
        text: str, 
        options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Mock depression detection.
        
        Args:
            text: Text to analyze
            options: Additional options
            
        Returns:
            Depression analysis results
        """
        self._ensure_initialized()
        self._validate_text(text)
        
        has_depression_keywords = any(word in text.lower() for word in 
                                    ["sad", "down", "depressed", "hopeless"])
        
        return {
            "detected": has_depression_keywords,
            "confidence": 0.85 if has_depression_keywords else 0.15,
            "severity": "moderate" if has_depression_keywords else "none",
            "indicators": ["low_mood", "anhedonia"] if has_depression_keywords else [],
            "metadata": {
                "model": self._model_name,
                "timestamp": datetime.now().isoformat()
            }
        }
        
    def assess_risk(
        self, 
        text: str, 
        options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Mock risk assessment.
        
        Args:
            text: Text to analyze
            options: Additional options
            
        Returns:
            Risk assessment results
        """
        self._ensure_initialized()
        self._validate_text(text)
        
        has_risk_keywords = any(word in text.lower() for word in 
                              ["hurt", "suicide", "die", "kill", "end", "life"])
        
        return {
            "risk_level": "moderate" if has_risk_keywords else "low",
            "confidence": 0.8,
            "risk_factors": ["suicidal_ideation"] if has_risk_keywords else [],
            "recommendations": ["immediate_follow_up"] if has_risk_keywords else ["routine_monitoring"],
            "metadata": {
                "model": self._model_name,
                "timestamp": datetime.now().isoformat()
            }
        }
    
    def analyze_sentiment(
        self, 
        text: str, 
        options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Mock sentiment analysis.
        
        Args:
            text: Text to analyze
            options: Additional options
            
        Returns:
            Sentiment analysis results
        """
        self._ensure_initialized()
        self._validate_text(text)
        
        # Simple sentiment analysis based on keywords
        positive_words = ["happy", "good", "better", "improved", "well"]
        negative_words = ["sad", "bad", "worse", "difficult", "hard", "down"]
        
        text_lower = text.lower()
        positive_count = sum(word in text_lower for word in positive_words)
        negative_count = sum(word in text_lower for word in negative_words)
        
        # Determine sentiment based on word counts
        if positive_count > negative_count:
            sentiment = "positive"
            score = 0.5 + (0.5 * (positive_count / (positive_count + negative_count + 1)))
        elif negative_count > positive_count:
            sentiment = "negative"
            score = 0.5 - (0.5 * (negative_count / (positive_count + negative_count + 1)))
        else:
            sentiment = "neutral"
            score = 0.5
            
        return {
            "sentiment": sentiment,
            "score": score,
            "positive_indicators": positive_count,
            "negative_indicators": negative_count,
            "metadata": {
                "model": self._model_name,
                "timestamp": datetime.now().isoformat()
            }
        }
    
    def analyze_wellness_dimensions(
        self, 
        text: str, 
        options: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """
        Mock wellness dimensions analysis.
        
        Args:
            text: Text to analyze
            options: Additional options
            
        Returns:
            Wellness dimensions analysis results
        """
        self._ensure_initialized()
        self._validate_text(text)
        
        # Define wellness dimensions and their keywords
        dimensions = {
            "physical": ["exercise", "sleep", "diet", "pain", "tired"],
            "emotional": ["happy", "sad", "angry", "anxious", "calm"],
            "social": ["friends", "family", "relationship", "community", "support"],
            "cognitive": ["thinking", "memory", "focus", "concentration", "confusion"],
            "spiritual": ["meaning", "purpose", "faith", "meditation", "belief"]
        }
        
        text_lower = text.lower()
        results = {}
        
        # Generate mock scores for each dimension based on keyword presence
        for dimension, keywords in dimensions.items():
            keyword_count = sum(word in text_lower for word in keywords)
            # Calculate a score based on keyword presence
            if keyword_count == 0:
                # No keywords found, assign random baseline
                score = round(random.uniform(0.3, 0.7), 2)
            else:
                # Adjust score based on keyword presence
                score = round(min(0.3 + (keyword_count * 0.15), 1.0), 2)
            
            results[dimension] = score
        
        return {
            "dimensions": results,
            "overall_wellness": round(sum(results.values()) / len(results), 2),
            "metadata": {
                "model": self._model_name,
                "timestamp": datetime.now().isoformat()
            }
        }

# Re-export the clean architecture implementation for code that needs it directly
MockMentalLLaMAService = MockMentalLLaMAService

# Export both implementations for backward compatibility
__all__ = ["MockMentaLLaMA", "MockMentalLLaMAService"]
