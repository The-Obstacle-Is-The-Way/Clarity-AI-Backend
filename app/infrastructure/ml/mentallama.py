"""
MentaLLaMA Service.

This module provides integration with MentaLLaMA, a specialized LLM
for mental health analysis and clinical decision support.
"""

import asyncio
from typing import Any

import aiohttp
import backoff

from app.core.utils.logging import get_logger
from app.infrastructure.ml.phi_detection.service import PHIDetectionService

logger = get_logger(__name__)


class MentaLLaMAError(Exception):
    """Base exception for MentaLLaMA service errors."""
    pass


class MentaLLaMAConnectionError(MentaLLaMAError):
    """Error connecting to MentaLLaMA API."""
    pass


class MentaLLaMAResult:
    """Result from MentaLLaMA analysis."""
    
    def __init__(
        self,
        text: str,
        analysis: dict[str, Any],
        confidence: float,
        metadata: dict[str, Any] | None = None
    ):
        """
        Initialize MentaLLaMA result.
        
        Args:
            text: Analyzed text (potentially anonymized)
            analysis: Analysis results
            confidence: Confidence score for analysis
            metadata: Additional metadata about the analysis
        """
        self.text = text
        self.analysis = analysis
        self.confidence = confidence
        self.metadata = metadata or {}
        
    def get_insights(self) -> list[str]:
        """
        Get clinical insights from analysis.
        
        Returns:
            List of clinical insights
        """
        return self.analysis.get("insights", [])
        
    def get_suggested_actions(self) -> list[str]:
        """
        Get suggested clinical actions from analysis.
        
        Returns:
            List of suggested actions
        """
        return self.analysis.get("suggested_actions", [])
        
    def get_risk_factors(self) -> dict[str, float]:
        """
        Get identified risk factors with confidence scores.
        
        Returns:
            Dictionary of risk factors and scores
        """
        return self.analysis.get("risk_factors", {})
        
    def to_dict(self) -> dict[str, Any]:
        """
        Convert result to dictionary.
        
        Returns:
            Dictionary representation of the result
        """
        return {
            "text": self.text,
            "analysis": self.analysis,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


class MentaLLaMAService:
    """
    Service for interacting with MentaLLaMA API.
    
    This service provides HIPAA-compliant integration with MentaLLaMA
    for clinical text analysis and decision support.
    """
    
    def __init__(
        self,
        phi_detection_service: PHIDetectionService,
        api_key: str | None = None,
        api_endpoint: str = "https://api.mentallama.com/v1",
        model_name: str = "mentallama-7b",
        temperature: float = 0.7
    ):
        """
        Initialize MentaLLaMA service.
        
        Args:
            phi_detection_service: Service for detecting and redacting PHI
            api_key: MentaLLaMA API key
            api_endpoint: MentaLLaMA API endpoint
            model_name: Model to use for analysis
            temperature: Temperature parameter for model
        """
        self.phi_detection_service = phi_detection_service
        self.api_key = api_key
        self.api_endpoint = api_endpoint
        self.model_name = model_name
        self.temperature = temperature
        self.session = None
        
    async def _ensure_session(self) -> None:
        """
        Ensure that an HTTP session exists.
        
        This method creates a new aiohttp session if one doesn't exist.
        """
        if self.session is None:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
            )
            
    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, asyncio.TimeoutError),
        max_tries=3
    )
    async def analyze_text(
        self,
        text: str,
        analysis_type: str = "general",
        anonymize_phi: bool = True
    ) -> MentaLLaMAResult:
        """
        Analyze text using MentaLLaMA.
        
        This method sends text to MentaLLaMA for analysis, with optional
        PHI anonymization for HIPAA compliance.
        
        Args:
            text: Text to analyze
            analysis_type: Type of analysis to perform
            anonymize_phi: Whether to anonymize PHI before analysis
            
        Returns:
            Analysis result
            
        Raises:
            MentaLLaMAError: If analysis fails
        """
        await self._ensure_session()
        
        # Anonymize PHI if requested
        processed_text = text
        if anonymize_phi:
            self.phi_detection_service.ensure_initialized()
            if self.phi_detection_service.contains_phi(text):
                processed_text = self.phi_detection_service.redact_phi(text)
                logger.info("PHI detected and redacted before MentaLLaMA analysis")
                
        # In a real implementation, this would call the MentaLLaMA API
        # For now, we'll simulate a response
        analysis_result = {
            "insights": [
                "Patient shows signs of moderate anxiety",
                "Sleep disturbance noted in patient history"
            ],
            "suggested_actions": [
                "Consider anxiety screening using GAD-7",
                "Evaluate sleep patterns with sleep diary"
            ],
            "risk_factors": {
                "anxiety": 0.8,
                "depression": 0.4,
                "substance_use": 0.1
            }
        }
        
        # Create and return result
        return MentaLLaMAResult(
            text=processed_text,
            analysis=analysis_result,
            confidence=0.85,
            metadata={
                "model": self.model_name,
                "analysis_type": analysis_type
            }
        )
    
    async def close(self) -> None:
        """
        Close HTTP session.
        
        This method should be called when the service is no longer needed.
        """
        if self.session is not None:
            await self.session.close()
            self.session = None