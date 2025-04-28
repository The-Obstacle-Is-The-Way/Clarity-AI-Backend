# -*- coding: utf-8 -*-
"""
MentaLLaMA Models.

This module defines data models for the MentaLLaMA service.
"""

from typing import Dict, List, Optional, Any


class MentaLLaMAResult:
    """Result from MentaLLaMA analysis."""
    
    def __init__(
        self,
        text: str,
        analysis: Dict[str, Any],
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None
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
        
    def get_insights(self) -> List[str]:
        """
        Get clinical insights from analysis.
        
        Returns:
            List of clinical insights
        """
        return self.analysis.get("insights", [])
        
    def get_suggested_actions(self) -> List[str]:
        """
        Get suggested clinical actions from analysis.
        
        Returns:
            List of suggested actions
        """
        return self.analysis.get("suggested_actions", [])
        
    def get_risk_factors(self) -> Dict[str, float]:
        """
        Get identified risk factors with confidence scores.
        
        Returns:
            Dictionary of risk factors and scores
        """
        return self.analysis.get("risk_factors", {})
        
    def to_dict(self) -> Dict[str, Any]:
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


class MentaLLaMAError(Exception):
    """Base exception for MentaLLaMA service errors."""
    pass


class MentaLLaMAConnectionError(MentaLLaMAError):
    """Error connecting to MentaLLaMA API."""
    pass