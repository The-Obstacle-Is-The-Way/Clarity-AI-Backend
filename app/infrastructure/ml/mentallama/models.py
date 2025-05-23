"""
MentaLLaMA Models.

This module defines data models for the MentaLLaMA service.
"""

from typing import Any


class MentaLLaMAResult:
    """Result from MentaLLaMA analysis."""

    def __init__(
        self,
        text: str,
        analysis: dict[str, Any],
        confidence: float,
        metadata: dict[str, Any] | None = None,
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
        insights = self.analysis.get("insights", [])
        return list(insights) if isinstance(insights, list) else []

    def get_suggested_actions(self) -> list[str]:
        """
        Get suggested clinical actions from analysis.

        Returns:
            List of suggested actions
        """
        actions = self.analysis.get("suggested_actions", [])
        return list(actions) if isinstance(actions, list) else []

    def get_risk_factors(self) -> dict[str, float]:
        """
        Get identified risk factors with confidence scores.

        Returns:
            Dictionary of risk factors and scores
        """
        risk_factors = self.analysis.get("risk_factors", {})
        if isinstance(risk_factors, dict):
            return {str(k): float(v) for k, v in risk_factors.items()}
        return {}

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
            "metadata": self.metadata,
        }


class MentaLLaMAError(Exception):
    """Base exception for MentaLLaMA service errors."""

    pass


class MentaLLaMAConnectionError(MentaLLaMAError):
    """Error connecting to MentaLLaMA API."""

    pass
