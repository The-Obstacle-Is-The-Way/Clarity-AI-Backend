"""
ML Service API Schemas.

This module defines the Pydantic schemas for the ML service APIs.
"""

from typing import Any

from pydantic import BaseModel, Field

from .ml import DetectionLevel, PHIDetected


class MentaLLaMABaseRequest(BaseModel):
    """Base request model for MentaLLaMA APIs."""

    model: str | None = Field(None, description="Model ID to use for processing")
    max_tokens: int | None = Field(None, description="Maximum tokens to generate", ge=1, le=4000)
    temperature: float | None = Field(None, description="Sampling temperature", ge=0.0, le=1.0)


class ProcessTextRequest(MentaLLaMABaseRequest):
    """Request model for processing text with MentaLLaMA."""

    prompt: str = Field(..., description="Text prompt to process", min_length=1)
    task: str | None = Field(
        None,
        description="Task to perform (e.g., depression_detection, risk_assessment)",
    )
    context: dict[str, Any] | None = Field(None, description="Optional context for processing")


class DepressionDetectionRequest(MentaLLaMABaseRequest):
    """Request model for depression detection."""

    text: str = Field(..., description="Text to analyze for depression indicators", min_length=1)
    include_rationale: bool = Field(
        True, description="Whether to include rationale in the response"
    )
    severity_assessment: bool = Field(
        True, description="Whether to include severity assessment in the response"
    )
    context: dict[str, Any] | None = Field(None, description="Optional context for analysis")


class RiskAssessmentRequest(MentaLLaMABaseRequest):
    """Request model for risk assessment."""

    text: str = Field(..., description="Text to analyze for risk indicators", min_length=1)
    include_key_phrases: bool = Field(
        True, description="Whether to include key phrases in the response"
    )
    include_suggested_actions: bool = Field(
        True, description="Whether to include suggested actions in the response"
    )
    context: dict[str, Any] | None = Field(None, description="Optional context for analysis")


class SentimentAnalysisRequest(MentaLLaMABaseRequest):
    """Request model for sentiment analysis."""

    text: str = Field(..., description="Text to analyze for sentiment", min_length=1)
    include_emotion_distribution: bool = Field(
        True, description="Whether to include emotion distribution in the response"
    )
    context: dict[str, Any] | None = Field(None, description="Optional context for analysis")


class WellnessDimensionsRequest(MentaLLaMABaseRequest):
    """Request model for wellness dimensions analysis."""

    text: str = Field(..., description="Text to analyze for wellness dimensions", min_length=1)
    dimensions: list[str] | None = Field(None, description="Optional list of dimensions to analyze")
    include_recommendations: bool = Field(
        True, description="Whether to include recommendations in the response"
    )
    context: dict[str, Any] | None = Field(None, description="Optional context for analysis")


class DigitalTwinConversationRequest(MentaLLaMABaseRequest):
    """Request model for digital twin conversation."""

    prompt: str = Field(..., description="Text prompt for the conversation", min_length=1)
    patient_id: str = Field(..., description="Patient ID")
    session_id: str | None = Field(
        None, description="Optional session ID for continued conversations"
    )
    context: dict[str, Any] | None = Field(
        None, description="Optional context for the conversation"
    )


class PHIDetectionRequest(BaseModel):
    """Request model for PHI detection."""

    text: str = Field(..., description="Text to analyze for PHI", min_length=1)
    detection_level: str | None = Field(
        None, description="Detection level (strict, moderate, relaxed)"
    )


class PHIDetectionResponse(BaseModel):
    """Response model for PHI detection."""

    phi_detected: list[PHIDetected] = Field(description="Detected PHI")
    detection_level: DetectionLevel = Field(description="Detection level used")
    phi_count: int = Field(description="Number of PHI instances detected", ge=0)
    has_phi: bool = Field(description="Whether PHI was detected")
    timestamp: str = Field(description="Timestamp of the detection")


class PHIRedactionRequest(BaseModel):
    """Request model for PHI redaction."""

    text: str = Field(..., description="Text to redact PHI from", min_length=1)
    replacement: str = Field("[REDACTED]", description="Replacement text for redacted PHI")
    detection_level: str | None = Field(
        None, description="Detection level (strict, moderate, relaxed)"
    )


class DigitalTwinSessionCreateRequest(BaseModel):
    """Request model for creating a digital twin session."""

    patient_id: str = Field(..., description="Patient ID")
    context: dict[str, Any] | None = Field(None, description="Optional context for the session")


class DigitalTwinMessageRequest(BaseModel):
    """Request model for sending a message to a digital twin."""

    message: str = Field(..., description="Message to send", min_length=1)


class DigitalTwinInsightsRequest(BaseModel):
    """Request model for getting digital twin insights."""

    patient_id: str = Field(..., description="Patient ID")
    insight_type: str | None = Field(None, description="Type of insights to retrieve")
    time_period: str | None = Field(None, description="Time period for insights")


class PIISanitizationRequest(BaseModel):
    """Request model for PII Sanitization."""

    text: str = Field(..., description="Text to sanitize for PII.")
    # Add other relevant fields if needed, e.g., sanitization level, context


class PIISanitizationResponse(BaseModel):
    """Response model for PII Sanitization."""

    sanitized_text: str = Field(..., description="Text with PII sanitized.")
    # Add other relevant fields if needed, e.g., details of PII found


class PIITextAnalysisRequest(BaseModel):
    """Request model for PII text analysis."""

    text: str = Field(..., description="Text to analyze for PII.")
    # Add other relevant fields if needed, e.g., analysis level, context


class PIITextAnalysisResponse(BaseModel):
    """Response model for PII text analysis."""

    analysis_results: dict = Field(..., description="Results of the PII analysis.")
    # Add other relevant fields if needed, e.g., confidence scores, detected PII types


class APIResponse(BaseModel):
    """Generic API response model."""

    success: bool = Field(..., description="Whether the request was successful")
    message: str | None = Field(None, description="Message describing the result")
    data: Any | None = Field(None, description="Response data")
    error: str | None = Field(None, description="Error message if request failed")
