# -*- coding: utf-8 -*-
"""
ML Service API Schemas.

This module defines the Pydantic schemas for the ML service APIs.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


class MentaLLaMABaseRequest(BaseModel):
    """Base request model for MentaLLaMA APIs."""
    
    model: Optional[str] = Field(
        None,
        description="Model ID to use for processing"
    )
    max_tokens: Optional[int] = Field(
        None,
        description="Maximum tokens to generate",
        ge=1,
        le=4000
    )
    temperature: Optional[float] = Field(
        None,
        description="Sampling temperature",
        ge=0.0,
        le=1.0
    )
    

class ProcessTextRequest(MentaLLaMABaseRequest):
    """Request model for processing text with MentaLLaMA."""
    
    prompt: str = Field(
        ...,
        description="Text prompt to process",
        min_length=1
    )
    task: Optional[str] = Field(
        None,
        description="Task to perform (e.g., depression_detection, risk_assessment)"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for processing"
    )
    

class DepressionDetectionRequest(MentaLLaMABaseRequest):
    """Request model for depression detection."""
    
    text: str = Field(
        ...,
        description="Text to analyze for depression indicators",
        min_length=1
    )
    include_rationale: bool = Field(
        True,
        description="Whether to include rationale in the response"
    )
    severity_assessment: bool = Field(
        True,
        description="Whether to include severity assessment in the response"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for analysis"
    )


class RiskAssessmentRequest(MentaLLaMABaseRequest):
    """Request model for risk assessment."""
    
    text: str = Field(
        ...,
        description="Text to analyze for risk indicators",
        min_length=1
    )
    include_key_phrases: bool = Field(
        True,
        description="Whether to include key phrases in the response"
    )
    include_suggested_actions: bool = Field(
        True,
        description="Whether to include suggested actions in the response"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for analysis"
    )


class SentimentAnalysisRequest(MentaLLaMABaseRequest):
    """Request model for sentiment analysis."""
    
    text: str = Field(
        ...,
        description="Text to analyze for sentiment",
        min_length=1
    )
    include_emotion_distribution: bool = Field(
        True,
        description="Whether to include emotion distribution in the response"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for analysis"
    )


class WellnessDimensionsRequest(MentaLLaMABaseRequest):
    """Request model for wellness dimensions analysis."""
    
    text: str = Field(
        ...,
        description="Text to analyze for wellness dimensions",
        min_length=1
    )
    dimensions: Optional[List[str]] = Field(
        None,
        description="Optional list of dimensions to analyze"
    )
    include_recommendations: bool = Field(
        True,
        description="Whether to include recommendations in the response"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for analysis"
    )


class DigitalTwinConversationRequest(MentaLLaMABaseRequest):
    """Request model for digital twin conversation."""
    
    prompt: str = Field(
        ...,
        description="Text prompt for the conversation",
        min_length=1
    )
    patient_id: str = Field(
        ...,
        description="Patient ID"
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional session ID for continued conversations"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for the conversation"
    )


class PHIDetectionRequest(BaseModel):
    """Request model for PHI detection."""
    
    text: str = Field(
        ...,
        description="Text to analyze for PHI",
        min_length=1
    )
    detection_level: Optional[str] = Field(
        None,
        description="Detection level (strict, moderate, relaxed)"
    )


class PHIRedactionRequest(BaseModel):
    """Request model for PHI redaction."""
    
    text: str = Field(
        ...,
        description="Text to redact PHI from",
        min_length=1
    )
    replacement: str = Field(
        "[REDACTED]",
        description="Replacement text for redacted PHI"
    )
    detection_level: Optional[str] = Field(
        None,
        description="Detection level (strict, moderate, relaxed)"
    )


class DigitalTwinSessionCreateRequest(BaseModel):
    """Request model for creating a digital twin session."""
    
    patient_id: str = Field(
        ...,
        description="Patient ID"
    )
    context: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional context for the session"
    )


class DigitalTwinMessageRequest(BaseModel):
    """Request model for sending a message to a digital twin."""
    
    message: str = Field(
        ...,
        description="Message to send",
        min_length=1
    )


class DigitalTwinInsightsRequest(BaseModel):
    """Request model for getting digital twin insights."""
    
    patient_id: str = Field(
        ...,
        description="Patient ID"
    )
    insight_type: Optional[str] = Field(
        None,
        description="Type of insights to retrieve"
    )
    time_period: Optional[str] = Field(
        None,
        description="Time period for insights"
    )


class APIResponse(BaseModel):
    """Generic API response model."""
    
    model_config = ConfigDict(
        extra="allow"
    )
    
    success: bool = Field(
        ...,
        description="Whether the request was successful"
    )
    message: Optional[str] = Field(
        None,
        description="Message describing the result"
    )
    data: Optional[Any] = Field(
        None,
        description="Response data"
    )
    error: Optional[str] = Field(
        None,
        description="Error message if request failed"
    )