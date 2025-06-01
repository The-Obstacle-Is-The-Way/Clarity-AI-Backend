"""
MentaLLaMA Schemas Module.

This module defines Pydantic models for MentaLLaMA API validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data for HIPAA compliance.
"""

from enum import Enum
from typing import Any, ClassVar

from pydantic import Field

from app.presentation.api.schemas.base import BaseModelConfig


class AnalysisType(str, Enum):
    """Types of text analysis that MentaLLaMA can perform."""

    GENERAL = "general"
    CLINICAL = "clinical"
    THERAPEUTIC = "therapeutic"
    CONDITIONS = "conditions"
    SUICIDE_RISK = "suicide_risk"
    WELLNESS = "wellness"


class RiskLevel(str, Enum):
    """Risk levels for suicide risk assessment."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"
    IMMINENT = "imminent"


class WellnessDimension(str, Enum):
    """Dimensions of wellness that can be assessed."""

    EMOTIONAL = "emotional"
    SOCIAL = "social"
    PHYSICAL = "physical"
    INTELLECTUAL = "intellectual"
    SPIRITUAL = "spiritual"
    OCCUPATIONAL = "occupational"
    ENVIRONMENTAL = "environmental"
    FINANCIAL = "financial"


class ProcessTextRequest(BaseModelConfig):
    """Request schema for processing text through MentaLLaMA."""

    prompt: str = Field(..., description="The text prompt to process")
    user_id: str = Field(..., description="User ID for logging and personalization")
    model: str = Field("default", description="Model identifier to use for processing")
    temperature: float = Field(0.7, ge=0.0, le=1.0, description="Sampling temperature for generation")
    max_tokens: int = Field(1024, ge=1, le=4096, description="Maximum number of tokens to generate")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "prompt": "I've been feeling really anxious lately and it's affecting my sleep.",
                "user_id": "user123",
                "model": "default",
                "temperature": 0.7,
                "max_tokens": 1024
            }
        }


class AnalyzeTextRequest(BaseModelConfig):
    """Request schema for analyzing text for mental health insights."""

    text: str = Field(..., description="Text to analyze")
    user_id: str = Field(..., description="User ID for logging and personalization")
    analysis_type: AnalysisType = Field(AnalysisType.GENERAL, description="Type of analysis to perform")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "text": "I've been feeling really anxious lately and it's affecting my sleep.",
                "user_id": "user123",
                "analysis_type": "general"
            }
        }


class DetectConditionsRequest(BaseModelConfig):
    """Request schema for detecting mental health conditions in text."""

    text: str = Field(..., description="Text to analyze for mental health conditions")
    user_id: str = Field(..., description="User ID for logging and personalization")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "text": "I've been feeling really anxious lately and it's affecting my sleep.",
                "user_id": "user123"
            }
        }


class ConversationMessage(BaseModelConfig):
    """Schema for a single conversation message."""

    role: str = Field(..., description="Role of the message sender (user, therapist, etc.)")
    content: str = Field(..., description="Content of the message")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "role": "user",
                "content": "I've been feeling really anxious lately and it's affecting my sleep."
            }
        }


class TherapeuticResponseRequest(BaseModelConfig):
    """Request schema for generating therapeutic responses."""

    conversation_history: list[ConversationMessage] = Field(
        ..., description="Conversation history with user and therapist messages"
    )
    user_id: str = Field(..., description="User ID for logging and personalization")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "conversation_history": [
                    {
                        "role": "user",
                        "content": "I've been feeling really anxious lately and it's affecting my sleep."
                    },
                    {
                        "role": "therapist",
                        "content": "I'm sorry to hear you're experiencing anxiety. Can you tell me more about when this started?"
                    },
                    {
                        "role": "user",
                        "content": "It started about two weeks ago when I began a new project at work."
                    }
                ],
                "user_id": "user123"
            }
        }


class SuicideRiskRequest(BaseModelConfig):
    """Request schema for assessing suicide risk in text."""

    text: str = Field(..., description="Text to analyze for suicide risk")
    user_id: str = Field(..., description="User ID for logging and personalization")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "text": "I've been feeling really down lately and sometimes wonder if it's worth continuing.",
                "user_id": "user123"
            }
        }


class WellnessRequest(BaseModelConfig):
    """Request schema for assessing wellness dimensions in text."""

    text: str = Field(..., description="Text to analyze for wellness dimensions")
    user_id: str = Field(..., description="User ID for logging and personalization")
    dimensions: list[WellnessDimension] | None = Field(
        None, description="Specific wellness dimensions to analyze"
    )

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "text": "I've been feeling balanced lately, getting enough exercise, and maintaining good relationships with friends.",
                "user_id": "user123",
                "dimensions": ["emotional", "social", "physical"]
            }
        }


class ProcessTextResponse(BaseModelConfig):
    """Response schema for processed text from MentaLLaMA."""

    response: str = Field(..., description="Generated response text")
    model_used: str = Field(..., description="Model identifier used for processing")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about processing")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "response": "It sounds like you're experiencing anxiety that's disrupting your sleep pattern. This is a common experience when stress levels increase...",
                "model_used": "default",
                "metadata": {
                    "processing_time_ms": 256,
                    "tokens_generated": 128
                }
            }
        }


class AnalysisResponse(BaseModelConfig):
    """Response schema for text analysis from MentaLLaMA."""

    analysis: str = Field(..., description="Analysis of the text")
    themes: list[str] = Field(..., description="Detected themes in the text")
    emotions: dict[str, float] = Field(..., description="Emotions detected with confidence scores")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about analysis")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "analysis": "The text indicates significant anxiety symptoms affecting sleep patterns.",
                "themes": ["anxiety", "sleep disruption", "stress"],
                "emotions": {
                    "anxiety": 0.85,
                    "worry": 0.72,
                    "frustration": 0.41
                },
                "metadata": {
                    "processing_time_ms": 189,
                    "model_version": "v2.1"
                }
            }
        }


class ConditionResult(BaseModelConfig):
    """Schema for a detected mental health condition with confidence score."""

    condition: str = Field(..., description="Name of the detected condition")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score for the detection")
    evidence: list[str] = Field(..., description="Evidence in the text supporting the detection")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "condition": "Generalized Anxiety Disorder",
                "confidence": 0.78,
                "evidence": [
                    "reporting ongoing anxiety",
                    "sleep disruption",
                    "persistent worry"
                ]
            }
        }


class ConditionsResponse(BaseModelConfig):
    """Response schema for condition detection from MentaLLaMA."""

    conditions: list[ConditionResult] = Field(..., description="Detected conditions with confidence scores")
    summary: str = Field(..., description="Summary of the detected conditions")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about detection")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "conditions": [
                    {
                        "condition": "Generalized Anxiety Disorder",
                        "confidence": 0.78,
                        "evidence": [
                            "reporting ongoing anxiety",
                            "sleep disruption",
                            "persistent worry"
                        ]
                    }
                ],
                "summary": "The text indicates symptoms consistent with Generalized Anxiety Disorder.",
                "metadata": {
                    "processing_time_ms": 215,
                    "model_version": "v2.1"
                }
            }
        }


class TherapeuticResponseResult(BaseModelConfig):
    """Schema for a therapeutic response result."""

    response: str = Field(..., description="Generated therapeutic response")
    approach: str = Field(..., description="Therapeutic approach used")
    reasoning: str = Field(..., description="Reasoning behind the response")
    suggestions: list[str] = Field(..., description="Suggested follow-up questions or interventions")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "response": "It sounds like your anxiety might be connected to the new project at work. How are you managing your workload?",
                "approach": "Cognitive Behavioral Therapy",
                "reasoning": "Exploring the connection between work stressors and anxiety symptoms to identify potential interventions",
                "suggestions": [
                    "Explore sleep hygiene practices",
                    "Discuss stress management techniques",
                    "Assess work-life balance"
                ]
            }
        }


class TherapeuticResponseResponse(BaseModelConfig):
    """Response schema for therapeutic response generation from MentaLLaMA."""

    result: TherapeuticResponseResult = Field(..., description="Generated therapeutic response details")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about generation")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "result": {
                    "response": "It sounds like your anxiety might be connected to the new project at work. How are you managing your workload?",
                    "approach": "Cognitive Behavioral Therapy",
                    "reasoning": "Exploring the connection between work stressors and anxiety symptoms to identify potential interventions",
                    "suggestions": [
                        "Explore sleep hygiene practices",
                        "Discuss stress management techniques",
                        "Assess work-life balance"
                    ]
                },
                "metadata": {
                    "processing_time_ms": 342,
                    "model_version": "therapeutic-v1.2"
                }
            }
        }


class SuicideRiskAssessment(BaseModelConfig):
    """Schema for a suicide risk assessment result."""

    risk_level: RiskLevel = Field(..., description="Assessed risk level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the risk assessment")
    warning_signs: list[str] = Field(..., description="Detected warning signs")
    recommended_actions: list[str] = Field(..., description="Recommended actions based on risk level")
    urgent: bool = Field(..., description="Whether the situation requires urgent intervention")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "risk_level": "low",
                "confidence": 0.65,
                "warning_signs": [
                    "expressing feelings of hopelessness",
                    "questioning meaning in life"
                ],
                "recommended_actions": [
                    "Continue monitoring",
                    "Provide supportive resources",
                    "Schedule follow-up assessment"
                ],
                "urgent": False
            }
        }


class SuicideRiskResponse(BaseModelConfig):
    """Response schema for suicide risk assessment from MentaLLaMA."""

    assessment: SuicideRiskAssessment = Field(..., description="Suicide risk assessment details")
    disclaimer: str = Field(
        "This assessment is not a clinical diagnosis and should be verified by a qualified mental health professional.",
        description="Disclaimer about the assessment"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about assessment")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "assessment": {
                    "risk_level": "low",
                    "confidence": 0.65,
                    "warning_signs": [
                        "expressing feelings of hopelessness",
                        "questioning meaning in life"
                    ],
                    "recommended_actions": [
                        "Continue monitoring",
                        "Provide supportive resources",
                        "Schedule follow-up assessment"
                    ],
                    "urgent": False
                },
                "disclaimer": "This assessment is not a clinical diagnosis and should be verified by a qualified mental health professional.",
                "metadata": {
                    "processing_time_ms": 276,
                    "model_version": "risk-v2.0"
                }
            }
        }


class WellnessDimensionAssessment(BaseModelConfig):
    """Schema for assessment of a specific wellness dimension."""

    dimension: WellnessDimension = Field(..., description="Wellness dimension being assessed")
    score: float = Field(..., ge=0.0, le=1.0, description="Score for this dimension")
    strengths: list[str] = Field(..., description="Identified strengths in this dimension")
    areas_for_improvement: list[str] = Field(..., description="Areas for improvement in this dimension")
    recommendations: list[str] = Field(..., description="Recommendations for improving this dimension")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "dimension": "emotional",
                "score": 0.72,
                "strengths": [
                    "emotional awareness",
                    "healthy expression of feelings"
                ],
                "areas_for_improvement": [
                    "stress management",
                    "emotional regulation during conflicts"
                ],
                "recommendations": [
                    "Daily mindfulness practice",
                    "Journaling about emotional triggers",
                    "Practice deep breathing techniques"
                ]
            }
        }


class WellnessResponse(BaseModelConfig):
    """Response schema for wellness dimension assessment from MentaLLaMA."""

    overall_wellness: float = Field(..., ge=0.0, le=1.0, description="Overall wellness score")
    dimensions: list[WellnessDimensionAssessment] = Field(..., description="Assessment of individual dimensions")
    summary: str = Field(..., description="Summary of the wellness assessment")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about assessment")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "overall_wellness": 0.68,
                "dimensions": [
                    {
                        "dimension": "emotional",
                        "score": 0.72,
                        "strengths": [
                            "emotional awareness",
                            "healthy expression of feelings"
                        ],
                        "areas_for_improvement": [
                            "stress management",
                            "emotional regulation during conflicts"
                        ],
                        "recommendations": [
                            "Daily mindfulness practice",
                            "Journaling about emotional triggers",
                            "Practice deep breathing techniques"
                        ]
                    }
                ],
                "summary": "Overall wellness appears balanced with particular strength in the emotional dimension.",
                "metadata": {
                    "processing_time_ms": 412,
                    "model_version": "wellness-v1.5"
                }
            }
        }


class HealthCheckResponse(BaseModelConfig):
    """Response schema for MentaLLaMA health check."""

    status: str = Field(..., description="Health status of the service")
    service_status: bool = Field(..., description="Status of the underlying MentaLLaMA service")
    uptime: int | None = Field(None, description="Service uptime in seconds")
    models_available: list[str] | None = Field(None, description="List of available models")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about service health")

    class Config:
        """Pydantic configuration."""

        schema_extra: ClassVar[dict] = {
            "example": {
                "status": "healthy",
                "service_status": True,
                "uptime": 86400,
                "models_available": [
                    "default",
                    "therapeutic",
                    "analysis",
                    "conditions",
                    "risk"
                ],
                "metadata": {
                    "version": "2.1.0",
                    "last_updated": "2023-06-01T12:00:00Z"
                }
            }
        }
