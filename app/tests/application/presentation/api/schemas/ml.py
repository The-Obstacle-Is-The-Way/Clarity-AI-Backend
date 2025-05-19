"""
ML API Schemas.

This module defines Pydantic schemas for ML API requests and responses.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ServiceHealthResponse(BaseModel):
    """Response model for service health check."""

    is_healthy: bool = Field(description="Whether the service is healthy")
    timestamp: str = Field(description="Timestamp of the health check")


class MentaLLaMAModelType(str, Enum):
    """MentaLLaMA model types."""

    GENERAL = "general"
    DEPRESSION_DETECTION = "depression_detection"
    RISK_ASSESSMENT = "risk_assessment"
    SENTIMENT_ANALYSIS = "sentiment_analysis"
    WELLNESS_DIMENSIONS = "wellness_dimensions"
    DIGITAL_TWIN = "digital_twin"


class MentaLLaMAProcessRequest(BaseModel):
    """Request model for processing text with MentaLLaMA."""

    text: str = Field(description="Text to process", min_length=1)
    model_type: MentaLLaMAModelType | None = Field(
        default=MentaLLaMAModelType.GENERAL,
        description="Type of model to use for processing",
    )
    options: dict[str, Any] | None = Field(
        default=None, description="Additional processing options"
    )


class MentaLLaMAProcessResponse(BaseModel):
    """Response model for processing text with MentaLLaMA."""

    model_config = {"protected_namespaces": ()}

    model: str = Field(description="Model used for processing")
    model_type: str = Field(description="Type of model used for processing")
    timestamp: str = Field(description="Timestamp of the processing")
    content: str | None = Field(default=None, description="Processed content (for text responses)")

    # Allow additional fields for different model types
    model_config = ConfigDict(extra="allow")


class DepressionDetectionRequest(BaseModel):
    """Request model for depression detection."""

    text: str = Field(description="Text to analyze for depression signals", min_length=1)
    options: dict[str, Any] | None = Field(
        default=None, description="Additional processing options"
    )


class DepressionSignal(BaseModel):
    """Model for a depression signal indicator."""

    type: str = Field(description="Type of indicator (linguistic, content, behavioral, cognitive)")
    description: str = Field(description="Description of the specific indicator")
    evidence: str = Field(description="Evidence from the text")


class DepressionAnalysis(BaseModel):
    """Model for depression analysis."""

    severity: str = Field(description="Severity level (none, mild, moderate, severe)")
    confidence: float = Field(description="Confidence score (0-1)", ge=0, le=1)
    key_indicators: list[DepressionSignal] = Field(description="Key indicators of depression")


class DepressionRecommendations(BaseModel):
    """Model for depression recommendations."""

    suggested_assessments: list[str] = Field(description="Suggested formal assessments")
    discussion_points: list[str] = Field(description="Suggested topics for clinical follow-up")


class DepressionDetectionResponse(BaseModel):
    """Response model for depression detection."""

    model_config = {"protected_namespaces": ()}

    depression_signals: DepressionAnalysis = Field(description="Depression signals analysis")
    analysis: dict[str, Any] = Field(description="Detailed analysis")
    recommendations: DepressionRecommendations = Field(
        description="Recommendations based on analysis"
    )
    model: str = Field(description="Model used for detection")
    model_type: str = Field(description="Type of model used for detection")
    timestamp: str = Field(description="Timestamp of the detection")


class RiskType(str, Enum):
    """Risk types for risk assessment."""

    SUICIDE = "suicide"
    SELF_HARM = "self-harm"
    HARM_TO_OTHERS = "harm-to-others"
    NEGLECT = "neglect"
    OTHER = "other"


class RiskAssessmentRequest(BaseModel):
    """Request model for risk assessment."""

    text: str = Field(description="Text to analyze for risk signals", min_length=1)
    risk_type: RiskType | None = Field(default=None, description="Type of risk to assess")
    options: dict[str, Any] | None = Field(
        default=None, description="Additional processing options"
    )


class RiskLevel(str, Enum):
    """Risk levels for risk assessment."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    IMMINENT = "imminent"


class IdentifiedRisk(BaseModel):
    """Model for an identified risk."""

    risk_type: RiskType = Field(description="Type of risk")
    severity: RiskLevel = Field(description="Severity of the risk")
    evidence: str = Field(description="Evidence from the text")
    temporality: str = Field(description="Temporality of the risk (past, current, future)")


class RiskAssessmentAnalysis(BaseModel):
    """Model for risk assessment analysis."""

    overall_risk_level: RiskLevel = Field(description="Overall risk level")
    confidence: float = Field(description="Confidence score (0-1)", ge=0, le=1)
    identified_risks: list[IdentifiedRisk] = Field(description="Identified risks")


class RiskAssessmentRecommendations(BaseModel):
    """Model for risk assessment recommendations."""

    immediate_actions: list[str] = Field(description="Immediate actions for high/imminent risk")
    clinical_follow_up: list[str] = Field(description="Recommended clinical steps")
    screening_tools: list[str] = Field(description="Relevant formal assessments")


class RiskAssessmentResponse(BaseModel):
    """Response model for risk assessment."""

    model_config = {"protected_namespaces": ()}

    risk_assessment: RiskAssessmentAnalysis = Field(description="Risk assessment analysis")
    analysis: dict[str, Any] = Field(description="Detailed analysis")
    recommendations: RiskAssessmentRecommendations = Field(
        description="Recommendations based on analysis"
    )
    model: str = Field(description="Model used for assessment")
    model_type: str = Field(description="Type of model used for assessment")
    timestamp: str = Field(description="Timestamp of the assessment")


class SentimentAnalysisRequest(BaseModel):
    """Request model for sentiment analysis."""

    text: str = Field(description="Text to analyze for sentiment", min_length=1)
    options: dict[str, Any] | None = Field(
        default=None, description="Additional processing options"
    )


class Emotion(BaseModel):
    """Model for an emotion."""

    emotion: str = Field(description="Name of emotion")
    intensity: float = Field(description="Intensity of emotion (0-1)", ge=0, le=1)
    evidence: str = Field(description="Evidence from the text")


class EmotionalAnalysis(BaseModel):
    """Model for emotional analysis."""

    primary_emotions: list[Emotion] = Field(description="Primary emotions detected")
    emotional_range: str = Field(description="Emotional range (narrow, moderate, wide)")
    emotional_stability: str = Field(
        description="Emotional stability (stable, variable, rapidly_shifting)"
    )


class SentimentScore(BaseModel):
    """Model for sentiment score."""

    overall_score: float = Field(description="Overall sentiment score (-1 to 1)", ge=-1, le=1)
    intensity: float = Field(description="Intensity of sentiment (0-1)", ge=0, le=1)
    dominant_valence: str = Field(
        description="Dominant valence (positive, negative, neutral, mixed)"
    )


class SentimentAnalysisResponse(BaseModel):
    """Response model for sentiment analysis."""

    model_config = {"protected_namespaces": ()}

    sentiment: SentimentScore = Field(description="Sentiment score")
    emotions: EmotionalAnalysis = Field(description="Emotional analysis")
    analysis: dict[str, Any] = Field(description="Detailed analysis")
    model: str = Field(description="Model used for analysis")
    model_type: str = Field(description="Type of model used for analysis")
    timestamp: str = Field(description="Timestamp of the analysis")


class WellnessDimension(str, Enum):
    """Wellness dimensions for wellness analysis."""

    EMOTIONAL = "emotional"
    SOCIAL = "social"
    PHYSICAL = "physical"
    INTELLECTUAL = "intellectual"
    OCCUPATIONAL = "occupational"
    ENVIRONMENTAL = "environmental"
    SPIRITUAL = "spiritual"
    FINANCIAL = "financial"


class WellnessAnalysisRequest(BaseModel):
    """Request model for wellness dimensions analysis."""

    text: str = Field(description="Text to analyze for wellness dimensions", min_length=1)
    dimensions: list[WellnessDimension] | None = Field(
        default=None, description="List of dimensions to analyze"
    )
    options: dict[str, Any] | None = Field(
        default=None, description="Additional processing options"
    )


class WellnessDimensionAnalysis(BaseModel):
    """Model for wellness dimension analysis."""

    dimension: WellnessDimension = Field(description="Wellness dimension")
    score: float = Field(description="Wellness score (0-1)", ge=0, le=1)
    summary: str = Field(description="Brief summary of findings")
    strengths: list[str] = Field(description="Positive aspects identified")
    challenges: list[str] = Field(description="Areas of concern")
    evidence: list[str] = Field(description="Evidence from text")


class WellnessRecommendations(BaseModel):
    """Model for wellness recommendations."""

    clinical_focus_areas: list[str] = Field(description="Suggested clinical priorities")
    suggested_resources: list[str] = Field(description="Potentially helpful resources")
    assessment_tools: list[str] = Field(description="Relevant formal assessments")


class WellnessAnalysisResponse(BaseModel):
    """Response model for wellness dimensions analysis."""

    model_config = {"protected_namespaces": ()}

    wellness_dimensions: list[WellnessDimensionAnalysis] = Field(
        description="Wellness dimensions analysis"
    )
    analysis: dict[str, Any] = Field(description="Detailed analysis")
    recommendations: WellnessRecommendations = Field(
        description="Recommendations based on analysis"
    )
    model: str = Field(description="Model used for analysis")
    model_type: str = Field(description="Type of model used for analysis")
    timestamp: str = Field(description="Timestamp of the analysis")


class DetectionLevel(str, Enum):
    """PHI detection levels."""

    STRICT = "strict"
    MODERATE = "moderate"
    RELAXED = "relaxed"


class PHIDetectionRequest(BaseModel):
    """Request model for PHI detection."""

    text: str = Field(description="Text to analyze for PHI", min_length=1)
    detection_level: DetectionLevel | None = Field(
        default=DetectionLevel.MODERATE, description="Detection level"
    )


class PHIDetected(BaseModel):
    """Model for detected PHI."""

    type: str = Field(description="Type of PHI")
    value: str = Field(description="PHI value")
    start: int = Field(description="Start position in text", ge=0)
    end: int = Field(description="End position in text", ge=0)


class PHIDetectionResponse(BaseModel):
    """Response model for PHI detection."""

    phi_detected: list[PHIDetected] = Field(description="Detected PHI")
    detection_level: DetectionLevel = Field(description="Detection level used")
    phi_count: int = Field(description="Number of PHI instances detected", ge=0)
    has_phi: bool = Field(description="Whether PHI was detected")
    timestamp: str = Field(description="Timestamp of the detection")


class PHIRedactionRequest(BaseModel):
    """Request model for PHI redaction."""

    text: str = Field(description="Text to redact PHI from", min_length=1)
    replacement: str | None = Field(
        default="[REDACTED]", description="Replacement text for redacted PHI"
    )
    detection_level: DetectionLevel | None = Field(
        default=DetectionLevel.MODERATE, description="Detection level"
    )


class PHIRedactionResponse(BaseModel):
    """Response model for PHI redaction."""

    original_length: int = Field(description="Length of original text", ge=0)
    redacted_length: int = Field(description="Length of redacted text", ge=0)
    redacted_text: str = Field(description="Redacted text")
    detection_level: DetectionLevel = Field(description="Detection level used")
    phi_count: int = Field(description="Number of PHI instances redacted", ge=0)
    has_phi: bool = Field(description="Whether PHI was detected and redacted")
    timestamp: str = Field(description="Timestamp of the redaction")


# Digital Twin schemas


class GenerateDigitalTwinRequest(BaseModel):
    """Request model for generating a Digital Twin."""

    patient_id: str = Field(description="ID of the patient")
    patient_data: dict[str, Any] | None = Field(
        default=None, description="Additional patient data for Digital Twin generation"
    )
    options: dict[str, Any] | None = Field(
        default=None, description="Additional generation options"
    )


class DigitalTwinDimension(BaseModel):
    """Model for a Digital Twin dimension."""

    name: str = Field(description="Name of the dimension")
    score: float = Field(description="Score for this dimension (0-1)", ge=0, le=1)
    confidence: float = Field(description="Confidence in the score (0-1)", ge=0, le=1)
    key_features: list[str] = Field(description="Key features of this dimension")


class GenerateDigitalTwinResponse(BaseModel):
    """Response model for generating a Digital Twin."""

    model_config = {"protected_namespaces": ()}

    patient_id: str = Field(description="ID of the patient")
    digital_twin_id: str = Field(description="ID of the generated Digital Twin")
    creation_timestamp: str = Field(description="Timestamp of Digital Twin creation")
    status: str = Field(description="Status of the Digital Twin (active, inactive, training)")
    model_type: str = Field(description="Type of model used")
    version: str = Field(description="Version of the Digital Twin model")
    metrics: dict[str, Any] = Field(description="Model metrics")
    dimensions: list[DigitalTwinDimension] = Field(description="Digital Twin dimensions")
    clinical_summary: str = Field(description="Clinical summary of the Digital Twin")


class DigitalTwinSessionType(str, Enum):
    """Digital Twin session types."""

    THERAPY = "therapy"
    ASSESSMENT = "assessment"
    COACHING = "coaching"


class CreateSessionRequest(BaseModel):
    """Request model for creating a Digital Twin session."""

    therapist_id: str = Field(description="ID of the therapist")
    patient_id: str | None = Field(
        default=None, description="ID of the patient (optional for anonymous sessions)"
    )
    session_type: DigitalTwinSessionType | None = Field(
        default=DigitalTwinSessionType.THERAPY, description="Type of session"
    )
    session_params: dict[str, Any] | None = Field(
        default=None, description="Additional session parameters"
    )


class CreateSessionResponse(BaseModel):
    """Response model for creating a Digital Twin session."""

    session_id: str = Field(description="ID of the created session")
    created_at: str = Field(description="Timestamp of session creation")
    status: str = Field(description="Status of the session")
    session_type: DigitalTwinSessionType = Field(description="Type of session")
    therapist_id: str = Field(description="ID of the therapist")
    patient_id: str | None = Field(default=None, description="ID of the patient")
    model: str | None = Field(default=None, description="Model used for the session")


class GetSessionRequest(BaseModel):
    """Request model for getting a Digital Twin session."""

    session_id: str = Field(description="ID of the session")


class DigitalTwinMessage(BaseModel):
    """Model for a Digital Twin session message."""

    message_id: str = Field(description="ID of the message")
    session_id: str = Field(description="ID of the session")
    content: str = Field(description="Message content")
    sender_type: str = Field(description="Type of sender")
    sender_id: str | None = Field(default=None, description="ID of the sender")
    timestamp: str = Field(description="Timestamp of the message")
    params: dict[str, Any] | None = Field(default=None, description="Additional message parameters")


class GetSessionResponse(BaseModel):
    """Response model for getting a Digital Twin session."""

    session_id: str = Field(description="ID of the session")
    therapist_id: str = Field(description="ID of the therapist")
    patient_id: str | None = Field(default=None, description="ID of the patient")
    session_type: DigitalTwinSessionType = Field(description="Type of session")
    created_at: str = Field(description="Timestamp of session creation")
    updated_at: str = Field(description="Timestamp of last session update")
    status: str = Field(description="Status of the session")
    message_count: int = Field(description="Number of messages in the session", ge=0)
    insights_count: int = Field(description="Number of insights generated for the session", ge=0)
    messages: list[DigitalTwinMessage] | None = Field(default=None, description="Session messages")
    model: str | None = Field(default=None, description="Model used for the session")


class SenderType(str, Enum):
    """Digital Twin message sender types."""

    USER = "user"
    THERAPIST = "therapist"
    SYSTEM = "system"
    DIGITAL_TWIN = "digital_twin"


class SendMessageRequest(BaseModel):
    """Request model for sending a message to a Digital Twin session."""

    session_id: str = Field(description="ID of the session")
    message: str = Field(description="Message content", min_length=1)
    sender_type: SenderType | None = Field(default=SenderType.USER, description="Type of sender")
    sender_id: str | None = Field(default=None, description="ID of the sender")
    message_params: dict[str, Any] | None = Field(
        default=None, description="Additional message parameters"
    )


class DigitalTwinResponse(BaseModel):
    """Model for Digital Twin response."""

    message_id: str = Field(description="ID of the response message")
    content: str = Field(description="Response content")
    timestamp: str = Field(description="Timestamp of the response")
    session_id: str = Field(description="ID of the session")
    sender_type: str = Field(default=SenderType.DIGITAL_TWIN, description="Type of sender")
    sender_id: str | None = Field(default=None, description="ID of the sender (Digital Twin)")


class SendMessageResponse(BaseModel):
    """Response model for sending a message to a Digital Twin session."""

    message: DigitalTwinMessage = Field(description="Sent message")
    response: DigitalTwinResponse = Field(description="Digital Twin's response")
    session_status: str = Field(description="Current session status")


class EndSessionRequest(BaseModel):
    """Request model for ending a Digital Twin session."""

    session_id: str = Field(description="ID of the session")
    end_reason: str | None = Field(default=None, description="Reason for ending the session")


class SessionSummary(BaseModel):
    """Model for Digital Twin session summary."""

    key_themes: list[str] | None = Field(
        default=None, description="Key themes identified in the session"
    )
    emotional_patterns: dict[str, Any] | None = Field(
        default=None, description="Emotional patterns observed"
    )
    therapeutic_insights: list[str] | None = Field(
        default=None, description="Therapeutic insights generated"
    )
    progress_indicators: dict[str, float] | None = Field(
        default=None, description="Progress indicators"
    )
    suggested_focus_areas: list[str] | None = Field(
        default=None, description="Suggested focus areas for future sessions"
    )
    session_metrics: dict[str, Any] | None = Field(default=None, description="Session metrics")


class EndSessionResponse(BaseModel):
    """Response model for ending a Digital Twin session."""

    session_id: str = Field(description="ID of the session")
    status: str = Field(description="Status of the session")
    end_reason: str = Field(description="Reason for ending the session")
    ended_at: str = Field(description="Timestamp of session end")
    message_count: int = Field(description="Number of messages in the session", ge=0)
    duration_minutes: int = Field(description="Duration of the session in minutes", ge=0)
    summary: SessionSummary = Field(description="Session summary")


class InsightType(str, Enum):
    """Digital Twin insight types."""

    LINGUISTIC = "linguistic"
    CLINICAL = "clinical"
    THERAPEUTIC = "therapeutic"
    PROGRESS = "progress"


class GetInsightsRequest(BaseModel):
    """Request model for getting insights from a Digital Twin session."""

    session_id: str = Field(description="ID of the session")
    insight_type: InsightType | None = Field(
        default=None, description="Type of insights to retrieve"
    )


class SessionInsight(BaseModel):
    """Model for a session insight."""

    type: InsightType = Field(description="Type of insight")
    data: dict[str, Any] = Field(description="Insight data")
    timestamp: str = Field(description="Timestamp of the insight")
    confidence: float | None = Field(
        default=None, description="Confidence score for the insight (0-1)", ge=0, le=1
    )


class GetInsightsResponse(BaseModel):
    """Response model for getting insights from a Digital Twin session."""

    session_id: str = Field(description="ID of the session")
    generated_at: str = Field(description="Timestamp of the insights generation")
    session_type: DigitalTwinSessionType = Field(description="Type of session")
    message_count: int = Field(description="Number of messages in the session", ge=0)
    session_status: str = Field(description="Status of the session")
    insights: list[SessionInsight] = Field(description="Session insights")
