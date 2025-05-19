"""
Pydantic schemas for XGBoost prediction API.

This module defines the request and response models for the XGBoost prediction API
endpoints, providing strict validation and documentation of the API contract.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ClinicalData(BaseModel):
    """Clinical data for prediction."""

    severity_score: int = Field(
        ...,
        ge=0,
        le=27,
        description="Severity score (0-27 scale). Higher values indicate greater symptom severity.",
    )
    phq9_score: int | None = Field(
        None,
        ge=0,
        le=27,
        description="PHQ-9 depression score (0-27 scale). Higher values indicate more severe depression.",
    )
    gad7_score: int | None = Field(
        None,
        ge=0,
        le=21,
        description="GAD-7 anxiety score (0-21 scale). Higher values indicate more severe anxiety.",
    )
    sleep_quality: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Sleep quality score (0-1 scale). Higher values indicate better sleep quality.",
    )
    medication_adherence: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Medication adherence rate (0-1 scale). Higher values indicate better adherence.",
    )
    previous_episodes: int | None = Field(
        None, ge=0, description="Number of previous psychiatric episodes."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity_score": 15,
                "phq9_score": 12,
                "gad7_score": 10,
                "sleep_quality": 0.7,
                "medication_adherence": 0.8,
                "previous_episodes": 2,
            }
        }
    )


class DemographicData(BaseModel):
    """Demographic data for prediction."""

    age_range: str | None = Field(
        None,
        description="Age range (e.g., '18-24', '25-34', '35-44', '45-54', '55-64', '65+')",
    )
    biological_sex: str | None = Field(
        None, description="Biological sex (e.g., 'male', 'female', 'other')"
    )
    education_level: str | None = Field(
        None,
        description="Education level (e.g., 'high_school', 'bachelors', 'masters', 'doctoral')",
    )
    employment_status: str | None = Field(
        None,
        description="Employment status (e.g., 'employed', 'unemployed', 'student', 'retired')",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "age_range": "25-34",
                "biological_sex": "female",
                "education_level": "bachelors",
                "employment_status": "employed",
            }
        }
    )


class TemporalData(BaseModel):
    """Temporal data for prediction."""

    time_of_day: str | None = Field(
        None,
        description="Time of day (e.g., 'morning', 'afternoon', 'evening', 'night')",
    )
    day_of_week: int | None = Field(
        None, ge=0, le=6, description="Day of week (0-6, where 0 is Monday)"
    )
    season: str | None = Field(
        None, description="Season (e.g., 'spring', 'summer', 'fall', 'winter')"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"time_of_day": "morning", "day_of_week": 2, "season": "winter"}
        }
    )


class TreatmentDetails(BaseModel):
    """Treatment details for prediction."""

    name: str = Field(
        ..., description="Name of the treatment (e.g., medication name or therapy type)"
    )
    class_: str = Field(
        ...,
        description="Class of the treatment (e.g., 'SSRI', 'SNRI', 'CBT')",
        alias="class",
    )
    dosage: str | None = Field(
        None, description="Dosage information for medications (e.g., '50mg daily')"
    )
    duration: str | None = Field(
        None, description="Duration of treatment (e.g., '12 weeks')"
    )

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "name": "Sertraline",
                "class": "SSRI",
                "dosage": "50mg daily",
                "duration": "8 weeks",
            }
        },
    )


class GeneticData(BaseModel):
    """Genetic data for prediction."""

    cyp2d6_status: str | None = Field(
        None,
        description="CYP2D6 metabolizer status (e.g., 'normal', 'poor', 'rapid', 'ultrarapid')",
    )
    cyp2c19_status: str | None = Field(
        None,
        description="CYP2C19 metabolizer status (e.g., 'normal', 'poor', 'rapid', 'ultrarapid')",
    )
    cyp1a2_status: str | None = Field(
        None,
        description="CYP1A2 metabolizer status (e.g., 'normal', 'poor', 'rapid', 'ultrarapid')",
    )
    cyp3a4_status: str | None = Field(
        None,
        description="CYP3A4 metabolizer status (e.g., 'normal', 'poor', 'rapid', 'ultrarapid')",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cyp2d6_status": "normal",
                "cyp2c19_status": "rapid",
                "cyp1a2_status": "normal",
                "cyp3a4_status": "normal",
            }
        }
    )


class TreatmentHistory(BaseModel):
    """Treatment history for prediction."""

    previous_treatments: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of previous treatments and their outcomes",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "previous_treatments": [
                    {
                        "name": "Fluoxetine",
                        "class": "SSRI",
                        "response": 0.4,
                        "side_effects": ["nausea", "insomnia"],
                        "duration": "3 months",
                        "discontinued_reason": "side effects",
                    },
                    {
                        "name": "CBT",
                        "type": "therapy",
                        "response": 0.6,
                        "duration": "12 weeks",
                        "discontinued_reason": "completed course",
                    },
                ]
            }
        }
    )


class TreatmentPlan(BaseModel):
    """Treatment plan for prediction."""

    treatments: list[dict[str, Any]] = Field(
        ..., description="List of planned treatments"
    )
    intensity: str = Field(
        ..., description="Treatment plan intensity (LOW, MODERATE, HIGH)"
    )
    duration: str | None = Field(
        None, description="Planned duration of treatment (e.g., '12 weeks')"
    )
    goals: list[str] | None = Field(None, description="Treatment goals")

    @field_validator("intensity")
    @classmethod
    def validate_intensity(cls, v: str) -> str:
        """Validate intensity value."""
        valid_intensities = ["LOW", "MODERATE", "HIGH"]
        if v.upper() not in valid_intensities:
            raise ValueError(f"Intensity must be one of {valid_intensities}")
        return v.upper()

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "treatments": [
                    {
                        "name": "Sertraline",
                        "class": "SSRI",
                        "dosage": "50mg daily",
                        "duration": "8 weeks",
                    },
                    {
                        "name": "CBT",
                        "type": "therapy",
                        "frequency": "weekly",
                        "sessions": 12,
                    },
                ],
                "intensity": "MODERATE",
                "duration": "12 weeks",
                "goals": [
                    "Reduce depression symptoms by 50%",
                    "Improve sleep quality",
                    "Develop coping strategies",
                ],
            }
        }
    )


class SocialDeterminants(BaseModel):
    """Social determinants of health for prediction."""

    support_network_score: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Support network score (0-1 scale). Higher values indicate stronger support.",
    )
    access_to_care: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Access to care score (0-1 scale). Higher values indicate better access.",
    )
    housing_stability: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Housing stability score (0-1 scale). Higher values indicate more stable housing.",
    )
    financial_stability: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Financial stability score (0-1 scale). Higher values indicate more stable finances.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "support_network_score": 0.7,
                "access_to_care": 0.8,
                "housing_stability": 0.9,
                "financial_stability": 0.6,
            }
        }
    )


class Comorbidities(BaseModel):
    """Comorbidities for prediction."""

    conditions: list[dict[str, Any]] = Field(
        default_factory=list, description="List of comorbid conditions"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "conditions": [
                    {
                        "name": "hypertension",
                        "severity": "moderate",
                        "treatment": "lisinopril",
                    },
                    {
                        "name": "type 2 diabetes",
                        "severity": "mild",
                        "treatment": "metformin",
                    },
                ]
            }
        }
    )


# Request Models


class RiskPredictionRequest(BaseModel):
    """Request model for risk prediction."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    risk_type: str = Field(
        ...,
        description="Type of risk to predict (e.g., 'symptom-risk', 'relapse-risk')",
    )
    clinical_data: ClinicalData = Field(..., description="Clinical data for prediction")
    demographic_data: DemographicData | None = Field(
        None, description="Demographic data for prediction"
    )
    temporal_data: TemporalData | None = Field(
        None, description="Temporal data for prediction"
    )
    confidence_threshold: float | None = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Confidence threshold for prediction (0-1 scale)",
    )

    @field_validator("risk_type")
    @classmethod
    def validate_risk_type(cls, v: str) -> str:
        """Validate risk type."""
        valid_types = ["symptom-risk", "relapse-risk"]
        normalized = v.lower().replace(" ", "-")
        if normalized not in valid_types:
            raise ValueError(f"Risk type must be one of {valid_types}")
        return normalized

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "patient_id": "patient-123",
                "risk_type": "relapse-risk",
                "clinical_data": {
                    "severity_score": 15,
                    "phq9_score": 12,
                    "gad7_score": 10,
                    "sleep_quality": 0.7,
                    "medication_adherence": 0.8,
                    "previous_episodes": 2,
                },
                "demographic_data": {"age_range": "25-34", "biological_sex": "female"},
                "confidence_threshold": 0.7,
            }
        }
    )


class TreatmentResponseRequest(BaseModel):
    """Request model for treatment response prediction."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    treatment_type: str = Field(
        ...,
        description="Type of treatment (e.g., 'medication-response', 'therapy-response')",
    )
    treatment_details: TreatmentDetails = Field(
        ..., description="Details of the treatment"
    )
    clinical_data: ClinicalData = Field(..., description="Clinical data for prediction")
    genetic_data: GeneticData | None = Field(
        None, description="Genetic data for prediction"
    )
    treatment_history: TreatmentHistory | None = Field(
        None, description="Treatment history for prediction"
    )

    @field_validator("treatment_type")
    @classmethod
    def validate_treatment_type(cls, v: str) -> str:
        """Validate treatment type."""
        valid_types = ["medication-response", "therapy-response"]
        normalized = v.lower().replace(" ", "-")
        if normalized not in valid_types:
            raise ValueError(f"Treatment type must be one of {valid_types}")
        return normalized

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "patient_id": "patient-123",
                "treatment_type": "medication-response",
                "treatment_details": {
                    "name": "Sertraline",
                    "class": "SSRI",
                    "dosage": "50mg daily",
                },
                "clinical_data": {
                    "severity_score": 15,
                    "phq9_score": 12,
                    "gad7_score": 10,
                },
                "genetic_data": {"cyp2d6_status": "normal", "cyp2c19_status": "rapid"},
            }
        }
    )


class OutcomePredictionRequest(BaseModel):
    """Request model for outcome prediction."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    outcome_timeframe: str = Field(
        ..., description="Timeframe for prediction (e.g., '3-month', '1-year')"
    )
    clinical_data: ClinicalData = Field(..., description="Clinical data for prediction")
    treatment_plan: TreatmentPlan = Field(..., description="Planned treatment regimen")
    social_determinants: SocialDeterminants | None = Field(
        None, description="Social determinants of health"
    )
    comorbidities: Comorbidities | None = Field(None, description="Comorbid conditions")

    @field_validator("outcome_timeframe")
    @classmethod
    def validate_timeframe(cls, v: str) -> str:
        """Validate outcome timeframe format."""
        import re

        if not re.match(r"^\d+-(?:week|month|year)$", v):
            raise ValueError("Timeframe must be in format '3-month', '1-year', etc.")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "patient_id": "patient-123",
                "outcome_timeframe": "3-month",
                "clinical_data": {
                    "severity_score": 15,
                    "phq9_score": 12,
                    "gad7_score": 10,
                },
                "treatment_plan": {
                    "treatments": [
                        {"name": "Sertraline", "class": "SSRI", "dosage": "50mg daily"},
                        {"name": "CBT", "type": "therapy", "frequency": "weekly"},
                    ],
                    "intensity": "MODERATE",
                    "duration": "12 weeks",
                },
                "social_determinants": {
                    "support_network_score": 0.7,
                    "access_to_care": 0.8,
                },
            }
        }
    )


class FeatureImportanceRequest(BaseModel):
    """Request model for feature importance."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    model_type: str = Field(
        ..., description="Type of model (e.g., 'symptom-risk', 'medication-response')"
    )
    prediction_id: str = Field(..., description="ID of the prediction to explain")

    @field_validator("model_type")
    @classmethod
    def validate_model_type(cls, v: str) -> str:
        """Validate model type."""
        valid_types = [
            "symptom-risk",
            "relapse-risk",
            "medication-response",
            "therapy-response",
            "outcome-prediction",
        ]
        normalized = v.lower().replace(" ", "-")
        if normalized not in valid_types:
            raise ValueError(f"Model type must be one of {valid_types}")
        return normalized

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "patient_id": "patient-123",
                "model_type": "relapse-risk",
                "prediction_id": "prediction-456",
            }
        },
        protected_namespaces=(),
    )


class DigitalTwinIntegrationRequest(BaseModel):
    """Request model for digital twin integration."""

    patient_id: str = Field(..., description="Unique identifier for the patient")
    profile_id: str = Field(..., description="ID of the digital twin profile")
    prediction_id: str = Field(..., description="ID of the prediction to integrate")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "patient_id": "patient-123",
                "profile_id": "profile-456",
                "prediction_id": "prediction-789",
            }
        }
    )


class ModelInfoRequest(BaseModel):
    """Request model for model information."""

    model_type: str = Field(
        ..., description="Type of model (e.g., 'symptom-risk', 'medication-response')"
    )

    @field_validator("model_type")
    @classmethod
    def validate_model_type(cls, v: str) -> str:
        """Validate model type."""
        valid_types = [
            "symptom-risk",
            "relapse-risk",
            "medication-response",
            "therapy-response",
            "outcome-prediction",
        ]
        normalized = v.lower().replace(" ", "-")
        if normalized not in valid_types:
            raise ValueError(f"Model type must be one of {valid_types}")
        return normalized

    model_config = ConfigDict(
        json_schema_extra={"example": {"model_type": "relapse-risk"}},
        protected_namespaces=(),
    )


# Response Models


class RiskPredictionResponse(BaseModel):
    """Response model for risk prediction."""

    model_config = ConfigDict(protected_namespaces=())

    prediction_id: str = Field(..., description="Unique identifier for this prediction")
    patient_id: str = Field(..., description="Unique identifier for the patient")
    model_type: str = Field(..., description="Type of model used for prediction")
    timestamp: str = Field(..., description="Timestamp of prediction")
    risk_score: float = Field(
        ..., ge=0.0, le=1.0, description="Numeric risk score (0-1 scale)"
    )
    risk_level: str = Field(
        ..., description="Categorical risk level (LOW, MODERATE, HIGH)"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence level in prediction (0-1 scale)"
    )
    meets_threshold: bool = Field(
        ..., description="Whether prediction meets confidence threshold"
    )
    contributing_factors: list[str] = Field(
        ..., description="Factors contributing to risk"
    )
    recommended_actions: list[str] = Field(
        ..., description="Recommended clinical actions"
    )
    detailed_factors: dict[str, Any] | None = Field(
        None, description="Detailed analysis of contributing factors"
    )
    detailed_actions: dict[str, Any] | None = Field(
        None, description="Detailed recommended actions"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prediction_id": "pred-123-456",
                "patient_id": "patient-123",
                "model_type": "relapse-risk",
                "timestamp": "2025-03-28T12:00:00Z",
                "risk_score": 0.72,
                "risk_level": "HIGH",
                "confidence": 0.85,
                "meets_threshold": True,
                "contributing_factors": [
                    "Recent medication adherence issues",
                    "Elevated PHQ-9 score",
                    "Sleep disruption pattern",
                ],
                "recommended_actions": [
                    "Increase appointment frequency",
                    "Review medication regimen",
                    "Implement sleep hygiene protocol",
                ],
            }
        }
    )


class TreatmentResponseResponse(BaseModel):
    """Response model for treatment response prediction."""

    model_config = ConfigDict(protected_namespaces=())

    prediction_id: str = Field(..., description="Unique identifier for this prediction")
    patient_id: str = Field(..., description="Unique identifier for the patient")
    model_type: str = Field(..., description="Type of model used for prediction")
    timestamp: str = Field(..., description="Timestamp of prediction")
    response_probability: float = Field(
        ..., ge=0.0, le=1.0, description="Likelihood of positive response (0-1 scale)"
    )
    response_label: str = Field(
        ..., description="Categorical response prediction (POOR, MODERATE, GOOD)"
    )
    expected_timeframe: str = Field(..., description="Expected timeframe for response")
    side_effects_risk: dict[str, float] = Field(..., description="Risk of side effects")
    alternatives: list[dict[str, Any]] = Field(
        ..., description="Alternative treatment options"
    )
    detailed_side_effects: dict[str, Any] | None = Field(
        None, description="Detailed analysis of side effects"
    )
    detailed_alternatives: dict[str, Any] | None = Field(
        None, description="Detailed alternative options"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prediction_id": "pred-123-456",
                "patient_id": "patient-123",
                "model_type": "medication-response",
                "timestamp": "2025-03-28T12:00:00Z",
                "response_probability": 0.68,
                "response_label": "GOOD",
                "expected_timeframe": "4 weeks",
                "side_effects_risk": {
                    "nausea": 0.15,
                    "insomnia": 0.22,
                    "headache": 0.10,
                },
                "alternatives": [
                    {
                        "name": "Escitalopram",
                        "class": "SSRI",
                        "estimated_response": 0.64,
                        "advantages": ["Lower side effect profile"],
                        "disadvantages": ["Slower onset"],
                    },
                    {
                        "name": "CBT",
                        "type": "therapy",
                        "estimated_response": 0.72,
                        "advantages": ["No medication side effects"],
                        "disadvantages": ["Time intensive"],
                    },
                ],
            }
        }
    )


class OutcomePredictionResponse(BaseModel):
    """Response model for outcome prediction."""

    model_config = ConfigDict(protected_namespaces=())

    prediction_id: str = Field(..., description="Unique identifier for this prediction")
    patient_id: str = Field(..., description="Unique identifier for the patient")
    model_type: str = Field(..., description="Type of model used for prediction")
    timestamp: str = Field(..., description="Timestamp of prediction")
    timeframe: str = Field(..., description="Timeframe for prediction")
    outcomes: dict[str, float] = Field(
        ..., description="Predicted outcomes for various measures"
    )
    expected_trajectory: dict[str, Any] = Field(
        ..., description="Expected clinical trajectory over time"
    )
    key_factors: list[str] = Field(..., description="Key factors affecting outcomes")
    suggested_adjustments: list[str] = Field(
        ..., description="Suggested adjustments to treatment plan"
    )
    detailed_trajectory: dict[str, Any] | None = Field(
        None, description="Detailed trajectory analysis"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prediction_id": "pred-123-456",
                "patient_id": "patient-123",
                "model_type": "outcome-prediction",
                "timestamp": "2025-03-28T12:00:00Z",
                "timeframe": "3-month",
                "outcomes": {
                    "symptom_improvement": 0.65,
                    "functional_improvement": 0.58,
                    "remission": 0.42,
                    "relapse": 0.25,
                },
                "expected_trajectory": {
                    "timeframe": "3-month",
                    "points": [
                        {"week": 0, "symptom_level": 1.0, "functional_level": 0.5},
                        {"week": 4, "symptom_level": 0.8, "functional_level": 0.6},
                        {"week": 8, "symptom_level": 0.6, "functional_level": 0.7},
                        {"week": 12, "symptom_level": 0.4, "functional_level": 0.8},
                    ],
                    "milestones": [
                        {
                            "week": 4,
                            "description": "Initial response assessment",
                            "probability": 0.7,
                        },
                        {
                            "week": 12,
                            "description": "End of 3-month assessment",
                            "probability": 0.6,
                        },
                    ],
                },
                "key_factors": [
                    "Intensive treatment approach",
                    "Strong support network",
                    "Medication adherence",
                ],
                "suggested_adjustments": [
                    "Consider adding sleep hygiene intervention",
                    "Increase therapy frequency in weeks 4-8",
                ],
            }
        }
    )


class FeatureImportanceResponse(BaseModel):
    """Response model for feature importance."""

    prediction_id: str = Field(..., description="ID of the prediction being explained")
    patient_id: str = Field(..., description="Unique identifier for the patient")
    model_type: str = Field(..., description="Type of model used for prediction")
    timestamp: str = Field(
        ..., description="Timestamp of feature importance calculation"
    )
    features: list[dict[str, Any]] = Field(
        ..., description="List of features with importance scores"
    )
    explanation_method: str = Field(
        ..., description="Method used for explanation (e.g., SHAP)"
    )
    model_version: str = Field(..., description="Version of the model")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "prediction_id": "pred-123-456",
                "patient_id": "patient-123",
                "model_type": "relapse-risk",
                "timestamp": "2025-03-28T12:05:00Z",
                "features": [
                    {
                        "feature": "Medication adherence",
                        "importance": 0.35,
                        "direction": "negative",
                        "description": "Lower adherence increases risk",
                    },
                    {
                        "feature": "PHQ-9 score",
                        "importance": 0.25,
                        "direction": "positive",
                        "description": "Higher score increases risk",
                    },
                    {
                        "feature": "Sleep quality",
                        "importance": 0.20,
                        "direction": "negative",
                        "description": "Lower quality increases risk",
                    },
                ],
                "explanation_method": "SHAP",
                "model_version": "1.2.3",
            }
        },
        protected_namespaces=(),
    )


class DigitalTwinIntegrationResponse(BaseModel):
    """Response model for digital twin integration."""

    integration_id: str = Field(
        ..., description="Unique identifier for this integration"
    )
    patient_id: str = Field(..., description="Unique identifier for the patient")
    profile_id: str = Field(..., description="ID of the digital twin profile")
    prediction_id: str = Field(..., description="ID of the integrated prediction")
    timestamp: str = Field(..., description="Timestamp of integration")
    status: str = Field(
        ..., description="Status of integration (SUCCESS, PARTIAL, FAILED)"
    )
    digital_twin_components_updated: list[str] = Field(
        ..., description="Components of digital twin that were updated"
    )
    insights_generated: list[str] = Field(
        ..., description="Clinical insights generated from integration"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "integration_id": "int-123-456",
                "patient_id": "patient-123",
                "profile_id": "profile-456",
                "prediction_id": "pred-123-456",
                "timestamp": "2025-03-28T12:10:00Z",
                "status": "SUCCESS",
                "digital_twin_components_updated": [
                    "Risk profile",
                    "Clinical trajectory",
                    "Alert thresholds",
                ],
                "insights_generated": [
                    "Updated relapse risk profile with latest prediction",
                    "Adjusted risk thresholds based on new data",
                    "Updated early warning indicators",
                ],
            }
        }
    )


class ModelInfoResponse(BaseModel):
    """Response model for model information."""

    model_config = {"protected_namespaces": ()}

    model_type: str = Field(..., description="Type of model")
    version: str = Field(..., description="Model version")
    last_updated: str = Field(..., description="Last update date")
    description: str = Field(..., description="Model description")
    features: list[str] = Field(..., description="Features used by the model")
    performance_metrics: dict[str, float] = Field(
        ..., description="Performance metrics"
    )
    training_dataset: str = Field(..., description="Description of training dataset")
    supports_explanations: bool = Field(
        ..., description="Whether the model supports feature importance explanations"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "model_type": "relapse-risk",
                "version": "1.2.3",
                "last_updated": "2025-02-15",
                "description": "Predicts risk of psychiatric relapse",
                "features": [
                    "severity_score",
                    "phq9_score",
                    "gad7_score",
                    "sleep_quality",
                    "medication_adherence",
                ],
                "performance_metrics": {
                    "auc": 0.85,
                    "accuracy": 0.82,
                    "precision": 0.78,
                    "recall": 0.81,
                },
                "training_dataset": "De-identified clinical data from 10,000 patients",
                "supports_explanations": True,
            }
        }
    )
