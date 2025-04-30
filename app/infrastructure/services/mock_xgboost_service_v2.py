"""
Mock implementation of XGBoostInterface for testing.
Provides synthetic predictions without requiring the actual XGBoost model.
"""
from datetime import datetime, timedelta
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union
import random

from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.core.services.ml.xgboost.constants import ModelType
from app.core.services.ml.xgboost.exceptions import (
    XGBoostServiceError,
    ValidationError,
    ModelNotFoundError,
    ResourceNotFoundError,
    ServiceUnavailableError
)

class MockXGBoostService(XGBoostInterface):
    """
    Mock implementation of XGBoostInterface that provides synthetic responses for testing.
    """
    
    def __init__(self):
        """Initialize the mock service with default configuration."""
        self._predictions = {}  # Store predictions for retrieval
        self._features = {}  # Store feature importance data
        self._initialized = True
    
    async def predict_risk(
        self, 
        patient_id: str, 
        risk_type: str, 
        clinical_data: Dict[str, Any],
        time_frame_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """Mock implementation of risk prediction."""
        # Validate input
        if not patient_id:
            raise ValidationError("Patient ID is required")
        
        if not risk_type:
            raise ValidationError("Risk type is required")
        
        if not clinical_data:
            raise ValidationError("Clinical data is required")
        
        # Generate prediction ID
        prediction_id = f"risk-{uuid.uuid4()}"
        
        # Generate mock risk prediction
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "risk_type": risk_type,
            "risk_score": round(random.uniform(0.1, 0.9), 2),
            "risk_level": random.choice(["low", "moderate", "high"]),
            "confidence": round(random.uniform(0.7, 0.95), 2),
            "factors": {
                "age": round(random.uniform(0.1, 0.5), 2),
                "symptoms": round(random.uniform(0.2, 0.6), 2),
                "history": round(random.uniform(0.3, 0.7), 2)
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Store prediction for later retrieval
        self._predictions[prediction_id] = result
        
        return result
    
    async def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: Dict[str, Any],
        clinical_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mock implementation of treatment response prediction."""
        # Validate input
        if not patient_id:
            raise ValidationError("Patient ID is required")
        
        if not treatment_type:
            raise ValidationError("Treatment type is required")
        
        # Generate prediction ID
        prediction_id = f"treatment-{uuid.uuid4()}"
        
        # Generate mock treatment response prediction
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "treatment_type": treatment_type,
            "efficacy_score": round(random.uniform(0.2, 0.9), 2),
            "response_likelihood": random.choice(["low", "moderate", "high"]),
            "expected_outcome": {
                "symptom_improvement": random.choice(["minimal", "moderate", "significant"]),
                "time_to_response": f"{random.randint(2, 8)} weeks",
                "functional_improvement": random.choice(["minimal", "moderate", "significant"])
            },
            "confidence": round(random.uniform(0.7, 0.9), 2),
            "side_effect_risk": {
                "common": random.sample(["nausea", "headache", "insomnia", "fatigue"], k=random.randint(0, 2)),
                "rare": random.sample(["dizziness", "palpitations", "tremor"], k=random.randint(0, 1))
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Store prediction for later retrieval
        self._predictions[prediction_id] = result
        
        return result
    
    async def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: Dict[str, Any],
        clinical_data: Dict[str, Any],
        treatment_plan: Dict[str, Any],
        social_determinants: Optional[Dict[str, Any]] = None,
        comorbidities: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Mock implementation of outcome prediction."""
        # Validate input
        if not patient_id:
            raise ValidationError("Patient ID is required")
        
        # Generate prediction ID
        prediction_id = f"outcome-{uuid.uuid4()}"
        
        # Generate mock outcome prediction
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "outcome_score": round(random.uniform(0.3, 0.8), 2),
            "confidence": round(random.uniform(0.7, 0.9), 2),
            "trajectory": {
                "points": [
                    {"time_point": "2 weeks", "days_from_start": 14, "improvement_percentage": round(random.uniform(5, 15), 1)},
                    {"time_point": "4 weeks", "days_from_start": 28, "improvement_percentage": round(random.uniform(15, 30), 1)},
                    {"time_point": "8 weeks", "days_from_start": 56, "improvement_percentage": round(random.uniform(30, 50), 1)}
                ],
                "visualization_type": "line_chart"
            },
            "outcome_details": {
                "overall_improvement": random.choice(["minimal", "moderate", "significant"]),
                "domains": [
                    {"name": "Mood", "improvement": random.choice(["minimal", "moderate", "significant"])},
                    {"name": "Anxiety", "improvement": random.choice(["minimal", "moderate", "significant"])}
                ]
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Store prediction for later retrieval
        self._predictions[prediction_id] = result
        
        return result
    
    async def get_model_info(
        self, 
        model_type: Union[str, ModelType]
    ) -> Dict[str, Any]:
        """Mock implementation of model info retrieval."""
        # Convert enum to string if needed
        if isinstance(model_type, ModelType):
            model_type = model_type.value
        
        # Return mock model info based on type
        if model_type == ModelType.RISK_RELAPSE.value:
            return {
                "model_type": model_type,
                "version": "2.0.1",
                "last_updated": datetime.now().isoformat(),
                "description": "XGBoost model for predicting relapse risk",
                "performance_metrics": {
                    "accuracy": 0.87,
                    "precision": 0.83,
                    "recall": 0.82,
                    "f1_score": 0.83,
                    "auc_roc": 0.89
                },
                "features": [
                    {"name": "age", "importance": 0.15},
                    {"name": "symptom_severity", "importance": 0.25},
                    {"name": "previous_episodes", "importance": 0.35},
                    {"name": "treatment_adherence", "importance": 0.25}
                ]
            }
        elif model_type == ModelType.TREATMENT_MEDICATION_SSRI.value:
            return {
                "model_type": model_type,
                "version": "1.5.2",
                "last_updated": datetime.now().isoformat(),
                "description": "XGBoost model for predicting SSRI treatment response",
                "performance_metrics": {
                    "accuracy": 0.84,
                    "precision": 0.82,
                    "recall": 0.79,
                    "f1_score": 0.80,
                    "auc_roc": 0.88
                },
                "features": [
                    {"name": "age", "importance": 0.10},
                    {"name": "symptom_profile", "importance": 0.30},
                    {"name": "genetic_markers", "importance": 0.40},
                    {"name": "previous_medications", "importance": 0.20}
                ]
            }
        else:
            raise ModelNotFoundError(f"Model type '{model_type}' not found")
    
    async def get_feature_importance(
        self,
        model_type: Union[str, ModelType],
        prediction_id: str,
        patient_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Mock implementation of feature importance retrieval."""
        # Validate input
        if not prediction_id:
            raise ValidationError("Prediction ID is required")
        
        # Convert enum to string if needed
        if isinstance(model_type, ModelType):
            model_type = model_type.value
        
        # Check if prediction exists
        if prediction_id not in self._predictions:
            raise ResourceNotFoundError(f"Prediction with ID '{prediction_id}' not found")
        
        # Return mock feature importance
        return {
            "prediction_id": prediction_id,
            "model_type": model_type,
            "features": [
                {"name": "age", "importance": round(random.uniform(0.05, 0.15), 2), "value": 35},
                {"name": "symptom_severity", "importance": round(random.uniform(0.15, 0.35), 2), "value": 7.2},
                {"name": "previous_episodes", "importance": round(random.uniform(0.25, 0.45), 2), "value": 2},
                {"name": "treatment_adherence", "importance": round(random.uniform(0.15, 0.25), 2), "value": 0.8}
            ],
            "total_features": 4,
            "top_features": 4,
            "timestamp": datetime.now().isoformat()
        }
    
    async def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        prediction_id: str,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Mock implementation of digital twin integration."""
        # Validate input
        if not patient_id:
            raise ValidationError("Patient ID is required")
        
        if not profile_id:
            raise ValidationError("Profile ID is required")
        
        if not prediction_id:
            raise ValidationError("Prediction ID is required")
        
        # Check if prediction exists
        if prediction_id not in self._predictions:
            raise ResourceNotFoundError(f"Prediction with ID '{prediction_id}' not found")
        
        # Return mock integration result
        return {
            "integration_id": f"int-{uuid.uuid4()}",
            "patient_id": patient_id,
            "profile_id": profile_id,
            "prediction_id": prediction_id,
            "status": "success",
            "digital_twin_updates": {
                "updated_fields": ["risk_factors", "treatment_recommendations", "outcome_trajectory"],
                "update_timestamp": datetime.now().isoformat()
            },
            "message": "Successfully integrated prediction with digital twin"
        }
    
    async def healthcheck(self) -> Dict[str, Any]:
        """Check service health."""
        return {
            "status": "healthy",
            "version": "2.0.0",
            "models_available": [m.value for m in ModelType]
        }
