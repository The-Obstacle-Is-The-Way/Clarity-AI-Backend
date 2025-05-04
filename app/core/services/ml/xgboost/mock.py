"""
Mock implementation of the XGBoost service interface.

This module provides a mock implementation of the XGBoost service
for testing, development, and demonstration purposes.
"""

import hashlib
import logging
import random
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

from app.core.services.ml.xgboost.exceptions import (
    ConfigurationError,
    DataPrivacyError,
    ModelNotFoundError,
    ResourceNotFoundError,
    ValidationError,
)
from app.core.services.ml.xgboost.interface import (
    EventType,
    ModelType,
    Observer,
    PrivacyLevel,
    XGBoostInterface,
)


class MockXGBoostService(XGBoostInterface):
    """Mock implementation of the XGBoost service interface for testing and development."""

    @property
    def is_initialized(self) -> bool:
        return True

    async def get_available_models(self) -> list[dict]:
        return []

    async def get_model_info(self, model_type: str) -> dict:
        return {"model_type": model_type, "version": "mock", "info": "Mock model info"}

    async def integrate_with_digital_twin(self, patient_id: str, profile_id: str, prediction_id: str) -> dict:
        return {"patient_id": patient_id, "profile_id": profile_id, "prediction_id": prediction_id, "status": "integrated (mock)"}

    def __init__(self):
        """Initialize a new mock XGBoost service."""
        super().__init__()
        
        # In-memory storage for predictions
        self._predictions: dict[str, dict[str, Any]] = {}
        
        # In-memory storage for digital twin profiles
        self._profiles: dict[str, dict[str, Any]] = {}
        
        # Configuration
        self._mock_delay_ms = 200
        self._risk_level_distribution = {
            "very_low": 5,
            "low": 20,
            "moderate": 50,
            "high": 20,
            "very_high": 5
        }
        self._privacy_level = PrivacyLevel.STANDARD
        
        # PHI patterns for different privacy levels (simplified version)
        self._phi_patterns = {
            PrivacyLevel.STANDARD: [
                re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
                re.compile(r"\bMRN\s*\d{5,10}\b"),  # MRN
                re.compile(r"\b(Dr\.?\s+)?[A-Z][a-z]+\s+[A-Z][a-z]+\b")  # Name
            ],
            PrivacyLevel.ENHANCED: [
                re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),  # Email
                re.compile(r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")  # Phone
            ],
            PrivacyLevel.MAXIMUM: [
                re.compile(r"\b\d{5}(-\d{4})?\b"),  # ZIP
                re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b")  # DOB
            ]
        }
        
        # Observer pattern support
        self._observers: dict[EventType | str, set[Observer]] = {}
        
        # Logger
        self._logger = logging.getLogger(__name__)
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the mock XGBoost service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        try:
            # Configure logging
            log_level = config.get("log_level", "INFO")
            numeric_level = getattr(logging, log_level.upper(), None)
            if not isinstance(numeric_level, int):
                raise ConfigurationError(
                    f"Invalid log level: {log_level}",
                    field="log_level",
                    value=log_level
                )
            
            self._logger.setLevel(numeric_level)
            
            # Set mock delay
            self._mock_delay_ms = config.get("mock_delay_ms", 200)
            
            # Set risk level distribution
            if "risk_level_distribution" in config:
                self._risk_level_distribution = config["risk_level_distribution"]
                
                # Validate distribution
                required_levels = {"very_low", "low", "moderate", "high", "very_high"}
                if not all(level in self._risk_level_distribution for level in required_levels):
                    raise ConfigurationError(
                        "Risk level distribution must include all risk levels",
                        field="risk_level_distribution",
                        value=self._risk_level_distribution
                    )
                
                # Ensure values sum to approximately 100
                total = sum(self._risk_level_distribution.values())
                if not (99 <= total <= 101):  # Allow some rounding error
                    raise ConfigurationError(
                        f"Risk level distribution must sum to 100, got {total}",
                        field="risk_level_distribution",
                        value=self._risk_level_distribution
                    )
            
            # Set privacy level
            privacy_level = config.get("privacy_level", PrivacyLevel.STANDARD)
            if not isinstance(privacy_level, PrivacyLevel):
                raise ConfigurationError(
                    f"Invalid privacy level: {privacy_level}",
                    field="privacy_level",
                    value=privacy_level
                )
            self._privacy_level = privacy_level
            
            # Mark as initialized
            self._initialized = True
            
            # Notify observers
            self._notify_observers(EventType.INITIALIZATION, {"status": "initialized"})
            
            self._logger.info("Mock XGBoost service initialized successfully")
        except Exception as e:
            self._logger.error(f"Failed to initialize mock XGBoost service: {e}")
            if isinstance(e, ConfigurationError):
                raise
            else:
                raise ConfigurationError(
                    f"Failed to initialize mock XGBoost service: {e!s}",
                    details=str(e)
                )
    
    def register_observer(self, event_type: EventType | str, observer: Observer) -> None:
        """
        Register an observer for a specific event type.
        
        Args:
            event_type: Type of event to observe, or "*" for all events
            observer: Observer to register
        """
        event_key = event_type
        if event_key not in self._observers:
            self._observers[event_key] = set()
        self._observers[event_key].add(observer)
        self._logger.debug(f"Observer registered for event type {event_type}")
    
    def unregister_observer(self, event_type: EventType | str, observer: Observer) -> None:
        """
        Unregister an observer for a specific event type.
        
        Args:
            event_type: Type of event to stop observing
            observer: Observer to unregister
        """
        event_key = event_type
        if event_key in self._observers:
            self._observers[event_key].discard(observer)
            if not self._observers[event_key]:
                del self._observers[event_key]
            self._logger.debug(f"Observer unregistered for event type {event_type}")
    
    async def predict(self, patient_id: str, features: dict[str, Any], model_type: str, **kwargs) -> dict[str, Any]:
        """
        Generic prediction method required by MLServiceInterface.
        
        Args:
            patient_id: ID of the patient
            features: Dictionary of features for prediction
            model_type: Type of model to use for prediction
            **kwargs: Additional arguments for prediction
            
        Returns:
            Dictionary with prediction results
        """
        # Choose the appropriate specialized prediction method based on model_type
        if model_type.lower() == "risk":
            risk_type = kwargs.get("risk_type", "general")
            clinical_data = features
            time_frame_days = kwargs.get("time_frame_days", 30)
            
            return await self.predict_risk(
                patient_id=patient_id,
                risk_type=risk_type,
                clinical_data=clinical_data,
                time_frame_days=time_frame_days
            )
            
        elif model_type.lower() == "treatment_response":
            treatment_type = kwargs.get("treatment_type", "medication")
            treatment_details = kwargs.get("treatment_details", {})
            clinical_data = features
            
            return await self.predict_treatment_response(
                patient_id=patient_id,
                treatment_type=treatment_type,
                treatment_details=treatment_details,
                clinical_data=clinical_data
            )
            
        elif model_type.lower() == "outcome":
            outcome_timeframe = kwargs.get("outcome_timeframe", {"timeframe": "short_term"})
            clinical_data = features
            treatment_plan = kwargs.get("treatment_plan", {})
            social_determinants = kwargs.get("social_determinants")
            comorbidities = kwargs.get("comorbidities")
            
            return await self.predict_outcome(
                patient_id=patient_id,
                outcome_timeframe=outcome_timeframe,
                clinical_data=clinical_data,
                treatment_plan=treatment_plan,
                social_determinants=social_determinants,
                comorbidities=comorbidities
            )
            
        else:
            # Generic fallback prediction
            self._simulate_processing_delay()
            prediction_id = str(uuid.uuid4())
            
            result = {
                "prediction_id": prediction_id,
                "patient_id": patient_id,
                "model_type": model_type,
                "timestamp": datetime.now().isoformat(),
                "result": {
                    "score": round(random.uniform(0.1, 0.9), 2),
                    "confidence": round(random.uniform(0.6, 0.9), 2),
                    "explanation": f"Generic mock prediction for model type: {model_type}"
                },
                "model_info": {
                    "name": f"mock_{model_type.lower()}_model",
                    "version": "1.0.0",
                    "last_updated": datetime.now().isoformat()
                }
            }
            
            # Store the prediction
            self._predictions[prediction_id] = result
            
            return result
    
    async def predict_risk(
        self,
        patient_id: str,
        risk_type: str,
        clinical_data: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
        """
        Predict risk level using a risk model.
        
        Args:
            patient_id: Patient identifier
            risk_type: Type of risk to predict
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Risk prediction result
            
        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        self._ensure_initialized()
        
        # Simulate network latency
        self._simulate_delay()
        
        # Validate parameters
        self._validate_risk_type(risk_type)
        
        # Check for PHI in data
        self._check_phi_in_data(clinical_data)
        
        # Generate prediction ID
        prediction_id = f"risk-{uuid.uuid4()}"
        
        # Generate a deterministic risk score based on inputs
        # This ensures consistent results for the same inputs
        risk_score = self._generate_deterministic_risk_score(
            patient_id, risk_type, clinical_data, **kwargs
        )
        
        # Map score to risk level
        risk_level = self._map_score_to_risk_level(risk_score)
        
        # Create prediction result
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "risk_type": risk_type,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": round(0.5 + risk_score * 0.4, 2),  # Higher score, higher confidence
            "features": self._extract_features(clinical_data),
            "timestamp": datetime.now().isoformat(),
            "time_frame_days": kwargs.get("time_frame_days", 30)
        }
        
        # Add supporting evidence based on risk level
        result["supporting_evidence"] = self._generate_supporting_evidence(
            risk_type, risk_level, clinical_data
        )
        
        # Add risk factors
        result["risk_factors"] = self._generate_risk_factors(
            risk_type, clinical_data
        )
        
        # Store prediction for later retrieval
        self._predictions[prediction_id] = result
        
        # Notify observers
        self._notify_observers(EventType.PREDICTION, {
            "prediction_type": "risk",
            "risk_type": risk_type,
            "patient_id": patient_id,
            "prediction_id": prediction_id
        })
        
        return result
    
    async def predict_treatment_response(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
        """
        Predict response to a psychiatric treatment.
        
        Args:
            patient_id: Patient identifier
            treatment_type: Type of treatment (e.g., medication_ssri)
            treatment_details: Treatment details
            clinical_data: Clinical data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Treatment response prediction result
            
        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        self._ensure_initialized()
        
        # Simulate network latency
        self._simulate_delay()
        
        # Validate parameters
        self._validate_treatment_type(treatment_type, treatment_details)
        
        # Check for PHI in data
        self._check_phi_in_data(clinical_data)
        self._check_phi_in_data(treatment_details)
        
        # Generate prediction ID
        prediction_id = f"treatment-{uuid.uuid4()}"
        
        # Generate a deterministic efficacy score based on inputs
        efficacy_score = self._generate_deterministic_efficacy_score(
            patient_id, treatment_type, treatment_details, clinical_data, **kwargs
        )
        
        # Map score to response likelihood
        response_likelihood = self._map_score_to_response_level(efficacy_score)
        
        # Create prediction result
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "treatment_type": treatment_type,
            "treatment_details": treatment_details,
            "response_likelihood": response_likelihood,
            "efficacy_score": efficacy_score,
            "confidence": round(0.5 + efficacy_score * 0.4, 2),
            "features": self._extract_features(clinical_data),
            "treatment_features": self._extract_features(treatment_details),
            "timestamp": datetime.now().isoformat(),
            "prediction_horizon": kwargs.get("prediction_horizon", "8_weeks")
        }
        
        # Add expected outcome
        result["expected_outcome"] = self._generate_expected_outcome(
            treatment_type, efficacy_score, clinical_data
        )
        
        # Add side effect risk
        result["side_effect_risk"] = self._generate_side_effect_risk(
            treatment_type, treatment_details, clinical_data
        )
        
        # Store prediction for later retrieval
        self._predictions[prediction_id] = result
        
        # Notify observers
        self._notify_observers(EventType.PREDICTION, {
            "prediction_type": "treatment_response",
            "treatment_type": treatment_type,
            "patient_id": patient_id,
            "prediction_id": prediction_id
        })
        
        return result
    
    async def predict_outcome(
        self,
        patient_id: str,
        outcome_timeframe: dict[str, int],
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
        """
        Predict clinical outcomes based on treatment plan.
        
        Args:
            patient_id: Patient identifier
            outcome_timeframe: Timeframe for outcome prediction
            clinical_data: Clinical data for prediction
            treatment_plan: Treatment plan details
            **kwargs: Additional prediction parameters
            
        Returns:
            Outcome prediction result
            
        Raises:
            ValidationError: If parameters are invalid
            DataPrivacyError: If PHI is detected in data
            PredictionError: If prediction fails
        """
        self._ensure_initialized()
        
        # Simulate network latency
        self._simulate_delay()
        
        # Validate parameters
        self._validate_outcome_params(outcome_timeframe)
        
        # Check for PHI in data
        self._check_phi_in_data(clinical_data)
        self._check_phi_in_data(treatment_plan)
        
        # Generate prediction ID
        prediction_id = f"outcome-{uuid.uuid4()}"
        
        # Convert timeframe to days for consistent representation
        time_frame_days = 0
        if "days" in outcome_timeframe:
            time_frame_days += outcome_timeframe["days"]
        if "weeks" in outcome_timeframe:
            time_frame_days += outcome_timeframe["weeks"] * 7
        if "months" in outcome_timeframe:
            time_frame_days += outcome_timeframe["months"] * 30
        
        # Determine outcome type from kwargs or default to symptom
        outcome_type = kwargs.get("outcome_type", "symptom")
        
        # Generate a deterministic outcome score based on inputs
        outcome_score = self._generate_deterministic_outcome_score(
            patient_id, time_frame_days, clinical_data, treatment_plan, outcome_type
        )
        
        # Create prediction result
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "outcome_type": outcome_type,
            "outcome_score": outcome_score,
            "time_frame_days": time_frame_days,
            "confidence": round(0.5 + outcome_score * 0.3, 2),
            "features": self._extract_features(clinical_data),
            "treatment_features": self._extract_features(treatment_plan),
            "timestamp": datetime.now().isoformat()
        }
        
        # Add trajectory prediction
        result["trajectory"] = self._generate_outcome_trajectory(
            outcome_type, outcome_score, time_frame_days
        )
        
        # Add outcome details
        result["outcome_details"] = self._generate_outcome_details(
            outcome_type, outcome_score, clinical_data, treatment_plan
        )
        
        # Store prediction for later retrieval
        self._predictions[prediction_id] = result
        
        # Notify observers
        self._notify_observers(EventType.PREDICTION, {
            "prediction_type": "outcome",
            "outcome_type": outcome_type,
            "patient_id": patient_id,
            "prediction_id": prediction_id
        })
        
        return result
    
    def get_feature_importance(
        self,
        patient_id: str,
        model_type: str,
        prediction_id: str
    ) -> dict[str, Any]:
        """
        Get feature importance for a prediction.
        
        Args:
            patient_id: Patient identifier
            model_type: Type of model
            prediction_id: Prediction identifier
            
        Returns:
            Feature importance data
            
        Raises:
            ResourceNotFoundError: If prediction not found
            ValidationError: If parameters are invalid
        """
        self._ensure_initialized()
        
        # Simulate network latency
        self._simulate_delay()
        
        # Check if prediction exists
        if prediction_id not in self._predictions:
            raise ResourceNotFoundError(
                f"Prediction not found: {prediction_id}",
                resource_type="prediction",
                resource_id=prediction_id
            )
        
        # Get prediction data
        prediction = self._predictions[prediction_id]
        
        # Verify patient ID
        if prediction.get("patient_id") != patient_id:
            raise ValidationError(
                "Patient ID mismatch",
                field="patient_id",
                value=patient_id
            )
        
        # Generate feature importance
        features = prediction.get("features", {})
        if "treatment_features" in prediction:
            features.update(prediction["treatment_features"])
        
        # Generate feature importance based on feature values
        feature_importance = {}
        
        # Sort features by name for consistent results
        sorted_features = sorted(features.items(), key=lambda x: x[0])
        
        # Generate mock feature importance
        for i, (feature, value) in enumerate(sorted_features):
            # Generate a deterministic importance value based on the feature name and value
            if isinstance(value, (int, float)):
                # Normalize value to be between 0 and 1
                normalized_value = min(max(value / 10.0, 0), 1)
                importance = normalized_value * 0.8 + 0.2
            elif isinstance(value, bool):
                importance = 0.7 if value else 0.3
            else:
                # Generate a hash based on the feature name for deterministic results
                hash_value = int(hashlib.md5(feature.encode()).hexdigest(), 16) % 100
                importance = hash_value / 100.0
            
            # Occasionally make some features negative to show that they reduce risk
            if i % 3 == 0:
                importance = -importance
            
            feature_importance[feature] = round(importance, 3)
        
        # Create visualization data
        visualization = {
            "type": "bar_chart",
            "data": {
                "labels": list(feature_importance.keys()),
                "values": list(feature_importance.values())
            }
        }
        
        # Create result
        result = {
            "prediction_id": prediction_id,
            "patient_id": patient_id,
            "model_type": model_type,
            "feature_importance": feature_importance,
            "visualization": visualization,
            "timestamp": datetime.now().isoformat()
        }
        
        return result
    
    def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        prediction_id: str
    ) -> dict[str, Any]:
        """
        Integrate prediction with digital twin profile.
        
        Args:
            patient_id: Patient identifier
            profile_id: Digital twin profile identifier
            prediction_id: Prediction identifier
            
        Returns:
            Integration result
            
        Raises:
            ResourceNotFoundError: If prediction not found
            ValidationError: If parameters are invalid
        """
        self._ensure_initialized()
        
        # Simulate network latency
        self._simulate_delay()
        
        # Check if prediction exists
        if prediction_id not in self._predictions:
            raise ResourceNotFoundError(
                f"Prediction not found: {prediction_id}",
                resource_type="prediction",
                resource_id=prediction_id
            )
        
        # Get prediction data
        prediction = self._predictions[prediction_id]
        
        # Verify patient ID
        if prediction.get("patient_id") != patient_id:
            raise ValidationError(
                "Patient ID mismatch",
                field="patient_id",
                value=patient_id
            )
        
        # Create or retrieve digital twin profile
        profile = self._profiles.get(profile_id, {
            "profile_id": profile_id,
            "patient_id": patient_id,
            "created_at": datetime.now().isoformat(),
            "predictions": [],
            "version": 1
        })
        
        # Add prediction to profile
        profile["predictions"].append({
            "prediction_id": prediction_id,
            "prediction_type": self._determine_prediction_type(prediction),
            "integrated_at": datetime.now().isoformat()
        })
        
        # Increment version
        profile["version"] += 1
        
        # Update last_updated
        profile["last_updated"] = datetime.now().isoformat()
        
        # Store updated profile
        self._profiles[profile_id] = profile
        
        # Create integration result
        result = {
            "profile_id": profile_id,
            "patient_id": patient_id,
            "prediction_id": prediction_id,
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "recommendations_generated": True,
            "statistics_updated": True
        }
        
        # Notify observers
        self._notify_observers(EventType.INTEGRATION, {
            "integration_type": "digital_twin",
            "patient_id": patient_id,
            "profile_id": profile_id,
            "prediction_id": prediction_id,
            "status": "success"
        })
        
        return result
    
    def get_model_info(self, model_type: str) -> dict[str, Any]:
        """
        Get information about a model.
        
        Args:
            model_type: Type of model
            
        Returns:
            Model information
            
        Raises:
            ModelNotFoundError: If model not found
        """
        self._ensure_initialized()
        
        # Simulate network latency
        self._simulate_delay()
        
        # Check if model type is valid
        valid_model_types = [model.value for model in ModelType]
        normalized_type = model_type.lower().replace("_", "-")
        
        if normalized_type not in valid_model_types:
            raise ModelNotFoundError(
                f"Model not found: {model_type}",
                model_type=model_type
            )
        
        # Generate features based on model type
        features = []
        
        if "risk" in normalized_type:
            features = [
                "symptom_severity",
                "medication_adherence",
                "previous_episodes",
                "social_support",
                "stress_level",
                "sleep_quality",
                "substance_use"
            ]
        elif "medication" in normalized_type:
            features = [
                "previous_medication_response",
                "age",
                "weight_kg",
                "symptom_severity",
                "medication_adherence",
                "comorbid_conditions",
                "genetic_markers"
            ]
        elif "therapy" in normalized_type:
            features = [
                "previous_therapy_response",
                "motivation",
                "insight",
                "social_support",
                "symptom_severity",
                "functional_impairment"
            ]
        elif "outcome" in normalized_type:
            features = [
                "baseline_severity",
                "treatment_adherence",
                "social_support",
                "functional_status",
                "comorbidity_burden"
            ]
        
        # Generate performance metrics
        performance_metrics = {
            "accuracy": round(0.75 + random.random() * 0.15, 2),
            "precision": round(0.70 + random.random() * 0.20, 2),
            "recall": round(0.70 + random.random() * 0.20, 2),
            "f1_score": round(0.70 + random.random() * 0.20, 2),
            "auc_roc": round(0.80 + random.random() * 0.15, 2),
        }
        
        # Create result
        result = {
            "model_type": model_type,
            "version": "1.0.0",
            "last_updated": (datetime.now() - timedelta(days=30)).isoformat(),
            "description": f"XGBoost model for {model_type}",
            "features": features,
            "performance_metrics": performance_metrics,
            "hyperparameters": {
                "n_estimators": 100,
                "max_depth": 5,
                "learning_rate": 0.1,
                "subsample": 0.8,
                "colsample_bytree": 0.8
            },
            "status": "active"
        }
        
        return result
    
    def _simulate_delay(self) -> None:
        """Simulate network latency."""
        if self._mock_delay_ms > 0:
            time.sleep(self._mock_delay_ms / 1000)
    
    def _notify_observers(self, event_type: EventType, data: dict[str, Any]) -> None:
        """
        Notify observers of an event.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        # Add timestamp to event data
        data["timestamp"] = datetime.now().isoformat()
        
        # Notify observers registered for this event type
        event_key = event_type
        if event_key in self._observers:
            for observer in self._observers[event_key]:
                try:
                    observer.update(event_type, data)
                except Exception as e:
                    self._logger.error(f"Error notifying observer: {e}")
        
        # Notify observers registered for all events
        if "*" in self._observers:
            for observer in self._observers["*"]:
                try:
                    observer.update(event_type, data)
                except Exception as e:
                    self._logger.error(f"Error notifying wildcard observer: {e}")
    
    def _check_phi_in_data(self, data: dict[str, Any]) -> None:
        """
        Check for PHI in data.
        
        Args:
            data: Data to check
            
        Raises:
            DataPrivacyError: If PHI is detected
        """
        if not data:
            return
        
        # Get patterns for current privacy level
        patterns = []
        for level in PrivacyLevel:
            if level.value <= self._privacy_level.value and level in self._phi_patterns:
                patterns.extend(self._phi_patterns[level])
        
        # Check each key and value in the data
        phi_found = []
        
        for key, value in data.items():
            # Check values for PHI
            if isinstance(value, str):
                for pattern in patterns:
                    if pattern.search(value):
                        phi_found.append(pattern.pattern)
            
            # Recursively check nested dictionaries
            elif isinstance(value, dict):
                try:
                    self._check_phi_in_data(value)
                except DataPrivacyError as e:
                    phi_found.extend(e.pattern_types)
        
        # If PHI found, raise exception
        if phi_found:
            unique_phi_types = list(set(phi_found))
            raise DataPrivacyError(
                f"PHI detected in input data: {', '.join(unique_phi_types)}",
                pattern_types=unique_phi_types
            )
    
    def _generate_deterministic_risk_score(
        self,
        patient_id: str,
        risk_type: str,
        clinical_data: dict[str, Any],
        **kwargs
    ) -> float:
        """
        Generate a deterministic risk score based on inputs.
        
        Args:
            patient_id: Patient identifier
            risk_type: Type of risk
            clinical_data: Clinical data
            **kwargs: Additional parameters
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        # Create a seed for deterministic randomness
        seed = int(hashlib.md5(f"{patient_id}:{risk_type}".encode()).hexdigest(), 16)
        random.seed(seed)
        
        # Base score is random but deterministic for the same patient and risk type
        base_score = random.random() * 0.4 + 0.3  # Between 0.3 and 0.7
        
        # Adjust based on clinical data
        modifiers = 0.0
        
        # Common risk factors
        if clinical_data.get("previous_episodes", 0) > 0:
            modifiers += 0.1 * min(clinical_data["previous_episodes"], 3) / 3
            
        if "medication_adherence" in clinical_data:
            adherence = clinical_data["medication_adherence"]
            if isinstance(adherence, (int, float)) and adherence <= 0.7:
                modifiers += 0.15 * (1 - adherence)
        
        if "symptom_severity" in clinical_data:
            severity = clinical_data["symptom_severity"]
            if isinstance(severity, (int, float)):
                modifiers += 0.2 * min(severity, 10) / 10
        
        if "stress_level" in clinical_data:
            stress = clinical_data["stress_level"]
            if isinstance(stress, (int, float)):
                modifiers += 0.1 * min(stress, 10) / 10
        
        if "social_support" in clinical_data:
            support = clinical_data["social_support"]
            if isinstance(support, (int, float)):
                modifiers -= 0.1 * min(support, 10) / 10  # Negative modifier (reduces risk)
        
        # Risk type specific factors
        if risk_type == "suicide":
            if clinical_data.get("suicidal_ideation", False):
                modifiers += 0.25
            if clinical_data.get("suicide_attempt_history", False):
                modifiers += 0.35
        
        elif risk_type == "relapse":
            if clinical_data.get("medication_discontinued", False):
                modifiers += 0.3
            if clinical_data.get("therapy_discontinued", False):
                modifiers += 0.2
        
        elif risk_type == "hospitalization":
            if clinical_data.get("recent_emergency_visit", False):
                modifiers += 0.25
            if clinical_data.get("unstable_housing", False):
                modifiers += 0.15
        
        # Clamp the final score between 0.0 and 1.0
        return max(0.0, min(1.0, base_score + modifiers))
    
    def _generate_deterministic_efficacy_score(
        self,
        patient_id: str,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any],
        **kwargs
    ) -> float:
        """
        Generate a deterministic efficacy score based on inputs.
        
        Args:
            patient_id: Patient identifier
            treatment_type: Type of treatment
            treatment_details: Treatment details
            clinical_data: Clinical data
            **kwargs: Additional parameters
            
        Returns:
            Efficacy score between 0.0 and 1.0
        """
        # Create a seed for deterministic randomness
        seed = int(hashlib.md5(f"{patient_id}:{treatment_type}".encode()).hexdigest(), 16)
        random.seed(seed)
        
        # Base score is random but deterministic for the same patient and treatment type
        base_score = random.random() * 0.4 + 0.4  # Between 0.4 and 0.8
        
        # Adjust based on clinical data and treatment details
        modifiers = 0.0
        
        # Treatment type specific factors
        if "medication" in treatment_type:
            # Previous response to medication
            previous_response = clinical_data.get("previous_medication_response", {})
            if treatment_details.get("medication") in previous_response:
                response_value = previous_response[treatment_details["medication"]]
                if isinstance(response_value, (int, float)):
                    modifiers += 0.2 * min(response_value, 10) / 10
            
            # Appropriateness of dose
            if "dose_mg" in treatment_details and "weight_kg" in clinical_data:
                dose = treatment_details["dose_mg"]
                weight = clinical_data["weight_kg"]
                if isinstance(dose, (int, float)) and isinstance(weight, (int, float)):
                    # Very simplified dose appropriateness check
                    dose_per_kg = dose / weight
                    if dose_per_kg < 0.01 or dose_per_kg > 0.5:
                        modifiers -= 0.15  # Dose might be too low or too high
            
            # Medication adherence history
            adherence = clinical_data.get("medication_adherence", 0.5)
            if isinstance(adherence, (int, float)):
                modifiers += 0.1 * min(adherence, 1.0)
        
        elif "therapy" in treatment_type:
            # Previous response to therapy
            previous_response = clinical_data.get("previous_therapy_response", {})
            therapy_type = treatment_type.split("_")[1] if "_" in treatment_type else "unknown"
            if therapy_type in previous_response:
                response_value = previous_response[therapy_type]
                if isinstance(response_value, (int, float)):
                    modifiers += 0.2 * min(response_value, 10) / 10
            
            # Session frequency
            frequency = treatment_details.get("frequency", "weekly")
            if frequency == "twice_weekly":
                modifiers += 0.1
            elif frequency == "monthly":
                modifiers -= 0.1
            
            # Patient motivation
            motivation = clinical_data.get("motivation_for_therapy", 5)
            if isinstance(motivation, (int, float)):
                modifiers += 0.15 * min(motivation, 10) / 10
        
        # Common factors
        symptom_duration = clinical_data.get("symptom_duration_months", 6)
        if isinstance(symptom_duration, (int, float)):
            # Longer duration may predict poorer response
            modifiers -= 0.05 * min(symptom_duration, 24) / 24
        
        if clinical_data.get("treatment_resistant", False):
            modifiers -= 0.2
        
        # Clamp the final score between 0.0 and 1.0
        return max(0.0, min(1.0, base_score + modifiers))
    
    def _generate_deterministic_outcome_score(
        self,
        patient_id: str,
        time_frame_days: int,
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any],
        outcome_type: str
    ) -> float:
        """
        Generate a deterministic outcome score based on inputs.
        
        Args:
            patient_id: Patient identifier
            time_frame_days: Time frame in days
            clinical_data: Clinical data
            treatment_plan: Treatment plan
            outcome_type: Type of outcome
            
        Returns:
            Outcome score between 0.0 and 1.0
        """
        # Create a seed for deterministic randomness
        seed = int(hashlib.md5(f"{patient_id}:{outcome_type}:{time_frame_days}".encode()).hexdigest(), 16)
        random.seed(seed)
        
        # Base score is random but deterministic
        base_score = random.random() * 0.4 + 0.4  # Between 0.4 and 0.8
        
        # Adjust based on clinical data and treatment plan
        modifiers = 0.0
        
        # Treatment intensity factor
        treatments = treatment_plan.get("treatments", [])
        treatment_count = len(treatments)
        modifiers += 0.05 * min(treatment_count, 3)  # More treatments might be better up to a point
        
        # Baseline severity
        severity = clinical_data.get("symptom_severity", 5)
        if isinstance(severity, (int, float)):
            # Higher severity might predict greater improvement (more room to improve)
            # but also might be harder to treat
            modifiers += 0.05 * (min(severity, 10) / 10) * 2 - 0.1
        
        # Treatment adherence
        adherence = clinical_data.get("treatment_adherence", 0.7)
        if isinstance(adherence, (int, float)):
            modifiers += 0.15 * min(adherence, 1.0)
        
        # Time frame effect
        # Short term (under 30 days) - moderate effect
        # Medium term (30-90 days) - higher effect
        # Long term (over 90 days) - variable effect
        if time_frame_days < 30:
            modifiers += 0.05
        elif 30 <= time_frame_days <= 90:
            modifiers += 0.15
        else:
            # For long term, more variable
            time_factor = random.random() * 0.2 - 0.1  # Between -0.1 and 0.1
            modifiers += time_factor
        
        # Outcome type specific factors
        if outcome_type == "symptom":
            # Treatment appropriateness for symptoms
            symptom_treatment_match = 0.7  # Default moderate match
            modifiers += 0.1 * symptom_treatment_match
            
        elif outcome_type == "functional":
            # Functional outcomes might take longer
            if time_frame_days < 60:
                modifiers -= 0.1
                
            # Psychosocial interventions
            if any("therapy" in t.get("type", "") for t in treatments):
                modifiers += 0.15
                
        elif outcome_type == "quality_of_life":
            # Quality of life outcomes often depend on multiple factors
            if treatment_count >= 2:
                modifiers += 0.1
                
            # Social support is important for quality of life
            social_support = clinical_data.get("social_support", 5)
            if isinstance(social_support, (int, float)):
                modifiers += 0.1 * min(social_support, 10) / 10
        
        # Clamp the final score between 0.0 and 1.0
        return max(0.0, min(1.0, base_score + modifiers))
    
    def _map_score_to_risk_level(self, score: float) -> str:
        """
        Map a risk score to a risk level.
        
        Args:
            score: Risk score between 0.0 and 1.0
            
        Returns:
            Risk level as a string
        """
        if score < 0.2:
            return "very_low"
        elif score < 0.4:
            return "low"
        elif score < 0.6:
            return "moderate"
        elif score < 0.8:
            return "high"
        else:
            return "very_high"
    
    def _map_score_to_response_level(self, score: float) -> str:
        """
        Map an efficacy score to a response likelihood level.
        
        Args:
            score: Efficacy score between 0.0 and 1.0
            
        Returns:
            Response likelihood as a string
        """
        if score < 0.2:
            return "poor"
        elif score < 0.4:
            return "limited"
        elif score < 0.6:
            return "moderate"
        elif score < 0.8:
            return "good"
        else:
            return "excellent"
    
    def _extract_features(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Extract features from data.
        
        Args:
            data: Input data
            
        Returns:
            Dictionary of features
        """
        # Skip extraction if data is empty
        if not data:
            return {}
        
        # Skip nested dictionaries and lists, just use top-level fields
        features = {}
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                features[key] = value
        
        return features
    
    def _generate_supporting_evidence(
        self,
        risk_type: str,
        risk_level: str,
        clinical_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Generate supporting evidence for a risk prediction.
        
        Args:
            risk_type: Type of risk
            risk_level: Risk level
            clinical_data: Clinical data
            
        Returns:
            List of supporting evidence items
        """
        evidence = []
        
        # Add evidence based on risk type and clinical data
        if risk_type == "suicide":
            if clinical_data.get("suicidal_ideation", False):
                evidence.append({
                    "factor": "suicidal_ideation",
                    "impact": "high",
                    "description": "Patient reports active suicidal ideation"
                })
            
            if clinical_data.get("suicide_attempt_history", False):
                evidence.append({
                    "factor": "suicide_attempt_history",
                    "impact": "high",
                    "description": "Patient has prior suicide attempts"
                })
            
            if clinical_data.get("hopelessness", 0) > 7:
                evidence.append({
                    "factor": "hopelessness",
                    "impact": "moderate",
                    "description": "Patient reports significant hopelessness"
                })
        
        elif risk_type == "relapse":
            if clinical_data.get("medication_discontinued", False):
                evidence.append({
                    "factor": "medication_discontinued",
                    "impact": "high",
                    "description": "Recent discontinuation of medication"
                })
            
            if clinical_data.get("sleep_quality", 10) < 4:
                evidence.append({
                    "factor": "sleep_disturbance",
                    "impact": "moderate",
                    "description": "Poor sleep quality reported"
                })
            
            if clinical_data.get("stress_level", 0) > 7:
                evidence.append({
                    "factor": "elevated_stress",
                    "impact": "moderate",
                    "description": "Elevated stress levels reported"
                })
        
        elif risk_type == "hospitalization":
            if clinical_data.get("medication_adherence", 1.0) < 0.6:
                evidence.append({
                    "factor": "poor_medication_adherence",
                    "impact": "high",
                    "description": "Poor adherence to prescribed medication"
                })
            
            if clinical_data.get("recent_emergency_visit", False):
                evidence.append({
                    "factor": "recent_emergency_visit",
                    "impact": "high",
                    "description": "Recent emergency department visit"
                })
            
            if clinical_data.get("symptom_severity", 0) > 7:
                evidence.append({
                    "factor": "severe_symptoms",
                    "impact": "moderate",
                    "description": "Severe psychiatric symptoms"
                })
        
        # Add general evidence
        if "previous_episodes" in clinical_data and clinical_data["previous_episodes"] > 0:
            evidence.append({
                "factor": "previous_episodes",
                "impact": "moderate",
                "description": f"{clinical_data['previous_episodes']} previous episodes"
            })
        
        if "social_support" in clinical_data and clinical_data["social_support"] < 5:
            evidence.append({
                "factor": "low_social_support",
                "impact": "moderate",
                "description": "Limited social support network"
            })
        
        return evidence
    
    def _generate_risk_factors(
        self,
        risk_type: str,
        clinical_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate risk factors for a risk prediction.
        
        Args:
            risk_type: Type of risk
            clinical_data: Clinical data
            
        Returns:
            Dictionary of risk factors
        """
        risk_factors = {
            "contributing_factors": [],
            "protective_factors": []
        }
        
        # Add contributing factors based on clinical data
        if clinical_data.get("previous_episodes", 0) > 0:
            risk_factors["contributing_factors"].append({
                "name": "Previous episodes",
                "weight": "moderate"
            })
        
        if clinical_data.get("medication_adherence", 1.0) < 0.7:
            risk_factors["contributing_factors"].append({
                "name": "Poor medication adherence",
                "weight": "high"
            })
        
        if clinical_data.get("substance_use", False):
            risk_factors["contributing_factors"].append({
                "name": "Substance use",
                "weight": "high"
            })
        
        if clinical_data.get("stress_level", 0) > 7:
            risk_factors["contributing_factors"].append({
                "name": "High stress levels",
                "weight": "moderate"
            })
        
        # Risk type specific contributing factors
        if risk_type == "suicide":
            if clinical_data.get("suicidal_ideation", False):
                risk_factors["contributing_factors"].append({
                    "name": "Active suicidal ideation",
                    "weight": "high"
                })
            
            if clinical_data.get("suicide_attempt_history", False):
                risk_factors["contributing_factors"].append({
                    "name": "Previous suicide attempts",
                    "weight": "high"
                })
            
            if clinical_data.get("access_to_lethal_means", False):
                risk_factors["contributing_factors"].append({
                    "name": "Access to lethal means",
                    "weight": "high"
                })
        
        # Add protective factors
        if clinical_data.get("social_support", 0) > 7:
            risk_factors["protective_factors"].append({
                "name": "Strong social support",
                "weight": "high"
            })
        
        if clinical_data.get("engaged_in_treatment", False):
            risk_factors["protective_factors"].append({
                "name": "Engaged in treatment",
                "weight": "high"
            })
        
        if clinical_data.get("coping_skills", 0) > 7:
            risk_factors["protective_factors"].append({
                "name": "Strong coping skills",
                "weight": "moderate"
            })
        
        return risk_factors
    
    def _generate_expected_outcome(
        self,
        treatment_type: str,
        efficacy_score: float,
        clinical_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate expected outcome for a treatment response prediction.
        
        Args:
            treatment_type: Type of treatment
            efficacy_score: Efficacy score
            clinical_data: Clinical data
            
        Returns:
            Dictionary of expected outcome
        """
        # Base improvement percentage based on efficacy score
        base_improvement = int(efficacy_score * 100)
        
        # Adjust for severity
        severity = clinical_data.get("symptom_severity", 5)
        if isinstance(severity, (int, float)):
            severity_factor = 1.0
            if severity > 7:
                # Higher severity might show more dramatic improvement
                severity_factor = 1.2
            elif severity < 4:
                # Lower severity might show less dramatic improvement
                severity_factor = 0.8
            
            adjusted_improvement = int(base_improvement * severity_factor)
        else:
            adjusted_improvement = base_improvement
        
        # Expected time to response
        time_to_response = "unknown"
        if "medication" in treatment_type:
            if efficacy_score > 0.7:
                time_to_response = "2-4 weeks"
            elif efficacy_score > 0.4:
                time_to_response = "4-6 weeks"
            else:
                time_to_response = "6-8 weeks"
        elif "therapy" in treatment_type:
            if efficacy_score > 0.7:
                time_to_response = "4-6 weeks"
            elif efficacy_score > 0.4:
                time_to_response = "8-12 weeks"
            else:
                time_to_response = "12-16 weeks"
        
        # Create outcome
        outcome = {
            "symptom_improvement": f"{adjusted_improvement}%",
            "time_to_response": time_to_response,
            "sustained_response_likelihood": self._map_score_to_response_level(efficacy_score),
            "functional_improvement": "moderate"
        }
        
        return outcome
    
    def _generate_side_effect_risk(
        self,
        treatment_type: str,
        treatment_details: dict[str, Any],
        clinical_data: dict[str, Any]
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Generate side effect risk for a treatment response prediction.
        
        Args:
            treatment_type: Type of treatment
            treatment_details: Treatment details
            clinical_data: Clinical data
            
        Returns:
            Dictionary of side effect risks
        """
        side_effects = {"common": [], "rare": []}
        
        if "medication" in treatment_type:
            if "ssri" in treatment_type:
                side_effects["common"] = [
                    {"effect": "Nausea", "likelihood": "30%", "severity": "mild"},
                    {"effect": "Headache", "likelihood": "25%", "severity": "mild"},
                    {"effect": "Insomnia", "likelihood": "20%", "severity": "moderate"},
                    {"effect": "Sexual dysfunction", "likelihood": "35%", "severity": "moderate"}
                ]
                side_effects["rare"] = [
                    {"effect": "Serotonin syndrome", "likelihood": "<1%", "severity": "severe"},
                    {"effect": "Hyponatremia", "likelihood": "2%", "severity": "moderate"}
                ]
            elif "snri" in treatment_type:
                side_effects["common"] = [
                    {"effect": "Nausea", "likelihood": "35%", "severity": "mild"},
                    {"effect": "Dry mouth", "likelihood": "30%", "severity": "mild"},
                    {"effect": "Excessive sweating", "likelihood": "20%", "severity": "mild"},
                    {"effect": "Increased blood pressure", "likelihood": "15%", "severity": "moderate"}
                ]
                side_effects["rare"] = [
                    {"effect": "Liver problems", "likelihood": "<1%", "severity": "severe"},
                    {"effect": "Seizures", "likelihood": "<1%", "severity": "severe"}
                ]
            elif "atypical" in treatment_type:
                side_effects["common"] = [
                    {"effect": "Weight gain", "likelihood": "40%", "severity": "moderate"},
                    {"effect": "Sedation", "likelihood": "35%", "severity": "moderate"},
                    {"effect": "Metabolic changes", "likelihood": "20%", "severity": "moderate"}
                ]
                side_effects["rare"] = [
                    {"effect": "Tardive dyskinesia", "likelihood": "3%", "severity": "severe"},
                    {"effect": "Agranulocytosis", "likelihood": "<1%", "severity": "severe"}
                ]
        elif "therapy" in treatment_type:
            # Therapy typically has fewer physical side effects
            side_effects["common"] = [
                {"effect": "Temporary emotional discomfort", "likelihood": "40%", "severity": "mild"},
                {"effect": "Increased anxiety initially", "likelihood": "25%", "severity": "mild"}
            ]
            side_effects["rare"] = [
                {"effect": "Worsening of symptoms", "likelihood": "5%", "severity": "moderate"},
                {"effect": "Dependency on therapist", "likelihood": "3%", "severity": "moderate"}
            ]
        
        return side_effects
    
    def _generate_outcome_trajectory(
        self,
        outcome_type: str,
        outcome_score: float,
        time_frame_days: int
    ) -> dict[str, Any]:
        """
        Generate outcome trajectory for an outcome prediction.
        
        Args:
            outcome_type: Type of outcome
            outcome_score: Outcome score
            time_frame_days: Time frame in days
            
        Returns:
            Dictionary containing trajectory data
        """
        # Number of data points based on time frame
        if time_frame_days <= 30:
            num_points = 4  # Weekly for a month
        elif time_frame_days <= 90:
            num_points = 6  # Biweekly for 3 months
        else:
            num_points = 8  # Monthly for longer periods
        
        # Generate trajectory points
        trajectory_points = []
        
        # Starting point is always current state (0% improvement)
        trajectory_points.append({
            "time_point": "current",
            "days_from_start": 0,
            "improvement_percentage": 0
        })
        
        # Calculate days between points
        days_between_points = time_frame_days / (num_points - 1)
        
        # Final improvement percentage based on outcome score
        final_improvement = int(outcome_score * 100)
        
        # Generate points with non-linear improvement curve
        # (faster improvement initially, then plateauing)
        for i in range(1, num_points):
            days = int(i * days_between_points)
            
            # Non-linear improvement: sqrt curve normalized to final improvement
            progress_ratio = (i / (num_points - 1)) ** 0.5
            improvement = int(final_improvement * progress_ratio)
            
            trajectory_points.append({
                "time_point": f"point_{i}",
                "days_from_start": days,
                "improvement_percentage": improvement
            })
        
        return {
            "points": trajectory_points,
            "final_improvement": final_improvement,
            "time_frame_days": time_frame_days,
            "visualization_type": "line_chart"
        }
    
    def _generate_outcome_details(
        self,
        outcome_type: str,
        outcome_score: float,
        clinical_data: dict[str, Any],
        treatment_plan: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Generate outcome details for an outcome prediction.
        
        Args:
            outcome_type: Type of outcome
            outcome_score: Outcome score
            clinical_data: Clinical data
            treatment_plan: Treatment plan
            
        Returns:
            Dictionary containing outcome details
        """
        # Base details from outcome score
        final_improvement = int(outcome_score * 100)
        
        details = {
            "overall_improvement": f"{final_improvement}%",
            "domains": []
        }
        
        # Add domains based on outcome type
        if outcome_type == "symptom":
            # Add symptom domains
            details["domains"] = [
                {
                    "name": "Mood",
                    "improvement": f"{int(final_improvement * random.uniform(0.9, 1.1))}%",
                    "notes": "Expected improvement in mood symptoms"
                },
                {
                    "name": "Anxiety",
                    "improvement": f"{int(final_improvement * random.uniform(0.8, 1.0))}%",
                    "notes": "Expected reduction in anxiety"
                },
                {
                    "name": "Sleep",
                    "improvement": f"{int(final_improvement * random.uniform(0.7, 1.2))}%",
                    "notes": "Expected improvement in sleep quality"
                }
            ]
            
        elif outcome_type == "functional":
            # Add functional domains
            details["domains"] = [
                {
                    "name": "Work performance",
                    "improvement": f"{int(final_improvement * random.uniform(0.8, 1.0))}%",
                    "notes": "Expected improvement in occupational functioning"
                },
                {
                    "name": "Social functioning",
                    "improvement": f"{int(final_improvement * random.uniform(0.7, 1.1))}%",
                    "notes": "Expected improvement in interpersonal relationships"
                },
                {
                    "name": "Self-care",
                    "improvement": f"{int(final_improvement * random.uniform(0.9, 1.1))}%",
                    "notes": "Expected improvement in activities of daily living"
                }
            ]
            
        elif outcome_type == "quality_of_life":
            # Add quality of life domains
            details["domains"] = [
                {
                    "name": "Life satisfaction",
                    "improvement": f"{int(final_improvement * random.uniform(0.7, 1.0))}%",
                    "notes": "Expected improvement in overall life satisfaction"
                },
                {
                    "name": "Physical well-being",
                    "improvement": f"{int(final_improvement * random.uniform(0.6, 0.9))}%",
                    "notes": "Expected improvement in physical health"
                },
                {
                    "name": "Emotional well-being",
                    "improvement": f"{int(final_improvement * random.uniform(0.8, 1.1))}%",
                    "notes": "Expected improvement in emotional state"
                }
            ]
        
        # Add recommendations based on outcome
        details["recommendations"] = []
        
        if outcome_score < 0.4:
            details["recommendations"].append(
                "Consider adjusting treatment plan for better outcomes"
            )
            details["recommendations"].append(
                "More frequent monitoring recommended"
            )
        elif outcome_score < 0.7:
            details["recommendations"].append(
                "Current treatment plan appears adequate"
            )
            details["recommendations"].append(
                "Regular follow-up recommended to ensure progress"
            )
        else:
            details["recommendations"].append(
                "Treatment plan appears highly effective"
            )
            details["recommendations"].append(
                "Maintenance strategy should be developed for sustained outcomes"
            )
        
        return details
    
    def _determine_prediction_type(self, prediction: dict[str, Any]) -> str:
        """
        Determine the type of prediction from prediction data.
        
        Args:
            prediction: Prediction data
            
        Returns:
            Type of prediction as a string
        """
        if "risk_level" in prediction:
            return f"{prediction.get('risk_type', 'unknown')}_risk"
        elif "response_likelihood" in prediction:
            return f"{prediction.get('treatment_type', 'unknown')}_response"
        elif "outcome_score" in prediction:
            return f"{prediction.get('outcome_type', 'unknown')}_outcome"
        else:
            return "unknown"
    
    def _validate_risk_type(self, risk_type: str) -> None:
        """
        Validate risk type.
        
        Args:
            risk_type: Risk type to validate
            
        Raises:
            ValidationError: If risk type is invalid
        """
        valid_risk_types = ["relapse", "suicide", "hospitalization"]
        
        if risk_type not in valid_risk_types:
            raise ValidationError(
                f"Invalid risk type: {risk_type}. Valid risk types: {', '.join(valid_risk_types)}",
                field="risk_type",
                value=risk_type
            )
    
    def _validate_treatment_type(
        self,
        treatment_type: str,
        treatment_details: dict[str, Any]
    ) -> None:
        """
        Validate treatment type and details.
        
        Args:
            treatment_type: Treatment type to validate
            treatment_details: Treatment details to validate
            
        Raises:
            ValidationError: If treatment type or details are invalid
        """
        # Check if treatment type is valid
        valid_medication_types = ["medication_ssri", "medication_snri", "medication_atypical"]
        valid_therapy_types = ["therapy_cbt", "therapy_dbt", "therapy_ipt", "therapy_psychodynamic"]
        
        valid_treatment_types = valid_medication_types + valid_therapy_types
        
        if treatment_type not in valid_treatment_types:
            raise ValidationError(
                f"Invalid treatment type: {treatment_type}. Valid treatment types: {', '.join(valid_treatment_types)}",
                field="treatment_type",
                value=treatment_type
            )
        
        # Check required details for medication
        if treatment_type in valid_medication_types:
            if "medication" not in treatment_details:
                raise ValidationError(
                    "Missing required field 'medication' in treatment_details",
                    field="treatment_details.medication"
                )
        
        # Check required details for therapy
        if treatment_type in valid_therapy_types:
            if "frequency" not in treatment_details:
                raise ValidationError(
                    "Missing required field 'frequency' in treatment_details",
                    field="treatment_details.frequency"
                )
    
    def _validate_outcome_params(self, outcome_timeframe: dict[str, int]) -> None:
        """
        Validate outcome prediction parameters.
        
        Args:
            outcome_timeframe: Outcome timeframe to validate
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not outcome_timeframe:
            raise ValidationError(
                "Empty outcome timeframe",
                field="outcome_timeframe"
            )
        
        valid_units = ["days", "weeks", "months"]
        
        if not any(unit in outcome_timeframe for unit in valid_units):
            raise ValidationError(
                f"Invalid outcome timeframe. Must include at least one of: {', '.join(valid_units)}",
                field="outcome_timeframe"
            )
        
        for unit, value in outcome_timeframe.items():
            if unit not in valid_units:
                raise ValidationError(
                    f"Invalid time unit: {unit}. Valid units: {', '.join(valid_units)}",
                    field=f"outcome_timeframe.{unit}",
                    value=unit
                )
            
            if not isinstance(value, int) or value <= 0:
                raise ValidationError(
                    f"Invalid value for {unit}: {value}. Must be a positive integer.",
                    field=f"outcome_timeframe.{unit}",
                    value=value
                )
