"""
Mock implementation of XGBoostService for testing.
Provides synthetic predictions without requiring the actual XGBoost model.
"""
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union, Optional, Any
from uuid import UUID

from app.core.domain.entities.patient import Patient
from app.core.domain.entities.user import User
from app.core.services.ml.xgboost.interface import XGBoostInterface


class MockXGBoostService(XGBoostInterface):
    """Mock implementation of the XGBoost service for testing.
    
    This implementation provides synthetic predictions without requiring
    the actual XGBoost model or AWS infrastructure.
    """
    
    async def predict(self, patient_id: UUID, features: Dict[str, Any], model_type: str, **kwargs) -> Dict[str, Any]:
        """Generic prediction method required by MLServiceInterface.
        
        Args:
            patient_id: UUID of the patient
            features: Dictionary of features for prediction
            model_type: Type of model to use for prediction
            **kwargs: Additional arguments for prediction
            
        Returns:
            Dictionary with prediction results
        """
        # Choose the appropriate specialized prediction method based on model_type
        if model_type.lower() == "risk":
            risk_type = kwargs.get("risk_type", "general")
            time_horizon = kwargs.get("time_horizon", "short_term")
            digital_twin_state_id = kwargs.get("digital_twin_state_id", uuid.uuid4())
            risk_factors = kwargs.get("risk_factors", ["relapse", "hospitalization"])
            
            return await self.predict_risk(
                patient_id=patient_id,
                digital_twin_state_id=digital_twin_state_id,
                risk_factors=risk_factors,
                time_horizon=time_horizon
            )
            
        elif model_type.lower() == "treatment_response":
            treatment_options = kwargs.get("treatment_options", [])
            time_horizon = kwargs.get("time_horizon", "short_term")
            digital_twin_state_id = kwargs.get("digital_twin_state_id", uuid.uuid4())
            
            return await self.predict_treatment_response(
                patient_id=patient_id,
                digital_twin_state_id=digital_twin_state_id,
                treatment_options=treatment_options,
                time_horizon=time_horizon
            )
            
        elif model_type.lower() == "outcome":
            outcomes = kwargs.get("outcomes", ["remission", "relapse"])
            time_horizon = kwargs.get("time_horizon", "medium_term")
            digital_twin_state_id = kwargs.get("digital_twin_state_id", uuid.uuid4())
            with_treatment = kwargs.get("with_treatment")
            
            return await self.predict_outcomes(
                patient_id=patient_id,
                digital_twin_state_id=digital_twin_state_id,
                outcomes=outcomes,
                time_horizon=time_horizon,
                with_treatment=with_treatment
            )
            
        elif model_type.lower() == "symptom_progression":
            symptoms = kwargs.get("symptoms", ["depression", "anxiety"])
            time_points = kwargs.get("time_points", [7, 14, 30, 90])
            digital_twin_state_id = kwargs.get("digital_twin_state_id", uuid.uuid4())
            with_treatment = kwargs.get("with_treatment")
            
            return await self.forecast_symptom_progression(
                patient_id=patient_id,
                digital_twin_state_id=digital_twin_state_id,
                symptoms=symptoms,
                time_points=time_points,
                with_treatment=with_treatment
            )
            
        else:
            # Generic fallback prediction
            return {
                "patient_id": str(patient_id),
                "model_type": model_type,
                "prediction_timestamp": datetime.now().isoformat(),
                "predictions": {
                    "value": round(random.uniform(0.1, 0.9), 2),
                    "confidence": round(random.uniform(0.6, 0.9), 2)
                },
                "model_version": "mock-xgboost-v1.0"
            }
    
    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)
    
    async def predict_risk(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID,
        risk_factors: List[str],
        time_horizon: str
    ) -> Dict:
        """Generate mock risk predictions.
        
        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: UUID of the current Digital Twin state
            risk_factors: List of risk factors to predict
            time_horizon: Time horizon for prediction (short_term, medium_term, long_term)
            
        Returns:
            Dictionary with risk predictions
        """
        # Initialize response structure
        response = {
            "patient_id": str(patient_id),
            "digital_twin_state_id": str(digital_twin_state_id),
            "prediction_timestamp": datetime.now().isoformat(),
            "time_horizon": time_horizon,
            "risk_predictions": [],
            "model_version": "mock-xgboost-v1.0",
            "confidence_adjustment": 0.9 if time_horizon == "short_term" else 
                                    0.7 if time_horizon == "medium_term" else 0.5
        }
        
        # Generate synthetic predictions for each risk factor
        for risk_factor in risk_factors:
            risk_factor_lower = risk_factor.lower()
            
            # Initialize base risk and confidence
            base_risk = random.uniform(0.2, 0.8)
            confidence = random.uniform(0.6, 0.9)
            
            # Adjust based on time horizon
            if time_horizon == "medium_term":
                base_risk = min(base_risk * random.uniform(1.1, 1.3), 0.95)
                confidence *= 0.9
            elif time_horizon == "long_term":
                base_risk = min(base_risk * random.uniform(1.2, 1.5), 0.95)
                confidence *= 0.8
            
            # Create prediction entry
            prediction = {
                "risk_factor": risk_factor,
                "probability": round(base_risk, 2),
                "confidence": round(confidence, 2),
                "contributing_factors": self._generate_contributing_factors(risk_factor_lower)
            }
            
            response["risk_predictions"].append(prediction)
        
        return response
        
    def _generate_contributing_factors(self, risk_factor: str) -> List[Dict]:
        """Generate mock contributing factors for a risk factor.
        
        Args:
            risk_factor: The risk factor to generate contributing factors for
            
        Returns:
            List of contributing factors
        """
        factors = []
        
        if "suicide" in risk_factor or "self_harm" in risk_factor:
            factors = [
                {"factor": "Previous suicide attempt", "contribution": round(random.uniform(0.3, 0.7), 2)},
                {"factor": "Depression severity", "contribution": round(random.uniform(0.2, 0.5), 2)},
                {"factor": "Social isolation", "contribution": round(random.uniform(0.1, 0.4), 2)},
                {"factor": "Substance use", "contribution": round(random.uniform(0.1, 0.3), 2)},
            ]
        elif "relapse" in risk_factor or "recurrence" in risk_factor:
            factors = [
                {"factor": "Treatment adherence", "contribution": round(random.uniform(0.3, 0.6), 2)},
                {"factor": "Stress level", "contribution": round(random.uniform(0.2, 0.5), 2)},
                {"factor": "Sleep pattern", "contribution": round(random.uniform(0.1, 0.4), 2)},
                {"factor": "Social support", "contribution": round(random.uniform(0.1, 0.3), 2)},
            ]
        elif "hospitalization" in risk_factor or "readmission" in risk_factor:
            factors = [
                {"factor": "Symptom severity", "contribution": round(random.uniform(0.3, 0.6), 2)},
                {"factor": "Medication adherence", "contribution": round(random.uniform(0.2, 0.5), 2)},
                {"factor": "Previous hospitalizations", "contribution": round(random.uniform(0.2, 0.4), 2)},
                {"factor": "Outpatient follow-up", "contribution": round(random.uniform(0.1, 0.3), 2)},
            ]
        else:
            # Generic factors
            factors = [
                {"factor": "Symptom severity", "contribution": round(random.uniform(0.2, 0.5), 2)},
                {"factor": "Treatment engagement", "contribution": round(random.uniform(0.1, 0.4), 2)},
                {"factor": "Support system", "contribution": round(random.uniform(0.1, 0.3), 2)},
            ]
        
        # Randomize a bit to avoid same numbers every time
        for factor in factors:
            factor["contribution"] = round(factor["contribution"] * random.uniform(0.9, 1.1), 2)
        
        return factors
    
    async def forecast_symptom_progression(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID,
        symptoms: List[str],
        time_points: List[int],  # days into the future
        with_treatment: Optional[Dict] = None
    ) -> Dict:
        """Forecast symptom progression over time with or without treatment.
        
        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: UUID of the current Digital Twin state
            symptoms: List of symptoms to forecast
            time_points: List of time points (in days) for forecasting
            with_treatment: Optional treatment to consider in forecast
            
        Returns:
            Dictionary with symptom trajectories and confidence intervals
        """
        # Initialize response structure
        response = {
            "patient_id": str(patient_id),
            "digital_twin_state_id": str(digital_twin_state_id),
            "prediction_timestamp": datetime.now().isoformat(),
            "forecast_days": max(time_points),
            "symptom_trajectories": [],
            "model_version": "mock-xgboost-v1.0"
        }
        
        has_treatment = with_treatment is not None
        treatment_type = with_treatment.get("type", "unknown") if has_treatment else None
        treatment_name = with_treatment.get("name", "Unknown Treatment") if has_treatment else None
        
        # Generate trajectories for each symptom
        for symptom in symptoms:
            symptom_lower = symptom.lower()
            
            # Start with current severity (between 0.5-0.9)
            current_severity = random.uniform(0.5, 0.9)
            
            # Determine if treatment helps this symptom
            treatment_effect = 0.0
            if has_treatment:
                if treatment_type == "medication":
                    # Medications have stronger effect on mood/anxiety, less on cognitive symptoms
                    if "mood" in symptom_lower or "depress" in symptom_lower or "anxiety" in symptom_lower:
                        treatment_effect = random.uniform(0.3, 0.5)
                    else:
                        treatment_effect = random.uniform(0.1, 0.3)
                elif treatment_type == "therapy":
                    # Therapy has balanced effects across symptoms
                    treatment_effect = random.uniform(0.2, 0.4)
                else:
                    # Generic treatment
                    treatment_effect = random.uniform(0.1, 0.3)
            
            # Generate trajectory points
            trajectory = []
            for day in time_points:
                # Natural symptom progression (slightly worsening without treatment)
                if not has_treatment:
                    # Symptoms generally worsen slightly over time without treatment
                    natural_change = day * random.uniform(0.001, 0.003)
                    severity = min(current_severity + natural_change, 1.0)
                else:
                    # Treatment gradually improves symptoms
                    # Most treatments take 2-4 weeks to show effect
                    if day < 14:
                        effect_ratio = day / 14.0  # Gradual increase in effect
                    else:
                        effect_ratio = 1.0  # Full effect after 2 weeks
                    
                    treatment_impact = treatment_effect * effect_ratio
                    severity = max(current_severity - treatment_impact, 0.1)
                
                # Add some noise to make it realistic
                severity = max(0.1, min(1.0, severity + random.uniform(-0.05, 0.05)))
                
                # Calculate confidence interval (wider as we go further in time)
                ci_width = 0.05 + (day / max(time_points)) * 0.15
                
                trajectory.append({
                    "day": day,
                    "severity": round(severity, 2),
                    "confidence_interval": [
                        round(max(0.0, severity - ci_width), 2),
                        round(min(1.0, severity + ci_width), 2)
                    ]
                })
            
            # Create trajectory entry
            symptom_trajectory = {
                "symptom": symptom,
                "with_treatment": has_treatment,
                "treatment_details": with_treatment if has_treatment else None,
                "trajectory": trajectory
            }
            
            response["symptom_trajectories"].append(symptom_trajectory)
        
        return response
    
    async def predict_treatment_response(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID,
        treatment_options: List[Dict],
        time_horizon: str
    ) -> Dict:
        """Predict response to different treatment options.
        
        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: UUID of the current Digital Twin state
            treatment_options: List of treatment options to consider
            time_horizon: Time horizon for prediction (short_term, medium_term, long_term)
            
        Returns:
            Dictionary with treatment response predictions
        """
        # Initialize response structure
        response = {
            "patient_id": str(patient_id),
            "digital_twin_state_id": str(digital_twin_state_id),
            "prediction_timestamp": datetime.now().isoformat(),
            "time_horizon": time_horizon,
            "treatment_responses": [],
            "model_version": "mock-xgboost-v1.0",
            "confidence_adjustment": 0.9 if time_horizon == "short_term" else 
                                    0.7 if time_horizon == "medium_term" else 0.5
        }
        
        # Generate synthetic predictions for each treatment option
        for i, treatment in enumerate(treatment_options):
            treatment_type = treatment.get("type", "medication")
            treatment_name = treatment.get("name", f"Treatment {i+1}")
            
            # Base prediction values
            base_efficacy = random.uniform(0.5, 0.9)
            base_side_effects = random.uniform(0.1, 0.4)
            
            # Adjust based on treatment type
            if treatment_type == "medication":
                if "SSRI" in treatment_name or "sertraline" in treatment_name.lower():
                    base_efficacy = random.uniform(0.65, 0.85)
                    base_side_effects = random.uniform(0.2, 0.4)
                elif "therapy" in treatment_name.lower() or "CBT" in treatment_name:
                    base_efficacy = random.uniform(0.6, 0.8)
                    base_side_effects = random.uniform(0.05, 0.15)
            
            # Adjust by time horizon (longer term has more uncertainty)
            if time_horizon == "medium_term":
                confidence_mod = 0.9
            elif time_horizon == "long_term":
                confidence_mod = 0.7
            else:
                confidence_mod = 1.0
            
            # Create prediction
            treatment_response = {
                "treatment_id": treatment.get("id", f"treatment_{i}"),
                "treatment_name": treatment_name,
                "treatment_type": treatment_type,
                "efficacy_prediction": {
                    "value": round(base_efficacy, 2),
                    "confidence": round(confidence_mod * random.uniform(0.7, 0.9), 2)
                },
                "side_effect_prediction": {
                    "value": round(base_side_effects, 2),
                    "confidence": round(confidence_mod * random.uniform(0.7, 0.9), 2)
                },
                "adherence_prediction": {
                    "value": round(random.uniform(0.6, 0.95), 2),
                    "confidence": round(confidence_mod * random.uniform(0.7, 0.85), 2)
                },
                "time_to_response": {
                    "value": random.randint(1, 8),  # weeks
                    "confidence": round(confidence_mod * random.uniform(0.6, 0.8), 2)
                }
            }
            
            response["treatment_responses"].append(treatment_response)
        
        return response
    
    async def predict_outcomes(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID,
        outcomes: List[str],
        time_horizon: str,
        with_treatment: Optional[Dict] = None
    ) -> Dict:
        """Predict clinical outcomes with or without treatment.
        
        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: UUID of the current Digital Twin state
            outcomes: List of outcomes to predict
            time_horizon: Time horizon for prediction
            with_treatment: Optional treatment to include in prediction
            
        Returns:
            Dictionary with outcome predictions
        """
        # Initialize response structure
        response = {
            "patient_id": str(patient_id),
            "digital_twin_state_id": str(digital_twin_state_id),
            "prediction_timestamp": datetime.now().isoformat(),
            "time_horizon": time_horizon,
            "outcome_predictions": [],
            "model_version": "mock-xgboost-v1.0"
        }
        
        has_treatment = with_treatment is not None
        treatment_type = with_treatment.get("type", "unknown") if has_treatment else None
        treatment_name = with_treatment.get("name", "Unknown Treatment") if has_treatment else None
        
        # Time horizon affects base probabilities
        if time_horizon == "short_term":  # 1-3 months
            base_modifier = 0.3
            confidence = random.uniform(0.7, 0.9)
        elif time_horizon == "medium_term":  # 3-6 months
            base_modifier = 0.5
            confidence = random.uniform(0.6, 0.8)
        else:  # long term: 6-12 months
            base_modifier = 0.7
            confidence = random.uniform(0.5, 0.7)
        
        # Generate predictions for each outcome
        for outcome in outcomes:
            outcome_lower = outcome.lower()
            
            # Base probability depends on the outcome type
            if "remission" in outcome_lower or "recovery" in outcome_lower:
                # Treatment improves chance of remission
                base_prob = random.uniform(0.3, 0.5) if has_treatment else random.uniform(0.1, 0.3)
                base_prob += base_modifier * 0.3  # More likely over time
            elif "relapse" in outcome_lower or "recurrence" in outcome_lower:
                # Treatment reduces chance of relapse
                base_prob = random.uniform(0.2, 0.4) if has_treatment else random.uniform(0.4, 0.7)
                base_prob += base_modifier * 0.2  # More likely over time
            elif "hospitalization" in outcome_lower or "admission" in outcome_lower:
                # Treatment reduces chance of hospitalization
                base_prob = random.uniform(0.05, 0.2) if has_treatment else random.uniform(0.15, 0.35)
                base_prob += base_modifier * 0.1  # Slightly more likely over time
            elif "functional" in outcome_lower or "recovery" in outcome_lower:
                # Treatment improves functional recovery
                base_prob = random.uniform(0.4, 0.7) if has_treatment else random.uniform(0.2, 0.4)
                base_prob += base_modifier * 0.3  # Much more likely over time
            else:
                # Generic outcome
                base_prob = random.uniform(0.3, 0.6) if has_treatment else random.uniform(0.2, 0.4)
                base_prob += base_modifier * 0.2  # More likely over time
            
            # Ensure probability is in valid range
            probability = min(max(base_prob, 0.05), 0.95)
            
            # Generate prediction
            prediction = {
                "outcome": outcome,
                "probability": round(probability, 2),
                "confidence": round(confidence, 2),
                "with_treatment": has_treatment,
                "treatment_details": with_treatment if has_treatment else None,
                "contributing_factors": self._generate_contributing_factors(outcome_lower)
            }
            
            response["outcome_predictions"].append(prediction)
        
        return response
    
    async def compare_treatments(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID,
        treatment_options: List[Dict],
        evaluation_metrics: List[str]
    ) -> List[Tuple[Dict, Dict]]:
        """Compare multiple treatment options based on predicted outcomes.
        
        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: UUID of the current Digital Twin state
            treatment_options: List of treatment options to compare
            evaluation_metrics: Metrics to use for evaluation
            
        Returns:
            List of tuples with treatment option and evaluation results
        """
        # Initialize results
        results = []
        
        for treatment in treatment_options:
            treatment_type = treatment.get("type", "unknown")
            treatment_name = treatment.get("name", "Unknown Treatment")
            
            # Generate synthetic evaluation results
            evaluation = {}
            
            for metric in evaluation_metrics:
                metric_lower = metric.lower()
                
                if "efficacy" in metric_lower or "effectiveness" in metric_lower:
                    # Medications tend to be more effective for certain conditions
                    if treatment_type == "medication":
                        base_score = random.uniform(0.65, 0.85)
                    else:
                        base_score = random.uniform(0.6, 0.8)
                    
                    evaluation[metric] = {
                        "score": round(base_score, 2),
                        "confidence_interval": [
                            round(base_score - random.uniform(0.05, 0.15), 2),
                            round(base_score + random.uniform(0.05, 0.15), 2)
                        ],
                        "confidence": round(random.uniform(0.7, 0.9), 2)
                    }
                
                elif "side_effect" in metric_lower or "adverse" in metric_lower:
                    # Medications tend to have more side effects
                    if treatment_type == "medication":
                        base_score = random.uniform(0.2, 0.4)
                    else:
                        base_score = random.uniform(0.05, 0.2)
                    
                    evaluation[metric] = {
                        "score": round(base_score, 2),
                        "confidence_interval": [
                            round(base_score - random.uniform(0.05, 0.1), 2),
                            round(base_score + random.uniform(0.05, 0.1), 2)
                        ],
                        "confidence": round(random.uniform(0.7, 0.85), 2)
                    }
                
                elif "adherence" in metric_lower or "compliance" in metric_lower:
                    # Adherence can vary by treatment complexity
                    if "complex" in treatment_name.lower():
                        base_score = random.uniform(0.5, 0.7)
                    else:
                        base_score = random.uniform(0.7, 0.9)
                    
                    evaluation[metric] = {
                        "score": round(base_score, 2),
                        "confidence_interval": [
                            round(base_score - random.uniform(0.05, 0.15), 2),
                            round(base_score + random.uniform(0.05, 0.15), 2)
                        ],
                        "confidence": round(random.uniform(0.7, 0.85), 2)
                    }
                
                else:
                    # Generic metric
                    evaluation[metric] = {
                        "score": round(random.uniform(0.5, 0.8), 2),
                        "confidence_interval": [
                            round(random.uniform(0.4, 0.6), 2),
                            round(random.uniform(0.7, 0.9), 2)
                        ],
                        "confidence": round(random.uniform(0.7, 0.85), 2)
                    }
            
            results.append((treatment, evaluation))
        
        return results
