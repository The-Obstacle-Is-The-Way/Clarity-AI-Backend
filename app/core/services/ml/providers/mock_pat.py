"""
Mock PAT Implementation.

This module provides a mock implementation of the PAT interface for testing purposes.
"""

import random
import time
from datetime import datetime, timedelta
from typing import Any

from app.core.services.ml.pat_interface import PATInterface
from app.core.utils.logging import get_logger

# Create logger
logger = get_logger(__name__)


class MockPAT(PATInterface):
    """
    Mock implementation of the PAT interface.
    
    This class provides a mock implementation of the PAT interface for testing purposes.
    """
    
    def __init__(self):
        """Initialize the MockPAT service."""
        self.config = {}
        self.initialized = False
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Service configuration parameters
        """
        logger.info("Initializing MockPAT service")
        self.config = config
        self.initialized = True
        logger.info("MockPAT service initialized")
    
    def is_healthy(self) -> bool:
        """
        Check if the service is operational.
        
        Returns:
            bool: True if service is operational, False otherwise
        """
        return self.initialized
    
    def shutdown(self) -> None:
        """Clean up resources when shutting down the service."""
        logger.info("Shutting down MockPAT service")
        self.initialized = False
    
    def _validate_initialization(self) -> None:
        """
        Validate that the service is initialized.
        
        Raises:
            RuntimeError: If the service is not initialized
        """
        if not self.initialized:
            raise RuntimeError("MockPAT service not initialized")
    
    def _generate_mock_sleep_data(self, start_date: str, end_date: str) -> list[dict[str, Any]]:
        """
        Generate mock sleep data for testing.
        
        Args:
            start_date: Start date (ISO 8601 format)
            end_date: End date (ISO 8601 format)
            
        Returns:
            List of sleep data entries
        """
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        days = (end - start).days + 1
        sleep_data = []
        
        for i in range(days):
            current_date = start + timedelta(days=i)
            
            # Generate random sleep metrics
            sleep_onset = f"{current_date.strftime('%Y-%m-%d')}T23:{random.randint(0, 59):02d}:00Z"
            wake_time = f"{(current_date + timedelta(days=1)).strftime('%Y-%m-%d')}T07:{random.randint(0, 59):02d}:00Z"
            
            total_sleep_minutes = random.randint(300, 540)  # 5-9 hours
            deep_sleep_percentage = random.uniform(0.15, 0.30)
            rem_sleep_percentage = random.uniform(0.20, 0.35)
            light_sleep_percentage = 1 - deep_sleep_percentage - rem_sleep_percentage
            
            awakenings = random.randint(0, 5)
            sleep_efficiency = random.uniform(0.75, 0.95)
            
            entry = {
                "date": current_date.strftime('%Y-%m-%d'),
                "sleep_onset": sleep_onset,
                "wake_time": wake_time,
                "total_sleep_minutes": total_sleep_minutes,
                "deep_sleep_minutes": round(total_sleep_minutes * deep_sleep_percentage),
                "rem_sleep_minutes": round(total_sleep_minutes * rem_sleep_percentage),
                "light_sleep_minutes": round(total_sleep_minutes * light_sleep_percentage),
                "awakenings": awakenings,
                "sleep_efficiency": sleep_efficiency,
                "sleep_score": round(sleep_efficiency * 100)
            }
            
            sleep_data.append(entry)
        
        return sleep_data
    
    def _generate_mock_activity_data(self, start_date: str, end_date: str) -> list[dict[str, Any]]:
        """
        Generate mock activity data for testing.
        
        Args:
            start_date: Start date (ISO 8601 format)
            end_date: End date (ISO 8601 format)
            
        Returns:
            List of activity data entries
        """
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        days = (end - start).days + 1
        activity_data = []
        
        for i in range(days):
            current_date = start + timedelta(days=i)
            
            # Generate random activity metrics
            steps = random.randint(3000, 15000)
            active_minutes = random.randint(30, 180)
            sedentary_minutes = random.randint(480, 960)
            calories_burned = random.randint(1800, 3000)
            
            entry = {
                "date": current_date.strftime('%Y-%m-%d'),
                "steps": steps,
                "active_minutes": active_minutes,
                "sedentary_minutes": sedentary_minutes,
                "calories_burned": calories_burned,
                "distance_km": round(steps * 0.0007, 2),
                "active_hours": [
                    {"hour": 8, "activity_level": random.uniform(0.2, 0.8)},
                    {"hour": 12, "activity_level": random.uniform(0.2, 0.8)},
                    {"hour": 17, "activity_level": random.uniform(0.2, 0.8)},
                    {"hour": 20, "activity_level": random.uniform(0.2, 0.8)}
                ],
                "activity_score": random.randint(50, 100)
            }
            
            activity_data.append(entry)
        
        return activity_data
    
    def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, str],
        analysis_types: list[str],
        **kwargs
    ) -> dict[str, Any]:
        """
        Analyze actigraphy data using the PAT model.
        
        Args:
            patient_id: Patient identifier
            readings: Accelerometer readings with timestamp and x,y,z values
            start_time: Start time of recording (ISO 8601 format)
            end_time: End time of recording (ISO 8601 format)
            sampling_rate_hz: Sampling rate in Hz
            device_info: Information about the device used
            analysis_types: Types of analysis to perform (e.g., "sleep", "activity", "mood")
            **kwargs: Additional parameters
            
        Returns:
            Dict containing analysis results and metadata
        """
        self._validate_initialization()
        
        logger.info(f"Mock analyzing actigraphy data for patient {patient_id}")
        
        # Prepare results
        results = {
            "patient_id": patient_id,
            "analysis_id": f"analysis_{int(time.time())}",
            "start_time": start_time,
            "end_time": end_time,
            "data_points": len(readings),
            "analysis_types": analysis_types,
            "results": {}
        }
        
        # Process each analysis type
        for analysis_type in analysis_types:
            if analysis_type == "sleep":
                results["results"]["sleep"] = {
                    "sleep_efficiency": random.uniform(0.75, 0.95),
                    "total_sleep_time": random.randint(300, 540),  # minutes
                    "sleep_onset_latency": random.randint(5, 30),  # minutes
                    "wake_after_sleep_onset": random.randint(10, 60),  # minutes
                    "sleep_stages": {
                        "deep": random.uniform(0.15, 0.30),
                        "light": random.uniform(0.40, 0.60),
                        "rem": random.uniform(0.15, 0.25)
                    },
                    "circadian_rhythm": {
                        "regularity": random.uniform(0.6, 0.9),
                        "phase": "normal" if random.random() > 0.3 else "delayed"
                    },
                    "confidence": random.uniform(0.7, 0.95)
                }
            elif analysis_type == "activity":
                results["results"]["activity"] = {
                    "activity_level": random.uniform(0.3, 0.8),
                    "steps_estimate": random.randint(5000, 15000),
                    "active_minutes": random.randint(30, 180),
                    "sedentary_minutes": random.randint(480, 960),
                    "activity_patterns": {
                        "morning": random.uniform(0.2, 0.6),
                        "afternoon": random.uniform(0.3, 0.7),
                        "evening": random.uniform(0.2, 0.5)
                    },
                    "energy_expenditure": {
                        "calories": random.randint(1800, 3000),
                        "confidence": random.uniform(0.7, 0.9)
                    },
                    "confidence": random.uniform(0.7, 0.95)
                }
            elif analysis_type == "mood":
                results["results"]["mood"] = {
                    "mood_estimate": {
                        "valence": random.uniform(-0.5, 0.5),
                        "arousal": random.uniform(-0.3, 0.7)
                    },
                    "depression_risk": {
                        "score": random.uniform(0.1, 0.7),
                        "confidence": random.uniform(0.6, 0.9)
                    },
                    "anxiety_indicators": {
                        "score": random.uniform(0.1, 0.6),
                        "confidence": random.uniform(0.6, 0.9)
                    },
                    "behavioral_patterns": {
                        "regularity": random.uniform(0.5, 0.9),
                        "social_activity_estimate": random.uniform(0.3, 0.8)
                    },
                    "confidence": random.uniform(0.6, 0.9)
                }
            elif analysis_type == "anomaly":
                results["results"]["anomaly"] = {
                    "anomalies_detected": random.randint(0, 3),
                    "anomaly_details": [
                        {
                            "type": random.choice(["activity", "sleep", "circadian"]),
                            "severity": random.uniform(0.3, 0.9),
                            "description": f"Anomaly in {random.choice(['morning', 'afternoon', 'evening'])} pattern",
                            "timestamp": (datetime.fromisoformat(start_time.replace('Z', '+00:00')) + 
                                         timedelta(hours=random.randint(1, 24))).isoformat() + 'Z'
                        } for _ in range(random.randint(0, 3))
                    ],
                    "confidence": random.uniform(0.6, 0.9)
                }
        
        return results
    
    def get_sleep_metrics(
        self,
        patient_id: str,
        start_date: str,
        end_date: str,
        **kwargs
    ) -> dict[str, Any]:
        """
        Get sleep metrics for a patient over a specified time period.
        
        Args:
            patient_id: Patient identifier
            start_date: Start date (ISO 8601 format)
            end_date: End date (ISO 8601 format)
            **kwargs: Additional parameters
            
        Returns:
            Dict containing sleep metrics
        """
        self._validate_initialization()
        
        logger.info(f"Mock getting sleep metrics for patient {patient_id}")
        
        sleep_data = self._generate_mock_sleep_data(start_date, end_date)
        
        return {
            "patient_id": patient_id,
            "start_date": start_date,
            "end_date": end_date,
            "metrics": sleep_data,
            "summary": {
                "average_sleep_duration": sum(entry["total_sleep_minutes"] for entry in sleep_data) / len(sleep_data),
                "average_sleep_efficiency": sum(entry["sleep_efficiency"] for entry in sleep_data) / len(sleep_data),
                "average_sleep_score": sum(entry["sleep_score"] for entry in sleep_data) / len(sleep_data),
                "sleep_trend": random.choice(["improving", "stable", "declining"])
            }
        }
    
    def get_activity_metrics(
        self,
        patient_id: str,
        start_date: str,
        end_date: str,
        **kwargs
    ) -> dict[str, Any]:
        """
        Get activity metrics for a patient over a specified time period.
        
        Args:
            patient_id: Patient identifier
            start_date: Start date (ISO 8601 format)
            end_date: End date (ISO 8601 format)
            **kwargs: Additional parameters
            
        Returns:
            Dict containing activity metrics
        """
        self._validate_initialization()
        
        logger.info(f"Mock getting activity metrics for patient {patient_id}")
        
        activity_data = self._generate_mock_activity_data(start_date, end_date)
        
        return {
            "patient_id": patient_id,
            "start_date": start_date,
            "end_date": end_date,
            "metrics": activity_data,
            "summary": {
                "average_steps": sum(entry["steps"] for entry in activity_data) / len(activity_data),
                "average_active_minutes": sum(entry["active_minutes"] for entry in activity_data) / len(activity_data),
                "average_activity_score": sum(entry["activity_score"] for entry in activity_data) / len(activity_data),
                "activity_trend": random.choice(["improving", "stable", "declining"])
            }
        }
    
    def detect_anomalies(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        baseline_period: dict[str, str] | None = None,
        **kwargs
    ) -> dict[str, Any]:
        """
        Detect anomalies in actigraphy data compared to baseline or population norms.
        
        Args:
            patient_id: Patient identifier
            readings: Accelerometer readings with timestamp and x,y,z values
            baseline_period: Optional period to use as baseline (start_date, end_date)
            **kwargs: Additional parameters
            
        Returns:
            Dict containing detected anomalies
        """
        self._validate_initialization()
        
        logger.info(f"Mock detecting anomalies for patient {patient_id}")
        
        # Generate random anomalies
        num_anomalies = random.randint(0, 5)
        anomalies = []
        
        for _ in range(num_anomalies):
            anomaly_type = random.choice(["activity", "sleep", "circadian"])
            severity = random.uniform(0.3, 0.9)
            
            if anomaly_type == "activity":
                description = random.choice([
                    "Unusually low activity level",
                    "Unusually high activity level",
                    "Irregular activity pattern",
                    "Sudden decrease in activity"
                ])
            elif anomaly_type == "sleep":
                description = random.choice([
                    "Fragmented sleep pattern",
                    "Delayed sleep onset",
                    "Early morning awakening",
                    "Reduced deep sleep"
                ])
            else:  # circadian
                description = random.choice([
                    "Irregular sleep-wake pattern",
                    "Delayed circadian phase",
                    "Advanced circadian phase",
                    "Disrupted daily rhythm"
                ])
            
            # Generate random timestamp within readings
            if readings:
                timestamp = readings[random.randint(0, len(readings) - 1)].get("timestamp", "2025-01-01T00:00:00Z")
            else:
                timestamp = "2025-01-01T00:00:00Z"
            
            anomalies.append({
                "type": anomaly_type,
                "severity": severity,
                "description": description,
                "timestamp": timestamp,
                "confidence": random.uniform(0.6, 0.9)
            })
        
        return {
            "patient_id": patient_id,
            "analysis_id": f"anomaly_{int(time.time())}",
            "data_points": len(readings),
            "anomalies": anomalies,
            "summary": {
                "total_anomalies": len(anomalies),
                "average_severity": sum(a["severity"] for a in anomalies) / len(anomalies) if anomalies else 0,
                "most_common_type": max(
                    ["activity", "sleep", "circadian"],
                    key=lambda t: sum(1 for a in anomalies if a["type"] == t)
                ) if anomalies else None
            }
        }
    
    def predict_mood_state(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        historical_context: dict[str, Any] | None = None,
        **kwargs
    ) -> dict[str, Any]:
        """
        Predict mood state based on actigraphy patterns.
        
        Args:
            patient_id: Patient identifier
            readings: Accelerometer readings with timestamp and x,y,z values
            historical_context: Optional historical context for the patient
            **kwargs: Additional parameters
            
        Returns:
            Dict containing mood state predictions
        """
        self._validate_initialization()
        
        logger.info(f"Mock predicting mood state for patient {patient_id}")
        
        # Generate random mood predictions
        mood_states = ["neutral", "positive", "negative", "mixed"]
        mood_weights = [0.4, 0.2, 0.3, 0.1]  # Probabilities for each state
        
        # Generate predictions for each day
        if readings:
            # Extract timestamps and group by day
            timestamps = [r.get("timestamp", "2025-01-01T00:00:00Z") for r in readings]
            dates = list(set(t.split("T")[0] for t in timestamps))
            dates.sort()
        else:
            # Generate random dates if no readings provided
            base_date = datetime.now()
            dates = [(base_date - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]
        
        predictions = []
        for date in dates:
            mood_state = random.choices(mood_states, weights=mood_weights)[0]
            
            if mood_state == "positive":
                valence = random.uniform(0.5, 1.0)
                arousal = random.uniform(0.0, 1.0)
            elif mood_state == "negative":
                valence = random.uniform(-1.0, -0.2)
                arousal = random.uniform(-0.5, 0.5)
            elif mood_state == "neutral":
                valence = random.uniform(-0.2, 0.2)
                arousal = random.uniform(-0.2, 0.2)
            else:  # mixed
                valence = random.uniform(-0.5, 0.5)
                arousal = random.uniform(-0.5, 0.5)
            
            predictions.append({
                "date": date,
                "mood_state": mood_state,
                "valence": valence,
                "arousal": arousal,
                "confidence": random.uniform(0.6, 0.9)
            })
        
        # Generate contributing factors
        factors = []
        possible_factors = [
            "sleep_quality", "physical_activity", "circadian_regularity", 
            "social_activity", "environmental_factors"
        ]
        
        for factor in random.sample(possible_factors, random.randint(2, len(possible_factors))):
            factors.append({
                "factor": factor,
                "contribution": random.uniform(0.3, 0.9),
                "direction": random.choice(["positive", "negative"])
            })
        
        return {
            "patient_id": patient_id,
            "analysis_id": f"mood_{int(time.time())}",
            "data_points": len(readings),
            "mood_predictions": predictions,
            "confidence": {
                "overall": random.uniform(0.6, 0.9),
                "factors": random.uniform(0.5, 0.8)
            },
            "factors": factors
        }
    
    def integrate_with_digital_twin(
        self,
        patient_id: str,
        profile_id: str,
        actigraphy_analysis: dict[str, Any],
        **kwargs
    ) -> dict[str, Any]:
        """
        Integrate actigraphy analysis with digital twin profile.
        
        Args:
            patient_id: Patient identifier
            profile_id: Digital twin profile identifier
            actigraphy_analysis: Results from actigraphy analysis
            **kwargs: Additional parameters
            
        Returns:
            Dict containing integrated digital twin profile
        """
        self._validate_initialization()
        
        logger.info(f"Mock integrating actigraphy analysis with digital twin for patient {patient_id}")
        
        # Generate mock integrated profile
        integrated_profile = {
            "profile_id": profile_id,
            "patient_id": patient_id,
            "last_updated": datetime.now().isoformat() + "Z",
            "biometric_components": {
                "actigraphy": {
                    "last_analysis": datetime.now().isoformat() + "Z",
                    "sleep_quality": random.uniform(0.3, 0.9),
                    "activity_level": random.uniform(0.3, 0.9),
                    "circadian_regularity": random.uniform(0.3, 0.9),
                    "mood_indicators": {
                        "valence": random.uniform(-0.5, 0.5),
                        "arousal": random.uniform(-0.3, 0.7)
                    }
                }
            },
            "clinical_implications": {
                "depression_risk": {
                    "score": random.uniform(0.1, 0.7),
                    "contributing_factors": [
                        {"factor": "sleep_disruption", "weight": random.uniform(0.3, 0.9)},
                        {"factor": "activity_reduction", "weight": random.uniform(0.3, 0.9)},
                        {"factor": "circadian_disruption", "weight": random.uniform(0.3, 0.9)}
                    ]
                },
                "anxiety_indicators": {
                    "score": random.uniform(0.1, 0.7),
                    "contributing_factors": [
                        {"factor": "sleep_fragmentation", "weight": random.uniform(0.3, 0.9)},
                        {"factor": "activity_irregularity", "weight": random.uniform(0.3, 0.9)}
                    ]
                },
                "treatment_response": {
                    "trend": random.choice(["improving", "stable", "declining"]),
                    "confidence": random.uniform(0.5, 0.9)
                }
            },
            "integration_quality": {
                "confidence": random.uniform(0.6, 0.9),
                "data_completeness": random.uniform(0.7, 1.0)
            }
        }
        
        return {
            "patient_id": patient_id,
            "profile_id": profile_id,
            "integration_id": f"integration_{int(time.time())}",
            "integrated_profile": integrated_profile,
            "integration_summary": {
                "status": "success",
                "components_integrated": ["actigraphy", "clinical_data"],
                "confidence": random.uniform(0.7, 0.95)
            }
        }
