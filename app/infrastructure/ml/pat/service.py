"""
Pretrained Actigraphy Transformer (PAT) Service.

This module provides the implementation of the PAT service for analyzing
actigraphy data from wearable devices using transformer-based models.
"""

import json
import logging
import os
import time
from datetime import datetime
from enum import Enum
from typing import Any

import numpy as np
import tensorflow as tf

from app.core.config.settings import get_settings  # Import main settings function

# import sagemaker # Removed unused import
# from sagemaker.predictor import Predictor # Removed unused import
# Removed incorrect ml_settings import
# from app.config.ml_settings import ml_settings
from app.core.exceptions import (
    AnalysisError,
    ModelNotFoundError,
    ValidationError,  # Replaced DataPreprocessingError
)
from app.core.domain.entities.actigraphy_analysis import ActigraphyAnalysis
from app.core.domain.entities.patient import Patient

logger = logging.getLogger(__name__)


class PATModelSize(str, Enum):
    """Enumeration of available PAT model sizes."""
    
    SMALL = "small"  # PAT-S: ~10M parameters
    MEDIUM = "medium"  # PAT-M: ~50M parameters
    LARGE = "large"  # PAT-L: ~100M parameters


class AnalysisType(str, Enum):
    """Enumeration of actigraphy analysis types."""
    
    SLEEP_QUALITY = "sleep_quality"
    ACTIVITY_PATTERNS = "activity_patterns"
    CIRCADIAN_RHYTHM = "circadian_rhythm"
    ENERGY_EXPENDITURE = "energy_expenditure"
    MENTAL_STATE_CORRELATION = "mental_state_correlation"
    MEDICATION_RESPONSE = "medication_response"


class PATService:
    """
    Pretrained Actigraphy Transformer (PAT) service.
    
    This service provides functionality for analyzing actigraphy data
    from wearable devices to extract patterns related to physical activity,
    sleep, and other biometric indicators relevant to mental health assessment.
    """
    
    def __init__(
        self,
        model_size: PATModelSize = PATModelSize.MEDIUM,
        model_path: str | None = None,
        cache_dir: str | None = None,
        use_gpu: bool = True
    ):
        """
        Initialize the PAT service.
        
        Args:
            model_size: Size of the PAT model to use
            model_path: Custom path to model weights (overrides settings)
            cache_dir: Directory for caching model outputs (overrides settings)
            use_gpu: Whether to use GPU acceleration (overrides settings)
        """
        settings = get_settings() # Get settings object
        self.model_size = model_size
        # Use provided path, otherwise use path from settings based on model_size
        self.model_path = model_path or os.path.join(
            settings.ml.models_path, f"pat-{model_size.value}"
        ) 
        # Use provided cache_dir, otherwise use default PAT cache from settings
        self.cache_dir = cache_dir or settings.ml.pat.cache_dir 
        # Use provided GPU flag, otherwise use flag from settings
        self.use_gpu = use_gpu if use_gpu is not None else settings.ml.pat.use_gpu 
        self.model = None
        self.initialized = False
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Configure TensorFlow to use GPU if available and requested
        if self.use_gpu:
            physical_devices = tf.config.list_physical_devices('GPU')
            if physical_devices:
                try:
                    for device in physical_devices:
                        tf.config.experimental.set_memory_growth(device, True)
                    logger.info(f"GPU acceleration enabled with {len(physical_devices)} devices")
                except Exception as e:
                    logger.warning(f"Error configuring GPU: {e}")
            else:
                logger.warning("GPU acceleration requested but no GPU devices found")
    
    async def initialize(self) -> None:
        """
        Initialize the PAT model.
        
        This method loads the model weights and prepares the model for inference.
        It should be called before using the service.
        """
        if self.initialized:
            return
        
        try:
            logger.info(f"Loading PAT model (size: {self.model_size.value}) from {self.model_path}")
            
            # Check if model path exists
            if not os.path.exists(self.model_path):
                raise ModelNotFoundError(f"PAT model not found at {self.model_path}")
            
            # Load the model (implementation depends on how the model is saved)
            # For TensorFlow SavedModel format:
            self.model = tf.saved_model.load(self.model_path)
            
            self.initialized = True
            logger.info("PAT model successfully loaded")
        except Exception as e:
            logger.error(f"Failed to initialize PAT model: {e}")
            raise
    
    async def preprocess_actigraphy_data(
        self, 
        raw_data: list[dict[str, Any]] | np.ndarray,
        sampling_rate: float = 30.0,  # Default: 30 Hz
        window_size: int = 86400,     # Default: 1 day in seconds
        normalize: bool = True
    ) -> np.ndarray:
        """
        Preprocess raw actigraphy data for model input.
        
        Args:
            raw_data: Raw actigraphy data from wearable device
            sampling_rate: Sampling rate of the data in Hz
            window_size: Size of the analysis window in seconds
            normalize: Whether to normalize the data
            
        Returns:
            Preprocessed data ready for model input
        """
        try:
            # Convert to numpy array if not already
            if isinstance(raw_data, list):
                # Assuming raw_data is a list of dictionaries with 'timestamp' and 'x', 'y', 'z' keys
                timestamps = []
                x_values = []
                y_values = []
                z_values = []
                
                for entry in raw_data:
                    timestamps.append(datetime.fromisoformat(entry['timestamp']).timestamp())
                    x_values.append(float(entry['x']))
                    y_values.append(float(entry['y']))
                    z_values.append(float(entry['z']))
                
                # Create a structured array
                data = np.column_stack((x_values, y_values, z_values))
            else:
                # Assuming raw_data is already a numpy array
                data = raw_data
            
            # Resample to ensure consistent sampling rate
            # This is a simplified implementation; actual resampling would be more complex
            target_length = int(window_size * sampling_rate)
            if len(data) > target_length:
                # Downsample
                indices = np.linspace(0, len(data) - 1, target_length, dtype=int)
                data = data[indices]
            elif len(data) < target_length:
                # Upsample (simple repetition, in practice would use interpolation)
                ratio = target_length / len(data)
                data = np.repeat(data, int(np.ceil(ratio)), axis=0)[:target_length]
            
            # Normalize if requested
            if normalize:
                # Z-score normalization
                data = (data - np.mean(data, axis=0)) / np.std(data, axis=0)
            
            # Reshape for model input (batch_size=1, sequence_length, features)
            data = data.reshape(1, -1, data.shape[-1])
            
            return data
        except Exception as e:
            logger.error(f"Error preprocessing actigraphy data: {e}")
            raise ValidationError(f"Failed to preprocess actigraphy data: {e}")
    
    async def analyze(
        self,
        actigraphy_data: list[dict[str, Any]] | np.ndarray,
        analysis_type: AnalysisType,
        patient_metadata: dict[str, Any] | None = None,
        cache_results: bool = True
    ) -> dict[str, Any]:
        """
        Analyze actigraphy data using the PAT model.
        
        Args:
            actigraphy_data: Raw actigraphy data from wearable device
            analysis_type: Type of analysis to perform
            patient_metadata: Additional patient data for context
            cache_results: Whether to cache the results
            
        Returns:
            Analysis results
        """
        if not self.initialized:
            await self.initialize()
        
        # Generate a cache key if caching is enabled
        cache_key = None
        if cache_results:
            # Create a deterministic cache key based on input data and analysis type
            data_hash = hash(str(actigraphy_data))
            cache_key = f"{analysis_type.value}_{data_hash}_{self.model_size.value}"
            cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
            
            # Check if cached results exist
            if os.path.exists(cache_file):
                try:
                    with open(cache_file) as f:
                        cached_results = json.load(f)
                    logger.info(f"Using cached results for {analysis_type.value}")
                    return cached_results
                except Exception as e:
                    logger.warning(f"Failed to load cached results: {e}")
        
        try:
            # Preprocess the data
            processed_data = await self.preprocess_actigraphy_data(actigraphy_data)
            
            # Run model inference
            start_time = time.time()
            
            # The actual inference depends on how the model is implemented
            # This is a placeholder for the actual model call
            raw_predictions = self.model(processed_data)
            
            inference_time = time.time() - start_time
            logger.info(f"PAT inference completed in {inference_time:.2f} seconds")
            
            # Process the raw predictions based on analysis type
            results = await self._process_predictions(raw_predictions, analysis_type, patient_metadata)
            
            # Cache results if enabled
            if cache_results and cache_key:
                try:
                    with open(os.path.join(self.cache_dir, f"{cache_key}.json"), 'w') as f:
                        json.dump(results, f)
                except Exception as e:
                    logger.warning(f"Failed to cache results: {e}")
            
            return results
        except Exception as e:
            logger.error(f"Error during PAT analysis: {e}")
            raise AnalysisError(f"Failed to analyze actigraphy data: {e}")
    
    async def _process_predictions(
        self,
        predictions: Any,
        analysis_type: AnalysisType,
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Process raw model predictions into structured results.
        
        Args:
            predictions: Raw model output
            analysis_type: Type of analysis performed
            patient_metadata: Additional patient data for context
            
        Returns:
            Structured analysis results
        """
        # Convert predictions to numpy if they're TensorFlow tensors
        if isinstance(predictions, tf.Tensor):
            predictions = predictions.numpy()
        
        # Base result structure
        results = {
            "analysis_type": analysis_type.value,
            "timestamp": datetime.now().isoformat(),
            "model_version": f"PAT-{self.model_size.value.upper()}",
            "confidence_score": None,
            "metrics": {},
            "insights": [],
            "warnings": []
        }
        
        # Process based on analysis type
        if analysis_type == AnalysisType.SLEEP_QUALITY:
            results = await self._process_sleep_quality(predictions, results, patient_metadata)
        elif analysis_type == AnalysisType.ACTIVITY_PATTERNS:
            results = await self._process_activity_patterns(predictions, results, patient_metadata)
        elif analysis_type == AnalysisType.CIRCADIAN_RHYTHM:
            results = await self._process_circadian_rhythm(predictions, results, patient_metadata)
        elif analysis_type == AnalysisType.ENERGY_EXPENDITURE:
            results = await self._process_energy_expenditure(predictions, results, patient_metadata)
        elif analysis_type == AnalysisType.MENTAL_STATE_CORRELATION:
            results = await self._process_mental_state_correlation(predictions, results, patient_metadata)
        elif analysis_type == AnalysisType.MEDICATION_RESPONSE:
            results = await self._process_medication_response(predictions, results, patient_metadata)
        
        return results
    
    async def _process_sleep_quality(
        self,
        predictions: np.ndarray,
        results: dict[str, Any],
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process sleep quality analysis results."""
        # This is a placeholder implementation
        # In a real implementation, this would extract sleep metrics from the model predictions
        
        # Example sleep metrics
        results["metrics"] = {
            "total_sleep_time": float(np.random.normal(7.5, 1.0)),  # hours
            "sleep_efficiency": float(np.random.normal(0.85, 0.1)),  # percentage
            "sleep_latency": float(np.random.normal(15, 5)),  # minutes
            "wake_after_sleep_onset": float(np.random.normal(30, 10)),  # minutes
            "rem_percentage": float(np.random.normal(0.25, 0.05)),  # percentage
            "deep_sleep_percentage": float(np.random.normal(0.20, 0.05)),  # percentage
            "light_sleep_percentage": float(np.random.normal(0.55, 0.05)),  # percentage
            "sleep_disruptions": int(np.random.normal(3, 1))  # count
        }
        
        # Example insights
        sleep_efficiency = results["metrics"]["sleep_efficiency"]
        if sleep_efficiency < 0.7:
            results["insights"].append("Poor sleep efficiency detected. Consider sleep hygiene interventions.")
        elif sleep_efficiency < 0.8:
            results["insights"].append("Moderate sleep efficiency. Monitor for changes in sleep patterns.")
        else:
            results["insights"].append("Good sleep efficiency observed.")
        
        # Add confidence score
        results["confidence_score"] = float(np.random.normal(0.85, 0.05))
        
        return results
    
    async def _process_activity_patterns(
        self,
        predictions: np.ndarray,
        results: dict[str, Any],
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process activity patterns analysis results."""
        # Placeholder implementation
        
        results["metrics"] = {
            "daily_step_count": int(np.random.normal(8000, 2000)),
            "sedentary_hours": float(np.random.normal(8, 2)),
            "light_activity_hours": float(np.random.normal(4, 1)),
            "moderate_activity_minutes": float(np.random.normal(30, 15)),
            "vigorous_activity_minutes": float(np.random.normal(15, 10)),
            "activity_regularity": float(np.random.normal(0.7, 0.1))
        }
        
        # Example insights
        daily_steps = results["metrics"]["daily_step_count"]
        if daily_steps < 5000:
            results["insights"].append("Low physical activity detected. Consider gradual increase in daily movement.")
        elif daily_steps < 7500:
            results["insights"].append("Moderate physical activity. Encourage maintaining or increasing activity levels.")
        else:
            results["insights"].append("Good physical activity levels observed.")
        
        # Add confidence score
        results["confidence_score"] = float(np.random.normal(0.8, 0.05))
        
        return results
    
    async def _process_circadian_rhythm(
        self,
        predictions: np.ndarray,
        results: dict[str, Any],
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process circadian rhythm analysis results."""
        # Placeholder implementation
        
        results["metrics"] = {
            "sleep_onset_time": f"{int(np.random.normal(23, 1))}:{int(np.random.normal(30, 15)):02d}",
            "wake_time": f"{int(np.random.normal(7, 1))}:{int(np.random.normal(30, 15)):02d}",
            "rhythm_stability": float(np.random.normal(0.75, 0.1)),
            "day_to_day_variation_minutes": float(np.random.normal(25, 10)),
            "social_jet_lag_hours": float(np.random.normal(1.2, 0.5)),
            "light_exposure_morning_lux": float(np.random.normal(1000, 500))
        }
        
        # Example insights
        rhythm_stability = results["metrics"]["rhythm_stability"]
        if rhythm_stability < 0.6:
            results["insights"].append("Irregular circadian rhythm detected. Consider regular sleep-wake schedule.")
        elif rhythm_stability < 0.7:
            results["insights"].append("Moderately stable circadian rhythm. Minor improvements in sleep schedule consistency recommended.")
        else:
            results["insights"].append("Stable circadian rhythm observed.")
        
        # Add confidence score
        results["confidence_score"] = float(np.random.normal(0.82, 0.05))
        
        return results
    
    async def _process_energy_expenditure(
        self,
        predictions: np.ndarray,
        results: dict[str, Any],
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process energy expenditure analysis results."""
        # Placeholder implementation
        
        # Calculate base metabolic rate if height/weight available
        bmr = None
        if patient_metadata and 'height_cm' in patient_metadata and 'weight_kg' in patient_metadata and 'age' in patient_metadata and 'gender' in patient_metadata:
            height = patient_metadata['height_cm']
            weight = patient_metadata['weight_kg']
            age = patient_metadata['age']
            gender = patient_metadata['gender'].lower()
            
            # Mifflin-St Jeor Equation
            if gender == 'male':
                bmr = 10 * weight + 6.25 * height - 5 * age + 5
            else:
                bmr = 10 * weight + 6.25 * height - 5 * age - 161
        
        results["metrics"] = {
            "total_daily_energy_expenditure": int(np.random.normal(2200, 300)),  # kcal
            "base_metabolic_rate": int(bmr) if bmr else int(np.random.normal(1500, 200)),  # kcal
            "active_energy_expenditure": int(np.random.normal(700, 200)),  # kcal
            "activity_level_factor": float(np.random.normal(1.5, 0.2)),
            "peak_energy_hour": int(np.random.normal(14, 2))
        }
        
        # Example insights
        activity_level = results["metrics"]["activity_level_factor"]
        if activity_level < 1.4:
            results["insights"].append("Sedentary activity level detected. Consider increasing daily activity.")
        elif activity_level < 1.6:
            results["insights"].append("Light activity level. Gradual increase in physical activity recommended.")
        else:
            results["insights"].append("Moderate to active lifestyle observed.")
        
        # Add confidence score
        results["confidence_score"] = float(np.random.normal(0.78, 0.05))
        
        return results
    
    async def _process_mental_state_correlation(
        self,
        predictions: np.ndarray,
        results: dict[str, Any],
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process mental state correlation analysis results."""
        # Placeholder implementation
        
        results["metrics"] = {
            "activity_mood_correlation": float(np.random.normal(0.6, 0.2)),
            "sleep_anxiety_correlation": float(np.random.normal(-0.5, 0.2)),
            "circadian_stability_mood_correlation": float(np.random.normal(0.55, 0.15)),
            "activity_variability_stress_correlation": float(np.random.normal(0.4, 0.15)),
            "depression_risk_score": float(np.random.normal(0.3, 0.2)),
            "anxiety_risk_score": float(np.random.normal(0.35, 0.2))
        }
        
        # Example insights
        depression_risk = results["metrics"]["depression_risk_score"]
        anxiety_risk = results["metrics"]["anxiety_risk_score"]
        
        if depression_risk > 0.6:
            results["insights"].append("Activity patterns suggest elevated depression risk. Clinical assessment recommended.")
            results["warnings"].append("Elevated depression risk indicators detected.")
        elif depression_risk > 0.4:
            results["insights"].append("Activity patterns suggest moderate depression risk. Monitor for changes.")
        
        if anxiety_risk > 0.6:
            results["insights"].append("Activity patterns suggest elevated anxiety risk. Clinical assessment recommended.")
            results["warnings"].append("Elevated anxiety risk indicators detected.")
        elif anxiety_risk > 0.4:
            results["insights"].append("Activity patterns suggest moderate anxiety risk. Monitor for changes.")
        
        # Add confidence score
        results["confidence_score"] = float(np.random.normal(0.75, 0.08))
        
        return results
    
    async def _process_medication_response(
        self,
        predictions: np.ndarray,
        results: dict[str, Any],
        patient_metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process medication response analysis results."""
        # Placeholder implementation
        
        # Check if medication information is available
        medication_name = "Unknown"
        if patient_metadata and 'medications' in patient_metadata and patient_metadata['medications']:
            # Use the most recent medication
            medication_name = patient_metadata['medications'][0].get('name', "Unknown")
        
        results["metrics"] = {
            "pre_post_activity_change": float(np.random.normal(0.15, 0.1)),
            "pre_post_sleep_change": float(np.random.normal(0.2, 0.1)),
            "pre_post_circadian_change": float(np.random.normal(0.1, 0.05)),
            "side_effect_probability": float(np.random.normal(0.25, 0.15)),
            "response_trajectory": "improving" if np.random.random() > 0.3 else "stable",
            "days_to_observable_change": int(np.random.normal(14, 5))
        }
        
        # Example insights
        activity_change = results["metrics"]["pre_post_activity_change"]
        sleep_change = results["metrics"]["pre_post_sleep_change"]
        
        results["insights"].append(f"Analysis of response to {medication_name}:")
        
        if activity_change > 0.2:
            results["insights"].append("Significant positive change in activity patterns observed.")
        elif activity_change > 0.1:
            results["insights"].append("Moderate positive change in activity patterns observed.")
        elif activity_change < -0.1:
            results["insights"].append("Negative change in activity patterns observed. Consider clinical review.")
            results["warnings"].append("Potential negative medication effect on activity detected.")
        
        if sleep_change > 0.2:
            results["insights"].append("Significant improvement in sleep patterns observed.")
        elif sleep_change > 0.1:
            results["insights"].append("Moderate improvement in sleep patterns observed.")
        elif sleep_change < -0.1:
            results["insights"].append("Negative impact on sleep patterns observed. Consider clinical review.")
            results["warnings"].append("Potential negative medication effect on sleep detected.")
        
        # Add confidence score
        results["confidence_score"] = float(np.random.normal(0.7, 0.1))
        
        return results
    
    async def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the loaded PAT model.
        
        Returns:
            Dictionary with model information
        """
        if not self.initialized:
            await self.initialize()
        
        return {
            "model_name": f"PAT-{self.model_size.value.upper()}",
            "model_size": self.model_size.value,
            "model_path": self.model_path,
            "parameters": {
                "small": "~10M",
                "medium": "~50M",
                "large": "~100M"
            }[self.model_size.value],
            "supported_analysis_types": [t.value for t in AnalysisType],
            "gpu_enabled": self.use_gpu,
            "cache_enabled": bool(self.cache_dir)
        }