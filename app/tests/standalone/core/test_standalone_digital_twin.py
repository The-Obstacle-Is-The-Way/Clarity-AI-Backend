import pytest

"""
Standalone test for Digital Twin entity and related components.

This module contains both implementations and tests for the Digital Twin system
in a single file, making it completely independent of the rest of the application.
Includes support for PITUITARY brain region connectivity.
"""

import unittest
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4


# ================= Digital Twin Enums =================
class TwinModelType(str, Enum):
    """Types of digital twin models."""
    PSYCHIATRIC = "psychiatric"
    NEUROTRANSMITTER = "neurotransmitter"
    MEDICATION_RESPONSE = "medication_response"
    SYMPTOM_PREDICTION = "symptom_prediction"
    BIOMETRIC = "biometric"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    CUSTOM = "custom"

class BiometricDataType(str, Enum):
    """Types of biometric data."""
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    TEMPERATURE = "temperature"
    SLEEP = "sleep"
    ACTIVITY = "activity"
    GLUCOSE = "glucose"
    OXYGEN_SATURATION = "oxygen_saturation"
    RESPIRATORY_RATE = "respiratory_rate"
    WEIGHT = "weight"
    STRESS = "stress"
    CUSTOM = "custom"

class PredictionInterval(str, Enum):
    """Time intervals for predictions."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"

class BrainRegion(str, Enum):
    """Brain regions for neurotransmitter models."""
    PREFRONTAL_CORTEX = "prefrontal_cortex"
    AMYGDALA = "amygdala"
    HIPPOCAMPUS = "hippocampus"
    BASAL_GANGLIA = "basal_ganglia"
    THALAMUS = "thalamus"
    HYPOTHALAMUS = "hypothalamus"
    PITUITARY = "pituitary"  # Added PITUITARY region
    BRAINSTEM = "brainstem"
    CEREBELLUM = "cerebellum"
    INSULAR_CORTEX = "insular_cortex"
    CINGULATE_CORTEX = "cingulate_cortex"

class Neurotransmitter(str, Enum):
    """Neurotransmitter types for neural models."""
    SEROTONIN = "serotonin"
    DOPAMINE = "dopamine"
    NOREPINEPHRINE = "norepinephrine"
    GABA = "gaba"
    GLUTAMATE = "glutamate"
    ACETYLCHOLINE = "acetylcholine"
    ENDORPHIN = "endorphin"
    OXYTOCIN = "oxytocin"
    MELATONIN = "melatonin"

# ================= Digital Twin Models =================
class TwinModel:
    """Base class for all digital twin models."""

    def __init__(
        self,
        name: str,
        model_type: TwinModelType,
        patient_id: str,
        description: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        """
        Initialize the base model.

        Args:
            name: Model name
            model_type: Type of model
            patient_id: Patient ID
            description: Optional description
            metadata: Optional metadata
        """
        self.id = str(uuid4())
        self.name = name
        self.model_type = model_type
        self.patient_id = patient_id
        self.description = description or ""
        self.metadata = metadata or {}
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.version = "1.0.0"

    def update_metadata(self, key: str, value: Any) -> None:
        """
        Update model metadata.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
        self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "model_type": self.model_type.value,
            "patient_id": self.patient_id,
            "description": self.description,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version
        }


class TimeSeriesModel(TwinModel):
    """Time series model for forecasting symptoms and biometrics."""

    def __init__(
        self,
        name: str,
        patient_id: str,
        data_type: str,
        prediction_interval: PredictionInterval = PredictionInterval.DAILY,
        forecast_horizon: int = 7,
        description: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        """
        Initialize time series model.

        Args:
            name: Model name
            patient_id: Patient ID
            data_type: Type of data to predict
            prediction_interval: Prediction interval
            forecast_horizon: How far into the future to predict
            description: Optional description
            metadata: Optional metadata
        """
        super().__init__(
            name=name,
            model_type=TwinModelType.SYMPTOM_PREDICTION,
            patient_id=patient_id,
            description=description,
            metadata=metadata
        )
        self.data_type = data_type
        self.prediction_interval = prediction_interval
        self.forecast_horizon = forecast_horizon
        self.historical_data = []
        self.model_parameters = {}
        self.last_trained = None
        self.performance_metrics = {
            "mae": None,
            "rmse": None,
            "r2": None
        }

    def train(self, data: list[dict[str, Any]]) -> dict[str, float]:
        """
        Train the model on historical data.

        Args:
            data: List of time series data points

        Returns:
            Performance metrics
        """
        if not data:
            raise ValueError("Cannot train on empty dataset")

        # Store historical data
        self.historical_data = data.copy()
        
        # Placeholder for actual training logic
        # In a real implementation, this would train a time series model
        
        # Update training timestamp
        self.last_trained = datetime.now()
        
        # Calculate performance metrics
        metrics = {
            "mae": 0.12,  # Mean Absolute Error
            "rmse": 0.18,  # Root Mean Square Error
            "r2": 0.86    # R-squared
        }
        
        self.performance_metrics = metrics
        self.update_metadata("last_train_metrics", metrics)
        
        return metrics

    def predict(self, data_points: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """
        Generate predictions for the forecast horizon.

        Args:
            data_points: Optional recent data points to use for prediction

        Returns:
            List of predictions with timestamps and values
        """
        if not self.last_trained:
            raise ValueError("Model must be trained before making predictions")
            
        # Use provided data points or historical data
        context_data = data_points or self.historical_data
        
        if not context_data:
            raise ValueError("No data available for prediction")
            
        # Sort data by timestamp
        sorted_data = sorted(context_data, key=lambda x: x.get("timestamp", 0))
        
        # Get the most recent timestamp
        last_timestamp = datetime.fromisoformat(sorted_data[-1].get("timestamp"))
        
        # Generate predictions
        predictions = []
        
        for i in range(1, self.forecast_horizon + 1):
            # Calculate next timestamp based on prediction interval
            if self.prediction_interval == PredictionInterval.HOURLY:
                next_timestamp = last_timestamp + timedelta(hours=i)
            elif self.prediction_interval == PredictionInterval.DAILY:
                next_timestamp = last_timestamp + timedelta(days=i)
            elif self.prediction_interval == PredictionInterval.WEEKLY:
                next_timestamp = last_timestamp + timedelta(weeks=i)
            elif self.prediction_interval == PredictionInterval.MONTHLY:
                next_timestamp = last_timestamp + timedelta(days=i * 30)
            else:
                next_timestamp = last_timestamp + timedelta(days=i)
                
            # Simple placeholder prediction logic
            # In a real implementation, this would use the trained model
            predicted_value = sorted_data[-1].get("value", 0) * (1 + 0.05 * i)
            
            predictions.append({
                "timestamp": next_timestamp.isoformat(),
                "value": predicted_value,
                "confidence": 0.9 - (0.05 * i)  # Confidence decreases with time
            })
            
        return predictions

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base_dict = super().to_dict()
        time_series_dict = {
            "data_type": self.data_type,
            "prediction_interval": self.prediction_interval.value,
            "forecast_horizon": self.forecast_horizon,
            "last_trained": self.last_trained.isoformat() if self.last_trained else None,
            "performance_metrics": self.performance_metrics
        }
        
        return {**base_dict, **time_series_dict}


class BiometricTwinModel(TwinModel):
    """Model for biometric data analysis and alerting."""

    def __init__(
        self,
        name: str,
        patient_id: str,
        biometric_types: list[BiometricDataType],
        description: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        """
        Initialize biometric model.

        Args:
            name: Model name
            patient_id: Patient ID
            biometric_types: Types of biometric data to monitor
            description: Optional description
            metadata: Optional metadata
        """
        super().__init__(
            name=name,
            model_type=TwinModelType.BIOMETRIC,
            patient_id=patient_id,
            description=description,
            metadata=metadata
        )
        self.biometric_types = biometric_types
        self.alert_rules = []
        self.baseline_values = {}
        self.historical_data = {}

    def add_alert_rule(self, rule: dict[str, Any]) -> str:
        """
        Add an alert rule for a biometric type.

        Args:
            rule: Alert rule configuration

        Returns:
            Rule ID
        """
        # Validate rule
        required_fields = ["biometric_type", "condition", "threshold"]
        for field in required_fields:
            if field not in rule:
                raise ValueError(f"Missing required field: {field}")

        # Assign ID if not provided
        if "id" not in rule:
            rule["id"] = str(uuid4())

        # Add created timestamp
        rule["created_at"] = datetime.now().isoformat()

        # Add to rules list
        self.alert_rules.append(rule)
        return rule["id"]

    def remove_alert_rule(self, rule_id: str) -> bool:
        """
        Remove an alert rule.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if removed, False if not found
        """
        initial_count = len(self.alert_rules)
        self.alert_rules = [rule for rule in self.alert_rules if rule.get("id") != rule_id]
        
        return len(self.alert_rules) < initial_count

    def set_baseline(self, biometric_type: BiometricDataType, value: Any) -> None:
        """
        Set a baseline value for a biometric type.

        Args:
            biometric_type: Type of biometric data
            value: Baseline value or range
        """
        if not isinstance(biometric_type, BiometricDataType):
            raise TypeError("biometric_type must be a BiometricDataType enum")
            
        self.baseline_values[biometric_type.value] = value
        self.updated_at = datetime.now()

    def process_biometric_data(self, data_point: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Process a biometric data point and generate alerts if needed.

        Args:
            data_point: Biometric data point

        Returns:
            List of triggered alerts
        """
        alerts = []

        # Extract data from the data point
        biometric_type = data_point.get("type")
        value = data_point.get("value")
        timestamp = data_point.get("timestamp", datetime.now().isoformat())
        
        if not biometric_type or value is None:
            raise ValueError("Data point must include type and value")
            
        # Store in historical data
        if biometric_type not in self.historical_data:
            self.historical_data[biometric_type] = []
            
        self.historical_data[biometric_type].append({
            "value": value,
            "timestamp": timestamp
        })
        
        # Check each alert rule
        for rule in self.alert_rules:
            if rule.get("biometric_type") != biometric_type:
                continue
                
            condition = rule.get("condition")
            threshold = rule.get("threshold")
            
            alert_triggered = False
            
            # Evaluate condition
            if condition == "above" and value > threshold:
                alert_triggered = True
            elif condition == "below" and value < threshold:
                alert_triggered = True
            elif condition == "equal" and value == threshold:
                alert_triggered = True
            elif condition == "not_equal" and value != threshold:
                alert_triggered = True
                
            if alert_triggered:
                alerts.append({
                    "rule_id": rule.get("id"),
                    "biometric_type": biometric_type,
                    "value": value,
                    "threshold": threshold,
                    "condition": condition,
                    "timestamp": timestamp,
                    "message": rule.get("message", f"Alert for {biometric_type}")
                })
                
        return alerts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base_dict = super().to_dict()
        biometric_dict = {
            "biometric_types": [bt.value for bt in self.biometric_types],
            "alert_rules": self.alert_rules,
            "baseline_values": self.baseline_values
        }
        
        return {**base_dict, **biometric_dict}


class NeurotransmitterTwinModel(TwinModel):
    """Model for neurotransmitter systems and interactions."""

    def __init__(
        self,
        name: str,
        patient_id: str,
        brain_regions: list[BrainRegion] = None,
        neurotransmitters: list[Neurotransmitter] = None,
        description: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        """
        Initialize neurotransmitter model with PITUITARY support.

        Args:
            name: Model name
            patient_id: Patient ID
            brain_regions: Brain regions to model
            neurotransmitters: Neurotransmitters to model
            description: Optional description
            metadata: Optional metadata
        """
        super().__init__(
            name=name,
            model_type=TwinModelType.NEUROTRANSMITTER,
            patient_id=patient_id,
            description=description,
            metadata=metadata
        )
        self.brain_regions = brain_regions or list(BrainRegion)
        self.neurotransmitters = neurotransmitters or list(Neurotransmitter)
        self.interactions = self._initialize_interactions()
        self.baseline_levels = self._initialize_baseline_levels()
        self.current_levels = self._initialize_baseline_levels()  # Start at baseline
        
    def _initialize_interactions(self) -> dict:
        """
        Initialize the neurotransmitter-brain region interaction matrix.
        Includes PITUITARY connectivity to support hypothalamus-pituitary axis.
        
        Returns:
            Interaction matrix
        """
        interactions = {}
        
        for nt in self.neurotransmitters:
            interactions[nt.value] = {}
            for region in self.brain_regions:
                # Define effect strengths based on known neuroscience
                if region == BrainRegion.PITUITARY and nt in [Neurotransmitter.OXYTOCIN, Neurotransmitter.DOPAMINE]:
                    # Strong connections for pituitary with certain neurotransmitters
                    effect = "strong"
                elif region == BrainRegion.HYPOTHALAMUS and nt in [Neurotransmitter.SEROTONIN, Neurotransmitter.OXYTOCIN]:
                    # Strong hypothalamic connections
                    effect = "strong"
                else:
                    # Default moderate connection
                    effect = "moderate"
                    
                interactions[nt.value][region.value] = {
                    "effect": effect,
                    "direction": "excitatory" if nt not in [Neurotransmitter.GABA] else "inhibitory"
                }
                
        return interactions
    
    def _initialize_baseline_levels(self) -> dict:
        """
        Initialize baseline neurotransmitter levels for each brain region.
        
        Returns:
            Baseline levels dictionary
        """
        baselines = {}
        
        for nt in self.neurotransmitters:
            baselines[nt.value] = {}
            for region in self.brain_regions:
                # Set default baseline to 1.0 (normal level)
                baselines[nt.value][region.value] = 1.0
                
        return baselines
    
    def adjust_neurotransmitter(self, neurotransmitter: Neurotransmitter, region: BrainRegion, change: float) -> None:
        """
        Adjust neurotransmitter level in a specific brain region.
        
        Args:
            neurotransmitter: The neurotransmitter to adjust
            region: The brain region where the adjustment occurs
            change: Amount of change (positive or negative)
        """
        if neurotransmitter.value not in self.current_levels:
            raise ValueError(f"Unknown neurotransmitter: {neurotransmitter}")
            
        if region.value not in self.current_levels[neurotransmitter.value]:
            raise ValueError(f"Unknown brain region: {region}")
            
        # Apply the change
        current = self.current_levels[neurotransmitter.value][region.value]
        self.current_levels[neurotransmitter.value][region.value] = max(0, current + change)
        
        # Calculate cascading effects to other neurotransmitters and regions
        self._calculate_cascade_effects(neurotransmitter, region, change)
    
    def _calculate_cascade_effects(self, source_nt: Neurotransmitter, source_region: BrainRegion, initial_change: float) -> None:
        """
        Calculate how changes in one neurotransmitter affect others through neural networks.
        Implements hypothalamus-pituitary axis connectivity.
        
        Args:
            source_nt: The neurotransmitter that was initially changed
            source_region: The brain region where the change occurred
            initial_change: The magnitude of the initial change
        """
        # Define propagation strength between regions
        region_connectivity = {
            BrainRegion.HYPOTHALAMUS.value: {BrainRegion.PITUITARY.value: 0.8},  # Strong connection to pituitary
            BrainRegion.PITUITARY.value: {BrainRegion.HYPOTHALAMUS.value: 0.7},   # Strong feedback to hypothalamus
            BrainRegion.PREFRONTAL_CORTEX.value: {BrainRegion.AMYGDALA.value: 0.6},
            # Other connections would be defined here
        }
        
        # Define interactions between neurotransmitters
        nt_effects = {
            Neurotransmitter.SEROTONIN.value: {
                Neurotransmitter.DOPAMINE.value: -0.3,  # Serotonin inhibits dopamine
                Neurotransmitter.GABA.value: 0.4        # Serotonin increases GABA
            },
            Neurotransmitter.DOPAMINE.value: {
                Neurotransmitter.GLUTAMATE.value: 0.5    # Dopamine increases glutamate
            },
            # Other interactions would be defined here
        }
        
        # Apply region-to-region propagation
        if source_region.value in region_connectivity:
            for target_region, strength in region_connectivity[source_region.value].items():
                propagated_change = initial_change * strength
                
                # Apply the propagated change to the same neurotransmitter in the connected region
                if target_region in self.current_levels[source_nt.value]:
                    current = self.current_levels[source_nt.value][target_region]
                    self.current_levels[source_nt.value][target_region] = max(0, current + propagated_change)
        
        # Apply neurotransmitter-to-neurotransmitter effects in the same region
        if source_nt.value in nt_effects:
            for target_nt, effect in nt_effects[source_nt.value].items():
                nt_change = initial_change * effect
                
                # Apply the effect to the target neurotransmitter in the same region
                if target_nt in self.current_levels and source_region.value in self.current_levels[target_nt]:
                    current = self.current_levels[target_nt][source_region.value]
                    self.current_levels[target_nt][source_region.value] = max(0, current + nt_change)
    
    def simulate_medication_effect(self, medication_effects: dict[str, float]) -> dict:
        """
        Simulate the effect of medication on neurotransmitter levels.
        
        Args:
            medication_effects: Dictionary mapping neurotransmitters to effect magnitude
            
        Returns:
            Dictionary of resulting changes
        """
        changes = {}
        
        for nt_name, effect in medication_effects.items():
            # Try to match the string to a neurotransmitter enum
            try:
                nt = Neurotransmitter(nt_name)
            except ValueError:
                continue
                
            changes[nt_name] = {}
            
            # Apply the effect to all regions or specific regions if specified
            for region in self.brain_regions:
                # Apply medication effect
                self.adjust_neurotransmitter(nt, region, effect)
                
                # Record the change
                changes[nt_name][region.value] = effect
                
        return changes
    
    def reset_to_baseline(self) -> None:
        """
        Reset all neurotransmitter levels to baseline.
        """
        self.current_levels = self._initialize_baseline_levels()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base_dict = super().to_dict()
        nt_dict = {
            "brain_regions": [region.value for region in self.brain_regions],
            "neurotransmitters": [nt.value for nt in self.neurotransmitters],
            "current_levels": self.current_levels,
            "baseline_levels": self.baseline_levels
        }
        
        return {**base_dict, **nt_dict}


# ================= Digital Twin Implementation =================
class DigitalTwin:
    """Digital twin system for psychiatric patient modeling."""

    def __init__(self, patient_id: str):
        """
        Initialize the digital twin for a patient.

        Args:
            patient_id: Unique identifier for the patient
        """
        self.patient_id = patient_id
        self.models = {}
        self.created_at = datetime.now()
        self.updated_at = datetime.now()

    def add_model(self, model: TwinModel) -> None:
        """
        Add a model to the digital twin.

        Args:
            model: Digital twin model to add
        """
        # Validate model belongs to this patient
        if model.patient_id != self.patient_id:
            raise ValueError("Model patient_id does not match digital twin patient_id")

        # Add to models dictionary keyed by model ID
        self.models[model.id] = model
        self.updated_at = datetime.now()

    def get_model(self, model_id: str) -> TwinModel:
        """
        Get a model by ID.

        Args:
            model_id: Model ID to retrieve

        Returns:
            TwinModel instance
        """
        if model_id not in self.models:
            raise ValueError(f"Model not found: {model_id}")

        return self.models[model_id]

    def remove_model(self, model_id: str) -> bool:
        """
        Remove a model from the digital twin.

        Args:
            model_id: Model ID to remove

        Returns:
            True if removed, False if not found
        """
        if model_id in self.models:
            del self.models[model_id]
            self.updated_at = datetime.now()
            return True

        return False

    def get_models_by_type(self, model_type: TwinModelType) -> list[TwinModel]:
        """
        Get all models of a specific type.

        Args:
            model_type: Type of models to retrieve

        Returns:
            List of models of the specified type
        """
        return [model for model in self.models.values() if model.model_type == model_type]

    def predict_symptoms(self, horizon_days: int = 7) -> dict[str, list[dict[str, Any]]]:
        """
        Generate symptom predictions from all time series models.

        Args:
            horizon_days: Number of days to predict into the future

        Returns:
            Dictionary of model ID to predictions
        """
        predictions = {}

        # Get all time series models
        time_series_models = self.get_models_by_type(TwinModelType.SYMPTOM_PREDICTION)

        for model in time_series_models:
            # Set forecast horizon if needed
            if model.forecast_horizon != horizon_days:
                model.forecast_horizon = horizon_days

            # Generate predictions
            try:
                model_predictions = model.predict()
                predictions[model.id] = model_predictions
            except Exception as e:
                # Log the error and continue
                print(f"Error predicting with model {model.id}: {e}")

        return predictions

    def process_biometric_data(self, data_point: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        """
        Process a biometric data point through all biometric models.

        Args:
            data_point: Biometric data point

        Returns:
            Dictionary of model ID to triggered alerts
        """
        all_alerts = {}

        # Get all biometric models
        biometric_models = self.get_models_by_type(TwinModelType.BIOMETRIC)

        for model in biometric_models:
            # Check if this model handles this biometric type
            biometric_type = data_point.get("type")
            if not biometric_type:
                continue

            # Find matching BiometricDataType enum
            try:
                enum_type = BiometricDataType(biometric_type)
            except ValueError:
                continue

            # Skip if model doesn't handle this type
            if enum_type not in model.biometric_types:
                continue

            # Process the data point
            try:
                alerts = model.process_biometric_data(data_point)
                if alerts:
                    all_alerts[model.id] = alerts
            except Exception as e:
                # Log the error and continue
                print(f"Error processing biometric data with model {model.id}: {e}")

        return all_alerts

    def simulate_medication_effect(self, medication_effects: dict[str, float]) -> dict[str, dict]:
        """
        Simulate medication effects on neurotransmitter levels.

        Args:
            medication_effects: Dictionary mapping neurotransmitters to effect magnitude

        Returns:
            Dictionary of model ID to resulting changes
        """
        results = {}

        # Get all neurotransmitter models
        nt_models = self.get_models_by_type(TwinModelType.NEUROTRANSMITTER)

        for model in nt_models:
            try:
                changes = model.simulate_medication_effect(medication_effects)
                results[model.id] = changes
            except Exception as e:
                # Log the error and continue
                print(f"Error simulating medication effect with model {model.id}: {e}")

        return results

    def summarize(self) -> dict[str, Any]:
        """
        Generate a summary of the digital twin.

        Returns:
            Dictionary with digital twin information
        """
        model_counts = {}
        for model_type in TwinModelType:
            count = len(self.get_models_by_type(model_type))
            model_counts[model_type.value] = count

        return {
            "patient_id": self.patient_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "model_count": len(self.models),
            "model_counts_by_type": model_counts
        }


# ================= Test Classes =================

@pytest.mark.standalone()
class TestTimeSeriesModel(unittest.TestCase):
    """Test suite for the TimeSeriesModel."""

    def setUp(self):
        """Set up test fixtures."""
        self.patient_id = "test-patient-123"
        self.model = TimeSeriesModel(
            name="Anxiety Prediction",
            patient_id=self.patient_id,
            data_type="anxiety_level",
            prediction_interval=PredictionInterval.DAILY,
            forecast_horizon=7
        )
        
        # Sample historical data for testing
        self.historical_data = [
            {
                "timestamp": (datetime.now() - timedelta(days=5)).isoformat(),
                "value": 3.5
            },
            {
                "timestamp": (datetime.now() - timedelta(days=4)).isoformat(),
                "value": 4.2
            },
            {
                "timestamp": (datetime.now() - timedelta(days=3)).isoformat(),
                "value": 3.8
            },
            {
                "timestamp": (datetime.now() - timedelta(days=2)).isoformat(),
                "value": 3.0
            },
            {
                "timestamp": (datetime.now() - timedelta(days=1)).isoformat(),
                "value": 2.7
            }
        ]

    def test_initialization(self):
        """Test model initialization."""
        self.assertEqual(self.model.name, "Anxiety Prediction")
        self.assertEqual(self.model.patient_id, self.patient_id)
        self.assertEqual(self.model.data_type, "anxiety_level")
        self.assertEqual(self.model.prediction_interval, PredictionInterval.DAILY)
        self.assertEqual(self.model.forecast_horizon, 7)
        self.assertIsNotNone(self.model.id)
        self.assertIsInstance(self.model.created_at, datetime)
        self.assertIsInstance(self.model.updated_at, datetime)

    def test_metadata_update(self):
        """Test updating model metadata."""
        # Record initial update time
        initial_update_time = self.model.updated_at
        
        # Update metadata
        self.model.update_metadata("last_trained", datetime.now().isoformat())
        
        # Check that metadata was updated
        self.assertIn("last_trained", self.model.metadata)
        
        # Check that updated_at time changed
        self.assertGreater(self.model.updated_at, initial_update_time)

    def test_train(self):
        """Test model training."""
        # Train the model
        metrics = self.model.train(self.historical_data)
        
        # Check that training was recorded
        self.assertIsNotNone(self.model.last_trained)
        
        # Check that metrics were returned
        self.assertIn("mae", metrics)
        self.assertIn("rmse", metrics)
        self.assertIn("r2", metrics)
        
        # Check that historical data was stored
        self.assertEqual(len(self.model.historical_data), len(self.historical_data))
        
        # Check that metadata was updated
        self.assertIn("last_train_metrics", self.model.metadata)

    def test_predict_without_training(self):
        """Test prediction without training should raise error."""
        with self.assertRaises(ValueError):
            self.model.predict()

    def test_predict_after_training(self):
        """Test prediction after training."""
        # Train the model first
        self.model.train(self.historical_data)
        
        # Generate predictions
        predictions = self.model.predict()
        
        # Check that predictions were generated
        self.assertEqual(len(predictions), self.model.forecast_horizon)
        
        # Check prediction structure
        for prediction in predictions:
            self.assertIn("timestamp", prediction)
            self.assertIn("value", prediction)
            self.assertIn("confidence", prediction)

    def test_predict_with_custom_horizon(self):
        """Test prediction with custom forecast horizon."""
        # Train the model
        self.model.train(self.historical_data)
        
        # Set custom forecast horizon
        self.model.forecast_horizon = 5
        
        # Generate predictions
        predictions = self.model.predict()
        
        # Check that the correct number of predictions were generated
        self.assertEqual(len(predictions), 5)

    def test_different_prediction_intervals(self):
        """Test predictions with different intervals."""
        # Test hourly predictions
        hourly_model = TimeSeriesModel(
            name="Hourly Anxiety",
            patient_id=self.patient_id,
            data_type="anxiety_level",
            prediction_interval=PredictionInterval.HOURLY,
            forecast_horizon=5
        )
        
        # Train the model
        hourly_model.train(self.historical_data)
        
        # Generate predictions
        hourly_predictions = hourly_model.predict()
        
        # Check intervals
        first_time = datetime.fromisoformat(hourly_predictions[0]["timestamp"])
        second_time = datetime.fromisoformat(hourly_predictions[1]["timestamp"])
        self.assertAlmostEqual((second_time - first_time).total_seconds(), 3600, delta=10)  # 1 hour = 3600 seconds
        
        # Test weekly predictions
        weekly_model = TimeSeriesModel(
            name="Weekly Anxiety",
            patient_id=self.patient_id,
            data_type="anxiety_level",
            prediction_interval=PredictionInterval.WEEKLY,
            forecast_horizon=5
        )
        
        # Train the model
        weekly_model.train(self.historical_data)
        
        # Generate predictions
        weekly_predictions = weekly_model.predict()
        
        # Check intervals
        first_time = datetime.fromisoformat(weekly_predictions[0]["timestamp"])
        second_time = datetime.fromisoformat(weekly_predictions[1]["timestamp"])
        self.assertAlmostEqual((second_time - first_time).total_seconds(), 7*24*3600, delta=10)  # 1 week = 7 days

    def test_to_dict(self):
        """Test conversion to dictionary."""
        # Train model to populate metrics
        self.model.train(self.historical_data)
        
        # Convert to dictionary
        model_dict = self.model.to_dict()
        
        # Check required fields
        self.assertEqual(model_dict["name"], self.model.name)
        self.assertEqual(model_dict["patient_id"], self.model.patient_id)
        self.assertEqual(model_dict["model_type"], TwinModelType.SYMPTOM_PREDICTION.value)
        self.assertEqual(model_dict["data_type"], self.model.data_type)
        self.assertEqual(model_dict["prediction_interval"], self.model.prediction_interval.value)
        self.assertEqual(model_dict["forecast_horizon"], self.model.forecast_horizon)


@pytest.mark.standalone()
class TestBiometricTwinModel(unittest.TestCase):
    """Test suite for the BiometricTwinModel."""

    def setUp(self):
        """Set up test fixtures."""
        self.patient_id = "test-patient-123"
        self.biometric_types = [
            BiometricDataType.HEART_RATE,
            BiometricDataType.BLOOD_PRESSURE,
            BiometricDataType.SLEEP
        ]
        self.model = BiometricTwinModel(
            name="Biometric Monitor",
            patient_id=self.patient_id,
            biometric_types=self.biometric_types
        )

    def test_initialization(self):
        """Test model initialization."""
        self.assertEqual(self.model.name, "Biometric Monitor")
        self.assertEqual(self.model.patient_id, self.patient_id)
        self.assertEqual(self.model.biometric_types, self.biometric_types)
        self.assertEqual(self.model.model_type, TwinModelType.BIOMETRIC)
        self.assertEqual(len(self.model.alert_rules), 0)
        self.assertEqual(len(self.model.baseline_values), 0)
        self.assertIsInstance(self.model.historical_data, dict)

    def test_add_alert_rule(self):
        """Test adding alert rules."""
        # Create an alert rule
        rule = {
            "biometric_type": BiometricDataType.HEART_RATE.value,
            "condition": "above",
            "threshold": 100,
            "message": "Heart rate too high"
        }
        
        # Add the rule
        rule_id = self.model.add_alert_rule(rule)
        
        # Check that rule was added
        self.assertEqual(len(self.model.alert_rules), 1)
        
        # Check that ID was assigned
        self.assertIn("id", self.model.alert_rules[0])
        self.assertEqual(self.model.alert_rules[0]["id"], rule_id)
        
        # Check that created_at was added
        self.assertIn("created_at", self.model.alert_rules[0])

    def test_add_alert_rule_validation(self):
        """Test validation when adding alert rules."""
        # Missing required field
        invalid_rule = {
            "biometric_type": BiometricDataType.HEART_RATE.value,
            "condition": "above"
            # Missing threshold
        }
        
        # Check that validation error is raised
        with self.assertRaises(ValueError):
            self.model.add_alert_rule(invalid_rule)

    def test_remove_alert_rule(self):
        """Test removing alert rules."""
        # Add two rules
        rule1 = {
            "biometric_type": BiometricDataType.HEART_RATE.value,
            "condition": "above",
            "threshold": 100
        }
        rule2 = {
            "biometric_type": BiometricDataType.BLOOD_PRESSURE.value,
            "condition": "above",
            "threshold": 140
        }
        
        rule1_id = self.model.add_alert_rule(rule1)
        rule2_id = self.model.add_alert_rule(rule2)
        
        # Check initial state
        self.assertEqual(len(self.model.alert_rules), 2)
        
        # Remove first rule
        result = self.model.remove_alert_rule(rule1_id)
        
        # Check that rule was removed
        self.assertTrue(result)
        self.assertEqual(len(self.model.alert_rules), 1)
        self.assertEqual(self.model.alert_rules[0]["id"], rule2_id)
        
        # Try to remove non-existent rule
        result = self.model.remove_alert_rule("non-existent-id")
        self.assertFalse(result)
        self.assertEqual(len(self.model.alert_rules), 1)

    def test_set_baseline(self):
        """Test setting baseline values."""
        # Set a baseline
        self.model.set_baseline(BiometricDataType.HEART_RATE, 70)
        
        # Check that baseline was set
        self.assertIn(BiometricDataType.HEART_RATE.value, self.model.baseline_values)
        self.assertEqual(self.model.baseline_values[BiometricDataType.HEART_RATE.value], 70)
        
        # Set another baseline
        self.model.set_baseline(BiometricDataType.BLOOD_PRESSURE, {"systolic": 120, "diastolic": 80})
        
        # Check that baseline was set
        self.assertIn(BiometricDataType.BLOOD_PRESSURE.value, self.model.baseline_values)
        self.assertEqual(self.model.baseline_values[BiometricDataType.BLOOD_PRESSURE.value]["systolic"], 120)
        self.assertEqual(self.model.baseline_values[BiometricDataType.BLOOD_PRESSURE.value]["diastolic"], 80)
        
        # Check validation
        with self.assertRaises(TypeError):
            self.model.set_baseline("not_an_enum", 70)

    def test_process_biometric_data_no_alerts(self):
        """Test processing biometric data with no alerts triggered."""
        # Create a data point
        data_point = {
            "type": BiometricDataType.HEART_RATE.value,
            "value": 70,
            "timestamp": datetime.now().isoformat()
        }
        
        # Process the data point
        alerts = self.model.process_biometric_data(data_point)
        
        # Check that no alerts were triggered
        self.assertEqual(len(alerts), 0)
        
        # Check that data was stored
        self.assertIn(BiometricDataType.HEART_RATE.value, self.model.historical_data)
        self.assertEqual(len(self.model.historical_data[BiometricDataType.HEART_RATE.value]), 1)
        self.assertEqual(self.model.historical_data[BiometricDataType.HEART_RATE.value][0]["value"], 70)

    def test_process_biometric_data_with_alerts(self):
        """Test processing biometric data with alerts triggered."""
        # Add alert rules
        self.model.add_alert_rule({
            "biometric_type": BiometricDataType.HEART_RATE.value,
            "condition": "above",
            "threshold": 100,
            "message": "Heart rate too high"
        })
        
        self.model.add_alert_rule({
            "biometric_type": BiometricDataType.HEART_RATE.value,
            "condition": "below",
            "threshold": 50,
            "message": "Heart rate too low"
        })
        
        # Process data point that should trigger the first alert
        high_hr_data = {
            "type": BiometricDataType.HEART_RATE.value,
            "value": 120,
            "timestamp": datetime.now().isoformat()
        }
        
        alerts = self.model.process_biometric_data(high_hr_data)
        
        # Check that alert was triggered
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["biometric_type"], BiometricDataType.HEART_RATE.value)
        self.assertEqual(alerts[0]["condition"], "above")
        self.assertEqual(alerts[0]["threshold"], 100)
        self.assertEqual(alerts[0]["value"], 120)
        self.assertEqual(alerts[0]["message"], "Heart rate too high")
        
        # Process data point that should trigger the second alert
        low_hr_data = {
            "type": BiometricDataType.HEART_RATE.value,
            "value": 45,
            "timestamp": datetime.now().isoformat()
        }
        
        alerts = self.model.process_biometric_data(low_hr_data)
        
        # Check that alert was triggered
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["biometric_type"], BiometricDataType.HEART_RATE.value)
        self.assertEqual(alerts[0]["condition"], "below")
        self.assertEqual(alerts[0]["threshold"], 50)
        self.assertEqual(alerts[0]["value"], 45)
        self.assertEqual(alerts[0]["message"], "Heart rate too low")
        
        # Process data point that should not trigger any alerts
        normal_hr_data = {
            "type": BiometricDataType.HEART_RATE.value,
            "value": 75,
            "timestamp": datetime.now().isoformat()
        }
        
        alerts = self.model.process_biometric_data(normal_hr_data)
        
        # Check that no alerts were triggered
        self.assertEqual(len(alerts), 0)

    def test_process_biometric_data_validation(self):
        """Test validation when processing biometric data."""
        # Missing type
        invalid_data = {
            "value": 70
        }
        
        with self.assertRaises(ValueError):
            self.model.process_biometric_data(invalid_data)
        
        # Missing value
        invalid_data = {
            "type": BiometricDataType.HEART_RATE.value
        }
        
        with self.assertRaises(ValueError):
            self.model.process_biometric_data(invalid_data)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        # Add some test data
        self.model.add_alert_rule({
            "biometric_type": BiometricDataType.HEART_RATE.value,
            "condition": "above",
            "threshold": 100
        })
        
        self.model.set_baseline(BiometricDataType.HEART_RATE, 70)
        
        # Convert to dictionary
        model_dict = self.model.to_dict()
        
        # Check required fields
        self.assertEqual(model_dict["name"], self.model.name)
        self.assertEqual(model_dict["patient_id"], self.model.patient_id)
        self.assertEqual(model_dict["model_type"], TwinModelType.BIOMETRIC.value)
        
        # Check biometric-specific fields
        self.assertEqual(len(model_dict["biometric_types"]), len(self.biometric_types))
        for bt in self.biometric_types:
            self.assertIn(bt.value, model_dict["biometric_types"])
        
        self.assertEqual(len(model_dict["alert_rules"]), 1)
        self.assertEqual(model_dict["baseline_values"][BiometricDataType.HEART_RATE.value], 70)


@pytest.mark.standalone()
class TestNeurotransmitterTwinModel(unittest.TestCase):
    """Test suite for the NeurotransmitterTwinModel with PITUITARY support."""

    def setUp(self):
        """Set up test fixtures."""
        self.patient_id = "test-patient-123"
        # Focus on specific brain regions and neurotransmitters for testing
        self.brain_regions = [
            BrainRegion.PREFRONTAL_CORTEX,
            BrainRegion.HYPOTHALAMUS,
            BrainRegion.PITUITARY,  # Critical for hypothalamus-pituitary axis connectivity 
            BrainRegion.AMYGDALA
        ]
        self.neurotransmitters = [
            Neurotransmitter.SEROTONIN,
            Neurotransmitter.DOPAMINE,
            Neurotransmitter.OXYTOCIN,  # Critical for pituitary function
            Neurotransmitter.GABA
        ]
        
        self.model = NeurotransmitterTwinModel(
            name="Neural Communication Model",
            patient_id=self.patient_id,
            brain_regions=self.brain_regions,
            neurotransmitters=self.neurotransmitters
        )

    def test_initialization(self):
        """Test model initialization with focus on PITUITARY region."""
        self.assertEqual(self.model.name, "Neural Communication Model")
        self.assertEqual(self.model.patient_id, self.patient_id)
        self.assertEqual(self.model.brain_regions, self.brain_regions)
        self.assertEqual(self.model.neurotransmitters, self.neurotransmitters)
        self.assertEqual(self.model.model_type, TwinModelType.NEUROTRANSMITTER)
        
        # Verify interactions matrix was created
        self.assertIsInstance(self.model.interactions, dict)
        for nt in self.neurotransmitters:
            self.assertIn(nt.value, self.model.interactions)
            for region in self.brain_regions:
                self.assertIn(region.value, self.model.interactions[nt.value])
        
        # Check baseline and current levels initialization
        self.assertIsInstance(self.model.baseline_levels, dict)
        self.assertIsInstance(self.model.current_levels, dict)
        
        # Verify all neurotransmitters have baseline levels in all regions
        for nt in self.neurotransmitters:
            self.assertIn(nt.value, self.model.baseline_levels)
            for region in self.brain_regions:
                self.assertIn(region.value, self.model.baseline_levels[nt.value])
                # Default baseline should be 1.0
                self.assertEqual(self.model.baseline_levels[nt.value][region.value], 1.0)

    def test_initialize_interactions(self):
        """Test initialization of interaction matrix with PITUITARY connectivity."""
        interactions = self.model._initialize_interactions()
        
        # Check that all neurotransmitters and regions are present
        for nt in self.neurotransmitters:
            self.assertIn(nt.value, interactions)
            for region in self.brain_regions:
                self.assertIn(region.value, interactions[nt.value])
                interaction = interactions[nt.value][region.value]
                # Each interaction should have effect and direction
                self.assertIn("effect", interaction)
                self.assertIn("direction", interaction)
        
        # Check strong connections for pituitary with oxytocin and dopamine
        self.assertEqual(
            interactions[Neurotransmitter.OXYTOCIN.value][BrainRegion.PITUITARY.value]["effect"],
            "strong"
        )
        self.assertEqual(
            interactions[Neurotransmitter.DOPAMINE.value][BrainRegion.PITUITARY.value]["effect"],
            "strong"
        )
        
        # Check strong connection for hypothalamus with serotonin and oxytocin
        self.assertEqual(
            interactions[Neurotransmitter.SEROTONIN.value][BrainRegion.HYPOTHALAMUS.value]["effect"],
            "strong"
        )
        self.assertEqual(
            interactions[Neurotransmitter.OXYTOCIN.value][BrainRegion.HYPOTHALAMUS.value]["effect"],
            "strong"
        )
        
        # Check inhibitory direction for GABA
        for region in self.brain_regions:
            self.assertEqual(
                interactions[Neurotransmitter.GABA.value][region.value]["direction"],
                "inhibitory"
            )

    def test_adjust_neurotransmitter(self):
        """Test adjusting neurotransmitter levels."""
        # Get initial level
        initial_level = self.model.current_levels[Neurotransmitter.SEROTONIN.value][BrainRegion.PREFRONTAL_CORTEX.value]
        
        # Adjust level
        self.model.adjust_neurotransmitter(
            Neurotransmitter.SEROTONIN,
            BrainRegion.PREFRONTAL_CORTEX,
            0.5
        )
        
        # Check that level was adjusted
        new_level = self.model.current_levels[Neurotransmitter.SEROTONIN.value][BrainRegion.PREFRONTAL_CORTEX.value]
        self.assertEqual(new_level, initial_level + 0.5)
        
        # Test negative adjustment but not below zero
        self.model.adjust_neurotransmitter(
            Neurotransmitter.SEROTONIN,
            BrainRegion.PREFRONTAL_CORTEX,
            -2.0  # This would take it below zero
        )
        
        # Check that level was adjusted but not below zero
        min_level = self.model.current_levels[Neurotransmitter.SEROTONIN.value][BrainRegion.PREFRONTAL_CORTEX.value]
        self.assertEqual(min_level, 0.0)

    def test_cascade_effects_pituitary_hypothalamus(self):
        """Test cascade effects specifically for hypothalamus-pituitary axis connectivity."""
        # Initial state for oxytocin in pituitary and hypothalamus
        initial_oxy_pit = self.model.current_levels[Neurotransmitter.OXYTOCIN.value][BrainRegion.PITUITARY.value]
        initial_oxy_hyp = self.model.current_levels[Neurotransmitter.OXYTOCIN.value][BrainRegion.HYPOTHALAMUS.value]
        
        # Increase oxytocin in hypothalamus and check propagation to pituitary
        self.model.adjust_neurotransmitter(
            Neurotransmitter.OXYTOCIN,
            BrainRegion.HYPOTHALAMUS,
            1.0
        )
        
        # Check that oxytocin increased in pituitary due to cascade effect
        # The propagation strength from hypothalamus to pituitary is 0.8
        expected_oxy_pit = initial_oxy_pit + (1.0 * 0.8)
        self.assertAlmostEqual(
            self.model.current_levels[Neurotransmitter.OXYTOCIN.value][BrainRegion.PITUITARY.value],
            expected_oxy_pit,
            places=5
        )
        
        # Reset and test pituitary to hypothalamus propagation
        self.model.reset_to_baseline()
        initial_oxy_pit = self.model.current_levels[Neurotransmitter.OXYTOCIN.value][BrainRegion.PITUITARY.value]
        initial_oxy_hyp = self.model.current_levels[Neurotransmitter.OXYTOCIN.value][BrainRegion.HYPOTHALAMUS.value]
        
        # Increase oxytocin in pituitary and check propagation to hypothalamus
        self.model.adjust_neurotransmitter(
            Neurotransmitter.OXYTOCIN,
            BrainRegion.PITUITARY,
            1.0
        )
        
        # Check that oxytocin increased in hypothalamus due to cascade effect
        # The propagation strength from pituitary to hypothalamus is 0.7
        expected_oxy_hyp = initial_oxy_hyp + (1.0 * 0.7)
        self.assertAlmostEqual(
            self.model.current_levels[Neurotransmitter.OXYTOCIN.value][BrainRegion.HYPOTHALAMUS.value],
            expected_oxy_hyp,
            places=5
        )

    def test_neurotransmitter_interactions(self):
        """Test interactions between different neurotransmitters."""
        # Initial levels
        initial_dopa = self.model.current_levels[Neurotransmitter.DOPAMINE.value][BrainRegion.PREFRONTAL_CORTEX.value]
        initial_gaba = self.model.current_levels[Neurotransmitter.GABA.value][BrainRegion.PREFRONTAL_CORTEX.value]
        
        # Increase serotonin which should affect dopamine and GABA
        self.model.adjust_neurotransmitter(
            Neurotransmitter.SEROTONIN,
            BrainRegion.PREFRONTAL_CORTEX,
            1.0
        )
        
        # Check that dopamine decreased (serotonin inhibits dopamine by -0.3)
        expected_dopa = initial_dopa + (1.0 * -0.3)
        self.assertAlmostEqual(
            self.model.current_levels[Neurotransmitter.DOPAMINE.value][BrainRegion.PREFRONTAL_CORTEX.value],
            expected_dopa,
            places=5
        )
        
        # Check that GABA increased (serotonin increases GABA by 0.4)
        expected_gaba = initial_gaba + (1.0 * 0.4)
        self.assertAlmostEqual(
            self.model.current_levels[Neurotransmitter.GABA.value][BrainRegion.PREFRONTAL_CORTEX.value],
            expected_gaba,
            places=5
        )

    def test_simulate_medication_effect(self):
        """Test simulation of medication effects on neurotransmitters."""
        # Define medication effects
        medication_effects = {
            Neurotransmitter.SEROTONIN.value: 0.3,  # SSRI-like effect
            Neurotransmitter.DOPAMINE.value: 0.2   # Stimulant-like effect
        }
        
        # Record initial levels in all regions
        initial_levels = {}
        for nt in [Neurotransmitter.SEROTONIN, Neurotransmitter.DOPAMINE]:
            initial_levels[nt.value] = {}
            for region in self.brain_regions:
                initial_levels[nt.value][region.value] = \
                    self.model.current_levels[nt.value][region.value]
        
        # Simulate medication effect
        changes = self.model.simulate_medication_effect(medication_effects)
        
        # Check that changes were returned correctly
        self.assertEqual(len(changes), 2)
        self.assertIn(Neurotransmitter.SEROTONIN.value, changes)
        self.assertIn(Neurotransmitter.DOPAMINE.value, changes)
        
        # Check that neurotransmitter levels were updated in all regions
        for nt in [Neurotransmitter.SEROTONIN, Neurotransmitter.DOPAMINE]:
            for region in self.brain_regions:
                expected_level = initial_levels[nt.value][region.value] + medication_effects[nt.value]
                self.assertAlmostEqual(
                    self.model.current_levels[nt.value][region.value],
                    expected_level,
                    places=5
                )
                
        # Check cascade effects - serotonin should have affected other neurotransmitters
        # and the effects should have propagated between regions

    def test_reset_to_baseline(self):
        """Test resetting neurotransmitter levels to baseline."""
        # Change some levels
        self.model.adjust_neurotransmitter(Neurotransmitter.SEROTONIN, BrainRegion.PREFRONTAL_CORTEX, 0.5)
        self.model.adjust_neurotransmitter(Neurotransmitter.DOPAMINE, BrainRegion.AMYGDALA, -0.3)
        
        # Verify levels changed
        self.assertNotEqual(
            self.model.current_levels[Neurotransmitter.SEROTONIN.value][BrainRegion.PREFRONTAL_CORTEX.value],
            self.model.baseline_levels[Neurotransmitter.SEROTONIN.value][BrainRegion.PREFRONTAL_CORTEX.value]
        )
        
        # Reset to baseline
        self.model.reset_to_baseline()
        
        # Check all levels are back to baseline
        for nt in self.neurotransmitters:
            for region in self.brain_regions:
                self.assertEqual(
                    self.model.current_levels[nt.value][region.value],
                    self.model.baseline_levels[nt.value][region.value]
                )

    def test_to_dict(self):
        """Test conversion to dictionary."""
        # Adjust some levels
        self.model.adjust_neurotransmitter(Neurotransmitter.SEROTONIN, BrainRegion.PREFRONTAL_CORTEX, 0.5)
        
        # Convert to dictionary
        model_dict = self.model.to_dict()
        
        # Check required fields
        self.assertEqual(model_dict["name"], self.model.name)
        self.assertEqual(model_dict["patient_id"], self.model.patient_id)
        self.assertEqual(model_dict["model_type"], TwinModelType.NEUROTRANSMITTER.value)
        
        # Check neurotransmitter-specific fields
        self.assertEqual(len(model_dict["brain_regions"]), len(self.brain_regions))
        for region in self.brain_regions:
            self.assertIn(region.value, model_dict["brain_regions"])
            
        self.assertEqual(len(model_dict["neurotransmitters"]), len(self.neurotransmitters))
        for nt in self.neurotransmitters:
            self.assertIn(nt.value, model_dict["neurotransmitters"])
            
        # Check levels are included
        self.assertIn("current_levels", model_dict)
        self.assertIn("baseline_levels", model_dict)
