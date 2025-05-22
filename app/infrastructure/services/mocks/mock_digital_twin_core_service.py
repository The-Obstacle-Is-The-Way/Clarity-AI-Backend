"""
Mock implementation of the Digital Twin Core Service.

Provides realistic mock data for testing and development purposes.
Follows SOLID principles with proper dependency injection and type safety.
"""
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, cast
from uuid import UUID

from app.domain.entities.digital_twin_entity import (
    BrainRegion,
    BrainRegionState,
    ClinicalInsight,
    ClinicalSignificance,
    DigitalTwinState,
    NeuralConnection,
    Neurotransmitter,
    NeurotransmitterState,
    TemporalPattern,
)
from app.domain.entities.digital_twin_enums import ClinicalSignificance as ClinicalSignificanceEnum
from app.domain.services.digital_twin_core_service import DigitalTwinCoreService


class MockDigitalTwinCoreService(DigitalTwinCoreService):
    """
    Mock implementation of DigitalTwinCoreService for testing.
    
    Provides realistic mock data while maintaining proper type safety
    and following SOLID principles.
    """

    def __init__(
        self,
        digital_twin_repository: Any,
        patient_repository: Any,
        pat_service: Optional[Any] = None,
        mentalllama_service: Optional[Any] = None,
        xgboost_service: Optional[Any] = None,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """Initialize mock service with proper dependency injection."""
        self.digital_twin_repository = digital_twin_repository
        self.patient_repository = patient_repository
        self.pat_service = pat_service
        self.mentalllama_service = mentalllama_service
        self.xgboost_service = xgboost_service
        
        # Initialize mock data storage
        self._mock_states: Dict[str, DigitalTwinState] = {}
        self._mock_insights: Dict[str, List[ClinicalInsight]] = {}

    async def get_current_state(self, patient_id: str) -> DigitalTwinState:
        """Get current digital twin state for a patient."""
        if patient_id in self._mock_states:
            return self._mock_states[patient_id]
        
        # Create new mock state
        state = self._create_mock_state(patient_id)
        self._mock_states[patient_id] = state
        return state

    async def update_state(
        self, 
        patient_id: str, 
        new_data: Dict[str, Any], 
        source: str = "mock"
    ) -> DigitalTwinState:
        """Update digital twin state with new data."""
        current_state = await self.get_current_state(patient_id)
        
        # Update brain regions if provided
        if "brain_regions" in new_data:
            for region_name, region_data in new_data["brain_regions"].items():
                if hasattr(BrainRegion, region_name.upper()):
                    region = getattr(BrainRegion, region_name.upper())
                    current_state.brain_regions[region] = BrainRegionState(
                        region=region,
                        activation_level=region_data.get("activation_level", 0.5),
                        confidence=region_data.get("confidence", 0.8),
                        related_symptoms=region_data.get("related_symptoms", []),
                        clinical_significance=ClinicalSignificance.MODERATE
                    )
        
        # Update neurotransmitters if provided
        if "neurotransmitters" in new_data:
            for nt_name, nt_data in new_data["neurotransmitters"].items():
                if hasattr(Neurotransmitter, nt_name.upper()):
                    nt = getattr(Neurotransmitter, nt_name.upper())
                    current_state.neurotransmitters[nt] = NeurotransmitterState(
                        neurotransmitter=nt,
                        level=nt_data.get("level", 0.5),
                        confidence=nt_data.get("confidence", 0.8),
                        clinical_significance=ClinicalSignificance.MODERATE
                    )
        
        current_state.update_source = source
        current_state.timestamp = datetime.now()
        current_state.version += 1
        
        self._mock_states[patient_id] = current_state
        return current_state

    async def analyze_patterns(
        self, 
        patient_id: str, 
        time_range: Optional[tuple] = None
    ) -> Dict[str, Any]:
        """Analyze temporal patterns in patient data."""
        state = await self.get_current_state(patient_id)
        
        patterns = {
            "circadian_rhythm": {
                "strength": random.uniform(0.6, 0.9),
                "phase_shift": random.uniform(-2, 2),
                "amplitude": random.uniform(0.3, 0.8)
            },
            "weekly_patterns": {
                "weekday_variance": random.uniform(0.1, 0.4),
                "weekend_effect": random.uniform(-0.2, 0.3)
            },
            "treatment_response": {
                "onset_days": random.randint(3, 14),
                "peak_effect_days": random.randint(14, 42),
                "response_magnitude": random.uniform(0.2, 0.8)
            }
        }
        
        return patterns

    async def predict_outcomes(
        self, 
        patient_id: str, 
        intervention: Dict[str, Any], 
        time_horizon: int = 30
    ) -> Dict[str, Any]:
        """Predict outcomes for proposed interventions."""
        state = await self.get_current_state(patient_id)
        
        # Mock prediction based on intervention type
        intervention_type = intervention.get("type", "medication")
        
        if intervention_type == "medication":
            prediction = self._predict_medication_outcome(intervention, time_horizon)
        elif intervention_type == "therapy":
            prediction = self._predict_therapy_outcome(intervention, time_horizon)
        else:
            prediction = self._predict_general_outcome(intervention, time_horizon)
        
        return prediction

    async def get_insights(
        self, 
        patient_id: str, 
        insight_types: Optional[List[str]] = None
    ) -> List[ClinicalInsight]:
        """Get clinical insights for a patient."""
        if patient_id not in self._mock_insights:
            self._mock_insights[patient_id] = self._generate_mock_insights(patient_id)
        
        insights = self._mock_insights[patient_id]
        
        if insight_types:
            insights = [
                insight for insight in insights 
                if any(itype in insight.title.lower() for itype in insight_types)
            ]
        
        return insights

    async def simulate_intervention(
        self, 
        patient_id: str, 
        intervention: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Simulate the effects of an intervention."""
        state = await self.get_current_state(patient_id)
        
        simulation_results: Dict[str, Any] = {
            "baseline_state": self._state_to_dict(state),
            "predicted_changes": {},
            "confidence_intervals": {},
            "timeline": []
        }
        
        # Simulate changes over time
        for day in range(1, 31):  # 30-day simulation
            day_changes = self._simulate_daily_changes(intervention, day)
            cast(List[Dict[str, Any]], simulation_results["timeline"]).append({
                "day": day,
                "changes": day_changes,
                "confidence": random.uniform(0.7, 0.95)
            })
        
        return simulation_results

    def _create_mock_state(self, patient_id: str) -> DigitalTwinState:
        """Create a realistic mock digital twin state."""
        patient_uuid = UUID(patient_id) if isinstance(patient_id, str) else patient_id
        
        # Create brain region states
        brain_regions = {}
        for region in [BrainRegion.PREFRONTAL_CORTEX, BrainRegion.AMYGDALA, BrainRegion.HIPPOCAMPUS]:
            brain_regions[region] = BrainRegionState(
                region=region,
                activation_level=random.uniform(0.3, 0.8),
                confidence=random.uniform(0.7, 0.95),
                related_symptoms=["anxiety", "mood"],
                clinical_significance=random.choice(list(ClinicalSignificance))
            )
        
        # Create neurotransmitter states
        neurotransmitters = {}
        for nt in [Neurotransmitter.SEROTONIN, Neurotransmitter.DOPAMINE, Neurotransmitter.NOREPINEPHRINE]:
            neurotransmitters[nt] = NeurotransmitterState(
                neurotransmitter=nt,
                level=random.uniform(0.2, 0.9),
                confidence=random.uniform(0.6, 0.9),
                clinical_significance=random.choice(list(ClinicalSignificance))
            )
        
        # Create neural connections
        neural_connections = [
            NeuralConnection(
                source_region=BrainRegion.PREFRONTAL_CORTEX,
                target_region=BrainRegion.AMYGDALA,
                strength=random.uniform(0.4, 0.8),
                confidence=random.uniform(0.7, 0.9)
            )
        ]
        
        # Create clinical insights
        clinical_insights = self._generate_mock_insights(str(patient_uuid))
        
        # Create temporal patterns
        temporal_patterns = [
            TemporalPattern(
                pattern_type="circadian",
                description="Regular sleep-wake cycle with mild disruption",
                confidence=0.85,
                strength=0.7,
                clinical_significance=ClinicalSignificance.LOW
            )
        ]
        
        return DigitalTwinState(
            patient_id=patient_uuid,
            timestamp=datetime.now(),
            brain_regions=brain_regions,
            neurotransmitters=neurotransmitters,
            neural_connections=neural_connections,
            clinical_insights=clinical_insights,
            temporal_patterns=temporal_patterns,
            update_source="mock_service",
            version=1
        )

    def _generate_mock_insights(self, patient_id: str) -> List[ClinicalInsight]:
        """Generate realistic mock clinical insights."""
        insights = []
        
        # Serotonin-related insight
        insights.append(ClinicalInsight(
            id=uuid.uuid4(),
            title="Serotonin Deficiency Pattern",
            description="Analysis indicates potential serotonin deficiency affecting mood regulation",
            source="MockService",
            confidence=0.82,
            timestamp=datetime.now(),
            clinical_significance=ClinicalSignificance.MODERATE,
            patient_id=patient_id,
            brain_regions=[BrainRegion.PREFRONTAL_CORTEX, BrainRegion.ANTERIOR_CINGULATE],
            neurotransmitters=[Neurotransmitter.SEROTONIN],
            supporting_evidence=["Low morning cortisol", "Sleep pattern disruption"],
            recommended_actions=["Consider SSRI therapy", "Sleep hygiene assessment"]
        ))
        
        # Anxiety-related insight
        insights.append(ClinicalInsight(
            id=uuid.uuid4(),
            title="Elevated Anxiety Response",
            description="Heightened amygdala activity suggests increased anxiety sensitivity",
            source="MockService",
            confidence=0.76,
            timestamp=datetime.now(),
            clinical_significance=ClinicalSignificance.MODERATE,
            patient_id=patient_id,
            brain_regions=[BrainRegion.AMYGDALA, BrainRegion.ANTERIOR_CINGULATE],
            neurotransmitters=[Neurotransmitter.GABA, Neurotransmitter.NOREPINEPHRINE],
            supporting_evidence=["Elevated heart rate variability", "Stress response patterns"],
            recommended_actions=["Anxiety management techniques", "Consider anxiolytic therapy"]
        ))
        
        # Sleep-related insight
        insights.append(ClinicalInsight(
            id=uuid.uuid4(),
            title="Circadian Rhythm Disruption",
            description="Sleep-wake cycle shows phase delay and reduced amplitude",
            source="MockService",
            confidence=0.89,
            timestamp=datetime.now(),
            clinical_significance=ClinicalSignificance.MODERATE,
            patient_id=patient_id,
            brain_regions=[BrainRegion.HYPOTHALAMUS],
            neurotransmitters=[Neurotransmitter.SEROTONIN],
            supporting_evidence=["Delayed melatonin onset", "Irregular sleep patterns"],
            recommended_actions=["Light therapy", "Sleep schedule regulation"]
        ))
        
        # Cognitive insight
        insights.append(ClinicalInsight(
            id=uuid.uuid4(),
            title="Executive Function Concerns",
            description="Prefrontal cortex activity suggests attention and working memory challenges",
            source="MockService",
            confidence=0.71,
            timestamp=datetime.now(),
            clinical_significance=ClinicalSignificance.LOW,
            patient_id=patient_id,
            brain_regions=[BrainRegion.PREFRONTAL_CORTEX],
            neurotransmitters=[Neurotransmitter.DOPAMINE],
            supporting_evidence=["Cognitive assessment scores", "Attention task performance"],
            recommended_actions=["Cognitive training", "Attention enhancement strategies"]
        ))
        
        return insights

    def _predict_medication_outcome(self, intervention: Dict[str, Any], time_horizon: int) -> Dict[str, Any]:
        """Predict medication intervention outcomes."""
        medication = intervention.get("medication", "unknown")
        dosage = intervention.get("dosage", 50)
        
        # Mock prediction based on medication type
        if "ssri" in medication.lower():
            return {
                "response_probability": random.uniform(0.65, 0.85),
                "onset_days": random.randint(7, 21),
                "peak_effect_days": random.randint(28, 56),
                "side_effects_probability": random.uniform(0.2, 0.4),
                "predicted_improvement": random.uniform(0.3, 0.7)
            }
        else:
            return {
                "response_probability": random.uniform(0.5, 0.8),
                "onset_days": random.randint(3, 14),
                "peak_effect_days": random.randint(14, 42),
                "side_effects_probability": random.uniform(0.1, 0.3),
                "predicted_improvement": random.uniform(0.2, 0.6)
            }

    def _predict_therapy_outcome(self, intervention: Dict[str, Any], time_horizon: int) -> Dict[str, Any]:
        """Predict therapy intervention outcomes."""
        therapy_type = intervention.get("type", "cbt")
        
        return {
            "response_probability": random.uniform(0.7, 0.9),
            "onset_days": random.randint(14, 28),
            "peak_effect_days": random.randint(56, 84),
            "skill_acquisition_rate": random.uniform(0.6, 0.9),
            "predicted_improvement": random.uniform(0.4, 0.8)
        }

    def _predict_general_outcome(self, intervention: Dict[str, Any], time_horizon: int) -> Dict[str, Any]:
        """Predict general intervention outcomes."""
        return {
            "response_probability": random.uniform(0.4, 0.7),
            "onset_days": random.randint(7, 21),
            "peak_effect_days": random.randint(21, 49),
            "predicted_improvement": random.uniform(0.2, 0.5)
        }

    def _simulate_daily_changes(self, intervention: Dict[str, Any], day: int) -> Dict[str, Any]:
        """Simulate daily changes from an intervention."""
        # Mock daily progression
        progress_factor = min(day / 30.0, 1.0)  # Linear progression over 30 days
        
        return {
            "mood_change": random.uniform(-0.1, 0.3) * progress_factor,
            "anxiety_change": random.uniform(-0.4, 0.1) * progress_factor,
            "sleep_quality_change": random.uniform(-0.1, 0.2) * progress_factor,
            "energy_change": random.uniform(-0.1, 0.3) * progress_factor
        }

    def _state_to_dict(self, state: DigitalTwinState) -> Dict[str, Any]:
        """Convert DigitalTwinState to dictionary for serialization."""
        return {
            "patient_id": str(state.patient_id),
            "timestamp": state.timestamp.isoformat(),
            "version": state.version,
            "brain_regions": {
                region.value: {
                    "activation_level": region_state.activation_level,
                    "confidence": region_state.confidence,
                    "clinical_significance": region_state.clinical_significance.value
                }
                for region, region_state in state.brain_regions.items()
            },
            "neurotransmitters": {
                nt.value: {
                    "level": nt_state.level,
                    "confidence": nt_state.confidence,
                    "clinical_significance": nt_state.clinical_significance.value
                }
                for nt, nt_state in state.neurotransmitters.items()
            },
            "insights_count": len(state.clinical_insights),
            "patterns_count": len(state.temporal_patterns)
        }

    def _get_significance_factor(self, significance: ClinicalSignificance) -> float:
        """Convert clinical significance to numeric factor."""
        significance_map = {
            ClinicalSignificance.NONE: 0.0,
            ClinicalSignificance.LOW: 0.25,
            ClinicalSignificance.MODERATE: 0.5,
            ClinicalSignificance.HIGH: 0.75,
            ClinicalSignificance.CRITICAL: 1.0
        }
        return significance_map.get(significance, 0.5)
