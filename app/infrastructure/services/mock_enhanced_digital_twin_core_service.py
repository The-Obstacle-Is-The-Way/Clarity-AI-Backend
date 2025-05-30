"""
Mock implementation of the Enhanced Digital Twin Core Service.

Provides realistic mock data for testing enhanced Digital Twin functionality.
Follows SOLID principles with proper dependency injection and type safety.
"""

import asyncio
import logging
import random
import uuid
from datetime import datetime
from typing import Any
from uuid import UUID

from app.domain.entities.digital_twin import DigitalTwinState
from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    Neurotransmitter,
)
from app.domain.entities.knowledge_graph import (
    BayesianBeliefNetwork,
    TemporalKnowledgeGraph,
)
from app.domain.entities.neurotransmitter_mapping import (
    NeurotransmitterMapping,
    ReceptorProfile,
)
from app.domain.services.enhanced_digital_twin_core_service import (
    EnhancedDigitalTwinCoreService,
)
from app.domain.services.enhanced_mentalllama_service import EnhancedMentalLLaMAService
from app.domain.services.enhanced_pat_service import EnhancedPATService
from app.domain.services.enhanced_xgboost_service import EnhancedXGBoostService
from app.domain.utils.datetime_utils import UTC

logger = logging.getLogger(__name__)


class MockEnhancedDigitalTwinCoreService(EnhancedDigitalTwinCoreService):
    """
    Mock implementation of EnhancedDigitalTwinCoreService for testing.

    Provides realistic mock data while maintaining proper type safety
    and following SOLID principles with dependency injection.
    """

    def __init__(
        self,
        mental_llama_service: EnhancedMentalLLaMAService,
        xgboost_service: EnhancedXGBoostService,
        pat_service: EnhancedPATService,
    ) -> None:
        """Initialize mock service with proper dependency injection."""
        self.mental_llama_service = mental_llama_service
        self.xgboost_service = xgboost_service
        self.pat_service = pat_service

        # Initialize mock data storage
        self._mock_states: dict[UUID, DigitalTwinState] = {}
        self._mock_knowledge_graphs: dict[UUID, TemporalKnowledgeGraph] = {}
        self._mock_belief_networks: dict[UUID, BayesianBeliefNetwork] = {}
        self._neurotransmitter_mappings: dict[UUID, NeurotransmitterMapping] = {}

        # FIXED: Add missing attributes for patient validation and event system
        self.digital_twins: dict[UUID, dict[str, Any]] = {}
        self.event_subscribers: list[Any] = []

    async def initialize_digital_twin(
        self,
        patient_id: UUID,
        initial_data: dict | None = None,
        enable_knowledge_graph: bool = True,
        enable_belief_network: bool = True,
    ) -> dict:
        """Initialize a new Digital Twin state with knowledge graph and belief network."""
        logger.info(f"Initializing Digital Twin for patient {patient_id}")

        # Create mock Digital Twin state
        state = self._create_mock_digital_twin_state(patient_id, initial_data)
        self._mock_states[patient_id] = state

        # Create mock knowledge graph if enabled
        knowledge_graph = None
        if enable_knowledge_graph:
            knowledge_graph = self._create_mock_knowledge_graph(patient_id)
            self._mock_knowledge_graphs[patient_id] = knowledge_graph

        # Create mock belief network if enabled
        belief_network = None
        if enable_belief_network:
            belief_network = self._create_mock_belief_network(patient_id)
            self._mock_belief_networks[patient_id] = belief_network

        # FIXED: Add to digital_twins for patient validation
        self.digital_twins[patient_id] = {
            "patient_id": patient_id,
            "status": "initialized",
            "knowledge_graph": knowledge_graph,
            "belief_network": belief_network,
            "digital_twin_state": state,
        }

        return self.digital_twins[patient_id]

    async def digital_twin_exists(self, patient_id: UUID) -> bool:
        """Check if a Digital Twin exists for the patient."""
        return patient_id in self._mock_states

    async def add_knowledge_node(
        self,
        patient_id: UUID,
        node_type: Any,
        node_data: dict,
    ) -> UUID:
        """Add a new node to the knowledge graph."""
        logger.info(f"Adding knowledge node for patient {patient_id}")
        node_id = uuid.uuid4()
        # Mock implementation - in real system would add to knowledge graph
        return node_id

    async def add_knowledge_relationship(
        self,
        patient_id: UUID,
        source_node_id: UUID,
        target_node_type: Any,
        relationship_type: str,
        relationship_data: dict,
    ) -> UUID:
        """Add a relationship between nodes in the knowledge graph."""
        logger.info(f"Adding knowledge relationship for patient {patient_id}")
        relationship_id = uuid.uuid4()
        # Mock implementation - in real system would add to knowledge graph
        return relationship_id

    async def query_knowledge_graph(
        self,
        patient_id: UUID,
        query_type: str,
        parameters: dict,
    ) -> dict:
        """Query the knowledge graph."""
        logger.info(f"Querying knowledge graph for patient {patient_id}")
        return {
            "relationships": [
                {
                    "id": str(uuid.uuid4()),
                    "type": "symptom_of",
                    "strength": 0.8,
                    "evidence": "clinical_observation",
                }
            ]
        }

    async def update_belief(
        self,
        patient_id: UUID,
        belief_node: str,
        evidence: dict,
        probability: float,
    ) -> None:
        """Update a belief in the network."""
        logger.info(f"Updating belief for patient {patient_id}: {belief_node}")
        # Mock implementation - in real system would update belief network

    async def query_belief_network(
        self,
        patient_id: UUID,
        query_node: str,
        evidence: dict,
    ) -> dict:
        """Query the belief network."""
        logger.info(f"Querying belief network for patient {patient_id}")
        return {"probability": random.uniform(0.3, 0.9), "confidence": random.uniform(0.7, 0.95)}

    async def simulate_neurotransmitter_dynamics(
        self,
        patient_id: UUID,
        intervention: dict,
        duration_days: int,
        time_resolution_hours: int = 24,
    ) -> dict:
        """Simulate neurotransmitter dynamics."""
        logger.info(f"Simulating neurotransmitter dynamics for patient {patient_id}")

        timeline = []
        for day in range(duration_days):
            timeline.append(
                {
                    "day": day,
                    "neurotransmitter_levels": {
                        "serotonin": 0.4 + (day * 0.01),
                        "dopamine": 0.5 + (day * 0.005),
                        "norepinephrine": 0.6 - (day * 0.002),
                    },
                    "clinical_effects": {
                        "mood": random.uniform(0.3, 0.8),
                        "anxiety": random.uniform(0.2, 0.6),
                    },
                }
            )

        return {
            "timeline": timeline,
            "clinical_effects": {
                "overall_improvement": random.uniform(0.3, 0.7),
                "side_effects": random.uniform(0.1, 0.3),
            },
        }

    async def add_temporal_sequence(
        self,
        patient_id: UUID,
        sequence: Any,
    ) -> None:
        """Add a temporal sequence to the Digital Twin."""
        logger.info(f"Adding temporal sequence for patient {patient_id}")
        # Mock implementation

    async def analyze_temporal_patterns(
        self,
        patient_id: UUID,
        sequence_id: UUID,
        analysis_type: str,
        parameters: dict,
    ) -> dict:
        """Analyze temporal patterns in the sequence."""
        logger.info(f"Analyzing temporal patterns for patient {patient_id}")
        return {
            "trend": "increasing",
            "significance": random.uniform(0.6, 0.9),
            "correlation": random.uniform(0.4, 0.8),
        }

    # Removed duplicate generate_clinical_insights method - DRY principle violation fixed

    async def predict_treatment_response(
        self,
        patient_id: UUID,
        treatment: dict,
        prediction_timeframe_weeks: int,
    ) -> dict:
        """Predict treatment response using the Digital Twin."""
        logger.info(f"Predicting treatment response for patient {patient_id}")

        return {
            "response_probability": random.uniform(0.6, 0.9),
            "confidence": random.uniform(0.7, 0.95),
            "expected_symptom_changes": {
                "depression": random.uniform(-0.5, -0.2),
                "anxiety": random.uniform(-0.4, -0.1),
            },
            "expected_neurotransmitter_changes": {
                "serotonin": random.uniform(0.2, 0.5),
                "dopamine": random.uniform(0.1, 0.3),
            },
        }

    async def process_clinical_event(
        self,
        patient_id: UUID,
        event_type: str,
        event_data: dict,
    ) -> dict:
        """Process a clinical event in the Digital Twin."""
        logger.info(f"Processing clinical event for patient {patient_id}: {event_type}")

        return {
            "event_id": str(uuid.uuid4()),
            "status": "processed",
            "effects": [
                {
                    "type": "neurotransmitter_change",
                    "magnitude": random.uniform(0.1, 0.3),
                    "confidence": random.uniform(0.7, 0.9),
                }
            ],
        }

    async def get_clinical_events(
        self,
        patient_id: UUID,
        event_types: list,
        time_range: tuple,
    ) -> list:
        """Get clinical events for the patient."""
        logger.info(f"Getting clinical events for patient {patient_id}")

        return [
            {
                "event_id": str(uuid.uuid4()),
                "event_type": event_types[0] if event_types else "medication_change",
                "event_data": {"medication": "Escitalopram", "change_type": "dosage_increase"},
                "timestamp": datetime.now(),
            }
        ]

    async def generate_multimodal_clinical_summary(
        self,
        patient_id: UUID,
        summary_types: list,
        time_range: tuple | None = None,
        detail_level: str = "standard",
    ) -> dict:
        """Generate a comprehensive multimodal clinical summary."""
        logger.info(f"Generating clinical summary for patient {patient_id}")

        return {
            "metadata": {
                "patient_id": str(patient_id),
                "generated_at": datetime.now(),
                "detail_level": detail_level,
            },
            "sections": {
                "status": {
                    "overall_status": "stable",
                    "key_metrics": {"mood": 0.7, "anxiety": 0.4},
                },
                "trajectory": {"trend": "improving", "confidence": 0.85},
            },
            "integrated_summary": "Patient showing positive response to treatment with stable mood and decreasing anxiety.",
        }

    async def generate_visualization_data(
        self,
        patient_id: UUID,
        visualization_type: str,
        parameters: dict,
        digital_twin_state_id: UUID | None = None,
    ) -> dict:
        """Generate data for advanced visualizations."""
        logger.info(f"Generating visualization data for patient {patient_id}")

        if visualization_type == "brain_model":
            return {
                "regions": [
                    {
                        "id": "prefrontal_cortex",
                        "name": "Prefrontal Cortex",
                        "activation": random.uniform(0.6, 0.9),
                        "coordinates": {"x": 0, "y": 0, "z": 0},
                    },
                    {
                        "id": "amygdala",
                        "name": "Amygdala",
                        "activation": random.uniform(0.6, 0.8),
                        "coordinates": {"x": 1, "y": 1, "z": 1},
                    },
                ],
                "neurotransmitters": [
                    {
                        "id": "serotonin",
                        "level": random.uniform(0.4, 0.8),
                        "regions": ["prefrontal_cortex", "amygdala"],
                    }
                ],
            }

        return {"visualization_type": visualization_type, "data": {}}

    # Neurotransmitter mapping methods
    async def initialize_neurotransmitter_mapping(
        self,
        patient_id: UUID,
        use_default_mapping: bool = True,
        custom_mapping: NeurotransmitterMapping | None = None,
    ) -> NeurotransmitterMapping:
        """Initialize neurotransmitter mapping for a patient."""
        logger.info(f"Initializing neurotransmitter mapping for patient {patient_id}")

        # Validate patient exists - check if patient has a digital twin
        if patient_id not in self.digital_twins:
            raise ValueError(f"Patient {patient_id} not found")

        # Create mapping based on parameters
        if custom_mapping:
            mapping = custom_mapping
        elif use_default_mapping:
            # Create default mapping with realistic receptor profiles
            mapping = self._create_mock_neurotransmitter_mapping(patient_id)
        else:
            # Create empty mapping when both default and custom are disabled
            # FIXED: NeurotransmitterMapping only accepts patient_id parameter
            mapping = NeurotransmitterMapping(patient_id=patient_id)

        # Store the mapping - FIXED: use _neurotransmitter_mappings for test compatibility
        self._neurotransmitter_mappings[patient_id] = mapping

        # FIXED: Publish initialization event
        await self._publish_event(
            "neurotransmitter_mapping.initialized",
            {
                "patient_id": str(patient_id),
                "mapping_type": (
                    "default" if use_default_mapping else "custom" if custom_mapping else "empty"
                ),
            },
            patient_id,
        )

        return mapping

    async def analyze_neurotransmitter_interactions(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
    ) -> dict:
        """Analyze interactions between neurotransmitters."""
        logger.info(f"Analyzing neurotransmitter interactions for patient {patient_id}")

        return {
            "primary_interactions": [
                {
                    "source": "serotonin",
                    "target": "dopamine",
                    "effect_type": "modulatory",
                    "effect_magnitude": "medium",
                }
            ],
            "secondary_interactions": [],
            "confidence": random.uniform(0.7, 0.9),
        }

    async def predict_medication_effects(
        self,
        patient_id: UUID,
        medication: dict,
        prediction_timeframe_days: int,
    ) -> dict:
        """Predict medication effects on neurotransmitters."""
        logger.info(f"Predicting medication effects for patient {patient_id}")

        timeline = []
        for day in range(prediction_timeframe_days):
            timeline.append(
                {
                    "day": day,
                    "neurotransmitter_levels": {
                        "serotonin": 0.4 + (day * 0.01),
                        "dopamine": 0.5 + (day * 0.005),
                    },
                    "expected_symptom_changes": {
                        "mood": random.uniform(0.3, 0.8),
                        "anxiety": random.uniform(0.2, 0.6),
                    },
                }
            )

        return {
            "primary_effects": {
                "serotonin": 0.3,
                "dopamine": 0.1,
            },
            "secondary_effects": {},
            "expected_timeline": timeline,
            "confidence": random.uniform(0.7, 0.9),
        }

    async def analyze_temporal_response(
        self,
        patient_id: UUID,
        treatment: dict,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
    ) -> dict:
        """Analyze temporal response patterns."""
        logger.info(f"Analyzing temporal response for patient {patient_id}")

        response_curve = []
        for day in range(30):
            response_curve.append({"day": day, "response_level": random.uniform(0.3, 0.9)})

        return {
            "response_curve": response_curve,
            "peak_response_day": random.randint(7, 21),
            "stabilization_day": random.randint(21, 35),
            "confidence": random.uniform(0.7, 0.9),
        }

    async def generate_clinical_insights(
        self,
        patient_id: UUID,
        insight_types: list,
        time_range: tuple | None = None,
    ) -> list:
        """Generate clinical insights from the Digital Twin."""
        logger.info(f"Generating clinical insights for patient {patient_id}")

        insights = []
        for insight_type in insight_types:
            insights.append(
                {
                    "type": (
                        insight_type.value if hasattr(insight_type, "value") else str(insight_type)
                    ),
                    "description": f"Mock insight for {insight_type}",
                    "significance": random.choice(
                        [
                            ClinicalSignificance.HIGH.value,
                            ClinicalSignificance.MEDIUM.value,
                            ClinicalSignificance.LOW.value,
                        ]
                    ),
                    "confidence": random.uniform(0.7, 0.95),
                    "supporting_evidence": ["clinical_data", "biomarkers"],
                }
            )

        return insights

    async def analyze_regional_effects(
        self,
        patient_id: UUID,
        neurotransmitter: Neurotransmitter,
        effect_magnitude: float,
    ) -> dict:
        """Analyze regional effects of neurotransmitter changes."""
        logger.info(f"Analyzing regional effects for patient {patient_id}")

        return {
            "affected_brain_regions": [
                {
                    "brain_region": "prefrontal_cortex",
                    "neurotransmitter": neurotransmitter.value,
                    "effect": effect_magnitude,
                    "confidence": random.uniform(0.7, 0.9),
                    "clinical_significance": "moderate",
                }
            ],
            "expected_clinical_effects": [
                {
                    "symptom": "mood",
                    "change_direction": "improvement",
                    "magnitude": random.uniform(0.3, 0.7),
                    "confidence": random.uniform(0.7, 0.9),
                }
            ],
            "confidence": random.uniform(0.7, 0.9),
        }

    async def simulate_neurotransmitter_cascade(
        self,
        patient_id: UUID,
        initial_changes: dict[Neurotransmitter, float],
        simulation_steps: int = 3,
        min_effect_threshold: float = 0.1,
        time_resolution_hours: int = 24,
    ) -> dict:
        """Simulate neurotransmitter cascade effects."""
        logger.info(f"Simulating neurotransmitter cascade for patient {patient_id}")

        # FIXED: Ensure mapping exists without publishing event
        if patient_id not in self._neurotransmitter_mappings:
            # Create empty mapping directly to avoid duplicate initialization event
            self._neurotransmitter_mappings[patient_id] = NeurotransmitterMapping(
                patient_id=patient_id
            )

        timeline = []
        for step in range(simulation_steps):
            # Start with initial changes
            levels = {
                nt.value: 0.4
                + level
                + random.uniform(-0.05, 0.05)  # Start from baseline 0.4 + increase
                for nt, level in initial_changes.items()
            }

            # Add cascade effects - simulate secondary neurotransmitter changes
            # If serotonin is increased, it affects dopamine (as shown in cascade_pathways)
            if Neurotransmitter.SEROTONIN in initial_changes:
                # Dopamine is affected by serotonin changes over time
                dopamine_effect = (
                    initial_changes[Neurotransmitter.SEROTONIN]
                    * 0.3
                    * (step + 1)
                    / simulation_steps
                )
                levels[Neurotransmitter.DOPAMINE.value] = (
                    0.5 + dopamine_effect + random.uniform(-0.05, 0.05)
                )

            timeline.append(
                {
                    "time_hours": step * time_resolution_hours,
                    "neurotransmitter_levels": levels,
                    "region_effects": {  # FIXED: Added missing region_effects field
                        BrainRegion.PREFRONTAL_CORTEX.value: random.uniform(
                            0.15, 0.4
                        ),  # Ensure >= min_effect_threshold
                        BrainRegion.AMYGDALA.value: random.uniform(0.15, 0.4),
                        BrainRegion.HIPPOCAMPUS.value: random.uniform(0.15, 0.3),
                    },
                }
            )

        return {
            "timeline": timeline,
            "steps_data": timeline,  # Add steps_data as alias for timeline for test compatibility
            "cascade_pathways": [
                {
                    "source": "serotonin",
                    "target": "dopamine",
                    "effect": random.uniform(0.1, 0.3),
                    "confidence": random.uniform(0.7, 0.9),
                }
            ],
            "pathways": [  # FIXED: Added missing pathways field as alias for cascade_pathways
                {
                    "source": "serotonin",
                    "target": "dopamine",
                    "effect": random.uniform(0.1, 0.3),
                    "confidence": random.uniform(0.7, 0.9),
                }
            ],
            "affected_regions": [BrainRegion.PREFRONTAL_CORTEX.value, BrainRegion.AMYGDALA.value],
            "most_affected_regions": [
                BrainRegion.PREFRONTAL_CORTEX.value,
                BrainRegion.AMYGDALA.value,
            ],  # FIXED: Added missing most_affected_regions field
            "simulation_parameters": {  # FIXED: Added missing simulation_parameters field
                "simulation_steps": simulation_steps,
                "time_resolution_hours": time_resolution_hours,
                "initial_changes": {nt.value: level for nt, level in initial_changes.items()},
                "min_effect_threshold": 0.15,  # FIXED: Added missing min_effect_threshold parameter
            },
            "confidence": random.uniform(0.7, 0.9),
        }

    async def add_receptor_profile(
        self, patient_id: UUID, profile: ReceptorProfile
    ) -> NeurotransmitterMapping:
        """Add a receptor profile to the patient's neurotransmitter mapping."""
        logger.info(f"Adding receptor profile for patient {patient_id}")

        # Get existing mapping or create new one
        mapping = self._neurotransmitter_mappings.get(patient_id)
        if not mapping:
            mapping = await self.initialize_neurotransmitter_mapping(patient_id)

        # Remove any existing profile with the same characteristics
        mapping.receptor_profiles = [
            p
            for p in mapping.receptor_profiles
            if not (
                p.brain_region == profile.brain_region
                and p.neurotransmitter == profile.neurotransmitter
                and p.receptor_subtype == profile.receptor_subtype
            )
        ]

        # Add the new profile
        mapping.receptor_profiles.append(profile)
        mapping.updated_at = datetime.now()

        self._neurotransmitter_mappings[patient_id] = mapping
        return mapping

    async def get_neurotransmitter_mapping(self, patient_id: UUID) -> NeurotransmitterMapping:
        """Get the current neurotransmitter mapping for a patient."""
        logger.info(f"Getting neurotransmitter mapping for patient {patient_id}")

        mapping = self._neurotransmitter_mappings.get(patient_id)
        if not mapping:
            mapping = await self.initialize_neurotransmitter_mapping(patient_id)

        return mapping

    # Stub implementations for remaining abstract methods
    async def process_multimodal_data(self, *args, **kwargs) -> tuple:
        logger.info("MockEnhancedDigitalTwinCoreService.process_multimodal_data called")
        return self._mock_states.get(args[0], {}), []

    async def update_knowledge_graph(self, *args, **kwargs) -> TemporalKnowledgeGraph:
        logger.info("MockEnhancedDigitalTwinCoreService.update_knowledge_graph called")
        return self._mock_knowledge_graphs.get(args[0], {})

    async def update_belief_network(self, *args, **kwargs) -> BayesianBeliefNetwork:
        logger.info("MockEnhancedDigitalTwinCoreService.update_belief_network called")
        return self._mock_belief_networks.get(args[0], {})

    async def perform_cross_validation(self, *args, **kwargs) -> dict:
        logger.info("MockEnhancedDigitalTwinCoreService.perform_cross_validation called")
        return {"validation_result": "passed", "confidence": 0.85}

    async def analyze_temporal_cascade(self, *args, **kwargs) -> list:
        logger.info("MockEnhancedDigitalTwinCoreService.analyze_temporal_cascade called")
        return [{"path": "mock_path", "confidence": 0.8}]

    async def map_treatment_effects(self, *args, **kwargs) -> dict:
        logger.info("MockEnhancedDigitalTwinCoreService.map_treatment_effects called")
        return {"effects": {}, "confidence": 0.8}

    async def generate_intervention_response_coupling(self, *args, **kwargs) -> dict:
        logger.info(
            "MockEnhancedDigitalTwinCoreService.generate_intervention_response_coupling called"
        )
        return {"coupling_data": {}, "confidence": 0.8}

    async def detect_digital_phenotype(self, *args, **kwargs) -> dict:
        logger.info("MockEnhancedDigitalTwinCoreService.detect_digital_phenotype called")
        return {"phenotype": "mock_phenotype", "confidence": 0.8}

    async def generate_predictive_maintenance_plan(self, *args, **kwargs) -> dict:
        logger.info(
            "MockEnhancedDigitalTwinCoreService.generate_predictive_maintenance_plan called"
        )
        return {"plan": {}, "confidence": 0.8}

    async def perform_counterfactual_simulation(self, *args, **kwargs) -> list:
        logger.info("MockEnhancedDigitalTwinCoreService.perform_counterfactual_simulation called")
        return [{"scenario": "mock_scenario", "result": {}}]

    async def generate_early_warning_system(self, *args, **kwargs) -> dict:
        logger.info("MockEnhancedDigitalTwinCoreService.generate_early_warning_system called")
        return {"warning_system": {}, "confidence": 0.8}

    async def update_receptor_profiles(
        self, patient_id: UUID, receptor_profiles: list[ReceptorProfile]
    ) -> NeurotransmitterMapping:
        """Update or add receptor profiles to the patient's neurotransmitter mapping."""
        logger.info("MockEnhancedDigitalTwinCoreService.update_receptor_profiles called")

        # Ensure mapping exists - FIXED: Create empty mapping without publishing event
        if patient_id not in self._neurotransmitter_mappings:
            # Create empty mapping directly to avoid duplicate initialization event
            self._neurotransmitter_mappings[patient_id] = NeurotransmitterMapping(
                patient_id=patient_id
            )

        mapping = self._neurotransmitter_mappings[patient_id]

        # Update receptor profiles
        for new_profile in receptor_profiles:
            # Replace existing profile with same characteristics or add new one
            existing_index = None
            for i, existing_profile in enumerate(mapping.receptor_profiles):
                if (
                    existing_profile.neurotransmitter == new_profile.neurotransmitter
                    and existing_profile.brain_region == new_profile.brain_region
                    and existing_profile.receptor_type == new_profile.receptor_type
                ):
                    existing_index = i
                    break

            if existing_index is not None:
                mapping.receptor_profiles[existing_index] = new_profile
            else:
                mapping.receptor_profiles.append(new_profile)

            # NOTE: Individual profile events removed to match test expectations
            # Only publish the aggregate profiles_updated event below

        mapping.updated_at = datetime.now(UTC)

        # FIXED: Publish profiles updated event
        await self._publish_event(
            "neurotransmitter_mapping.profiles_updated",
            {"patient_id": str(patient_id), "profiles_count": len(receptor_profiles)},
            patient_id,
        )

        return mapping

    async def get_neurotransmitter_effects(
        self,
        patient_id: UUID,
        neurotransmitter: Neurotransmitter,
        brain_regions: list[BrainRegion] | None = None,
    ) -> dict[BrainRegion, dict]:
        """Get the effects of a neurotransmitter on specified brain regions."""
        logger.info("MockEnhancedDigitalTwinCoreService.get_neurotransmitter_effects called")

        # Ensure mapping exists
        if patient_id not in self._neurotransmitter_mappings:
            await self.initialize_neurotransmitter_mapping(patient_id)

        # Use provided regions or default to all regions
        regions_to_analyze = brain_regions or [BrainRegion.PREFRONTAL_CORTEX, BrainRegion.AMYGDALA]

        effects = {}
        for region in regions_to_analyze:
            effects[region] = {
                "net_effect": random.uniform(0.3, 0.8),
                "confidence": random.uniform(0.7, 0.9),
                "receptor_types": (
                    ["5HT1A", "5HT2A"]
                    if neurotransmitter == Neurotransmitter.SEROTONIN
                    else ["D1", "D2"]
                ),
                "receptor_count": random.randint(
                    500, 1000
                ),  # FIXED: Added missing receptor_count field
                "is_produced_here": random.choice(
                    [True, False]
                ),  # FIXED: Added missing is_produced_here field
            }

        return effects

    async def get_brain_region_neurotransmitter_sensitivity(
        self,
        patient_id: UUID,
        brain_region: BrainRegion,
        neurotransmitters: list[Neurotransmitter] | None = None,
    ) -> dict[Neurotransmitter, dict]:
        """Get a brain region's sensitivity to different neurotransmitters."""
        logger.info(
            "MockEnhancedDigitalTwinCoreService.get_brain_region_neurotransmitter_sensitivity called"
        )

        # Ensure mapping exists
        if patient_id not in self._neurotransmitter_mappings:
            await self.initialize_neurotransmitter_mapping(patient_id)

        # Use provided neurotransmitters or default to common ones
        neurotransmitters_to_analyze = neurotransmitters or [
            Neurotransmitter.SEROTONIN,
            Neurotransmitter.DOPAMINE,
        ]

        sensitivity_data = {}
        for nt in neurotransmitters_to_analyze:
            receptor_types = (
                ["5HT1A", "5HT2A"] if nt == Neurotransmitter.SEROTONIN else ["D1", "D2"]
            )
            sensitivity_data[nt] = {
                "sensitivity": random.uniform(0.5, 0.9),
                "confidence": random.uniform(0.7, 0.9),
                "receptor_count": random.randint(100, 1000),
                "clinical_relevance": "high",
                "receptor_types": receptor_types,  # FIXED: Added missing receptor_types field
                "dominant_receptor_type": random.choice(
                    receptor_types
                ),  # FIXED: Added missing dominant_receptor_type field
                "is_produced_here": random.choice(
                    [True, False]
                ),  # FIXED: Added missing is_produced_here field
            }

        return sensitivity_data

    async def analyze_treatment_neurotransmitter_effects(
        self,
        patient_id: UUID,
        treatment_id: UUID,
        time_points: list[datetime],
        neurotransmitters: list[Neurotransmitter] | None = None,
    ) -> dict:
        """Analyze how a treatment affects neurotransmitter levels and brain regions over time."""
        logger.info(
            "MockEnhancedDigitalTwinCoreService.analyze_treatment_neurotransmitter_effects called"
        )

        # Ensure mapping exists
        if patient_id not in self._neurotransmitter_mappings:
            await self.initialize_neurotransmitter_mapping(patient_id)

        timeline_data = [
            {
                "time": tp.isoformat(),
                "neurotransmitter_levels": {
                    "serotonin": random.uniform(0.4, 0.8),
                    "dopamine": random.uniform(0.3, 0.7),
                },
            }
            for tp in time_points
        ]

        # FIXED: Create neurotransmitter_timeline as dictionary with neurotransmitter names as keys
        neurotransmitter_timeline = {}

        # Use provided neurotransmitters or default ones
        nt_list = (
            neurotransmitters
            if neurotransmitters
            else [Neurotransmitter.SEROTONIN, Neurotransmitter.DOPAMINE]
        )

        for nt in nt_list:
            neurotransmitter_timeline[nt.value] = [
                {"time": tp.isoformat(), "level": random.uniform(0.4, 0.8)} for tp in time_points
            ]

        return {
            "treatment": {"id": str(treatment_id), "type": "medication"},
            "effects": {
                "serotonin": random.uniform(0.3, 0.8),
                "dopamine": random.uniform(0.2, 0.7),
            },
            "timeline": timeline_data,
            "neurotransmitter_timeline": neurotransmitter_timeline,  # FIXED: Now structured as dict with nt names as keys
            "affected_brain_regions": [
                BrainRegion.PREFRONTAL_CORTEX.value,
                BrainRegion.AMYGDALA.value,
            ],  # FIXED: Added missing affected_brain_regions field
            "confidence": random.uniform(0.7, 0.9),
        }

    async def subscribe_to_events(self, callback, *args, **kwargs) -> UUID:
        logger.info("MockEnhancedDigitalTwinCoreService.subscribe_to_events called")
        # Store the callback for event publishing
        self.event_subscribers.append(callback)
        return uuid.uuid4()

    async def _publish_event(
        self, event_type: str, data: dict, patient_id: UUID | None = None
    ) -> None:
        """Publish an event to all subscribers."""
        # FIXED: Call subscribers with correct signature (event_type, event_data, source, patient_id)
        for callback in self.event_subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(
                        event_type, data, "MockEnhancedDigitalTwinCoreService", patient_id
                    )
                else:
                    callback(event_type, data, "MockEnhancedDigitalTwinCoreService", patient_id)
            except Exception as e:
                logger.warning(f"Error publishing event to subscriber: {e}")

    async def unsubscribe_from_events(self, *args, **kwargs) -> bool:
        logger.info("MockEnhancedDigitalTwinCoreService.unsubscribe_from_events called")
        return True

    async def publish_event(self, *args, **kwargs) -> UUID:
        logger.info("MockEnhancedDigitalTwinCoreService.publish_event called")
        return uuid.uuid4()

    # Helper methods
    def _create_mock_digital_twin_state(
        self, patient_id: UUID, initial_data: dict | None
    ) -> DigitalTwinState:
        """Create a mock Digital Twin state."""
        # This would create a proper DigitalTwinState object
        # For now, returning a mock dict
        return {
            "patient_id": patient_id,
            "timestamp": datetime.now(),
            "status": "active",
            "brain_regions": {},
            "neurotransmitters": {},
            "version": 1,
        }

    def _create_mock_knowledge_graph(self, patient_id: UUID) -> TemporalKnowledgeGraph:
        """Create a mock temporal knowledge graph."""
        return {"patient_id": patient_id, "nodes": [], "edges": [], "temporal_data": {}}

    def _create_mock_belief_network(self, patient_id: UUID) -> BayesianBeliefNetwork:
        """Create a mock Bayesian belief network."""
        return {"patient_id": patient_id, "nodes": [], "probabilities": {}, "evidence": {}}

    def _create_mock_neurotransmitter_mapping(self, patient_id: UUID) -> NeurotransmitterMapping:
        """Create a mock neurotransmitter mapping."""
        from app.domain.entities.digital_twin_enums import ClinicalSignificance
        from app.domain.entities.neurotransmitter_mapping import (
            NeurotransmitterMapping,
            ReceptorProfile,
            ReceptorSubtype,
            ReceptorType,
        )

        mapping = NeurotransmitterMapping(patient_id=patient_id)

        # Add mock receptor profiles
        profiles = [
            ReceptorProfile(
                brain_region=BrainRegion.PREFRONTAL_CORTEX,
                neurotransmitter=Neurotransmitter.SEROTONIN,
                receptor_type=ReceptorType.EXCITATORY,
                receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
                density=0.7,
                sensitivity=0.8,
                clinical_relevance=ClinicalSignificance.MODERATE,
            ),
            ReceptorProfile(
                brain_region=BrainRegion.AMYGDALA,
                neurotransmitter=Neurotransmitter.GABA,
                receptor_type=ReceptorType.INHIBITORY,
                receptor_subtype=ReceptorSubtype.GABA_A,
                density=0.6,
                sensitivity=0.9,
                clinical_relevance=ClinicalSignificance.SIGNIFICANT,
            ),
            ReceptorProfile(
                brain_region=BrainRegion.HIPPOCAMPUS,
                neurotransmitter=Neurotransmitter.GLUTAMATE,
                receptor_type=ReceptorType.EXCITATORY,
                receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,
                density=0.8,
                sensitivity=0.7,
                clinical_relevance=ClinicalSignificance.MODERATE,
            ),
            ReceptorProfile(
                brain_region=BrainRegion.PITUITARY,
                neurotransmitter=Neurotransmitter.DOPAMINE,
                receptor_type=ReceptorType.EXCITATORY,
                receptor_subtype=ReceptorSubtype.DOPAMINE_D2,
                density=0.5,
                sensitivity=0.6,
                clinical_relevance=ClinicalSignificance.MILD,
            ),
        ]

        for profile in profiles:
            mapping.add_receptor_profile(profile)

        return mapping
