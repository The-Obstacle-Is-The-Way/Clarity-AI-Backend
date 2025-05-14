"""
Mock implementation of the Enhanced Digital Twin Neurotransmitter Service.
This service specializes in modeling and predicting neurotransmitter states and interactions
as part of the Enhanced Digital Twin Core.
"""
import random
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    Neurotransmitter,
)
from app.domain.entities.neurotransmitter_mapping import (
    NeurotransmitterMapping,
    ReceptorProfile,
    create_default_neurotransmitter_mapping,
)
from app.domain.services.enhanced_digital_twin_neurotransmitter_service import (
    EnhancedDigitalTwinNeurotransmitterService,
)


class MockEnhancedDigitalTwinNeurotransmitterService(EnhancedDigitalTwinNeurotransmitterService):
    """
    Mock implementation of the Enhanced Digital Twin Neurotransmitter Service.
    
    This service provides simulated neurotransmitter profiles, receptor interactions,
    and brain region states for use in the digital twin system.
    """
    
    def __init__(self) -> None:
        """Initialize the mock neurotransmitter service."""
        self._patient_mappings: Dict[UUID, NeurotransmitterMapping] = {}
        
    async def get_neurotransmitter_mapping(self, patient_id: UUID) -> NeurotransmitterMapping:
        """
        Get the neurotransmitter mapping for a patient.
        Creates a default mapping if one doesn't exist.
        
        Args:
            patient_id: UUID of the patient
            
        Returns:
            NeurotransmitterMapping for the patient
        """
        if patient_id not in self._patient_mappings:
            self._patient_mappings[patient_id] = create_default_neurotransmitter_mapping()
        
        return self._patient_mappings[patient_id]
    
    async def update_neurotransmitter_mapping(
        self, 
        patient_id: UUID, 
        mapping_updates: Dict[str, Any]
    ) -> NeurotransmitterMapping:
        """
        Update the neurotransmitter mapping for a patient.
        
        Args:
            patient_id: UUID of the patient
            mapping_updates: Updates to apply to the mapping
            
        Returns:
            Updated NeurotransmitterMapping
        """
        mapping = await self.get_neurotransmitter_mapping(patient_id)
        
        # Apply updates (this is simplified; a real implementation would validate and apply changes)
        if "receptor_profiles" in mapping_updates:
            for neurotransmitter, profile in mapping_updates["receptor_profiles"].items():
                nt = Neurotransmitter(neurotransmitter)
                mapping.receptor_profiles[nt] = ReceptorProfile(
                    neurotransmitter=nt,
                    affinity=profile.get("affinity", mapping.receptor_profiles[nt].affinity),
                    expression=profile.get("expression", mapping.receptor_profiles[nt].expression),
                    modulation=profile.get("modulation", mapping.receptor_profiles[nt].modulation),
                )
        
        return mapping
    
    async def predict_medication_impacts(
        self, 
        patient_id: UUID, 
        medications: List[Dict[str, Any]]
    ) -> Dict[Neurotransmitter, Dict[str, float]]:
        """
        Predict how medications will impact neurotransmitter levels.
        
        Args:
            patient_id: UUID of the patient
            medications: List of medications with dosage, type, etc.
            
        Returns:
            Dictionary mapping neurotransmitters to their predicted changes
        """
        results = {}
        
        for nt in Neurotransmitter:
            # Generate random impact values between -0.5 and 0.5
            results[nt] = {
                "baseline": random.uniform(0.3, 0.7),
                "predicted_change": random.uniform(-0.5, 0.5),
                "uncertainty": random.uniform(0.1, 0.3),
            }
            
            # Specific medication effects for common psychiatric medications
            for med in medications:
                med_name = med.get("name", "").lower()
                
                # SSRIs increase serotonin
                if "ssri" in med_name or any(ssri in med_name for ssri in ["fluoxetine", "sertraline", "escitalopram"]):
                    if nt == Neurotransmitter.SEROTONIN:
                        results[nt]["predicted_change"] = random.uniform(0.3, 0.7)
                        results[nt]["uncertainty"] = random.uniform(0.05, 0.15)
                
                # SNRIs affect both serotonin and norepinephrine
                elif "snri" in med_name or any(snri in med_name for snri in ["venlafaxine", "duloxetine"]):
                    if nt in [Neurotransmitter.SEROTONIN, Neurotransmitter.NOREPINEPHRINE]:
                        results[nt]["predicted_change"] = random.uniform(0.3, 0.6)
                        results[nt]["uncertainty"] = random.uniform(0.05, 0.2)
                
                # Dopamine agents
                elif any(da in med_name for da in ["methylphenidate", "amphetamine", "bupropion"]):
                    if nt == Neurotransmitter.DOPAMINE:
                        results[nt]["predicted_change"] = random.uniform(0.4, 0.8)
                        results[nt]["uncertainty"] = random.uniform(0.1, 0.25)
                
                # Benzodiazepines enhance GABA
                elif any(benzo in med_name for benzo in ["diazepam", "alprazolam", "lorazepam"]):
                    if nt == Neurotransmitter.GABA:
                        results[nt]["predicted_change"] = random.uniform(0.3, 0.7)
                        results[nt]["uncertainty"] = random.uniform(0.05, 0.15)
                
                # Atypical antipsychotics
                elif any(aa in med_name for aa in ["risperidone", "olanzapine", "quetiapine", "aripiprazole"]):
                    if nt == Neurotransmitter.DOPAMINE:
                        results[nt]["predicted_change"] = random.uniform(-0.7, -0.3)
                        results[nt]["uncertainty"] = random.uniform(0.1, 0.2)
                    elif nt == Neurotransmitter.SEROTONIN:
                        results[nt]["predicted_change"] = random.uniform(0.2, 0.5)
                        results[nt]["uncertainty"] = random.uniform(0.1, 0.25)
        
        return results
    
    async def predict_network_connectivity_changes(
        self, 
        patient_id: UUID, 
        baseline_data: Optional[Dict[str, Any]] = None,
        intervention_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Predict changes in neural network connectivity based on interventions.
        
        Args:
            patient_id: UUID of the patient
            baseline_data: Optional baseline connectivity data
            intervention_data: Optional intervention details
            
        Returns:
            Dictionary with predicted connectivity changes
        """
        # Generate simulated connectivity changes
        brain_regions = list(BrainRegion)
        results = {
            "timestamp": datetime.now().isoformat(),
            "patient_id": str(patient_id),
            "connectivity_changes": [],
            "global_metrics": {
                "network_efficiency": random.uniform(0.4, 0.8),
                "clustering_coefficient": random.uniform(0.3, 0.7),
                "modularity": random.uniform(0.5, 0.9),
            }
        }
        
        # Generate random connectivity changes between brain regions
        for _ in range(random.randint(5, 10)):
            region1 = random.choice(brain_regions)
            region2 = random.choice([r for r in brain_regions if r != region1])
            
            results["connectivity_changes"].append({
                "source_region": region1.name,
                "target_region": region2.name,
                "connectivity_change": random.uniform(-0.5, 0.5),
                "confidence_interval": [random.uniform(-0.7, -0.3), random.uniform(0.3, 0.7)],
                "clinical_significance": random.choice(list(ClinicalSignificance)).name
            })
        
        return results
    
    async def simulate_emotional_regulation_circuit(
        self, 
        patient_id: UUID, 
        emotional_stimulus: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Simulate the emotional regulation circuit's response to stimuli.
        
        Args:
            patient_id: UUID of the patient
            emotional_stimulus: Optional stimulus details
            
        Returns:
            Dictionary with simulated emotional regulation circuit response
        """
        # Define key regions involved in emotional regulation
        emotional_regulation_regions = [
            BrainRegion.PREFRONTAL_CORTEX, 
            BrainRegion.ANTERIOR_CINGULATE_CORTEX,
            BrainRegion.AMYGDALA,
            BrainRegion.HIPPOCAMPUS,
            BrainRegion.INSULAR_CORTEX
        ]
        
        # Generate activation patterns for each region
        region_activations = {}
        for region in emotional_regulation_regions:
            region_activations[region.name] = {
                "baseline_activation": random.uniform(0.3, 0.7),
                "peak_activation": random.uniform(0.5, 1.0),
                "recovery_time_ms": random.randint(500, 2000),
                "habituation_rate": random.uniform(0.1, 0.4)
            }
        
        # Generate neurotransmitter releases
        neurotransmitter_dynamics = {}
        for nt in [Neurotransmitter.DOPAMINE, Neurotransmitter.SEROTONIN, 
                  Neurotransmitter.GABA, Neurotransmitter.GLUTAMATE]:
            neurotransmitter_dynamics[nt.name] = {
                "baseline_level": random.uniform(0.3, 0.7),
                "peak_release": random.uniform(0.6, 1.0),
                "clearance_rate": random.uniform(0.1, 0.5),
                "primary_regions": [random.choice(emotional_regulation_regions).name 
                                   for _ in range(random.randint(1, 3))]
            }
        
        # Construct response
        return {
            "timestamp": datetime.now().isoformat(),
            "patient_id": str(patient_id),
            "stimulus_type": emotional_stimulus.get("type", "generic") if emotional_stimulus else "baseline",
            "region_activations": region_activations,
            "neurotransmitter_dynamics": neurotransmitter_dynamics,
            "circuit_dynamics": {
                "amygdala_prefrontal_coupling": random.uniform(-0.8, 0.8),
                "emotional_regulation_efficiency": random.uniform(0.2, 0.9),
                "habituation_learning": random.uniform(0.0, 0.5),
                "stress_response_magnitude": random.uniform(0.1, 1.0)
            },
            "clinical_insights": [
                f"Simulated {random.choice(['strong', 'moderate', 'weak'])} "
                f"{random.choice(['positive', 'negative'])} "
                f"emotional regulation response"
            ]
        }
    
    async def model_neural_pathway_activations(
        self, 
        patient_id: UUID, 
        pathway_name: str,
        stimulus_parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Model the activation patterns of specific neural pathways.
        
        Args:
            patient_id: UUID of the patient
            pathway_name: Name of the neural pathway to model
            stimulus_parameters: Optional stimulus parameters
            
        Returns:
            Dictionary with modeled neural pathway activations
        """
        # Define some common neural pathways
        pathways = {
            "reward_pathway": {
                "regions": [BrainRegion.VENTRAL_TEGMENTAL_AREA, BrainRegion.NUCLEUS_ACCUMBENS, 
                           BrainRegion.PREFRONTAL_CORTEX],
                "primary_neurotransmitter": Neurotransmitter.DOPAMINE
            },
            "fear_circuit": {
                "regions": [BrainRegion.AMYGDALA, BrainRegion.HIPPOCAMPUS, 
                           BrainRegion.PREFRONTAL_CORTEX],
                "primary_neurotransmitter": Neurotransmitter.GLUTAMATE
            },
            "default_mode_network": {
                "regions": [BrainRegion.MEDIAL_PREFRONTAL_CORTEX, BrainRegion.POSTERIOR_CINGULATE_CORTEX, 
                           BrainRegion.INFERIOR_PARIETAL_LOBE],
                "primary_neurotransmitter": Neurotransmitter.GLUTAMATE
            },
            "serotonergic_pathway": {
                "regions": [BrainRegion.RAPHE_NUCLEI, BrainRegion.PREFRONTAL_CORTEX, 
                           BrainRegion.HIPPOCAMPUS],
                "primary_neurotransmitter": Neurotransmitter.SEROTONIN
            }
        }
        
        # Use the requested pathway or default to a random one
        selected_pathway = pathways.get(pathway_name.lower(), random.choice(list(pathways.values())))
        
        # Generate activation pattern for the pathway
        region_activations = {}
        for region in selected_pathway["regions"]:
            region_activations[region.name] = {
                "activation_level": random.uniform(0.4, 0.9),
                "temporal_dynamics": [random.uniform(0.1, 0.9) for _ in range(10)],
                "functional_connectivity": random.uniform(0.3, 0.8)
            }
        
        # Generate neurotransmitter dynamics
        nt_dynamics = {
            selected_pathway["primary_neurotransmitter"].name: {
                "release_pattern": [random.uniform(0.2, 1.0) for _ in range(10)],
                "reuptake_efficiency": random.uniform(0.5, 0.9),
                "receptor_sensitivity": random.uniform(0.3, 0.9)
            }
        }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "patient_id": str(patient_id),
            "pathway_name": pathway_name,
            "pathway_components": [r.name for r in selected_pathway["regions"]],
            "region_activations": region_activations,
            "neurotransmitter_dynamics": nt_dynamics,
            "pathway_metrics": {
                "overall_efficiency": random.uniform(0.3, 0.9),
                "signal_propagation_speed": random.uniform(10, 50),  # ms
                "pathway_integrity": random.uniform(0.5, 1.0),
                "plasticity_potential": random.uniform(0.2, 0.8)
            }
        }
