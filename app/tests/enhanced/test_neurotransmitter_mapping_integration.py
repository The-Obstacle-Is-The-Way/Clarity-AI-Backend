"""
Integration tests for the Neurotransmitter Mapping functionality of the Enhanced Digital Twin.

These tests verify that the neurotransmitter mapping components work correctly with
the rest of the Digital Twin system.
"""
import uuid
from uuid import UUID

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout_asyncio

from app.domain.entities.digital_twin import DigitalTwinState
from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalInsight,
    ClinicalSignificance,
    Neurotransmitter,
)
from app.domain.entities.neurotransmitter_mapping import (
    NeurotransmitterMapping,
    ReceptorProfile,
    ReceptorSubtype,
    ReceptorType,
)
from app.domain.services.enhanced_digital_twin_core_service import (
    EnhancedDigitalTwinCoreService,
)
from app.infrastructure.factories.enhanced_mock_digital_twin_factory import (
    EnhancedMockDigitalTwinFactory,
)

# Commented out imports for missing service - requires further investigation
# from app.domain.services.neurotransmitter_mapping_service import (
#     NeurotransmitterMappingService
# )


@pytest.fixture
def enhanced_services() -> tuple[EnhancedDigitalTwinCoreService]:
    """Fixture to create enhanced mock services for testing."""
    services = EnhancedMockDigitalTwinFactory.create_enhanced_mock_services()
    # Only return the Digital Twin service for simplicity
    return (services[0],)


@pytest.fixture
def patient_id() -> UUID:
    """Fixture to create a consistent patient ID for tests."""
    return uuid.UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def initial_data() -> dict:
    """Fixture to provide initial patient data for testing."""
    return {
        "diagnoses": ["Major Depressive Disorder", "Generalized Anxiety Disorder"],
        "symptoms": ["fatigue", "insomnia", "worry", "anhedonia"],
        "medications": [
            {"name": "Escitalopram", "dosage": "10mg", "frequency": "daily"},
            {"name": "Bupropion", "dosage": "150mg", "frequency": "twice daily"},
        ],
        "neurotransmitter_baseline": {
            "serotonin": 0.4,
            "dopamine": 0.5,
            "norepinephrine": 0.6,
            "gaba": 0.4,
            "glutamate": 0.7,
        },
    }


@pytest_asyncio.fixture
async def initialized_patient(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initial_data: dict
) -> DigitalTwinState:
    """Fixture to provide an initialized patient digital twin."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize the Digital Twin
    result = await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id,
        initial_data=initial_data
    )
    
    return result


@pytest.mark.asyncio
async def test_neurotransmitter_mapping_initialization(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    initialized_patient,  # Ensure digital twin is initialized for patient
    patient_id: UUID
):
    """Test initialization of the neurotransmitter mapping."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize the mapping
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Verify mapping was created
    assert mapping is not None
    assert isinstance(mapping, NeurotransmitterMapping)
    assert mapping.patient_id == patient_id
    
    # Verify default profiles were created
    assert len(mapping.receptor_profiles) > 0
    
    # Check that all major brain regions are represented
    brain_regions = {
        profile.brain_region for profile in mapping.receptor_profiles
    }
    assert BrainRegion.PREFRONTAL_CORTEX in brain_regions
    assert BrainRegion.AMYGDALA in brain_regions
    assert BrainRegion.HIPPOCAMPUS in brain_regions
    assert BrainRegion.PITUITARY in brain_regions  # Added as per memory record
    
    # Check that all major neurotransmitters are represented
    neurotransmitters = {
        profile.neurotransmitter for profile in mapping.receptor_profiles
    }
    assert Neurotransmitter.SEROTONIN in neurotransmitters
    assert Neurotransmitter.DOPAMINE in neurotransmitters
    assert Neurotransmitter.GABA in neurotransmitters
    assert Neurotransmitter.GLUTAMATE in neurotransmitters


@pytest.mark.asyncio
async def test_add_custom_receptor_profile(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    initialized_patient,  # Ensure digital twin is initialized for patient
    patient_id: UUID
):
    """Test adding a custom receptor profile to the mapping."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize the mapping
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Create a custom profile
    custom_profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.9,  # Higher than default
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.HIGH,
    )
    
    # Add the custom profile
    await digital_twin_service.add_receptor_profile(
        patient_id=patient_id,
        profile=custom_profile
    )
    
    # Get the updated mapping
    updated_mapping = await digital_twin_service.get_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Find the custom profile
    matching_profiles = [
        p for p in updated_mapping.receptor_profiles
        if (p.brain_region == BrainRegion.PREFRONTAL_CORTEX and
            p.neurotransmitter == Neurotransmitter.SEROTONIN and
            p.receptor_subtype == ReceptorSubtype.SEROTONIN_5HT2A)
    ]
    
    # Verify the custom profile was added
    assert len(matching_profiles) > 0
    found_profile = matching_profiles[0]
    assert found_profile.density == 0.9
    assert found_profile.clinical_relevance == ClinicalSignificance.HIGH


@pytest.mark.asyncio
async def test_simulate_neurotransmitter_cascade(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test simulation of neurotransmitter cascade effects."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Simulate medication effect
    initial_changes = {
        Neurotransmitter.SEROTONIN: 0.3,  # Increase serotonin (like SSRI)
    }
    
    # Run simulation
    simulation_result = await digital_twin_service.simulate_neurotransmitter_cascade(
        patient_id=patient_id,
        initial_changes=initial_changes,
        simulation_steps=10,
        time_resolution_hours=24
    )
    
    # Verify simulation results
    assert simulation_result is not None
    assert "timeline" in simulation_result
    assert len(simulation_result["timeline"]) > 0
    
    # Check timeline structure
    first_point = simulation_result["timeline"][0]
    assert "time_hours" in first_point
    assert "neurotransmitter_levels" in first_point
    
    # Check that serotonin was increased
    assert Neurotransmitter.SEROTONIN.value in first_point["neurotransmitter_levels"]
    assert first_point["neurotransmitter_levels"][Neurotransmitter.SEROTONIN.value] > 0.4  # Baseline + increase
    
    # Check that cascade effects are present in later time points
    last_point = simulation_result["timeline"][-1]
    
    # Verify indirect effects on other neurotransmitters
    # For example, increased serotonin should affect dopamine levels
    assert Neurotransmitter.DOPAMINE.value in last_point["neurotransmitter_levels"]
    assert last_point["neurotransmitter_levels"][Neurotransmitter.DOPAMINE.value] != 0.5  # Changed from baseline


@pytest.mark.asyncio
async def test_analyze_neurotransmitter_interactions(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test analysis of interactions between neurotransmitters."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Analyze interactions
    interactions = await digital_twin_service.analyze_neurotransmitter_interactions(
        patient_id=patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX
    )
    
    # Verify interaction analysis
    assert interactions is not None
    assert "primary_interactions" in interactions
    assert "secondary_interactions" in interactions
    assert "confidence" in interactions
    
    # Check primary interactions
    primary = interactions["primary_interactions"]
    assert isinstance(primary, list)
    assert len(primary) > 0
    
    # Check first primary interaction
    first_interaction = primary[0]
    assert "source" in first_interaction
    assert "target" in first_interaction
    assert "effect_type" in first_interaction
    assert "effect_magnitude" in first_interaction
    
    # Verify effect magnitude is a string like 'large' or 'medium' as per memory record
    assert first_interaction["effect_magnitude"] in ["large", "medium", "small"]


@pytest.mark.asyncio
async def test_predict_medication_effects(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test prediction of medication effects on neurotransmitters."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Define medication data
    medication_data = {
        "name": "Fluoxetine",
        "class": "SSRI",
        "dosage": "20mg",
        "frequency": "daily"
    }
    
    # Predict effects
    prediction = await digital_twin_service.predict_medication_effects(
        patient_id=patient_id,
        medication=medication_data,
        prediction_timeframe_days=28
    )
    
    # Verify prediction
    assert prediction is not None
    assert "primary_effects" in prediction
    assert "secondary_effects" in prediction
    assert "expected_timeline" in prediction
    assert "confidence" in prediction
    
    # Check primary effects (direct effects on neurotransmitters)
    primary = prediction["primary_effects"]
    assert isinstance(primary, dict)
    
    # SSRIs primarily affect serotonin
    assert Neurotransmitter.SEROTONIN.value in primary
    assert primary[Neurotransmitter.SEROTONIN.value] > 0
    
    # Check timeline
    timeline = prediction["expected_timeline"]
    assert isinstance(timeline, list)
    assert len(timeline) > 0
    
    # Check timeline structure
    first_point = timeline[0]
    assert "day" in first_point
    assert "neurotransmitter_levels" in first_point
    assert "expected_symptom_changes" in first_point


@pytest.mark.asyncio
async def test_analyze_treatment_response(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test analysis of treatment response patterns."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Analyze temporal response
    temporal_analysis = await digital_twin_service.analyze_temporal_response(
        patient_id=patient_id,
        treatment={
            "type": "medication",
            "name": "Escitalopram",
            "class": "SSRI",
            "dosage": "10mg",
            "frequency": "daily"
        },
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN
    )
    
    # Verify temporal analysis
    assert temporal_analysis is not None
    assert "response_curve" in temporal_analysis
    assert "peak_response_day" in temporal_analysis
    assert "stabilization_day" in temporal_analysis
    assert "confidence" in temporal_analysis
    
    # Check response curve
    curve = temporal_analysis["response_curve"]
    assert isinstance(curve, list)
    assert len(curve) > 0
    
    # Check curve structure
    first_point = curve[0]
    assert "day" in first_point
    assert "response_level" in first_point
    
    # Verify peak and stabilization days are reasonable
    assert temporal_analysis["peak_response_day"] > 0
    assert temporal_analysis["stabilization_day"] >= temporal_analysis["peak_response_day"]


@pytest.mark.asyncio
async def test_generate_clinical_insights(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test generation of clinical insights from neurotransmitter data."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Generate clinical insights
    insights = await digital_twin_service.generate_clinical_insights(
        patient_id=patient_id,
        insight_types=[
            ClinicalInsight.TREATMENT_RESPONSE,
            ClinicalInsight.NEUROTRANSMITTER_IMBALANCE
        ]
    )
    
    # Verify insights
    assert insights is not None
    assert isinstance(insights, list)
    assert len(insights) > 0
    
    # Check insight structure
    insight = insights[0]
    assert "type" in insight
    assert "description" in insight
    assert "significance" in insight
    assert "confidence" in insight
    assert "supporting_evidence" in insight
    
    # Verify significance is valid
    assert insight["significance"] in [
        ClinicalSignificance.HIGH.value,
        ClinicalSignificance.MODERATE.value,
        ClinicalSignificance.MILD.value,
        ClinicalSignificance.MINIMAL.value
    ]


@pytest.mark.asyncio
async def test_analyze_regional_neurotransmitter_effects(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test analysis of neurotransmitter effects by brain region."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Analyze regional effects
    analysis_results = await digital_twin_service.analyze_regional_effects(
        patient_id=patient_id,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        effect_magnitude=0.3
    )
    
    # Verify analysis results
    assert analysis_results is not None
    assert "affected_brain_regions" in analysis_results
    assert "expected_clinical_effects" in analysis_results
    assert "confidence" in analysis_results
    
    # Check expected clinical effects
    clinical_effects = analysis_results["expected_clinical_effects"]
    assert isinstance(clinical_effects, list)
    assert len(clinical_effects) > 0
    
    # Check clinical effect structure
    effect = clinical_effects[0]
    assert "symptom" in effect
    assert "change_direction" in effect
    assert "magnitude" in effect
    assert "confidence" in effect
    
    # Check affected regions
    affected_regions = analysis_results["affected_brain_regions"]
    assert len(affected_regions) > 0
    
    # Check region data structure
    region_data = affected_regions[0]
    assert "brain_region" in region_data
    assert "neurotransmitter" in region_data
    assert "effect" in region_data
    assert "confidence" in region_data
    assert "clinical_significance" in region_data


@pytest.mark.asyncio
async def test_integrated_neurotransmitter_mapping_with_visualization(
    enhanced_services: tuple[EnhancedDigitalTwinCoreService],
    patient_id: UUID,
    initialized_patient: DigitalTwinState
):
    """Test integration of neurotransmitter mapping with visualization data generation."""
    (digital_twin_service,) = enhanced_services
    
    # Initialize mapping first
    mapping = await digital_twin_service.initialize_neurotransmitter_mapping(
        patient_id=patient_id
    )
    
    # Simulate medication effect
    initial_changes = {
        Neurotransmitter.SEROTONIN: 0.3,  # Increase serotonin (like SSRI)
    }
    
    # Run simulation to generate state changes
    await digital_twin_service.simulate_neurotransmitter_cascade(
        patient_id=patient_id, 
        initial_changes=initial_changes, 
        simulation_steps=2
    )
    
    # Generate visualization data
    brain_viz = await digital_twin_service.generate_visualization_data(
        patient_id=patient_id,
        visualization_type="brain_model",
        parameters={
            "highlight_neurotransmitters": True,
            "primary_neurotransmitter": Neurotransmitter.SEROTONIN,
        }
    )
    
    # Check visualization data
    assert brain_viz is not None
    assert "regions" in brain_viz
    
    # Check that there are activated regions
    activated_regions = [
        r for r in brain_viz["regions"] if r.get("activation", 0) > 0.5
    ]
    assert len(activated_regions) > 0
    
    # Check that neurotransmitter data is included
    assert "neurotransmitters" in brain_viz
    # Look for a neurotransmitter object with the correct id
    assert any(
        nt["id"] == Neurotransmitter.SEROTONIN.value
        for nt in brain_viz["neurotransmitters"]
    )