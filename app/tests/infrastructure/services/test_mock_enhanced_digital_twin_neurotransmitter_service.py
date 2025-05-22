"""
Tests for the neurotransmitter mapping methods in the MockEnhancedDigitalTwinCoreService.

These tests verify that the implementation of neurotransmitter mapping in the mock service
behaves correctly, handles errors appropriately, and follows the expected patterns.
"""
import uuid
from datetime import datetime, timedelta
from uuid import UUID

import pytest
import pytest_asyncio

from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    Neurotransmitter,
)
from app.domain.entities.neurotransmitter_mapping import (
    NeurotransmitterMapping,
    ReceptorProfile,
    ReceptorSubtype,
    ReceptorType,
)
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.services.mock_enhanced_digital_twin_core_service import (
    MockEnhancedDigitalTwinCoreService,
)
from app.infrastructure.ml.mentallama.mocks.mock_mentalllama_service import MockMentalLLaMAService
from app.infrastructure.services.mock_pat_service import MockPATService
from app.infrastructure.services.mock_xgboost_service import MockXGBoostService


@pytest.fixture
def mock_service():
    """Create an instance of the mock service for testing with proper dependency injection."""
    # Create mock service dependencies following SOLID principles
    mock_mental_llama = MockMentalLLaMAService()
    mock_xgboost = MockXGBoostService()
    mock_pat = MockPATService()
    
    # Inject dependencies into the main service
    return MockEnhancedDigitalTwinCoreService(
        mental_llama_service=mock_mental_llama,
        xgboost_service=mock_xgboost,
        pat_service=mock_pat,
    )


@pytest_asyncio.fixture
@pytest.mark.venv_only()
@pytest.mark.asyncio
async def test_patient_id(mock_service) -> UUID:
    """Create a test patient with an initialized digital twin."""
    patient_id = uuid.uuid4()

    # Initialize the Digital Twin
    await mock_service.initialize_digital_twin(
        patient_id=patient_id,
        initial_data={
            "diagnoses": ["Major Depressive Disorder"],
            "symptoms": ["fatigue", "insomnia"],
            "medications": [{"name": "Escitalopram", "dosage": "10mg", "frequency": "daily"}],
        },
    )

    return patient_id


@pytest.mark.asyncio
async def test_initialize_neurotransmitter_mapping_patient_not_found(mock_service):
    """Test that initialize_neurotransmitter_mapping raises an error for nonexistent patients."""
    non_existent_id = uuid.uuid4()

    # This should raise a ValueError because the patient doesn't exist
    with pytest.raises(ValueError, match=f"Patient {non_existent_id} not found"):
        await mock_service.initialize_neurotransmitter_mapping(
            patient_id=non_existent_id, use_default_mapping=True
        )


@pytest.mark.asyncio
async def test_initialize_neurotransmitter_mapping_with_default(mock_service, test_patient_id):
    """Test initializing a neurotransmitter mapping with default values."""
    # Initialize with default mapping
    mapping = await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Verify mapping was created and stored
    assert mapping is not None
    assert isinstance(mapping, NeurotransmitterMapping)
    assert len(mapping.receptor_profiles) > 0

    # Verify it was stored in the service's internal state
    assert test_patient_id in mock_service._neurotransmitter_mappings
    assert mock_service._neurotransmitter_mappings[test_patient_id] == mapping


@pytest.mark.asyncio
async def test_initialize_neurotransmitter_mapping_with_custom(mock_service, test_patient_id):
    """Test initializing a neurotransmitter mapping with a custom mapping."""
    # Create a custom mapping
    custom_mapping = NeurotransmitterMapping()

    # Add a profile
    profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.FIVE_HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    custom_mapping.add_receptor_profile(profile)

    # Initialize with custom mapping
    mapping = await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id,
        use_default_mapping=False,
        custom_mapping=custom_mapping,
    )

    # Verify mapping was stored and is the same as our custom mapping
    assert mapping is not None
    assert mapping == custom_mapping
    assert len(mapping.receptor_profiles) == 1
    assert mapping.receptor_profiles[0] == profile


@pytest.mark.asyncio
async def test_initialize_neurotransmitter_mapping_without_default_or_custom(
    mock_service, test_patient_id
):
    """Test initializing an empty neurotransmitter mapping."""
    # Initialize with neither default nor custom (should create an empty mapping)
    mapping = await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=False, custom_mapping=None
    )

    # Verify mapping was created but is empty
    assert mapping is not None
    assert isinstance(mapping, NeurotransmitterMapping)
    assert len(mapping.receptor_profiles) == 0
    assert len(mapping.production_map) == 0


@pytest.mark.asyncio
async def test_update_receptor_profiles_creates_mapping_if_needed(mock_service, test_patient_id):
    """Test that update_receptor_profiles creates a mapping if one doesn't exist."""
    # Define a profile
    profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.FIVE_HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    # Update profiles without initializing first
    mapping = await mock_service.update_receptor_profiles(
        patient_id=test_patient_id, receptor_profiles=[profile]
    )

    # Verify mapping was created
    assert mapping is not None
    assert test_patient_id in mock_service._neurotransmitter_mappings
    assert len(mapping.receptor_profiles) == 1
    assert mapping.receptor_profiles[0] == profile


@pytest.mark.asyncio
async def test_update_receptor_profiles_updates_existing_mapping(mock_service, test_patient_id):
    """Test that update_receptor_profiles updates an existing mapping."""
    # Initialize a mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    original_mapping = mock_service._neurotransmitter_mappings[test_patient_id]
    original_profile_count = len(original_mapping.receptor_profiles)

    # Define new profiles
    new_profiles = [
        ReceptorProfile(
            brain_region=BrainRegion.INSULA,
            neurotransmitter=Neurotransmitter.GLUTAMATE,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,
            density=0.6,
            sensitivity=0.7,
            clinical_relevance=ClinicalSignificance.MILD,
        ),
        ReceptorProfile(
            brain_region=BrainRegion.BRAIN_STEM,
            neurotransmitter=Neurotransmitter.ACETYLCHOLINE,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.NICOTINIC,
            density=0.5,
            sensitivity=0.6,
            clinical_relevance=ClinicalSignificance.MILD,
        ),
    ]

    # Update the profiles
    updated_mapping = await mock_service.update_receptor_profiles(
        patient_id=test_patient_id, receptor_profiles=new_profiles
    )

    # Verify profiles were added to the existing mapping
    assert updated_mapping is not None
    assert len(updated_mapping.receptor_profiles) == original_profile_count + 2

    # Check that the new profiles were added
    glutamate_profiles = updated_mapping.get_receptor_profiles(
        BrainRegion.INSULA, Neurotransmitter.GLUTAMATE
    )
    assert len(glutamate_profiles) > 0

    acetylcholine_profiles = updated_mapping.get_receptor_profiles(
        BrainRegion.BRAIN_STEM, Neurotransmitter.ACETYLCHOLINE
    )
    assert len(acetylcholine_profiles) > 0


@pytest.mark.asyncio
async def test_get_neurotransmitter_effects_creates_mapping_if_needed(
    mock_service, test_patient_id
):
    """Test that get_neurotransmitter_effects creates a mapping if one doesn't exist."""
    # Call the method without initializing a mapping first
    effects = await mock_service.get_neurotransmitter_effects(
        patient_id=test_patient_id,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        brain_regions=[BrainRegion.PREFRONTAL_CORTEX],
    )

    # Verify a mapping was created
    assert test_patient_id in mock_service._neurotransmitter_mappings
    assert effects is not None
    assert BrainRegion.PREFRONTAL_CORTEX in effects


@pytest.mark.asyncio
async def test_get_neurotransmitter_effects_with_regions(mock_service, test_patient_id):
    """Test getting neurotransmitter effects with specific brain regions."""
    # Initialize mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Test with specific regions
    regions_to_test = [
        BrainRegion.PREFRONTAL_CORTEX,
        BrainRegion.AMYGDALA,
        BrainRegion.HIPPOCAMPUS,
    ]

    effects = await mock_service.get_neurotransmitter_effects(
        patient_id=test_patient_id,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        brain_regions=regions_to_test,
    )

    # Verify only requested regions are included
    assert effects is not None
    assert set(effects.keys()) == set(regions_to_test)

    # Verify effect data structure
    for region in regions_to_test:
        assert "net_effect" in effects[region]
        assert "confidence" in effects[region]
        assert "receptor_types" in effects[region]
        assert "receptor_count" in effects[region]
        assert "is_produced_here" in effects[region]


@pytest.mark.asyncio
async def test_get_neurotransmitter_effects_without_regions(mock_service, test_patient_id):
    """Test getting neurotransmitter effects for all brain regions."""
    # Initialize mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Test without specifying regions (should return all)
    effects = await mock_service.get_neurotransmitter_effects(
        patient_id=test_patient_id, neurotransmitter=Neurotransmitter.SEROTONIN
    )

    # Verify at least some regions are included
    assert effects is not None
    assert len(effects) > 0
    assert any(region in effects for region in BrainRegion)


@pytest.mark.asyncio
async def test_get_brain_region_neurotransmitter_sensitivity_creates_mapping_if_needed(
    mock_service, test_patient_id
):
    """Test that get_brain_region_neurotransmitter_sensitivity creates a mapping if needed."""
    # Call the method without initializing a mapping first
    sensitivities = await mock_service.get_brain_region_neurotransmitter_sensitivity(
        patient_id=test_patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitters=[Neurotransmitter.SEROTONIN],
    )

    # Verify a mapping was created
    assert test_patient_id in mock_service._neurotransmitter_mappings
    assert sensitivities is not None


@pytest.mark.asyncio
async def test_get_brain_region_neurotransmitter_sensitivity_with_neurotransmitters(
    mock_service, test_patient_id
):
    """Test getting brain region sensitivity with specific neurotransmitters."""
    # Initialize mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Test with specific neurotransmitters
    neurotransmitters_to_test = [
        Neurotransmitter.SEROTONIN,
        Neurotransmitter.DOPAMINE,
        Neurotransmitter.GABA,
    ]

    sensitivities = await mock_service.get_brain_region_neurotransmitter_sensitivity(
        patient_id=test_patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitters=neurotransmitters_to_test,
    )

    # Verify results - not all requested neurotransmitters might have results
    # depending on the mock implementation
    assert sensitivities is not None
    assert isinstance(sensitivities, dict)

    # For each neurotransmitter with results, check data structure
    for nt, data in sensitivities.items():
        assert "sensitivity" in data
        assert "receptor_count" in data
        assert "receptor_types" in data
        assert "dominant_receptor_type" in data
        assert "clinical_relevance" in data
        assert "is_produced_here" in data


@pytest.mark.asyncio
async def test_get_brain_region_neurotransmitter_sensitivity_without_neurotransmitters(
    mock_service, test_patient_id
):
    """Test getting brain region sensitivity for all neurotransmitters."""
    # Initialize mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Test without specifying neurotransmitters (should return all)
    sensitivities = await mock_service.get_brain_region_neurotransmitter_sensitivity(
        patient_id=test_patient_id, brain_region=BrainRegion.PREFRONTAL_CORTEX
    )

    # Verify at least some neurotransmitters are included
    assert sensitivities is not None
    assert len(sensitivities) > 0


@pytest.mark.asyncio
async def test_simulate_neurotransmitter_cascade_creates_mapping_if_needed(
    mock_service, test_patient_id
):
    """Test that simulate_neurotransmitter_cascade creates a mapping if needed."""
    # Define initial changes
    initial_changes = {Neurotransmitter.SEROTONIN: 0.2, Neurotransmitter.DOPAMINE: 0.1}

    # Call the method without initializing a mapping first
    results = await mock_service.simulate_neurotransmitter_cascade(
        patient_id=test_patient_id, initial_changes=initial_changes, simulation_steps=2
    )

    # Verify a mapping was created
    assert test_patient_id in mock_service._neurotransmitter_mappings
    assert results is not None
    assert "steps_data" in results
    assert len(results["steps_data"]) == 2  # 2 steps as requested


@pytest.mark.asyncio
async def test_simulate_neurotransmitter_cascade_with_parameters(mock_service, test_patient_id):
    """Test simulating neurotransmitter cascade with various parameters."""
    # Initialize mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Define initial changes
    initial_changes = {
        Neurotransmitter.SEROTONIN: 0.3,
        Neurotransmitter.DOPAMINE: 0.2,
        Neurotransmitter.GABA: -0.1,
    }

    # Test with specific parameters
    results = await mock_service.simulate_neurotransmitter_cascade(
        patient_id=test_patient_id,
        initial_changes=initial_changes,
        simulation_steps=3,
        min_effect_threshold=0.15,
    )

    # Verify results
    assert results is not None
    assert "steps_data" in results
    assert "pathways" in results
    assert "most_affected_regions" in results
    assert "simulation_parameters" in results

    # Check steps match requested count
    assert len(results["steps_data"]) == 3

    # Check parameters were recorded correctly
    params = results["simulation_parameters"]
    assert params["simulation_steps"] == 3
    assert params["min_effect_threshold"] == 0.15
    assert "initial_changes" in params

    # Check that the threshold was applied
    for step_data in results["steps_data"]:
        for effect in step_data["region_effects"].values():
            assert abs(effect) >= 0.15


@pytest.mark.asyncio
async def test_analyze_treatment_neurotransmitter_effects_creates_mapping_if_needed(
    mock_service, test_patient_id
):
    """Test that analyze_treatment_neurotransmitter_effects creates a mapping if needed."""
    # Define test parameters
    treatment_id = uuid.uuid4()
    time_points = [datetime.now(UTC) + timedelta(days=i * 7) for i in range(3)]

    # Call the method without initializing a mapping first
    results = await mock_service.analyze_treatment_neurotransmitter_effects(
        patient_id=test_patient_id,
        treatment_id=treatment_id,
        time_points=time_points,
        neurotransmitters=[Neurotransmitter.SEROTONIN],
    )

    # Verify a mapping was created
    assert test_patient_id in mock_service._neurotransmitter_mappings
    assert results is not None
    assert "treatment" in results
    assert "neurotransmitter_timeline" in results
    assert "affected_brain_regions" in results


@pytest.mark.asyncio
async def test_analyze_treatment_neurotransmitter_effects_with_parameters(
    mock_service, test_patient_id
):
    """Test analyzing treatment effects with various parameters."""
    # Initialize mapping first
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Define test parameters
    treatment_id = uuid.uuid4()
    time_points = [
        datetime.now(UTC) + timedelta(days=i * 7) for i in range(5)  # 0, 7, 14, 21, 28 days
    ]

    neurotransmitters = [
        Neurotransmitter.SEROTONIN,
        Neurotransmitter.DOPAMINE,
        Neurotransmitter.NOREPINEPHRINE,
    ]

    # Run the analysis
    results = await mock_service.analyze_treatment_neurotransmitter_effects(
        patient_id=test_patient_id,
        treatment_id=treatment_id,
        time_points=time_points,
        neurotransmitters=neurotransmitters,
    )

    # Verify results
    assert results is not None
    assert results["treatment"]["id"] == str(treatment_id)

    # Check timeline data includes requested neurotransmitters
    timeline = results["neurotransmitter_timeline"]
    for nt in neurotransmitters:
        assert nt.value in timeline
        assert len(timeline[nt.value]) == len(time_points)

    # Check affected regions
    affected_regions = results["affected_brain_regions"]
    assert len(affected_regions) > 0


@pytest.mark.asyncio
async def test_events_are_published(mock_service, test_patient_id):
    """Test that events are published when neurotransmitter mapping operations are performed."""
    # Subscribe to events
    events_received = []

    async def event_handler(event_type, event_data, source, patient_id):
        events_received.append(
            {
                "event_type": event_type,
                "event_data": event_data,
                "source": source,
                "patient_id": patient_id,
            }
        )

    subscription_id = await mock_service.subscribe_to_events(
        event_types=[
            "neurotransmitter_mapping.initialized",
            "neurotransmitter_mapping.profiles_updated",
        ],
        callback=event_handler,
    )

    # Initialize mapping
    await mock_service.initialize_neurotransmitter_mapping(
        patient_id=test_patient_id, use_default_mapping=True
    )

    # Update profiles
    await mock_service.update_receptor_profiles(
        patient_id=test_patient_id,
        receptor_profiles=[
            ReceptorProfile(
                brain_region=BrainRegion.THALAMUS,
                neurotransmitter=Neurotransmitter.GLUTAMATE,
                receptor_type=ReceptorType.EXCITATORY,
                receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,
                density=0.6,
                sensitivity=0.7,
                clinical_relevance=ClinicalSignificance.MILD,
            )
        ],
    )

    # Verify events were published
    assert len(events_received) == 2

    # Check event types
    assert events_received[0]["event_type"] == "neurotransmitter_mapping.initialized"
    assert events_received[1]["event_type"] == "neurotransmitter_mapping.profiles_updated"

    # Check event data
    assert "patient_id" in events_received[0]["event_data"]
    assert events_received[0]["event_data"]["patient_id"] == str(test_patient_id)

    # Clean up subscription
    await mock_service.unsubscribe_from_events(subscription_id)
