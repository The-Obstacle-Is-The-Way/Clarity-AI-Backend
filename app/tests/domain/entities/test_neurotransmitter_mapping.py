"""
Unit tests for the NeurotransmitterMapping entity and related functionality.

These tests verify that the neurotransmitter mapping models behave correctly
and perform calculations accurately.
"""
import uuid

import pytest

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
    create_default_neurotransmitter_mapping,
)


@pytest.mark.venv_only()
def test_neurotransmitter_mapping_creation() -> None:
    """Test creating a new neurotransmitter mapping."""
    test_patient_id = uuid.uuid4()
    mapping = NeurotransmitterMapping(patient_id=test_patient_id)

    assert mapping is not None
    assert isinstance(mapping, NeurotransmitterMapping)
    assert len(mapping.receptor_profiles) == 0
    assert mapping.patient_id == test_patient_id


def test_add_receptor_profile() -> None:
    """Test adding receptor profiles to a mapping."""
    test_patient_id = uuid.uuid4()
    mapping = NeurotransmitterMapping(patient_id=test_patient_id)

    # Create a receptor profile
    profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    # Add it to the mapping
    mapping.add_receptor_profile(profile)

    # Verify it was added
    assert len(mapping.receptor_profiles) == 1
    assert mapping.receptor_profiles[0] == profile

    # Add another profile for the same region but different neurotransmitter
    profile2 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.DOPAMINE,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.DOPAMINE_D1,
        density=0.6,
        sensitivity=0.7,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    mapping.add_receptor_profile(profile2)

    # Verify both profiles are in the mapping
    assert len(mapping.receptor_profiles) == 2
    assert profile in mapping.receptor_profiles
    assert profile2 in mapping.receptor_profiles


def test_get_profiles_by_neurotransmitter() -> None:
    """Test retrieving profiles by neurotransmitter."""
    test_patient_id = uuid.uuid4()
    mapping = NeurotransmitterMapping(patient_id=test_patient_id)

    # Add profiles for different neurotransmitters
    serotonin_profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    dopamine_profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.DOPAMINE,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.DOPAMINE_D1,
        density=0.6,
        sensitivity=0.7,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    gaba_profile = ReceptorProfile(
        brain_region=BrainRegion.AMYGDALA,
        neurotransmitter=Neurotransmitter.GABA,
        receptor_type=ReceptorType.INHIBITORY,
        receptor_subtype=ReceptorSubtype.GABA_A,
        density=0.5,
        sensitivity=0.6,
        clinical_relevance=ClinicalSignificance.MILD,
    )

    mapping.add_receptor_profile(serotonin_profile)
    mapping.add_receptor_profile(dopamine_profile)
    mapping.add_receptor_profile(gaba_profile)

    # Get profiles by neurotransmitter
    serotonin_profiles = mapping.get_receptor_profiles(neurotransmitter=Neurotransmitter.SEROTONIN)
    dopamine_profiles = mapping.get_receptor_profiles(neurotransmitter=Neurotransmitter.DOPAMINE)
    gaba_profiles = mapping.get_receptor_profiles(neurotransmitter=Neurotransmitter.GABA)
    glutamate_profiles = mapping.get_receptor_profiles(neurotransmitter=Neurotransmitter.GLUTAMATE)

    # Verify results
    assert len(serotonin_profiles) == 1
    assert len(dopamine_profiles) == 1
    assert len(gaba_profiles) == 1
    assert len(glutamate_profiles) == 0  # No glutamate profiles added

    assert serotonin_profiles[0] == serotonin_profile
    assert dopamine_profiles[0] == dopamine_profile
    assert gaba_profiles[0] == gaba_profile


def test_get_profiles_by_brain_region() -> None:
    """Test retrieving profiles by brain region."""
    test_patient_id = uuid.uuid4()
    mapping = NeurotransmitterMapping(patient_id=test_patient_id)

    # Add profiles for different brain regions
    pfc_profile1 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    pfc_profile2 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.DOPAMINE,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.DOPAMINE_D1,
        density=0.6,
        sensitivity=0.7,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    amygdala_profile = ReceptorProfile(
        brain_region=BrainRegion.AMYGDALA,
        neurotransmitter=Neurotransmitter.GABA,
        receptor_type=ReceptorType.INHIBITORY,
        receptor_subtype=ReceptorSubtype.GABA_A,
        density=0.5,
        sensitivity=0.6,
        clinical_relevance=ClinicalSignificance.MILD,
    )

    hippocampus_profile = ReceptorProfile(
        brain_region=BrainRegion.HIPPOCAMPUS,
        neurotransmitter=Neurotransmitter.GLUTAMATE,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,
        density=0.8,
        sensitivity=0.9,
        clinical_relevance=ClinicalSignificance.HIGH,
    )

    mapping.add_receptor_profile(pfc_profile1)
    mapping.add_receptor_profile(pfc_profile2)
    mapping.add_receptor_profile(amygdala_profile)
    mapping.add_receptor_profile(hippocampus_profile)

    # Get profiles by brain region
    pfc_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.PREFRONTAL_CORTEX)
    amygdala_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.AMYGDALA)
    hippocampus_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.HIPPOCAMPUS)
    pituitary_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.PITUITARY)

    # Verify results
    assert len(pfc_profiles) == 2
    assert len(amygdala_profiles) == 1
    assert len(hippocampus_profiles) == 1
    assert len(pituitary_profiles) == 0  # No pituitary profiles added

    assert pfc_profile1 in pfc_profiles
    assert pfc_profile2 in pfc_profiles
    assert amygdala_profile in amygdala_profiles
    assert hippocampus_profile in hippocampus_profiles


def test_calculate_regional_activity() -> None:
    """Test calculating regional activity levels."""
    test_patient_id = uuid.uuid4()
    mapping = NeurotransmitterMapping(patient_id=test_patient_id)

    # Add profiles for a specific region
    pfc_profile1 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    pfc_profile2 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.DOPAMINE,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.DOPAMINE_D1,
        density=0.6,
        sensitivity=0.7,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    pfc_profile3 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.GABA,
        receptor_type=ReceptorType.INHIBITORY,
        receptor_subtype=ReceptorSubtype.GABA_A,
        density=0.5,
        sensitivity=0.6,
        clinical_relevance=ClinicalSignificance.MILD,
    )

    mapping.add_receptor_profile(pfc_profile1)
    mapping.add_receptor_profile(pfc_profile2)
    mapping.add_receptor_profile(pfc_profile3)

    # Calculate regional activity
    neurotransmitter_levels = {
        Neurotransmitter.SEROTONIN: 0.8,
        Neurotransmitter.DOPAMINE: 0.7,
        Neurotransmitter.GABA: 0.6,
    }

    activity = mapping.calculate_regional_activity(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter_levels=neurotransmitter_levels,
    )

    # Verify activity calculation
    assert activity is not None
    assert "excitatory" in activity
    assert "inhibitory" in activity
    assert "net_activity" in activity

    # Excitatory activity = (0.7 * 0.8 * 0.8) + (0.6 * 0.7 * 0.7) = 0.448 + 0.294 = 0.742
    # Inhibitory activity = (0.5 * 0.6 * 0.6) = 0.18
    # Net activity = 0.742 - 0.18 = 0.562
    assert abs(activity["excitatory"] - 0.742) < 0.001
    assert abs(activity["inhibitory"] - 0.18) < 0.001
    assert abs(activity["net_activity"] - 0.562) < 0.001


def test_create_default_mapping() -> None:
    """Test creating a default neurotransmitter mapping."""
    test_patient_id = uuid.uuid4()
    mapping = create_default_neurotransmitter_mapping(patient_id=test_patient_id)

    # Verify the mapping has default profiles
    assert mapping is not None
    assert len(mapping.receptor_profiles) > 0

    # Check that all major brain regions and neurotransmitters are represented
    pfc_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.PREFRONTAL_CORTEX)
    amygdala_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.AMYGDALA)
    hippocampus_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.HIPPOCAMPUS)
    pituitary_profiles = mapping.get_receptor_profiles(brain_region=BrainRegion.PITUITARY)

    assert len(pfc_profiles) > 0
    assert len(amygdala_profiles) > 0
    assert len(hippocampus_profiles) > 0
    assert len(pituitary_profiles) > 0  # Ensure PITUITARY region is included


def test_receptor_profile_creation() -> None:
    """Test creating and manipulating receptor profiles."""
    # Create a profile
    profile = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    # Check attributes
    assert profile.brain_region == BrainRegion.PREFRONTAL_CORTEX
    assert profile.neurotransmitter == Neurotransmitter.SEROTONIN
    assert profile.receptor_type == ReceptorType.EXCITATORY
    assert profile.receptor_subtype == ReceptorSubtype.SEROTONIN_5HT2A
    assert profile.density == 0.7
    assert profile.sensitivity == 0.8
    assert profile.clinical_relevance == ClinicalSignificance.MODERATE

    # Test equality
    profile2 = ReceptorProfile(
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    profile3 = ReceptorProfile(
        brain_region=BrainRegion.AMYGDALA,  # Different region
        neurotransmitter=Neurotransmitter.SEROTONIN,
        receptor_type=ReceptorType.EXCITATORY,
        receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
        density=0.7,
        sensitivity=0.8,
        clinical_relevance=ClinicalSignificance.MODERATE,
    )

    assert profile == profile2  # Same attributes
    assert profile != profile3  # Different brain region

    # Test string representation
    assert "PREFRONTAL_CORTEX" in str(profile)
    assert "SEROTONIN" in str(profile)
    assert "SEROTONIN_5HT2A" in str(profile)
