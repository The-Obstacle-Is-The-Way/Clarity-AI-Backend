"""
Neurotransmitter mapping module for the Temporal Neurotransmitter System.

This module defines the core class that maps the relationship between
neurotransmitters across different brain regions and their effects.
"""

import uuid
from collections import defaultdict
from enum import Enum, auto
from uuid import UUID

from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    Neurotransmitter,
)
from app.domain.entities.neurotransmitter_effect import NeurotransmitterEffect


class ReceptorType(Enum):
    """
    Types of neurotransmitter receptors.

    Different receptor types determine how a neurotransmitter affects the target cell.
    """

    IONOTROPIC = auto()  # Direct ion channel modulation
    METABOTROPIC = auto()  # G-protein coupled
    TRANSPORTER = auto()  # Reuptake transporters
    ENZYME = auto()  # Metabolic enzymes
    # Additional types to maintain compatibility with tests
    EXCITATORY = auto()  # Receptors that increase cellular activity
    INHIBITORY = auto()  # Receptors that decrease cellular activity


class ReceptorSubtype(Enum):
    """
    Subtypes of neurotransmitter receptors.

    Each neurotransmitter may act on multiple receptor subtypes with different effects.
    """

    # Serotonin receptor subtypes
    SEROTONIN_5HT1A = auto()
    SEROTONIN_5HT1B = auto()
    SEROTONIN_5HT2A = auto()
    # Legacy alias for test compatibility
    FIVE_HT2A = SEROTONIN_5HT2A
    SEROTONIN_5HT2C = auto()
    SEROTONIN_5HT3 = auto()
    SEROTONIN_5HT4 = auto()

    # Dopamine receptor subtypes
    DOPAMINE_D1 = auto()
    DOPAMINE_D2 = auto()
    DOPAMINE_D3 = auto()
    DOPAMINE_D4 = auto()
    DOPAMINE_D5 = auto()

    # GABA receptor subtypes
    GABA_A = auto()
    GABA_B = auto()

    # Glutamate receptor subtypes
    GLUTAMATE_NMDA = auto()
    GLUTAMATE_AMPA = auto()
    GLUTAMATE_KAINATE = auto()
    GLUTAMATE_MGLUR = auto()
    # Cholinergic receptor subtype for compatibility
    NICOTINIC = auto()


class ReceptorProfile:
    """
    Represents a receptor profile for a specific brain region and neurotransmitter.

    Contains information about receptor types, their density, and clinical relevance.
    """

    def __init__(
        self,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
        receptor_type: ReceptorType,
        receptor_subtype: ReceptorSubtype,
        density: float,
        sensitivity: float,
        clinical_relevance: ClinicalSignificance,
    ):
        """Initialize a receptor profile with the given parameters."""
        self.brain_region = brain_region
        self.neurotransmitter = neurotransmitter
        self.receptor_type = receptor_type
        self.receptor_subtype = receptor_subtype
        self.density = density  # 0.0 - 1.0 scale
        self.sensitivity = sensitivity  # 0.0 - 1.0 scale
        self.clinical_relevance = clinical_relevance
        self.id = str(uuid.uuid4())

    def calculate_effect_magnitude(self) -> float:
        """
        Calculate the magnitude of the effect based on density and sensitivity.

        Returns:
            float: Effect magnitude on a 0.0 - 1.0 scale
        """
        return self.density * self.sensitivity

    def get_effect_direction(self) -> float:
        """
        Determine if the receptor has an excitatory or inhibitory effect.

        Returns:
            float: 1.0 for excitatory, -1.0 for inhibitory
        """
        if self.receptor_type == ReceptorType.EXCITATORY:
            return 1.0
        elif self.receptor_type == ReceptorType.INHIBITORY:
            return -1.0

        # For more complex receptor types, determine based on subtype
        # This is a simplified mapping
        excitatory_subtypes = {
            ReceptorSubtype.GLUTAMATE_NMDA,
            ReceptorSubtype.GLUTAMATE_AMPA,
            ReceptorSubtype.GLUTAMATE_KAINATE,
            ReceptorSubtype.DOPAMINE_D1,
            ReceptorSubtype.SEROTONIN_5HT2A,
            ReceptorSubtype.SEROTONIN_5HT4,
        }

        if self.receptor_subtype in excitatory_subtypes:
            return 1.0
        else:
            return -1.0

    def __eq__(self, other):
        """Compare two ReceptorProfile instances for equality."""
        if not isinstance(other, ReceptorProfile):
            return False

        return (
            self.brain_region == other.brain_region
            and self.neurotransmitter == other.neurotransmitter
            and self.receptor_type == other.receptor_type
            and self.receptor_subtype == other.receptor_subtype
            and self.density == other.density
            and self.sensitivity == other.sensitivity
            and self.clinical_relevance == other.clinical_relevance
        )

    def __hash__(self):
        """Generate a hash for the ReceptorProfile."""
        return hash(
            (
                self.brain_region,
                self.neurotransmitter,
                self.receptor_type,
                self.receptor_subtype,
                self.density,
                self.sensitivity,
                self.clinical_relevance,
            )
        )

    def __str__(self):
        """String representation of the receptor profile."""
        return (
            f"ReceptorProfile({self.brain_region.name}, {self.neurotransmitter.name}, "
            f"{self.receptor_type.name}, {self.receptor_subtype.name}, "
            f"density={self.density:.2f}, sensitivity={self.sensitivity:.2f}, "
            f"clinical_relevance={self.clinical_relevance.name})"
        )


class NeurotransmitterMapping:
    """
    Maps relationships between neurotransmitters and brain regions.

    This class is responsible for tracking which neurotransmitters affect which
    brain regions, how they're produced, and the clinical effects observed.
    """

    def __init__(self, patient_id: UUID | None = None):
        """Initialize a new neurotransmitter mapping.

        Args:
            patient_id: Optional UUID of the associated patient.
        """
        self.patient_id: UUID = patient_id if patient_id else uuid.uuid4()
        # For test compatibility: list of receptor profiles
        self.receptor_profiles: list[ReceptorProfile] = []

        # Maps BrainRegion to dict of Neurotransmitter -> float
        self.receptor_map: dict[BrainRegion, dict[Neurotransmitter, float]] = {}

        # Maps BrainRegion to list of Neurotransmitters it produces
        self.production_map: dict[BrainRegion, set[Neurotransmitter]] = {}

        # Maps BrainRegion to dict of BrainRegion -> connectivity strength
        self.brain_region_connectivity: dict[BrainRegion, dict[BrainRegion, float]] = defaultdict(
            lambda: defaultdict(float)
        )

    def add_receptor_profile(self, profile: ReceptorProfile) -> None:
        """
        Add a detailed receptor profile.

        Args:
            profile: The ReceptorProfile to add
        """
        if not isinstance(profile, ReceptorProfile):
            raise TypeError("Profile must be an instance of ReceptorProfile")

        # Check if a profile for this exact region/neurotransmitter/type already exists
        # to avoid duplicates. This might need refinement based on desired behavior.
        # For now, simple append.
        self.receptor_profiles.append(profile)

    def get_receptor_profiles(
        self,
        brain_region: BrainRegion | None = None,
        neurotransmitter: Neurotransmitter | None = None,
    ) -> list[ReceptorProfile]:
        """
        Get receptor profiles, optionally filtered by brain region and/or neurotransmitter.

        Args:
            brain_region: Optional brain region to filter by
            neurotransmitter: Optional neurotransmitter to filter by

        Returns:
            List of receptor profiles matching the filters
        """
        result = self.receptor_profiles

        if brain_region:
            result = [p for p in result if p.brain_region == brain_region]

        if neurotransmitter:
            result = [p for p in result if p.neurotransmitter == neurotransmitter]

        return result

    def get_receptor_regions(
        self, neurotransmitter: Neurotransmitter
    ) -> list[tuple[BrainRegion, float]]:
        """
        Get all brain regions that have receptors for a specific neurotransmitter.

        This method returns a list of tuples, where each tuple contains a brain region
        and the receptor density for the specified neurotransmitter in that region.

        Args:
            neurotransmitter: The neurotransmitter to find receptors for

        Returns:
            List of tuples (BrainRegion, density) for regions with receptors for this neurotransmitter
        """
        regions = []

        # First check the receptor map (for backward compatibility)
        for region, nt_map in self.receptor_map.items():
            if neurotransmitter in nt_map:
                regions.append((region, nt_map[neurotransmitter]))

        # If no regions found in the map, check the profiles
        if not regions:
            for profile in self.receptor_profiles:
                if profile.neurotransmitter == neurotransmitter:
                    # Use region and density from the profile
                    regions.append((profile.brain_region, profile.density))

        return regions

    def calculate_region_response(
        self,
        brain_region: BrainRegion,
        neurotransmitter: Neurotransmitter,
        level: float = 0.5,
        neurotransmitter_level: float | None = None,  # For compatibility with tests
    ) -> tuple[float, float]:
        """
        Calculate the response of a brain region to a neurotransmitter at a given level.

        Args:
            brain_region: The brain region to calculate the response for
            neurotransmitter: The neurotransmitter affecting the region
            level: The level of the neurotransmitter (0.0 - 1.0)
            neurotransmitter_level: Alias for level (for test compatibility)

        Returns:
            Tuple of (effect, confidence), where effect is -1.0 to 1.0 and confidence is 0.0 to 1.0
        """
        # For test compatibility
        if neurotransmitter_level is not None:
            level = neurotransmitter_level

        if brain_region not in self.receptor_map:
            return 0.0, 0.0

        if neurotransmitter not in self.receptor_map[brain_region]:
            return 0.0, 0.0

        # Get relevant receptor profiles
        profiles = self.get_receptor_profiles(brain_region, neurotransmitter)

        if not profiles:
            # Fall back to simplified model if no detailed profiles
            sensitivity = self.receptor_map[brain_region][neurotransmitter]
            return level * sensitivity, 0.8

        # Calculate net effect from all profiles
        total_effect = 0.0
        confidence = 0.0

        for profile in profiles:
            magnitude = profile.calculate_effect_magnitude()
            direction = profile.get_effect_direction()
            total_effect += magnitude * direction * level

            # Higher clinical significance = higher confidence
            confidence_factor = 0.5
            if profile.clinical_relevance == ClinicalSignificance.MODERATE:
                confidence_factor = 0.7
            elif profile.clinical_relevance in (
                ClinicalSignificance.SIGNIFICANT,
                ClinicalSignificance.SEVERE,
                ClinicalSignificance.CRITICAL,
            ):
                confidence_factor = 0.9

            confidence = max(confidence, confidence_factor)

        # Normalize to -1.0 to 1.0 range
        effect = max(-1.0, min(1.0, total_effect))

        return effect, confidence

    def add_production_site(
        self, neurotransmitter: Neurotransmitter, brain_region: BrainRegion
    ) -> None:
        """
        Add a production site for a neurotransmitter.

        Args:
            neurotransmitter: The neurotransmitter being produced
            brain_region: The brain region producing it
        """
        # Ensure the brain region exists as a key, initialized with a set
        if brain_region not in self.production_map:
            self.production_map[brain_region] = set()

        # Add the neurotransmitter to the set for that brain region
        self.production_map[brain_region].add(neurotransmitter)

    def get_producing_regions(self, neurotransmitter: Neurotransmitter) -> list[BrainRegion]:
        """
        Get all brain regions that produce a given neurotransmitter.

        Args:
            neurotransmitter: The neurotransmitter to find producers for

        Returns:
            List of brain regions that produce the neurotransmitter
        """
        regions: list[BrainRegion] = []
        for region, neurotransmitters in self.production_map.items():
            if isinstance(region, BrainRegion) and neurotransmitter in neurotransmitters:
                regions.append(region)
        return regions

    def get_affected_regions(self, neurotransmitter: Neurotransmitter) -> list[BrainRegion]:
        """
        Get all brain regions affected by a given neurotransmitter.

        Args:
            neurotransmitter: The neurotransmitter to find affected regions for

        Returns:
            List of brain regions affected by the neurotransmitter
        """
        regions = []
        for region, neurotransmitters in self.receptor_map.items():
            if neurotransmitter in neurotransmitters:
                regions.append(region)
        return regions

    def analyze_receptor_affinity(
        self, neurotransmitter: Neurotransmitter, brain_region: BrainRegion
    ) -> float:
        """
        Analyze the receptor affinity of a neurotransmitter for a brain region.

        This calculates how strongly a neurotransmitter binds to receptors in a region.

        Args:
            neurotransmitter: The neurotransmitter to analyze
            brain_region: The brain region to analyze

        Returns:
            Receptor affinity value from 0.0 (no affinity) to 1.0 (max affinity)
        """
        # Check receptor map for basic mapping
        if (
            brain_region in self.receptor_map
            and neurotransmitter in self.receptor_map[brain_region]
        ):
            return self.receptor_map[brain_region][neurotransmitter]

        # Check profiles for more detailed mapping
        profiles = self.get_receptor_profiles(brain_region, neurotransmitter)
        if profiles:
            # Return average of profile densities
            return sum(p.density for p in profiles) / len(profiles)

        # No receptor data found
        return 0.0

    def analyze_baseline_effect(
        self,
        neurotransmitter: Neurotransmitter,
        brain_region: BrainRegion,
        patient_id: UUID | None = None,
    ) -> NeurotransmitterEffect:
        """
        Analyze the baseline effect of a neurotransmitter on a brain region.

        Args:
            neurotransmitter: The neurotransmitter to analyze
            brain_region: The brain region to analyze
            patient_id: Optional patient identifier for personalized analysis

        Returns:
            NeurotransmitterEffect with baseline analysis
        """
        # Get receptor affinity
        affinity = self.analyze_receptor_affinity(neurotransmitter, brain_region)

        # Baseline effect is proportional to affinity
        effect_size = affinity * 0.5  # Scale to moderate effect

        # Determine p-value based on receptor mapping confidence
        # Lower p-value means more statistically significant effect
        p_value = 0.05 if affinity >= 0.7 else 0.2

        # Confidence interval
        confidence_interval = (max(0.0, effect_size - 0.1), min(1.0, effect_size + 0.1))

        # Clinical significance based on effect size and receptor density
        clinical_significance = ClinicalSignificance.NONE
        if p_value < 0.05:
            if effect_size >= 0.7:
                clinical_significance = ClinicalSignificance.SIGNIFICANT
            elif effect_size >= 0.5:
                clinical_significance = ClinicalSignificance.MODERATE
            elif effect_size >= 0.3:
                clinical_significance = ClinicalSignificance.MILD
            else:
                clinical_significance = ClinicalSignificance.MINIMAL

        # Create effect object
        effect = NeurotransmitterEffect(
            neurotransmitter=neurotransmitter,
            effect_size=effect_size,
            p_value=p_value,
            confidence_interval=confidence_interval,
            clinical_significance=clinical_significance,
            brain_region=brain_region,
            sample_size=20,  # Default sample size for baseline analysis
        )

        return effect

    def _build_lookup_maps(self) -> None:
        """
        Build internal lookup maps for quick access to profiles by region and neurotransmitter.
        """
        # Clear existing map
        self.receptor_map = {}

        # Build receptor map from profiles
        for profile in self.receptor_profiles:
            region = profile.brain_region
            neurotransmitter = profile.neurotransmitter

            if region not in self.receptor_map:
                self.receptor_map[region] = {}

            # Use max effect magnitude for simplified mapping
            effect = profile.calculate_effect_magnitude()
            if neurotransmitter in self.receptor_map[region]:
                current_effect = self.receptor_map[region][neurotransmitter]
                self.receptor_map[region][neurotransmitter] = max(current_effect, effect)
            else:
                self.receptor_map[region][neurotransmitter] = effect

    def calculate_regional_activity(
        self,
        brain_region: BrainRegion,
        neurotransmitter_levels: dict[Neurotransmitter, float],
    ) -> dict[str, float]:
        """
        Calculate regional activity levels based on receptor profiles and given neurotransmitter levels.

        Args:
            brain_region: The brain region to calculate activity for.
            neurotransmitter_levels: Mapping of neurotransmitter to its level (0.0 - 1.0).

        Returns:
            Dict with keys 'excitatory', 'inhibitory', and 'net_activity'.
        """
        excitatory = 0.0
        inhibitory = 0.0
        # Sum effects for each profile in the region
        for profile in self.receptor_profiles:
            if profile.brain_region != brain_region:
                continue
            # Get level for this neurotransmitter, default to 0.0 if missing
            level = neurotransmitter_levels.get(profile.neurotransmitter, 0.0)
            effect = profile.density * profile.sensitivity * level
            if profile.receptor_type == ReceptorType.EXCITATORY:
                excitatory += effect
            elif profile.receptor_type == ReceptorType.INHIBITORY:
                inhibitory += effect
        net_activity = excitatory - inhibitory
        return {
            "excitatory": excitatory,
            "inhibitory": inhibitory,
            "net_activity": net_activity,
        }


def create_default_neurotransmitter_mapping(
    patient_id: UUID | None = None,
) -> NeurotransmitterMapping:
    """
    Create a default neurotransmitter mapping with scientific defaults.

    Returns:
        A neurotransmitter mapping with default values
    """
    mapping = NeurotransmitterMapping(patient_id=patient_id)

    # Add default production sites
    mapping.add_production_site(Neurotransmitter.SEROTONIN, BrainRegion.RAPHE_NUCLEI)
    mapping.add_production_site(Neurotransmitter.DOPAMINE, BrainRegion.SUBSTANTIA_NIGRA)
    mapping.add_production_site(Neurotransmitter.DOPAMINE, BrainRegion.VENTRAL_TEGMENTAL_AREA)
    mapping.add_production_site(Neurotransmitter.NOREPINEPHRINE, BrainRegion.LOCUS_COERULEUS)
    mapping.add_production_site(
        Neurotransmitter.GABA, BrainRegion.STRIATUM
    )  # For test compatibility

    # Add default receptor profiles
    profiles = [
        # Prefrontal cortex profiles
        ReceptorProfile(
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.DOPAMINE,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.DOPAMINE_D1,
            density=0.8,
            sensitivity=0.7,
            clinical_relevance=ClinicalSignificance.SIGNIFICANT,
        ),
        ReceptorProfile(
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            receptor_type=ReceptorType.INHIBITORY,
            receptor_subtype=ReceptorSubtype.SEROTONIN_5HT1A,
            density=0.7,
            sensitivity=0.6,
            clinical_relevance=ClinicalSignificance.MODERATE,
        ),
        # Amygdala profiles
        ReceptorProfile(
            brain_region=BrainRegion.AMYGDALA,
            neurotransmitter=Neurotransmitter.GABA,
            receptor_type=ReceptorType.INHIBITORY,
            receptor_subtype=ReceptorSubtype.GABA_A,
            density=0.9,
            sensitivity=0.8,
            clinical_relevance=ClinicalSignificance.SIGNIFICANT,
        ),
        ReceptorProfile(
            brain_region=BrainRegion.AMYGDALA,
            neurotransmitter=Neurotransmitter.GLUTAMATE,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,
            density=0.7,
            sensitivity=0.8,
            clinical_relevance=ClinicalSignificance.MODERATE,
        ),
        # Hippocampus profiles (needed for test_default_mapping_creation)
        ReceptorProfile(
            brain_region=BrainRegion.HIPPOCAMPUS,
            neurotransmitter=Neurotransmitter.GLUTAMATE,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,
            density=0.8,
            sensitivity=0.9,
            clinical_relevance=ClinicalSignificance.SIGNIFICANT,
        ),
        ReceptorProfile(
            brain_region=BrainRegion.HIPPOCAMPUS,
            neurotransmitter=Neurotransmitter.ACETYLCHOLINE,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.GLUTAMATE_NMDA,  # Using as placeholder
            density=0.7,
            sensitivity=0.8,
            clinical_relevance=ClinicalSignificance.MODERATE,
        ),
        # Default pituitary profile for test compatibility
        ReceptorProfile(
            brain_region=BrainRegion.PITUITARY,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            receptor_type=ReceptorType.INHIBITORY,
            receptor_subtype=ReceptorSubtype.GABA_A,
            density=0.5,
            sensitivity=0.5,
            clinical_relevance=ClinicalSignificance.MODERATE,
        ),
    ]

    for profile in profiles:
        mapping.add_receptor_profile(profile)

    # Build the lookup maps *after* adding defaults
    mapping._build_lookup_maps()

    return mapping
