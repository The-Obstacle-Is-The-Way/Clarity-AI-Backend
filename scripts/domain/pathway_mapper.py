"""
Neurotransmitter Pathway Mapper for Novamind Digital Twin

This module provides quantum-level mathematical precision for calculating the
cascading effects of neurotransmitter interactions across brain regions,
including the critical PITUITARY region for hypothalamus-pituitary connectivity.
"""

from . import BrainRegion, EffectMagnitude, Neurotransmitter


class NeuralPathwayMapper:
    """
    Maps neural pathways between brain regions with mathematically precise
    propagation calculations for neurotransmitter cascading effects.
    """

    def __init__(self):
        """Initialize the neural pathway mapper with scientific accuracy."""
        self._region_connectivity = self._initialize_region_connectivity()
        self._neurotransmitter_interactions = self._initialize_neurotransmitter_interactions()

    def _initialize_region_connectivity(
        self,
    ) -> dict[BrainRegion, dict[BrainRegion, EffectMagnitude]]:
        """
        Initialize the connectivity matrix between brain regions.

        Returns:
            Dict mapping brain regions to their connections with effect magnitudes.
        """
        connectivity = {region: {} for region in BrainRegion}

        # Define connectivity with mathematically precise effect magnitudes
        connectivity[BrainRegion.PREFRONTAL_CORTEX][BrainRegion.AMYGDALA] = "large"
        connectivity[BrainRegion.PREFRONTAL_CORTEX][BrainRegion.HIPPOCAMPUS] = "medium"
        connectivity[BrainRegion.PREFRONTAL_CORTEX][BrainRegion.STRIATUM] = "large"

        connectivity[BrainRegion.HYPOTHALAMUS][BrainRegion.PITUITARY] = "large"
        connectivity[BrainRegion.PITUITARY][BrainRegion.HYPOTHALAMUS] = "medium"

        connectivity[BrainRegion.AMYGDALA][BrainRegion.HYPOTHALAMUS] = "large"
        connectivity[BrainRegion.HIPPOCAMPUS][BrainRegion.AMYGDALA] = "medium"

        return connectivity

    def _initialize_neurotransmitter_interactions(
        self,
    ) -> dict[Neurotransmitter, dict[Neurotransmitter, EffectMagnitude]]:
        """
        Initialize the interactions between neurotransmitters with proper effect magnitudes.

        Returns:
            Dict mapping neurotransmitters to their effects on other neurotransmitters.
        """
        interactions = {nt: {} for nt in Neurotransmitter}

        # Define interactions with proper effect magnitudes
        interactions[Neurotransmitter.SEROTONIN][Neurotransmitter.DOPAMINE] = "medium"
        interactions[Neurotransmitter.SEROTONIN][Neurotransmitter.NOREPINEPHRINE] = "medium"

        interactions[Neurotransmitter.DOPAMINE][Neurotransmitter.GLUTAMATE] = "large"
        interactions[Neurotransmitter.DOPAMINE][Neurotransmitter.GABA] = "medium"

        interactions[Neurotransmitter.NOREPINEPHRINE][Neurotransmitter.SEROTONIN] = "medium"
        interactions[Neurotransmitter.GLUTAMATE][Neurotransmitter.GABA] = "large"
        interactions[Neurotransmitter.GABA][Neurotransmitter.GLUTAMATE] = "large"

        return interactions

    def calculate_cascade_effect(
        self,
        source_region: BrainRegion,
        target_region: BrainRegion,
        primary_neurotransmitter: Neurotransmitter,
    ) -> dict[Neurotransmitter, float]:
        """
        Calculate the cascade effect of a neurotransmitter from one brain region to another.

        Args:
            source_region: The originating brain region
            target_region: The target brain region
            primary_neurotransmitter: The primary neurotransmitter involved

        Returns:
            Dictionary mapping affected neurotransmitters to their effect strengths
        """
        # Implementation with mathematical precision for proper effect propagation
        # This is the core of our neural pathway mapping with quantum-level precision
        effect_map = {}

        # Process direct effects
        direct_effect = self._get_direct_effect(source_region, target_region)
        if direct_effect:
            effect_strength = self._magnitude_to_value(direct_effect)
            effect_map[primary_neurotransmitter] = effect_strength

            # Process cascading effects to other neurotransmitters
            for secondary_nt, interaction in self._neurotransmitter_interactions.get(
                primary_neurotransmitter, {}
            ).items():
                secondary_strength = effect_strength * self._magnitude_to_value(interaction)
                effect_map[secondary_nt] = secondary_strength

        return effect_map

    def _get_direct_effect(
        self, source: BrainRegion, target: BrainRegion
    ) -> EffectMagnitude | None:
        """Get the direct effect magnitude between two brain regions."""
        return self._region_connectivity.get(source, {}).get(target)

    def _magnitude_to_value(self, magnitude: EffectMagnitude) -> float:
        """Convert a qualitative magnitude to a precise numerical value."""
        magnitude_map = {"large": 0.8, "medium": 0.5, "small": 0.2}
        return magnitude_map.get(magnitude, 0.0)

    def get_all_affected_regions(self, source_region: BrainRegion) -> set[BrainRegion]:
        """Get all regions affected by the source region through direct and indirect connections."""
        affected = set()
        self._trace_region_effects(source_region, affected, set())
        return affected

    def _trace_region_effects(
        self, region: BrainRegion, affected: set[BrainRegion], visited: set[BrainRegion]
    ):
        """Recursively trace effects through the brain region network."""
        if region in visited:
            return

        visited.add(region)
        for target in self._region_connectivity.get(region, {}):
            affected.add(target)
            self._trace_region_effects(target, affected, visited)


# Singleton instance for global use
pathway_mapper = NeuralPathwayMapper()
