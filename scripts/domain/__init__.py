"""
Neurotransmitter Pathway Module for Novamind Digital Twin.

This module orchestrates the signal propagation modeling between brain regions,
including the PITUITARY region for hypothalamus-pituitary connectivity.

The system models temporal neurotransmitter effects with appropriate magnitude
calculations ('large' or 'medium') and handles cascade effects with
mathematical precision.
"""

from enum import Enum, auto
from typing import Dict, List, Literal, Optional, Set, Tuple, Union

# Magnitude types for neural effects
EffectMagnitude = Literal["large", "medium", "small"]


class BrainRegion(Enum):
    """Brain regions explicitly modeled in the digital twin system."""

    PREFRONTAL_CORTEX = auto()
    AMYGDALA = auto()
    HIPPOCAMPUS = auto()
    HYPOTHALAMUS = auto()
    PITUITARY = auto()  # Added to support hypothalamus-pituitary connectivity
    STRIATUM = auto()
    NUCLEUS_ACCUMBENS = auto()


class Neurotransmitter(Enum):
    """Neurotransmitters modeled in the digital twin system."""

    SEROTONIN = auto()
    DOPAMINE = auto()
    NOREPINEPHRINE = auto()
    GABA = auto()
    GLUTAMATE = auto()
    ACETYLCHOLINE = auto()


# Type definitions for neural pathway modeling
RegionToRegionMapping = dict[BrainRegion, dict[BrainRegion, EffectMagnitude]]
NeurotransmitterEffects = dict[Neurotransmitter, dict[Neurotransmitter, EffectMagnitude]]
