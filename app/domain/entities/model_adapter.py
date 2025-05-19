"""
Adapter classes for Digital Twin models.

This module provides adapter classes that allow compatibility between
different implementations of Digital Twin entities.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.domain.entities.digital_twin_entity import (
    ClinicalInsight,
)
from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    Neurotransmitter,
)


def ensure_enum_value(value, enum_class):
    """Convert string to enum value if necessary, or keep as enum value."""
    if isinstance(value, str):
        try:
            return enum_class(value)
        except ValueError:
            # If the string doesn't match any enum value, try matching by name
            try:
                return enum_class[value]
            except KeyError:
                # Return the original string if all conversions fail
                return value
    return value


@dataclass
class BrainRegionStateAdapter:
    """Adapter for brain region state information."""

    region: BrainRegion
    activation_level: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    related_symptoms: list[str] = field(default_factory=list)
    clinical_significance: ClinicalSignificance = ClinicalSignificance.NONE

    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        self.region = ensure_enum_value(self.region, BrainRegion)
        self.clinical_significance = ensure_enum_value(
            self.clinical_significance, ClinicalSignificance
        )

    def create_copy(self):
        """Create a copy of this brain region state."""
        return BrainRegionStateAdapter(
            region=self.region,
            activation_level=self.activation_level,
            confidence=self.confidence,
            related_symptoms=self.related_symptoms.copy(),
            clinical_significance=self.clinical_significance,
        )


@dataclass
class NeurotransmitterStateAdapter:
    """Adapter for neurotransmitter state information."""

    neurotransmitter: Neurotransmitter
    level: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    clinical_significance: ClinicalSignificance = ClinicalSignificance.NONE

    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        self.neurotransmitter = ensure_enum_value(self.neurotransmitter, Neurotransmitter)
        self.clinical_significance = ensure_enum_value(
            self.clinical_significance, ClinicalSignificance
        )

    def create_copy(self):
        """Create a copy of this neurotransmitter state."""
        return NeurotransmitterStateAdapter(
            neurotransmitter=self.neurotransmitter,
            level=self.level,
            confidence=self.confidence,
            clinical_significance=self.clinical_significance,
        )


@dataclass
class NeuralConnectionAdapter:
    """Adapter for neural connection information."""

    source_region: BrainRegion
    target_region: BrainRegion
    strength: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0

    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        self.source_region = ensure_enum_value(self.source_region, BrainRegion)
        self.target_region = ensure_enum_value(self.target_region, BrainRegion)

    def create_copy(self):
        """Create a copy of this neural connection."""
        return NeuralConnectionAdapter(
            source_region=self.source_region,
            target_region=self.target_region,
            strength=self.strength,
            confidence=self.confidence,
        )


@dataclass
class TemporalPatternAdapter:
    """Adapter for temporal pattern information."""

    pattern_type: str
    description: str
    confidence: float
    strength: float
    clinical_significance: ClinicalSignificance

    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        self.clinical_significance = ensure_enum_value(
            self.clinical_significance, ClinicalSignificance
        )

    def create_copy(self):
        """Create a copy of this temporal pattern."""
        return TemporalPatternAdapter(
            pattern_type=self.pattern_type,
            description=self.description,
            confidence=self.confidence,
            strength=self.strength,
            clinical_significance=self.clinical_significance,
        )


@dataclass
class DigitalTwinStateAdapter:
    """
    Adapter for Digital Twin state.

    This class adapts between different implementations of Digital Twin state
    to maintain compatibility across the codebase.
    """

    patient_id: UUID
    timestamp: datetime
    brain_regions: dict[BrainRegion, BrainRegionStateAdapter] = field(default_factory=dict)
    neurotransmitters: dict[Neurotransmitter, NeurotransmitterStateAdapter] = field(
        default_factory=dict
    )
    neural_connections: list[NeuralConnectionAdapter] = field(default_factory=list)
    clinical_insights: list[ClinicalInsight] = field(default_factory=list)
    temporal_patterns: list[TemporalPatternAdapter] = field(default_factory=list)
    update_source: str = None
    version: int = 1
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)
    biomarkers: dict[str, float] = field(default_factory=dict)
    predicted_states: dict[str, Any] = field(default_factory=dict)
    treatment_responses: dict[str, Any] = field(default_factory=dict)
    confidence_scores: dict[str, float] = field(default_factory=dict)
    active_treatments: set[str] = field(default_factory=set)

    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        # Ensure brain regions and neurotransmitters are properly converted
        brain_regions_copy = {}
        for key, value in self.brain_regions.items():
            brain_region = ensure_enum_value(key, BrainRegion)
            if not isinstance(value, BrainRegionStateAdapter):
                # Convert to adapter if not already
                value = BrainRegionStateAdapter(
                    region=brain_region,
                    activation_level=getattr(value, "activation_level", 0.5),
                    confidence=getattr(value, "confidence", 0.5),
                    related_symptoms=getattr(value, "related_symptoms", []),
                    clinical_significance=getattr(
                        value, "clinical_significance", ClinicalSignificance.NONE
                    ),
                )
            brain_regions_copy[brain_region] = value
        self.brain_regions = brain_regions_copy

        neurotransmitters_copy = {}
        for key, value in self.neurotransmitters.items():
            neurotransmitter = ensure_enum_value(key, Neurotransmitter)
            if not isinstance(value, NeurotransmitterStateAdapter):
                # Convert to adapter if not already
                value = NeurotransmitterStateAdapter(
                    neurotransmitter=neurotransmitter,
                    level=getattr(value, "level", 0.5),
                    confidence=getattr(value, "confidence", 0.5),
                    clinical_significance=getattr(
                        value, "clinical_significance", ClinicalSignificance.NONE
                    ),
                )
            neurotransmitters_copy[neurotransmitter] = value
        self.neurotransmitters = neurotransmitters_copy

        # Ensure neural connections are properly converted
        neural_connections_copy = []
        for conn in self.neural_connections:
            if not isinstance(conn, NeuralConnectionAdapter):
                # Convert to adapter if not already
                conn = NeuralConnectionAdapter(
                    source_region=getattr(conn, "source_region", None),
                    target_region=getattr(conn, "target_region", None),
                    strength=getattr(conn, "strength", 0.5),
                    confidence=getattr(conn, "confidence", 0.5),
                )
            neural_connections_copy.append(conn)
        self.neural_connections = neural_connections_copy

    def create_copy(self):
        """Create a copy of this digital twin state."""
        # Copy brain regions
        brain_regions_copy = {}
        for region, state in self.brain_regions.items():
            brain_regions_copy[region] = state.create_copy()

        # Copy neurotransmitters
        neurotransmitters_copy = {}
        for nt, state in self.neurotransmitters.items():
            neurotransmitters_copy[nt] = state.create_copy()

        # Copy neural connections
        neural_connections_copy = [conn.create_copy() for conn in self.neural_connections]

        # Copy temporal patterns
        temporal_patterns_copy = []
        for pattern in self.temporal_patterns:
            if isinstance(pattern, TemporalPatternAdapter):
                temporal_patterns_copy.append(pattern.create_copy())
            else:
                # Convert to adapter if not already
                temporal_patterns_copy.append(
                    TemporalPatternAdapter(
                        pattern_type=getattr(pattern, "pattern_type", ""),
                        description=getattr(pattern, "description", ""),
                        confidence=getattr(pattern, "confidence", 0.5),
                        strength=getattr(pattern, "strength", 0.5),
                        clinical_significance=getattr(
                            pattern, "clinical_significance", ClinicalSignificance.NONE
                        ),
                    )
                )

        return DigitalTwinStateAdapter(
            patient_id=self.patient_id,
            timestamp=self.timestamp,
            brain_regions=brain_regions_copy,
            neurotransmitters=neurotransmitters_copy,
            neural_connections=neural_connections_copy,
            clinical_insights=self.clinical_insights.copy(),
            temporal_patterns=temporal_patterns_copy,
            update_source=self.update_source,
            version=self.version,
            id=self.id,
            created_at=self.created_at,
            updated_at=self.updated_at,
            metadata=self.metadata.copy(),
            biomarkers=self.biomarkers.copy(),
            predicted_states=self.predicted_states.copy(),
            treatment_responses=self.treatment_responses.copy(),
            confidence_scores=self.confidence_scores.copy(),
            active_treatments=self.active_treatments.copy(),
        )

    def add_clinical_insight(self, insight: ClinicalInsight):
        """Add a clinical insight to the state."""
        # Make sure the insight isn't already present (by ID)
        existing_ids = {i.id for i in self.clinical_insights}
        if insight.id not in existing_ids:
            self.clinical_insights.append(insight)
