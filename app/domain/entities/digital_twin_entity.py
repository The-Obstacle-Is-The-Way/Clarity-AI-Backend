"""
Domain entities for the Digital Twin core component.
Pure domain models with no external dependencies.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID


class BrainRegion(Enum):
    """Brain regions of interest for the Digital Twin."""

    PREFRONTAL_CORTEX = "prefrontal_cortex"
    ANTERIOR_CINGULATE = "anterior_cingulate"
    AMYGDALA = "amygdala"
    HIPPOCAMPUS = "hippocampus"
    NUCLEUS_ACCUMBENS = "nucleus_accumbens"
    VENTRAL_TEGMENTAL = "ventral_tegmental"
    HYPOTHALAMUS = "hypothalamus"
    INSULA = "insula"
    ORBITOFRONTAL_CORTEX = "orbitofrontal_cortex"
    DORSOLATERAL_PREFRONTAL = "dorsolateral_prefrontal"


class Neurotransmitter(Enum):
    """Key neurotransmitters tracked in the Digital Twin."""

    SEROTONIN = "serotonin"
    DOPAMINE = "dopamine"
    NOREPINEPHRINE = "norepinephrine"
    GABA = "gaba"
    GLUTAMATE = "glutamate"


class ClinicalSignificance(Enum):
    """Clinical significance levels for insights and changes."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BrainRegionState:
    """State of a specific brain region in the Digital Twin."""

    region: BrainRegion
    activation_level: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    related_symptoms: list[str] = field(default_factory=list)
    clinical_significance: ClinicalSignificance = ClinicalSignificance.NONE


@dataclass
class NeurotransmitterState:
    """State of a specific neurotransmitter in the Digital Twin."""

    neurotransmitter: Neurotransmitter
    level: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    clinical_significance: ClinicalSignificance = ClinicalSignificance.NONE


@dataclass
class NeuralConnection:
    """Connection between brain regions in the Digital Twin."""

    source_region: BrainRegion
    target_region: BrainRegion
    strength: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0


@dataclass
class ClinicalInsight:
    """Clinical insight derived from Digital Twin analysis."""

    id: UUID
    title: str
    description: str
    source: str  # e.g., "PAT", "MentalLLaMA", "XGBoost"
    confidence: float  # 0.0 to 1.0
    timestamp: datetime = field(default_factory=datetime.now)
    clinical_significance: ClinicalSignificance = ClinicalSignificance.NONE
    patient_id: str | None = None
    brain_regions: list[BrainRegion] = field(default_factory=list)
    neurotransmitters: list[Neurotransmitter] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    related_data: dict = field(default_factory=dict)
    significance: ClinicalSignificance = ClinicalSignificance.NONE


@dataclass
class TemporalPattern:
    """Temporal pattern detected in patient data."""

    pattern_type: str  # e.g., "circadian", "weekly", "seasonal"
    description: str
    confidence: float
    strength: float
    clinical_significance: ClinicalSignificance


@dataclass
class DigitalTwinState:
    """
    Comprehensive state of the Digital Twin for a patient.
    Core domain entity that represents the complete mental health model.
    """

    patient_id: UUID
    timestamp: datetime
    brain_regions: dict[BrainRegion, BrainRegionState] = field(default_factory=dict)
    neurotransmitters: dict[Neurotransmitter, NeurotransmitterState] = field(default_factory=dict)
    neural_connections: list[NeuralConnection] = field(default_factory=list)
    clinical_insights: list[ClinicalInsight] = field(default_factory=list)
    temporal_patterns: list[TemporalPattern] = field(default_factory=list)
    update_source: str | None = None
    version: int = 1

    @property
    def significant_regions(self) -> list[BrainRegionState]:
        """Return brain regions with clinical significance above NONE."""
        return [
            region
            for region in self.brain_regions.values()
            if region.clinical_significance != ClinicalSignificance.NONE
        ]

    @property
    def critical_insights(self) -> list[ClinicalInsight]:
        """Return insights with HIGH or CRITICAL significance."""
        return [
            insight
            for insight in self.clinical_insights
            if insight.clinical_significance
            in [ClinicalSignificance.HIGH, ClinicalSignificance.CRITICAL]
        ]

    def generate_fingerprint(self) -> str:
        """Generate a unique fingerprint for this state for verification."""
        # Implementation would create a hash based on key properties
        return f"{self.patient_id}:{self.timestamp}:{self.version}"
