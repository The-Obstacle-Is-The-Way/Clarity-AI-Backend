"""
Enumerations for the Digital Twin system.

These enums define the standardized values for brain regions, neurotransmitters,
and clinical metrics used throughout the system.
"""
from enum import Enum


class ConnectionType(Enum):
    """Types of connections between brain regions."""

    EXCITATORY = "excitatory"
    INHIBITORY = "inhibitory"
    MODULATORY = "modulatory"
    BIDIRECTIONAL = "bidirectional"
    UNIDIRECTIONAL = "unidirectional"
    AFFERENT = "afferent"
    EFFERENT = "efferent"


class BrainRegion(Enum):
    """Brain regions involved in neuropsychiatric functions."""

    PREFRONTAL_CORTEX = "prefrontal_cortex"
    AMYGDALA = "amygdala"
    HIPPOCAMPUS = "hippocampus"
    NUCLEUS_ACCUMBENS = "nucleus_accumbens"
    LOCUS_COERULEUS = "locus_coeruleus"
    VENTRAL_TEGMENTAL_AREA = "ventral_tegmental_area"
    RAPHE_NUCLEI = "raphe_nuclei"
    STRIATUM = "striatum"
    SUBSTANTIA_NIGRA = "substantia_nigra"
    HYPOTHALAMUS = "hypothalamus"
    THALAMUS = "thalamus"
    INSULA = "insula"
    ANTERIOR_CINGULATE_CORTEX = "anterior_cingulate_cortex"
    ORBITOFRONTAL_CORTEX = "orbitofrontal_cortex"
    PARIETAL_CORTEX = "parietal_cortex"
    TEMPORAL_CORTEX = "temporal_cortex"
    OCCIPITAL_CORTEX = "occipital_cortex"
    BASAL_GANGLIA = "basal_ganglia"
    CEREBELLUM = "cerebellum"
    BRAIN_STEM = "brain_stem"
    # Additional regions needed for tests
    VENTRAL_STRIATUM = "ventral_striatum"
    DORSAL_STRIATUM = "dorsal_striatum"
    PITUITARY = "pituitary"


class Neurotransmitter(Enum):
    """Neurotransmitters relevant to psychiatry and mental health."""

    SEROTONIN = "serotonin"
    DOPAMINE = "dopamine"
    NOREPINEPHRINE = "norepinephrine"
    GABA = "gaba"
    GLUTAMATE = "glutamate"
    ACETYLCHOLINE = "acetylcholine"
    ENDORPHINS = "endorphins"
    SUBSTANCE_P = "substance_p"
    OXYTOCIN = "oxytocin"
    HISTAMINE = "histamine"
    GLYCINE = "glycine"
    ADENOSINE = "adenosine"


class ClinicalSignificance(Enum):
    """Clinical significance levels for neurotransmitter effects."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MINIMAL = "minimal"
    MILD = "mild"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    SEVERE = "severe"
    # Additional level needed for tests
    CRITICAL = "critical"


class BrainNetwork(Enum):
    """Major functional brain networks."""

    DEFAULT_MODE = "default_mode"
    SALIENCE = "salience"
    EXECUTIVE_CONTROL = "executive_control"
    SENSORIMOTOR = "sensorimotor"
    VISUAL = "visual"
    AUDITORY = "auditory"
    LANGUAGE = "language"
    FRONTOPARIETAL = "frontoparietal"
    REWARD = "reward"
    FEAR = "fear"
    MEMORY = "memory"


class NeurotransmitterState(Enum):
    """State of neurotransmitter levels."""

    DEFICIENT = "deficient"
    BELOW_NORMAL = "below_normal"
    NORMAL = "normal"
    ABOVE_NORMAL = "above_normal"
    EXCESSIVE = "excessive"


class TreatmentClass(Enum):
    """Classification of psychiatric treatments."""

    SSRI = "ssri"
    SNRI = "snri"
    NDRI = "ndri"
    MAOI = "maoi"
    TCA = "tca"
    ATYPICAL_ANTIDEPRESSANT = "atypical_antidepressant"
    TYPICAL_ANTIPSYCHOTIC = "typical_antipsychotic"
    ATYPICAL_ANTIPSYCHOTIC = "atypical_antipsychotic"
    BENZODIAZEPINE = "benzodiazepine"
    MOOD_STABILIZER = "mood_stabilizer"
    STIMULANT = "stimulant"
    COGNITIVE_ENHANCER = "cognitive_enhancer"
    PSYCHOTHERAPY = "psychotherapy"
    TMS = "tms"
    ECT = "ect"
    KETAMINE_THERAPY = "ketamine_therapy"
    PSYCHEDELIC_THERAPY = "psychedelic_therapy"


class TemporalResolution(Enum):
    """Time resolution for neurotransmitter analysis."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


# Renamed enums to avoid namespace collisions with domain entities


class ClinicalInsightType(Enum):
    """Clinical insights derived from digital twin analysis."""

    TREATMENT_RESPONSE = "treatment_response"
    SYMPTOM_TRAJECTORY = "symptom_trajectory"
    NEUROTRANSMITTER_IMBALANCE = "neurotransmitter_imbalance"
    RELAPSE_RISK = "relapse_risk"
    SIDE_EFFECT_PROFILE = "side_effect_profile"
    THERAPEUTIC_WINDOW = "therapeutic_window"
    NEUROADAPTATION = "neuroadaptation"
    NEUROTRANSMITTER_DYNAMICS = "neurotransmitter_dynamics"
    COGNITIVE_PROFILE = "cognitive_profile"
    EMOTIONAL_REGULATION = "emotional_regulation"
    STRESS_RESPONSE = "stress_response"
    SLEEP_PATTERN = "sleep_pattern"
    CIRCADIAN_RHYTHM = "circadian_rhythm"
    BIOMARKER_CORRELATION = "biomarker_correlation"


class DigitalTwinStatus(Enum):
    """Overall status of the digital twin model."""

    INITIALIZING = "initializing"
    CALIBRATING = "calibrating"
    ACTIVE = "active"
    LEARNING = "learning"
    PREDICTING = "predicting"
    ANALYZING = "analyzing"
    UPDATING = "updating"
    VALIDATING = "validating"
    ERROR = "error"
    INACTIVE = "inactive"


class NeuralConnectionType(Enum):
    """Types of neural connections in the digital twin model."""

    PRIMARY = "primary"
    SECONDARY = "secondary"
    TERTIARY = "tertiary"
    FEEDFORWARD = "feedforward"
    FEEDBACK = "feedback"
    LATERAL = "lateral"
    RECIPROCAL = "reciprocal"
    MODULATORY = "modulatory"


class TemporalPatternType(Enum):
    """Temporal patterns in neurotransmitter activity."""

    SUSTAINED = "sustained"
    PHASIC = "phasic"
    TONIC = "tonic"
    RHYTHMIC = "rhythmic"
    TRANSIENT = "transient"
    CIRCADIAN = "circadian"
    ULTRADIAN = "ultradian"
    HOMEOSTATIC = "homeostatic"
    REACTIVE = "reactive"


class BrainRegionStatus(Enum):
    """Status of activity in brain regions."""

    HYPOACTIVE = "hypoactive"
    BELOW_BASELINE = "below_baseline"
    BASELINE = "baseline"
    ABOVE_BASELINE = "above_baseline"
    HYPERACTIVE = "hyperactive"
    DYSREGULATED = "dysregulated"
    SYNCHRONIZED = "synchronized"
    DESYNCHRONIZED = "desynchronized"
