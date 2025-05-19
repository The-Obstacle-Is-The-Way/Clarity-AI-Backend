"""
Enhanced domain service interface for PAT (Pretrained Actigraphy Transformer) with advanced capabilities.
Pure domain interface with no infrastructure dependencies.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.entities.digital_twin_enums import (
    TemporalPattern,
)  # Corrected import path
from app.domain.entities.knowledge_graph import TemporalKnowledgeGraph


class EnhancedPATService(ABC):
    """
    Abstract interface for enhanced Pretrained Actigraphy Transformer operations.
    Extends basic PAT capabilities with multi-device fusion, chronobiology,
    movement semantics, and autonomic system modeling.

    Concrete implementations will be provided in the infrastructure layer.
    """

    @abstractmethod
    async def fuse_multi_device_data(
        self,
        patient_id: UUID,
        device_data: dict[str, dict],  # device_type -> device_data
        time_range: tuple[datetime, datetime],
        interpolation_method: str = "linear",  # "linear", "cubic", "nearest"
    ) -> dict:
        """
        Harmonize and fuse data from multiple wearable devices.

        Args:
            patient_id: UUID of the patient
            device_data: Dictionary mapping device types to their data
            time_range: Start and end times for the fusion
            interpolation_method: Method for interpolating missing data

        Returns:
            Dictionary with fused biosignal data and synchronization metadata
        """
        pass

    @abstractmethod
    async def process_oura_ring_data(
        self,
        patient_id: UUID,
        oura_data: dict,
        analysis_types: list[str] = ["sleep", "hrv", "temperature", "activity"],
    ) -> dict:
        """
        Process Oura Ring data to extract sleep architecture and other patterns.

        Args:
            patient_id: UUID of the patient
            oura_data: Raw data from Oura Ring
            analysis_types: Types of analyses to perform

        Returns:
            Dictionary with Oura analysis results
        """
        pass

    @abstractmethod
    async def process_continuous_glucose_data(
        self,
        patient_id: UUID,
        glucose_data: dict,
        activity_data: dict | None = None,
        food_log: dict | None = None,
    ) -> dict:
        """
        Process continuous glucose monitor data to extract metabolic patterns.

        Args:
            patient_id: UUID of the patient
            glucose_data: Raw data from continuous glucose monitor
            activity_data: Optional synchronized activity data
            food_log: Optional food log data

        Returns:
            Dictionary with glucose pattern analysis and correlations
        """
        pass

    @abstractmethod
    async def analyze_heart_rate_variability(
        self,
        patient_id: UUID,
        ecg_data: dict,
        analysis_window: int = 5,  # minutes
        frequency_domain: bool = True,
    ) -> dict:
        """
        Analyze ECG/PPG data for HRV patterns and cardiac coherence.

        Args:
            patient_id: UUID of the patient
            ecg_data: Raw ECG or PPG data
            analysis_window: Window size in minutes for analysis
            frequency_domain: Whether to include frequency domain analysis

        Returns:
            Dictionary with HRV analysis and cardiac coherence metrics
        """
        pass

    @abstractmethod
    async def process_electrodermal_activity(
        self, patient_id: UUID, eda_data: dict, contextual_data: dict | None = None
    ) -> dict:
        """
        Process skin conductance data for sympathetic nervous system activation.

        Args:
            patient_id: UUID of the patient
            eda_data: Raw electrodermal activity data
            contextual_data: Optional contextual data (events, stressors)

        Returns:
            Dictionary with EDA analysis and SNS activation patterns
        """
        pass

    @abstractmethod
    async def analyze_temperature_rhythms(
        self,
        patient_id: UUID,
        temperature_data: dict,
        ambient_data: dict | None = None,
        days: int = 14,
    ) -> dict:
        """
        Analyze body temperature data for circadian rhythm patterns.

        Args:
            patient_id: UUID of the patient
            temperature_data: Raw temperature sensor data
            ambient_data: Optional ambient temperature data
            days: Number of days to analyze

        Returns:
            Dictionary with temperature rhythm analysis
        """
        pass

    @abstractmethod
    async def detect_ultradian_rhythms(
        self,
        patient_id: UUID,
        physiological_data: dict,
        rhythm_period: int = 90,  # minutes
        detection_sensitivity: float = 0.7,  # 0.0 to 1.0
    ) -> list[dict]:
        """
        Detect ultradian rhythm disturbances (90-minute cycles).

        Args:
            patient_id: UUID of the patient
            physiological_data: Physiological data to analyze
            rhythm_period: Target rhythm period in minutes
            detection_sensitivity: Sensitivity level for detection

        Returns:
            List of detected ultradian rhythm patterns and disturbances
        """
        pass

    @abstractmethod
    async def analyze_circadian_phase(
        self,
        patient_id: UUID,
        longitudinal_data: dict,
        days: int = 14,
        reference_markers: dict | None = None,
    ) -> dict:
        """
        Analyze circadian phase shifts and social jet lag.

        Args:
            patient_id: UUID of the patient
            longitudinal_data: Time series data over multiple days
            days: Number of days to analyze
            reference_markers: Optional reference circadian markers

        Returns:
            Dictionary with circadian phase analysis and jet lag quantification
        """
        pass

    @abstractmethod
    async def detect_sleep_wake_imbalance(
        self,
        patient_id: UUID,
        sleep_data: dict,
        activity_data: dict,
        time_range: tuple[datetime, datetime],
    ) -> dict:
        """
        Detect sleep-wake homeostasis imbalances.

        Args:
            patient_id: UUID of the patient
            sleep_data: Sleep tracking data
            activity_data: Activity tracking data
            time_range: Time range for analysis

        Returns:
            Dictionary with sleep-wake balance analysis
        """
        pass

    @abstractmethod
    async def detect_seasonal_patterns(
        self,
        patient_id: UUID,
        longitudinal_data: dict,
        metrics: list[str],
        min_duration: int = 365,  # days
    ) -> list[dict]:
        """
        Detect seasonal affective patterns in longitudinal data.

        Args:
            patient_id: UUID of the patient
            longitudinal_data: Long-term physiological and behavioral data
            metrics: List of metrics to analyze for seasonality
            min_duration: Minimum duration in days for analysis

        Returns:
            List of detected seasonal patterns
        """
        pass

    @abstractmethod
    async def analyze_menstrual_cycle_impacts(
        self,
        patient_id: UUID,
        cycle_data: dict,
        mood_data: dict,
        physiological_data: dict | None = None,
    ) -> dict:
        """
        Analyze menstrual cycle phase impacts on mood and cognition.

        Args:
            patient_id: UUID of the patient
            cycle_data: Menstrual cycle tracking data
            mood_data: Mood tracking data
            physiological_data: Optional physiological measurements

        Returns:
            Dictionary with cycle-mood-cognition impact analysis
        """
        pass

    @abstractmethod
    async def detect_psychomotor_patterns(
        self,
        patient_id: UUID,
        movement_data: dict,
        clinical_context: dict | None = None,
        sensitivity: float = 0.8,  # 0.0 to 1.0
    ) -> dict:
        """
        Detect psychomotor retardation/agitation signatures in movement data.

        Args:
            patient_id: UUID of the patient
            movement_data: Fine-grained movement tracking data
            clinical_context: Optional clinical context information
            sensitivity: Sensitivity level for detection

        Returns:
            Dictionary with psychomotor pattern analysis
        """
        pass

    @abstractmethod
    async def analyze_behavioral_activation(
        self,
        patient_id: UUID,
        activity_data: dict,
        location_data: dict | None = None,
        timeframe: int = 30,  # days
    ) -> dict:
        """
        Analyze behavioral activation/withdrawal patterns.

        Args:
            patient_id: UUID of the patient
            activity_data: Activity tracking data
            location_data: Optional location/GPS data
            timeframe: Analysis timeframe in days

        Returns:
            Dictionary with behavioral activation analysis
        """
        pass

    @abstractmethod
    async def correlate_exercise_mood(
        self,
        patient_id: UUID,
        exercise_data: dict,
        mood_data: dict,
        time_lag: int = 3,  # days
    ) -> dict:
        """
        Analyze exercise intensity/consistency correlations with mood.

        Args:
            patient_id: UUID of the patient
            exercise_data: Exercise tracking data
            mood_data: Mood tracking data
            time_lag: Maximum time lag in days to analyze

        Returns:
            Dictionary with exercise-mood correlation analysis
        """
        pass

    @abstractmethod
    async def analyze_diurnal_variation(
        self,
        patient_id: UUID,
        activity_data: dict,
        days: int = 14,
        clinical_diagnosis: str | None = None,
    ) -> dict:
        """
        Analyze diurnal variation in activity as depression biomarker.

        Args:
            patient_id: UUID of the patient
            activity_data: Activity tracking data
            days: Number of days to analyze
            clinical_diagnosis: Optional clinical diagnosis

        Returns:
            Dictionary with diurnal variation analysis
        """
        pass

    @abstractmethod
    async def perform_movement_entropy_analysis(
        self,
        patient_id: UUID,
        movement_data: dict,
        analysis_window: int = 60,  # minutes
    ) -> dict:
        """
        Perform chaos/entropy analysis of movement patterns.

        Args:
            patient_id: UUID of the patient
            movement_data: Fine-grained movement data
            analysis_window: Window size in minutes for analysis

        Returns:
            Dictionary with movement entropy/chaos analysis
        """
        pass

    @abstractmethod
    async def map_autonomic_balance(
        self,
        patient_id: UUID,
        hrv_data: dict,
        time_range: tuple[datetime, datetime],
        eda_data: dict | None = None,
        respiratory_data: dict | None = None,
    ) -> dict:
        """
        Map sympathetic/parasympathetic balance throughout the day.

        Args:
            patient_id: UUID of the patient
            hrv_data: Heart rate variability data
            time_range: Time range for analysis
            eda_data: Optional electrodermal activity data
            respiratory_data: Optional respiratory data

        Returns:
            Dictionary with autonomic balance mapping
        """
        pass

    @abstractmethod
    async def analyze_stress_recovery(
        self,
        patient_id: UUID,
        hrv_data: dict,
        stressor_events: list[dict] | None = None,
        recovery_threshold: float = 0.7,  # 0.0 to 1.0
    ) -> dict:
        """
        Analyze stress recovery efficiency via HRV rebound metrics.

        Args:
            patient_id: UUID of the patient
            hrv_data: Heart rate variability data
            stressor_events: Optional recorded stressor events
            recovery_threshold: Threshold for recovery determination

        Returns:
            Dictionary with stress recovery efficiency analysis
        """
        pass

    @abstractmethod
    async def analyze_respiratory_sinus_arrhythmia(
        self,
        patient_id: UUID,
        ecg_data: dict,
        respiratory_data: dict | None = None,
        anxiety_context: dict | None = None,
    ) -> dict:
        """
        Analyze respiratory sinus arrhythmia as anxiety indicator.

        Args:
            patient_id: UUID of the patient
            ecg_data: ECG or PPG data
            respiratory_data: Optional respiratory data
            anxiety_context: Optional anxiety assessment data

        Returns:
            Dictionary with RSA analysis and anxiety correlation
        """
        pass

    @abstractmethod
    async def analyze_orthostatic_response(
        self,
        patient_id: UUID,
        heart_rate_data: dict,
        positional_data: dict,
        depression_context: dict | None = None,
    ) -> dict:
        """
        Analyze orthostatic heart rate response as depression biomarker.

        Args:
            patient_id: UUID of the patient
            heart_rate_data: Heart rate data
            positional_data: Body position data
            depression_context: Optional depression assessment data

        Returns:
            Dictionary with orthostatic response analysis
        """
        pass

    @abstractmethod
    async def analyze_nocturnal_autonomic_activity(
        self,
        patient_id: UUID,
        sleep_physiology_data: dict,
        next_day_mood: dict | None = None,
    ) -> dict:
        """
        Analyze nocturnal autonomic fluctuations predicting next-day mood.

        Args:
            patient_id: UUID of the patient
            sleep_physiology_data: Physiological data during sleep
            next_day_mood: Optional next-day mood data

        Returns:
            Dictionary with nocturnal autonomic analysis and mood prediction
        """
        pass

    @abstractmethod
    async def detect_microarousals(
        self,
        patient_id: UUID,
        sleep_data: dict,
        detection_threshold: float = 0.6,  # 0.0 to 1.0
        clinical_significance: bool = True,
    ) -> dict:
        """
        Detect microarousals during sleep and assess their significance.

        Args:
            patient_id: UUID of the patient
            sleep_data: Detailed sleep monitoring data
            detection_threshold: Threshold for microarousal detection
            clinical_significance: Whether to assess clinical significance

        Returns:
            Dictionary with microarousal detection and significance assessment
        """
        pass

    @abstractmethod
    async def analyze_rem_characteristics(
        self,
        patient_id: UUID,
        sleep_data: dict,
        depression_context: dict | None = None,
        longitudinal: bool = True,
    ) -> dict:
        """
        Analyze REM density and latency as depression biomarkers.

        Args:
            patient_id: UUID of the patient
            sleep_data: Detailed sleep architecture data
            depression_context: Optional depression assessment data
            longitudinal: Whether to perform longitudinal analysis

        Returns:
            Dictionary with REM characteristic analysis
        """
        pass

    @abstractmethod
    async def analyze_slow_wave_sleep(
        self, patient_id: UUID, sleep_data: dict, cognitive_data: dict | None = None
    ) -> dict:
        """
        Analyze slow-wave sleep quality and cognitive function correlation.

        Args:
            patient_id: UUID of the patient
            sleep_data: Detailed sleep architecture data
            cognitive_data: Optional cognitive assessment data

        Returns:
            Dictionary with SWS quality analysis and cognitive correlation
        """
        pass

    @abstractmethod
    async def detect_rem_behavior_precursors(
        self,
        patient_id: UUID,
        sleep_data: dict,
        movement_data: dict,
        detection_sensitivity: float = 0.7,  # 0.0 to 1.0
    ) -> dict:
        """
        Detect REM behavior disorder precursor signatures.

        Args:
            patient_id: UUID of the patient
            sleep_data: Detailed sleep architecture data
            movement_data: Movement data during sleep
            detection_sensitivity: Sensitivity for detection

        Returns:
            Dictionary with RBD precursor analysis
        """
        pass

    @abstractmethod
    async def analyze_sleep_spindles(
        self, patient_id: UUID, sleep_eeg_data: dict, memory_context: dict | None = None
    ) -> dict:
        """
        Analyze sleep spindles for memory consolidation assessment.

        Args:
            patient_id: UUID of the patient
            sleep_eeg_data: EEG data during sleep
            memory_context: Optional memory assessment data

        Returns:
            Dictionary with sleep spindle analysis
        """
        pass

    @abstractmethod
    async def integrate_with_knowledge_graph(
        self,
        patient_id: UUID,
        biometric_data: dict,
        knowledge_graph: TemporalKnowledgeGraph,
        integration_type: str = "temporal_patterns",
    ) -> tuple[list[TemporalPattern], TemporalKnowledgeGraph]:
        """
        Integrate biometric insights with temporal knowledge graph.

        Args:
            patient_id: UUID of the patient
            biometric_data: Processed biometric data
            knowledge_graph: Existing temporal knowledge graph
            integration_type: Type of integration to perform

        Returns:
            Tuple of extracted temporal patterns and updated knowledge graph
        """
        pass
