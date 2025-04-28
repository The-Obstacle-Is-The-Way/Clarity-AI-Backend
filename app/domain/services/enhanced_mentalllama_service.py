"""
Enhanced domain service interface for MentalLLaMA-33B with advanced capabilities.
Pure domain interface with no infrastructure dependencies.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.services.digital_twin_core_service import DigitalTwinCoreService
from app.domain.entities.patient import Patient
from app.domain.entities.digital_twin_entity import ClinicalInsight
from app.domain.entities.knowledge_graph import (
    KnowledgeGraphEdge,
    KnowledgeGraphNode,
)
from app.infrastructure.ml.mentallama.service import MentaLLaMA # Corrected import to match class name


class EnhancedMentalLLaMAService(ABC):
    """
    Abstract interface for the enhanced MentalLLaMA-33B language model operations.
    Extends basic MentalLLaMA capabilities with advanced semantic, counterfactual,
    and multimodal reasoning.
    
    Concrete implementations will be provided in the infrastructure layer.
    """
    
    @abstractmethod
    async def process_multimodal_data(
        self,
        patient_id: UUID,
        text_data: str | None = None,
        image_data: dict | None = None,
        numerical_data: dict | None = None,
        temporal_data: dict | None = None,
        context: dict | None = None
    ) -> list[ClinicalInsight]:
        """
        Process multimodal patient data using MentalLLaMA-33B to extract unified insights.
        
        Args:
            patient_id: UUID of the patient
            text_data: Optional textual data (clinical notes, patient reports)
            image_data: Optional image data (brain scans, visual assessments)
            numerical_data: Optional numerical data (test scores, measurements)
            temporal_data: Optional temporal data (time series, longitudinal measurements)
            context: Optional additional context for the analysis
            
        Returns:
            List of ClinicalInsight objects derived from multimodal analysis
        """
        pass
    
    @abstractmethod
    async def construct_knowledge_graph(
        self,
        patient_id: UUID,
        clinical_data: dict,
        existing_graph_nodes: list[KnowledgeGraphNode] | None = None,
        existing_graph_edges: list[KnowledgeGraphEdge] | None = None
    ) -> tuple[list[KnowledgeGraphNode], list[KnowledgeGraphEdge]]:
        """
        Construct or update a semantic knowledge graph from clinical data.
        
        Args:
            patient_id: UUID of the patient
            clinical_data: Dictionary of clinical data to process
            existing_graph_nodes: Optional list of existing nodes to incorporate
            existing_graph_edges: Optional list of existing edges to incorporate
            
        Returns:
            Tuple of (nodes, edges) representing the knowledge graph
        """
        pass
    
    @abstractmethod
    async def discover_latent_variables(
        self,
        patient_id: UUID,
        clinical_data: dict,
        n_variables: int = 5,
        min_confidence: float = 0.7
    ) -> list[dict]:
        """
        Discover latent variables in patient data that may not be explicitly documented.
        
        Args:
            patient_id: UUID of the patient
            clinical_data: Dictionary of clinical data to analyze
            n_variables: Maximum number of latent variables to discover
            min_confidence: Minimum confidence threshold for reporting variables
            
        Returns:
            List of dictionaries describing discovered latent variables with explanations
        """
        pass
    
    @abstractmethod
    async def generate_counterfactual_scenarios(
        self,
        patient_id: UUID,
        base_state_id: UUID,
        intervention_params: dict,
        n_scenarios: int = 3,
        time_horizon: str = "short_term"  # "short_term", "medium_term", "long_term"
    ) -> list[dict]:
        """
        Generate counterfactual scenarios by simulating different treatment trajectories.
        
        Args:
            patient_id: UUID of the patient
            base_state_id: UUID of the current Digital Twin state to use as baseline
            intervention_params: Parameters for the interventions to simulate
            n_scenarios: Number of counterfactual scenarios to generate
            time_horizon: Time horizon for prediction
            
        Returns:
            List of dictionaries describing counterfactual scenarios
        """
        pass
    
    @abstractmethod
    async def perform_temporal_reasoning(
        self,
        patient_id: UUID,
        clinical_history: dict,
        query: str,
        time_points: list[datetime] | None = None
    ) -> dict:
        """
        Perform complex temporal reasoning about patient's condition over time.
        
        Args:
            patient_id: UUID of the patient
            clinical_history: Dictionary with clinical history data
            query: Specific question or analysis to perform
            time_points: Optional specific time points to analyze
            
        Returns:
            Dictionary with temporal reasoning results
        """
        pass
    
    @abstractmethod
    async def detect_suicidality_signals(
        self,
        patient_id: UUID,
        text_data: str,
        analysis_type: str = "comprehensive"  # "basic", "comprehensive", "longitudinal"
    ) -> dict:
        """
        Analyze text for suicidality signals with high sensitivity.
        
        Args:
            patient_id: UUID of the patient
            text_data: Text data to analyze
            analysis_type: Type of analysis to perform
            
        Returns:
            Dictionary with suicidality analysis results
        """
        pass
    
    @abstractmethod
    async def identify_medication_adherence_patterns(
        self,
        patient_id: UUID,
        communication_data: dict,
        medication_history: dict
    ) -> dict:
        """
        Identify medication adherence patterns from linguistic markers and history.
        
        Args:
            patient_id: UUID of the patient
            communication_data: Dictionary with patient communication data
            medication_history: Dictionary with medication history
            
        Returns:
            Dictionary with adherence pattern analysis
        """
        pass
    
    @abstractmethod
    async def extract_psychosocial_stressors(
        self,
        patient_id: UUID,
        clinical_notes: str,
        social_history: str | None = None,
        sensitivity: float = 0.8  # 0.0 to 1.0
    ) -> list[dict]:
        """
        Extract psychosocial stressors even when patients minimize their significance.
        
        Args:
            patient_id: UUID of the patient
            clinical_notes: Clinical notes text
            social_history: Optional social history text
            sensitivity: Sensitivity level for detection
            
        Returns:
            List of identified psychosocial stressors with analysis
        """
        pass
    
    @abstractmethod
    async def generate_psychoeducational_content(
        self,
        patient_id: UUID,
        topic: str,
        cognitive_style: str | None = None,
        reading_level: str | None = None,
        cultural_context: str | None = None
    ) -> dict:
        """
        Generate personalized psychoeducational content calibrated to patient's cognitive style.
        
        Args:
            patient_id: UUID of the patient
            topic: Clinical topic for psychoeducation
            cognitive_style: Optional cognitive style to tailor content to
            reading_level: Optional reading level to target
            cultural_context: Optional cultural context to consider
            
        Returns:
            Dictionary with personalized psychoeducational content
        """
        pass
    
    @abstractmethod
    async def integrate_with_belief_network(
        self,
        patient_id: UUID,
        clinical_evidence: dict,
        query_variables: list[str],
        existing_beliefs: dict | None = None
    ) -> dict:
        """
        Integrate clinical evidence with Bayesian belief network.
        
        Args:
            patient_id: UUID of the patient
            clinical_evidence: New clinical evidence to incorporate
            query_variables: Variables to query in the belief network
            existing_beliefs: Optional existing belief state
            
        Returns:
            Updated belief state dictionary
        """
        pass