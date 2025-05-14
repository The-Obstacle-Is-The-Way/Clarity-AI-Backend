"""
Mock implementation of the MentaLLaMA Service.

This module provides a stateless mock implementation of the MentaLLaMA Service
for developing and testing applications without requiring the actual
machine learning models or external dependencies.
"""
import random
import uuid
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from app.domain.entities.clinical_insight import ClinicalInsight, InsightCategory, InsightSeverity
from app.domain.interfaces.ml.mentallama import MentaLLaMAServiceInterface


class MockMentalLLaMAService(MentaLLaMAServiceInterface):
    """
    Mock implementation of the MentaLLaMA Service.
    
    This class provides synthetic NLP analysis results for testing and development
    purposes without requiring a real language model.
    """
    
    def __init__(self, error_simulation_mode: bool = False):
        """
        Initialize the mock MentaLLaMA service.
        
        Args:
            error_simulation_mode: If True, some calls will simulate errors
        """
        self.error_simulation_mode = error_simulation_mode
        self.initialized = True
        self.last_analysis_id: Optional[UUID] = None
        
        # Store some mock analyses for retrieval
        self.stored_analyses: dict[UUID, dict[str, Any]] = {}
    
    async def analyze_clinical_notes(
        self,
        patient_id: UUID,
        note_text: str,
        context: Optional[dict[str, Any]] = None
    ) -> list[ClinicalInsight]:
        """
        Analyze clinical notes to extract structured insights.
        
        Args:
            patient_id: UUID of the patient
            note_text: The clinical note text to analyze
            context: Optional additional context
            
        Returns:
            List of ClinicalInsight objects
        """
        if self.error_simulation_mode and random.random() < 0.2:
            raise Exception("Simulated error in MentaLLaMA service")
        
        if not note_text:
            return []
        
        # Generate an analysis ID for this request
        analysis_id = uuid.uuid4()
        self.last_analysis_id = analysis_id
        
        # Generate mock insights
        num_insights = random.randint(1, 5)
        insights = []
        
        # Categories and severities for the mock insights
        categories = list(InsightCategory)
        severities = list(InsightSeverity)
        
        # Common clinical topics for realistic test data
        clinical_topics = [
            "depressive symptoms",
            "anxiety",
            "sleep disturbance",
            "medication effects",
            "substance use",
            "social functioning",
            "mood changes",
            "cognitive functioning",
            "treatment adherence"
        ]
        
        for _ in range(num_insights):
            category = random.choice(categories)
            severity = random.choice(severities)
            topic = random.choice(clinical_topics)
            
            # Generate insight text based on the category
            if category == InsightCategory.SYMPTOM:
                text = f"Patient reports {topic} with {severity.name.lower()} intensity"
            elif category == InsightCategory.TREATMENT:
                text = f"Current treatment for {topic} shows {severity.name.lower()} effectiveness"
            elif category == InsightCategory.RISK:
                text = f"{severity.name.capitalize()} risk factor identified: {topic}"
            elif category == InsightCategory.PROGRESS:
                text = f"{severity.name.capitalize()} progress noted in {topic}"
            else:
                text = f"Clinical note indicates {severity.name.lower()} {topic}"
                
            # Extract a snippet from the actual note as the evidence
            # In a real system, this would be the exact sentence that led to the insight
            words = note_text.split()
            if len(words) > 10:
                evidence_start = random.randint(0, len(words) - 10)
                evidence = " ".join(words[evidence_start:evidence_start + 10])
            else:
                evidence = note_text
                
            # Create metadata dictionary with additional info
            metadata = {
                "model_version": "MockMentaLLaMA-1.0",
                "processing_time_ms": random.randint(100, 500),
                "related_concepts": [random.choice(clinical_topics) for _ in range(random.randint(1, 3))],
                "relative_time_reference": random.choice(["current", "past", "ongoing"])
            }
            
            # Create the insight using the correct constructor parameters
            insight = ClinicalInsight(
                text=text,
                category=category,
                severity=severity,
                patient_id=str(patient_id),
                analysis_id=str(analysis_id),
                evidence=evidence,
                confidence=random.uniform(0.7, 0.98),
                timestamp=datetime.now(),
                metadata=metadata
            )
            
            insights.append(insight)
            
        # Store the analysis for later retrieval
        self.stored_analyses[analysis_id] = {
            "patient_id": patient_id,
            "note_text": note_text,
            "insights": insights,
            "timestamp": datetime.now().isoformat()
        }
            
        return insights
    
    async def get_analysis_by_id(
        self,
        analysis_id: UUID | str,
        patient_id: Optional[UUID] = None
    ) -> dict[str, Any]:
        """
        Retrieve a previously generated analysis by its ID.
        
        Args:
            analysis_id: UUID of the analysis to retrieve
            patient_id: Optional UUID of the patient for validation
            
        Returns:
            Dictionary containing the complete analysis
            
        Raises:
            ValueError: If the analysis is not found
        """
        if isinstance(analysis_id, str):
            try:
                analysis_id = UUID(analysis_id)
            except ValueError as e:
                raise ValueError(f"Could not parse analysis ID: {e}") from e
                
        if analysis_id not in self.stored_analyses:
            raise ValueError(f"Analysis not found with ID: {analysis_id}")
            
        analysis = self.stored_analyses[analysis_id]
        
        # If patient_id is provided, verify it matches
        if patient_id and analysis["patient_id"] != patient_id:
            raise ValueError(f"Analysis {analysis_id} does not belong to patient {patient_id}")
            
        return analysis
    
    async def get_patient_analyses(
        self,
        patient_id: UUID,
        limit: int = 10,
        offset: int = 0
    ) -> list[dict[str, Any]]:
        """
        Retrieve all analyses for a specific patient.
        
        Args:
            patient_id: UUID of the patient
            limit: Maximum number of analyses to return
            offset: Number of analyses to skip
            
        Returns:
            List of analysis dictionaries
        """
        # Filter analyses by patient_id
        patient_analyses = [
            analysis for analysis_id, analysis in self.stored_analyses.items()
            if analysis["patient_id"] == patient_id
        ]
        
        # Apply pagination
        paginated_analyses = patient_analyses[offset:offset + limit]
        
        return paginated_analyses
    
    def _get_topic_insights(self, note_text: str, patient_id: Optional[str] = None) -> list[dict[str, Any]]:
        """
        Helper method to get topic insights.
        
        Args:
            note_text: The clinical note text to analyze
            patient_id: Optional patient ID
            
        Returns:
            list of topic insights
        """
        # TO DO: implement this method
        pass
    
    def _process_topics(self, note_text: str) -> dict[str, float]:
        """
        Helper method to process topics.
        
        Args:
            note_text: The clinical note text to analyze
            
        Returns:
            Dictionary with topic information
        """
        # TO DO: implement this method
        pass
    
    async def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the MentaLLaMA model.
        
        Returns:
            Dictionary with model information
        """
        return {
            "name": "MockMentaLLaMA",
            "version": "1.0.0",
            "description": "Mock implementation of the MentaLLaMA Service for testing",
            "capabilities": [
                "clinical_note_analysis",
                "insight_extraction",
                "risk_assessment"
            ],
            "performance_metrics": {
                "accuracy": 0.92,
                "precision": 0.89,
                "recall": 0.87,
                "f1_score": 0.88
            },
            "limitations": [
                "This is a mock implementation and does not use real NLP models",
                "Results are randomly generated and not clinically valid"
            ]
        }
