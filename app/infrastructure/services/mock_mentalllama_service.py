"""
Mock implementation of MentalLLaMAService for testing.
Provides synthetic NLP analysis without requiring the actual MentalLLaMA-33B model.
"""
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from app.domain.entities.digital_twin import (
    BrainRegion, ClinicalInsight, ClinicalSignificance
)
from app.domain.services.mentalllama_service import MentalLLaMAService


class MockMentalLLaMAService(MentalLLaMAService):
    """
    Mock implementation of MentalLLaMAService.
    Generates synthetic NLP analysis for testing and development.
    """
    
    async def analyze_clinical_notes(
        self, 
        patient_id: UUID, 
        note_text: str,
        context: Optional[Dict] = None
    ) -> List[ClinicalInsight]:
        """
        Analyze clinical notes using MentalLLaMA-33B to extract insights.
        
        Args:
            patient_id: UUID of the patient
            note_text: Raw text of the clinical note
            context: Optional additional context for the analysis
            
        Returns:
            List of ClinicalInsight objects derived from the notes
        """
        # Generate synthetic insights based on keywords in the note
        insights = []
        
        # Look for depression indicators
        if any(kw in note_text.lower() for kw in ["depress", "sad", "low mood", "anhedonia"]):
            # Ensure we import the necessary types
            from app.domain.entities.digital_twin_enums import Neurotransmitter
            
            insights.append(ClinicalInsight(
                id=uuid4(),
                title="Possible Depression Indicators",
                description="Patient's notes contain language suggesting depressive symptoms.",
                source="MentalLLaMA",
                confidence=0.85,
                timestamp=datetime.now(),
                clinical_significance=ClinicalSignificance.MODERATE,
                brain_regions=[
                    BrainRegion.PREFRONTAL_CORTEX,
                    BrainRegion.ANTERIOR_CINGULATE
                ],
                neurotransmitters=[
                    Neurotransmitter.SEROTONIN,
                    Neurotransmitter.DOPAMINE
                ],  # Add relevant neurotransmitters for depression
                supporting_evidence=["Lexical indicators of depression in clinical notes"],
                recommended_actions=["Consider PHQ-9 assessment", "Review treatment plan"]
            ))
        
        # Look for anxiety indicators
        if any(kw in note_text.lower() for kw in ["anxious", "worry", "panic", "tension"]):
            insights.append(ClinicalInsight(
                id=uuid4(),
                title="Anxiety Indicators",
                description="Language patterns consistent with anxiety symptoms detected.",
                source="MentalLLaMA",
                confidence=0.78,
                timestamp=datetime.now(),
                clinical_significance=ClinicalSignificance.MODERATE,
                brain_regions=[
                    BrainRegion.AMYGDALA,
                    BrainRegion.ANTERIOR_CINGULATE
                ],
                neurotransmitters=[
                    Neurotransmitter.GABA,
                    Neurotransmitter.NOREPINEPHRINE
                ],  # Add relevant neurotransmitters for anxiety
                supporting_evidence=["Anxiety-related language patterns in notes"],
                recommended_actions=["Consider GAD-7 assessment", "Evaluate coping strategies"]
            ))
        
        # Look for sleep issues
        if any(kw in note_text.lower() for kw in ["insomnia", "sleep", "tired", "fatigue"]):
            insights.append(ClinicalInsight(
                id=uuid4(),
                title="Sleep Disturbance Noted",
                description="References to sleep problems detected in clinical notes.",
                source="MentalLLaMA",
                confidence=0.90,
                timestamp=datetime.now(),
                clinical_significance=ClinicalSignificance.MODERATE,
                brain_regions=[
                    BrainRegion.HYPOTHALAMUS
                ],
                neurotransmitters=[
                    Neurotransmitter.SEROTONIN,
                    Neurotransmitter.MELATONIN
                ],  # Add relevant neurotransmitters for sleep regulation
                supporting_evidence=["Sleep-related complaints in notes"],
                recommended_actions=["Consider sleep hygiene assessment", "Evaluate for sleep study"]
            ))
        
        # If no specific insights, return a generic one
        if not insights:
            insights.append(ClinicalInsight(
                id=uuid4(),
                title="Routine Clinical Note",
                description="No specific clinical concerns identified in note text.",
                source="MentalLLaMA",
                confidence=0.70,
                timestamp=datetime.now(),
                clinical_significance=ClinicalSignificance.NONE,
                brain_regions=[],
                neurotransmitters=[],  # Empty list for generic insight with no specific neurotransmitter focus
                supporting_evidence=["General clinical documentation"],
                recommended_actions=["Continue routine monitoring"]
            ))
        
        return insights
    
    async def generate_treatment_recommendations(
        self,
        patient_id: UUID,
        diagnosis_codes: List[str],
        current_medications: List[str],
        clinical_history: str,
        digital_twin_state_id: Optional[UUID] = None
    ) -> List[Dict]:
        """
        Generate treatment recommendations based on patient information.
        
        Args:
            patient_id: UUID of the patient
            diagnosis_codes: List of diagnosis codes (ICD-10 or DSM-5)
            current_medications: List of current medications
            clinical_history: Summary of clinical history
            digital_twin_state_id: Optional reference to Digital Twin state
            
        Returns:
            List of dictionaries containing treatment recommendations
        """
        recommendations = []
        
        # Check for depression diagnosis codes
        if any(code.startswith("F32") or code.startswith("F33") for code in diagnosis_codes):
            ssri_already_prescribed = any(
                med.lower().startswith(("sertraline", "fluoxetine", "escitalopram", "citalopram"))
                for med in current_medications
            )
            
            if not ssri_already_prescribed:
                recommendations.append({
                    "recommendation_type": "medication",
                    "recommendation": "Consider SSRI antidepressant",
                    "options": ["Sertraline", "Escitalopram", "Fluoxetine"],
                    "rationale": "First-line pharmacotherapy for depression",
                    "evidence_level": "A",
                    "confidence": 0.85
                })
            
            recommendations.append({
                "recommendation_type": "therapy",
                "recommendation": "Cognitive Behavioral Therapy (CBT)",
                "frequency": "Weekly",
                "duration": "12 weeks",
                "rationale": "Strong evidence for efficacy in depression",
                "evidence_level": "A",
                "confidence": 0.90
            })
        
        # Check for anxiety diagnosis codes
        if any(code.startswith("F41") for code in diagnosis_codes):
            recommendations.append({
                "recommendation_type": "therapy",
                "recommendation": "Mindfulness-Based Stress Reduction",
                "frequency": "Weekly",
                "duration": "8 weeks",
                "rationale": "Evidence-based intervention for anxiety",
                "evidence_level": "B",
                "confidence": 0.80
            })
        
        # Add at least one recommendation if none were generated
        if not recommendations:
            recommendations.append({
                "recommendation_type": "monitoring",
                "recommendation": "Regular follow-up appointments",
                "frequency": "Monthly",
                "rationale": "Standard of care for ongoing monitoring",
                "evidence_level": "C",
                "confidence": 0.75
            })
        
        return recommendations
    
    async def analyze_risk_factors(
        self,
        patient_id: UUID,
        clinical_data: Dict,
        digital_twin_state_id: Optional[UUID] = None
    ) -> Dict:
        """
        Analyze risk factors from patient data using NLP techniques.
        
        Args:
            patient_id: UUID of the patient
            clinical_data: Dictionary containing relevant clinical data
            digital_twin_state_id: Optional reference to Digital Twin state
            
        Returns:
            Dictionary with risk factor analysis
        """
        # Extract age and diagnoses if available
        age = clinical_data.get("age", 35)
        diagnoses = clinical_data.get("diagnoses", [])
        medications = clinical_data.get("medications", [])
        
        # Initialize risk factors
        risk_factors = {
            "suicide_risk": {
                "level": "low",
                "score": 0.2,
                "contributing_factors": [],
                "confidence": 0.7
            },
            "self_harm_risk": {
                "level": "low",
                "score": 0.15,
                "contributing_factors": [],
                "confidence": 0.7
            },
            "hospitalization_risk": {
                "level": "low",
                "score": 0.1,
                "contributing_factors": [],
                "confidence": 0.8
            }
        }
        
        # Adjust risk based on diagnoses
        for diagnosis in diagnoses:
            diag_code = diagnosis.get("code", "")
            diag_name = diagnosis.get("name", "").lower()
            
            # Depression increases suicide risk
            if diag_code.startswith("F32") or diag_code.startswith("F33") or "depression" in diag_name:
                risk_factors["suicide_risk"]["level"] = "moderate"
                risk_factors["suicide_risk"]["score"] = 0.4
                risk_factors["suicide_risk"]["contributing_factors"].append("Depression diagnosis")
            
            # Bipolar increases risks
            if diag_code.startswith("F31") or "bipolar" in diag_name:
                risk_factors["suicide_risk"]["level"] = "moderate"
                risk_factors["suicide_risk"]["score"] = 0.45
                risk_factors["hospitalization_risk"]["level"] = "moderate"
                risk_factors["hospitalization_risk"]["score"] = 0.35
                risk_factors["suicide_risk"]["contributing_factors"].append("Bipolar disorder")
                risk_factors["hospitalization_risk"]["contributing_factors"].append("Bipolar disorder")
        
        # Return risk assessment
        return {
            "patient_id": str(patient_id),
            "assessment_timestamp": datetime.now().isoformat(),
            "risk_factors": risk_factors,
            "overall_risk_level": max(
                risk_factors["suicide_risk"]["level"],
                risk_factors["self_harm_risk"]["level"],
                risk_factors["hospitalization_risk"]["level"]
            ),
            "recommendations": [
                "Regular risk assessment",
                "Safety planning as appropriate"
            ]
        }
    
    async def semantic_search(
        self,
        patient_id: UUID,
        query: str,
        limit: int = 10
    ) -> List[Dict]:
        """
        Perform semantic search across patient records.
        
        Args:
            patient_id: UUID of the patient
            query: Search query text
            limit: Maximum number of results to return
            
        Returns:
            List of search results with relevance scores
        """
        # Mock implementation returns synthetic search results
        query_lower = query.lower()
        results = []
        
        # Generate mock results based on query terms
        if "medication" in query_lower or "prescri" in query_lower:
            results.append({
                "content_type": "medication_record",
                "timestamp": "2025-02-15T14:30:00Z",
                "title": "Medication Review",
                "snippet": "Patient reports taking sertraline 50mg daily as prescribed...",
                "relevance_score": 0.92,
                "source_document": "medication_review_2025_02_15.txt"
            })
        
        if "therapy" in query_lower or "cbt" in query_lower:
            results.append({
                "content_type": "therapy_notes",
                "timestamp": "2025-01-20T10:15:00Z",
                "title": "CBT Session Notes",
                "snippet": "Patient demonstrated good progress with cognitive restructuring techniques...",
                "relevance_score": 0.88,
                "source_document": "therapy_session_notes_2025_01_20.txt"
            })
        
        if "sleep" in query_lower or "insomnia" in query_lower:
            results.append({
                "content_type": "clinical_notes",
                "timestamp": "2025-03-01T09:45:00Z",
                "title": "Follow-up Appointment",
                "snippet": "Patient reports continued difficulty with sleep onset, averaging 90 minutes to fall asleep...",
                "relevance_score": 0.85,
                "source_document": "followup_notes_2025_03_01.txt"
            })
        
        # Add generic results if we have fewer than 3
        for i in range(len(results), min(3, limit)):
            results.append({
                "content_type": "clinical_notes",
                "timestamp": f"2025-03-{10+i}T11:30:00Z",
                "title": f"Clinical Note {i+1}",
                "snippet": f"General clinical documentation with some relevance to query: '{query}'...",
                "relevance_score": 0.7 - (i * 0.1),
                "source_document": f"clinical_notes_2025_03_{10+i}.txt"
            })
        
        return results[:limit]
    
    async def summarize_patient_history(
        self,
        patient_id: UUID,
        time_range: Optional[str] = "all",
        focus_areas: Optional[List[str]] = None
    ) -> str:
        """
        Generate a concise summary of patient history.
        
        Args:
            patient_id: UUID of the patient
            time_range: Optional time range to focus on (e.g., "last_month")
            focus_areas: Optional list of clinical areas to focus on
            
        Returns:
            Textual summary of patient history
        """
        # Create a synthetic patient summary
        summary = f"Patient {patient_id} Summary:\n\n"
        
        # Add demographic information
        summary += "32-year-old individual with history of major depressive disorder (F32.1) "
        summary += "and generalized anxiety disorder (F41.1).\n\n"
        
        # Add treatment history
        summary += "Treatment History:\n"
        summary += "- Sertraline 50mg daily, initiated 2024-09-15\n"
        summary += "- Weekly CBT sessions since 2024-10-01\n"
        summary += "- Sleep hygiene education provided 2024-11-12\n\n"
        
        # Add recent developments
        summary += "Recent Developments:\n"
        summary += "- Improvement in depressive symptoms noted in last assessment (PHQ-9 score decreased from 18 to 12)\n"
        summary += "- Continued challenges with anxiety in social situations\n"
        summary += "- Sleep quality improving gradually with current interventions\n\n"
        
        # If specific focus areas were requested
        if focus_areas:
            summary += "Focus Areas:\n"
            if "medication" in focus_areas:
                summary += "- Medication: Good adherence to sertraline, minimal side effects reported\n"
            if "therapy" in focus_areas:
                summary += "- Therapy: Good engagement in CBT, practicing cognitive restructuring techniques\n"
            if "sleep" in focus_areas:
                summary += "- Sleep: Sleep onset latency decreased from 120 to 60 minutes over past month\n"
        
        return summary