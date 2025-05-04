"""
MentaLLaMA service implementation.

This module implements the MentaLLaMA service interface.
"""

import json
import uuid
from typing import Any

import requests

from app.config.settings import get_settings
from app.core.patterns.observer import Subject  # Corrected import path for Subject

# Removed incorrect import of domain service: from app.domain.services.mentallama_service import MentaLLaMAService
from app.domain.repositories.clinical_note_repository import ClinicalNoteRepository

settings = get_settings()
from app.core.services.ml.interface import (
    MentaLLaMAInterface,  # Corrected import path and interface name
)
from app.core.utils.logging import get_logger  # Corrected import path for get_logger

logger = get_logger(__name__)


# REMOVE: Legacy MentaLLaMAServiceImpl from core.services.ml.mentallama.service. Use infrastructure layer only.
# Define the class correctly in the infrastructure layer
class MentaLLaMA(MentaLLaMAInterface, Subject): # Corrected interface name
    """
    Implementation of the MentaLLaMA service.

    This service provides natural language processing capabilities for clinical notes.
    """
    
    # Event types
    NOTE_ANALYSIS_COMPLETE = "note_analysis_complete"
    SEARCH_COMPLETE = "search_complete"
    SUMMARY_GENERATION_COMPLETE = "summary_generation_complete"
    TREATMENT_SUGGESTIONS_COMPLETE = "treatment_suggestions_complete"
    BRAIN_REGION_EXTRACTION_COMPLETE = "brain_region_extraction_complete"
    
    def __init__(
        self,
        clinical_note_repository: ClinicalNoteRepository,
        api_key: str | None = None,
        api_url: str | None = None
    ):
        """
        Initialize the MentaLLaMA service.
        
        Args:
            clinical_note_repository: The clinical note repository
            api_key: The API key for the MentaLLaMA service
            api_url: The URL of the MentaLLaMA service
        """
        super().__init__()  # Initialize the Subject base class
        self.clinical_note_repository = clinical_note_repository
        self.api_key = api_key or settings.MENTALLAMA_API_KEY
        self.api_url = api_url or settings.MENTALLAMA_API_URL
        
        if not self.api_key:
            logger.warning("MentaLLaMA API key not provided")
        
        if not self.api_url:
            logger.warning("MentaLLaMA API URL not provided")
    
    def analyze_clinical_note(
        self,
        patient_id: uuid.UUID,
        provider_id: uuid.UUID,
        content: str
    ) -> dict[str, Any]:
        """
        Analyze a clinical note and extract insights.
        
        Args:
            patient_id: The ID of the patient
            provider_id: The ID of the provider who wrote the note
            content: The content of the note
            
        Returns:
            A dictionary containing the note ID and extracted insights
            
        Raises:
            ValueError: If there is an error analyzing the note
        """
        try:
            # Extract insights using the MentaLLaMA API
            insights = self._call_mentallama_api(
                endpoint="analyze",
                payload={
                    "patient_id": str(patient_id),
                    "content": content
                }
            )
            
            # Store the note and insights in the database
            note_id = self.clinical_note_repository.create_note(
                patient_id=patient_id,
                provider_id=provider_id,
                content=content,
                insights=insights
            )
            
            logger.info(
                "Analyzed clinical note",
                extra={
                    "note_id": str(note_id),
                    "patient_id": str(patient_id),
                    "provider_id": str(provider_id)
                }
            )
            
            # Prepare result
            result = {
                "note_id": note_id,
                "insights": insights
            }
            
            # Notify observers
            self.notify(
                self.NOTE_ANALYSIS_COMPLETE,
                {
                    "patient_id": str(patient_id),
                    "provider_id": str(provider_id),
                    "note_id": str(note_id),
                    "result": result
                }
            )
            
            return result
        except Exception as e:
            logger.error(
                "Error analyzing clinical note",
                extra={
                    "patient_id": str(patient_id),
                    "provider_id": str(provider_id),
                    "error": str(e)
                }
            )
            raise ValueError(f"Error analyzing clinical note: {e!s}")
    
    def search_patient_notes(
        self,
        patient_id: uuid.UUID,
        query: str
    ) -> list[dict[str, Any]]:
        """
        Search clinical notes for a patient.
        
        Args:
            patient_id: The ID of the patient
            query: The search query
            
        Returns:
            A list of matching clinical notes
            
        Raises:
            ValueError: If there is an error searching the notes
        """
        try:
            # Get all notes for the patient
            notes = self.clinical_note_repository.get_patient_notes(
                patient_id=patient_id
            )
            
            if not notes:
                logger.info(
                    "No notes found for patient",
                    extra={"patient_id": str(patient_id)}
                )
                return []
            
            # Use the MentaLLaMA API to search the notes
            search_results = self._call_mentallama_api(
                endpoint="search",
                payload={
                    "patient_id": str(patient_id),
                    "query": query,
                    "notes": notes
                }
            )
            
            logger.info(
                "Searched patient notes",
                extra={
                    "patient_id": str(patient_id),
                    "query": query,
                    "result_count": len(search_results)
                }
            )
            
            # Notify observers
            self.notify(
                self.SEARCH_COMPLETE,
                {
                    "patient_id": str(patient_id),
                    "query": query,
                    "result_count": len(search_results)
                }
            )
            
            return search_results
        except Exception as e:
            logger.error(
                "Error searching patient notes",
                extra={
                    "patient_id": str(patient_id),
                    "query": query,
                    "error": str(e)
                }
            )
            raise ValueError(f"Error searching patient notes: {e!s}")
    
    def generate_patient_summary(
        self,
        patient_id: uuid.UUID
    ) -> dict[str, Any]:
        """
        Generate a summary of a patient's clinical history.
        
        Args:
            patient_id: The ID of the patient
            
        Returns:
            A dictionary containing the summary and key insights
            
        Raises:
            ValueError: If there is an error generating the summary
        """
        try:
            # Get all notes for the patient
            notes = self.clinical_note_repository.get_patient_notes(
                patient_id=patient_id
            )
            
            if not notes:
                logger.info(
                    "No notes found for patient",
                    extra={"patient_id": str(patient_id)}
                )
                return {
                    "summary": "No clinical notes available for this patient.",
                    "key_insights": []
                }
            
            # Use the MentaLLaMA API to generate a summary
            summary = self._call_mentallama_api(
                endpoint="summarize",
                payload={
                    "patient_id": str(patient_id),
                    "notes": notes
                }
            )
            
            logger.info(
                "Generated patient summary",
                extra={"patient_id": str(patient_id)}
            )
            
            # Notify observers
            self.notify(
                self.SUMMARY_GENERATION_COMPLETE,
                {
                    "patient_id": str(patient_id),
                    "summary": summary
                }
            )
            
            return summary
        except Exception as e:
            logger.error(
                "Error generating patient summary",
                extra={
                    "patient_id": str(patient_id),
                    "error": str(e)
                }
            )
            raise ValueError(f"Error generating patient summary: {e!s}")
    
    def generate_treatment_suggestions(
        self,
        patient_id: uuid.UUID
    ) -> list[dict[str, Any]]:
        """
        Generate treatment suggestions for a patient.
        
        Args:
            patient_id: The ID of the patient
            
        Returns:
            A list of treatment suggestions
            
        Raises:
            ValueError: If there is an error generating the suggestions
        """
        try:
            # Get all notes for the patient
            notes = self.clinical_note_repository.get_patient_notes(
                patient_id=patient_id
            )
            
            if not notes:
                logger.info(
                    "No notes found for patient",
                    extra={"patient_id": str(patient_id)}
                )
                return []
            
            # Use the MentaLLaMA API to generate treatment suggestions
            suggestions = self._call_mentallama_api(
                endpoint="suggest-treatments",
                payload={
                    "patient_id": str(patient_id),
                    "notes": notes
                }
            )
            
            logger.info(
                "Generated treatment suggestions",
                extra={
                    "patient_id": str(patient_id),
                    "suggestion_count": len(suggestions)
                }
            )
            
            # Notify observers
            self.notify(
                self.TREATMENT_SUGGESTIONS_COMPLETE,
                {
                    "patient_id": str(patient_id),
                    "suggestion_count": len(suggestions)
                }
            )
            
            return suggestions
        except Exception as e:
            logger.error(
                "Error generating treatment suggestions",
                extra={
                    "patient_id": str(patient_id),
                    "error": str(e)
                }
            )
            raise ValueError(f"Error generating treatment suggestions: {e!s}")
    
    def extract_brain_region_data(
        self,
        patient_id: uuid.UUID
    ) -> dict[str, dict[str, Any]]:
        """
        Extract brain region data from a patient's clinical notes.
        
        Args:
            patient_id: The ID of the patient
            
        Returns:
            A dictionary mapping brain regions to data points
            
        Raises:
            ValueError: If there is an error extracting the data
        """
        try:
            # Get all notes for the patient
            notes = self.clinical_note_repository.get_patient_notes(
                patient_id=patient_id
            )
            
            if not notes:
                logger.info(
                    "No notes found for patient",
                    extra={"patient_id": str(patient_id)}
                )
                return {}
            
            # Use the MentaLLaMA API to extract brain region data
            brain_data = self._call_mentallama_api(
                endpoint="extract-brain-regions",
                payload={
                    "patient_id": str(patient_id),
                    "notes": notes
                }
            )
            
            logger.info(
                "Extracted brain region data",
                extra={
                    "patient_id": str(patient_id),
                    "region_count": len(brain_data)
                }
            )
            
            # Notify observers
            self.notify(
                self.BRAIN_REGION_EXTRACTION_COMPLETE,
                {
                    "patient_id": str(patient_id),
                    "region_count": len(brain_data)
                }
            )
            
            return brain_data
        except Exception as e:
            logger.error(
                "Error extracting brain region data",
                extra={
                    "patient_id": str(patient_id),
                    "error": str(e)
                }
            )
            raise ValueError(f"Error extracting brain region data: {e!s}")
    
    def _call_mentallama_api(
        self,
        endpoint: str,
        payload: dict[str, Any]
    ) -> Any:
        """
        Call the MentaLLaMA API.
        
        Args:
            endpoint: The API endpoint to call
            payload: The payload to send
            
        Returns:
            The API response
            
        Raises:
            ValueError: If there is an error calling the API
        """
        if not self.api_url or not self.api_key:
            raise ValueError("MentaLLaMA API URL or API key not provided")
        
        url = f"{self.api_url}/{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        try:
            response = requests.post(
                url=url,
                headers=headers,
                data=json.dumps(payload),
                timeout=30
            )
            
            response.raise_for_status()
            
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(
                "Error calling MentaLLaMA API",
                extra={
                    "endpoint": endpoint,
                    "error": str(e)
                }
            )
            raise ValueError(f"Error calling MentaLLaMA API: {e!s}")
