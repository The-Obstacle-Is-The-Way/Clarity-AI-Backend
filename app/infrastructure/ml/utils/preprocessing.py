# -*- coding: utf-8 -*-
"""
Text preprocessing utilities for ML/AI services.

This module provides utilities for preprocessing clinical text,
extracting entities, and formatting prompts for ML/AI models.
"""

import re
import json
from typing import Any, Dict, List, Optional, Tuple, Union

from app.infrastructure.logging.phi_logger import get_phi_logger

# Configure PHI-safe logger
logger = get_phi_logger(__name__)


async def sanitize_text(
    text: str,
    detect_phi: bool = True,
    phi_detection_service = None
) -> Tuple[str, bool]:
    """
    Sanitize text to remove PHI.
    
    Args:
        text: Text to sanitize
        detect_phi: Whether to detect and remove PHI
        phi_detection_service: PHI detection service
        
    Returns:
        Tuple of (sanitized_text, phi_detected)
    """
    if not text:
        return text, False
    
    # Remove excessive whitespace and normalize
    sanitized = re.sub(r'\s+', ' ', text).strip()
    
    # Detect and remove PHI if requested
    phi_detected = False
    
    if detect_phi and phi_detection_service:
        try:
            detection_result = await phi_detection_service.detect_phi(
                text=sanitized,
                anonymize_method="redact"
            )
            
            if detection_result["phi_detected"]:
                phi_detected = True
                sanitized = detection_result["sanitized_text"]
                logger.info("PHI detected and sanitized in text")
                
        except Exception as e:
            logger.warning(f"Error during PHI detection: {str(e)}")
    
    return sanitized, phi_detected


def extract_clinical_entities(text: str) -> Dict[str, List[str]]:
    """
    Extract clinical entities from text.
    
    Args:
        text: Text to extract entities from
        
    Returns:
        Dictionary of entity types and their occurrences
    """
    if not text:
        return {}
    
    entities = {
        "diagnoses": [],
        "medications": [],
        "symptoms": [],
        "treatments": []
    }
    
    # Extract diagnoses using regex patterns
    # Note: These are simplified patterns - in production would use NER models
    
    # Diagnosis patterns - look for diagnostic terms with DSM/ICD references
    diagnosis_patterns = [
        r'(?:diagnosed with|diagnosis of|assessment for|impression of|dx:?)\s+([A-Z][a-zA-Z\s\-]+(?:\([^\)]+\))?)',
        r'(?:DSM-(?:IV|5|V)|ICD-(?:9|10|11)(?:CM)?)[- ](?:code|diagnosis|dx)?:?\s*([A-Z][a-zA-Z0-9\.\s\-]+)'
    ]
    
    for pattern in diagnosis_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if match.group(1) and len(match.group(1).strip()) > 3:
                diagnosis = match.group(1).strip()
                if diagnosis not in entities["diagnoses"]:
                    entities["diagnoses"].append(diagnosis)
    
    # Medication patterns
    medication_patterns = [
        r'(?:prescribed|taking|on|medication|med|rx:?)\s+([A-Z][a-zA-Z]+\s+\d+\s*(?:mg|mcg|g|ml))',
        r'([A-Z][a-zA-Z]+)\s+\d+\s*(?:mg|mcg|g|ml)(?:\s+\w+)?'
    ]
    
    for pattern in medication_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if match.group(1) and len(match.group(1).strip()) > 3:
                medication = match.group(1).strip()
                if medication not in entities["medications"]:
                    entities["medications"].append(medication)
    
    # Symptom patterns
    symptom_patterns = [
        r'(?:reports|experiencing|complains of|presents with|exhibits|symptoms?:?)\s+([a-z][a-zA-Z\s\-]+)'
    ]
    
    for pattern in symptom_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if match.group(1) and len(match.group(1).strip()) > 3:
                symptom = match.group(1).strip()
                if symptom not in entities["symptoms"]:
                    entities["symptoms"].append(symptom)
    
    # Treatment patterns
    treatment_patterns = [
        r'(?:treatment plan|plan|treatment|therapy|recommend(?:ed|ing)?|approach)\s+(?:includes?|with|of)?\s+([A-Za-z][a-zA-Z\s\-]+)'
    ]
    
    for pattern in treatment_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if match.group(1) and len(match.group(1).strip()) > 3:
                treatment = match.group(1).strip()
                if treatment not in entities["treatments"]:
                    entities["treatments"].append(treatment)
    
    return entities


def format_as_clinical_prompt(
    text: str,
    analysis_type: str = "diagnostic_impression",
    context: Optional[Dict[str, Any]] = None
) -> str:
    """
    Format text as a clinical prompt for ML models.
    
    Args:
        text: Clinical text to format
        analysis_type: Type of analysis to perform
        context: Additional context for analysis
        
    Returns:
        Formatted prompt
    """
    if not text:
        return ""
    
    # Set up analysis-specific headers
    headers = {
        "diagnostic_impression": "# Diagnostic Impression Request",
        "risk_assessment": "# Risk Assessment Request",
        "treatment_recommendation": "# Treatment Recommendation Request",
        "clinical_insight": "# Clinical Insight Request"
    }
    
    # Set up analysis-specific instructions
    instructions = {
        "diagnostic_impression": (
            "Please provide a comprehensive diagnostic impression based on the clinical information below. "
            "Include primary and differential diagnoses, severity assessment, and supporting evidence. "
            "Format your response with clear headings for DIAGNOSES, SEVERITY, and CASE FORMULATION."
        ),
        "risk_assessment": (
            "Please provide a detailed risk assessment based on the clinical information below. "
            "Evaluate suicide risk, violence risk, self-harm risk, and other relevant risk factors. "
            "Format your response with clear headings for RISK LEVEL, RISK FACTORS, and PROTECTIVE FACTORS."
        ),
        "treatment_recommendation": (
            "Please provide evidence-based treatment recommendations based on the clinical information below. "
            "Include pharmacotherapy options, psychotherapy approaches, level of care considerations, and monitoring recommendations. "
            "Format your response with clear headings for MEDICATIONS, PSYCHOTHERAPY, LEVEL OF CARE, and MONITORING."
        ),
        "clinical_insight": (
            "Please provide thoughtful clinical insights based on the information below. "
            "Identify patterns, underlying mechanisms, treatment implications, and prognostic considerations. "
            "Format your response with clear headings for KEY POINTS and CLINICAL IMPLICATIONS."
        )
    }
    
    # Default to diagnostic impression if unknown analysis type
    header = headers.get(analysis_type, headers["diagnostic_impression"])
    instruction = instructions.get(analysis_type, instructions["diagnostic_impression"])
    
    # Format context if provided
    context_section = ""
    if context:
        context_section = "## Patient Context\n"
        
        # Add diagnoses if available
        if "diagnoses" in context and context["diagnoses"]:
            if isinstance(context["diagnoses"], list):
                diagnoses_text = ", ".join(context["diagnoses"])
                context_section += f"- Previous diagnoses: {diagnoses_text}\n"
            else:
                context_section += f"- Previous diagnosis: {context['diagnoses']}\n"
        
        # Add medications if available
        if "medications" in context and context["medications"]:
            if isinstance(context["medications"], list):
                medications_text = ", ".join(context["medications"])
                context_section += f"- Current medications: {medications_text}\n"
            else:
                context_section += f"- Current medication: {context['medications']}\n"
        
        # Add treatment history if available
        if "treatment_history" in context and context["treatment_history"]:
            context_section += "- Treatment history: Patient has previous treatment experience\n"
        
        # Add a spacing line
        context_section += "\n"
    
    # Format the prompt
    prompt = (
        f"{header}\n\n"
        f"{instruction}\n\n"
        f"{context_section}"
        f"## Clinical Information\n\n"
        f"{text}\n\n"
        f"## Analysis\n"
    )
    
    return prompt
