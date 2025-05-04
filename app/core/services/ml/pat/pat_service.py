"""
PAT (Patient Assessment Tool) Service Implementation.

This module implements the PAT interface, providing patient assessment
functionality for the mental health platform.
"""

import datetime
import json
import logging
import uuid
from typing import Any

from app.core.exceptions import (
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
from app.core.services.ml.pat.pat_interface import PATInterface

logger = logging.getLogger(__name__)

class PATService(PATInterface):
    """
    Implementation of the Patient Assessment Tool service.
    
    This service provides functionality to create, manage, and analyze
    patient assessments for mental health evaluation.
    """
    
    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the PAT service."""
        self._initialized = False
        self._config = config or {}
        self._assessments = {}
        self._form_templates = {}
        self._healthy = True
        
        # Initialize default templates
        self._init_default_templates()
    
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the service with configuration."""
        self._config.update(config)
        logger.info("Initializing PAT service with config: %s", json.dumps({k: "***" if "key" in k.lower() or "secret" in k.lower() else v for k, v in self._config.items()}))
        
        if not self._form_templates:
            self._init_default_templates()
        
        self._initialized = True
        logger.info("PAT service initialized successfully")
    
    def is_healthy(self) -> bool:
        """Check if the service is healthy."""
        return self._initialized and self._healthy
    
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        logger.info("Shutting down PAT service")
        self._initialized = False
        self._assessments.clear()
        self._form_templates.clear()
        logger.info("PAT service shutdown complete")
    
    def _ensure_initialized(self) -> None:
        """Ensure the service is initialized."""
        if not self._initialized:
            logger.error("PAT service not initialized")
            raise ServiceUnavailableError("PAT service not initialized")
    
    def create_assessment(
        self,
        patient_id: str,
        assessment_type: str,
        clinician_id: str | None = None,
        initial_data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a new patient assessment."""
        self._ensure_initialized()
        
        if not patient_id:
            logger.error("Invalid request: patient_id is required")
            raise InvalidRequestError("Invalid request: patient_id is required")
        
        if not assessment_type:
            logger.error("Invalid request: assessment_type is required")
            raise InvalidRequestError("Invalid request: assessment_type is required")
        
        assessment_id = str(uuid.uuid4())
        
        # Find template for assessment type
        template_id = None
        for tid, template in self._form_templates.items():
            if template["form_type"] == assessment_type:
                template_id = tid
                break
        
        if not template_id:
            logger.error("Invalid assessment type: %s", assessment_type)
            raise InvalidRequestError(f"Invalid assessment type: {assessment_type}")
        
        initial_data = initial_data or {}
        
        # Create assessment record
        assessment = {
            "id": assessment_id,
            "patient_id": patient_id,
            "clinician_id": clinician_id,
            "assessment_type": assessment_type,
            "template_id": template_id,
            "status": "created",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "completed_at": None,
            "data": initial_data,
            "scores": {},
            "flags": [],
            "metadata": {}
        }
        
        # Store assessment
        self._assessments[assessment_id] = assessment
        logger.info(
            "Created assessment: %s, type: %s, patient: %s",
            assessment_id, assessment_type, patient_id
        )
        
        return {
            "assessment_id": assessment_id,
            "patient_id": patient_id,
            "clinician_id": clinician_id,
            "assessment_type": assessment_type,
            "template_id": template_id,
            "status": "created",
            "created_at": assessment["created_at"],
            "template": self._form_templates[template_id]
        }
    
    def get_assessment(self, assessment_id: str) -> dict[str, Any]:
        """Get information about an assessment."""
        self._ensure_initialized()
        
        if not assessment_id:
            logger.error("Invalid request: assessment_id is required")
            raise InvalidRequestError("Invalid request: assessment_id is required")
        
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            logger.error("Assessment not found: %s", assessment_id)
            raise ModelNotFoundError(f"Assessment not found: {assessment_id}")
        
        template = self._form_templates.get(assessment["template_id"])
        
        return {
            "assessment_id": assessment["id"],
            "patient_id": assessment["patient_id"],
            "clinician_id": assessment["clinician_id"],
            "assessment_type": assessment["assessment_type"],
            "template_id": assessment["template_id"],
            "status": assessment["status"],
            "created_at": assessment["created_at"],
            "updated_at": assessment["updated_at"],
            "completed_at": assessment["completed_at"],
            "data": assessment["data"],
            "scores": assessment["scores"],
            "flags": assessment["flags"],
            "template": template,
            "completion_percentage": self._calculate_completion_percentage(assessment, template)
        }
    
    def update_assessment(
        self,
        assessment_id: str,
        data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an assessment with new data."""
        self._ensure_initialized()
        
        if not assessment_id:
            logger.error("Invalid request: assessment_id is required")
            raise InvalidRequestError("Invalid request: assessment_id is required")
        
        if not data:
            logger.error("Invalid request: data is required")
            raise InvalidRequestError("Invalid request: data is required")
        
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            logger.error("Assessment not found: %s", assessment_id)
            raise ModelNotFoundError(f"Assessment not found: {assessment_id}")
        
        # Ensure assessment is not already completed
        if assessment["status"] == "completed":
            logger.error("Cannot update completed assessment: %s", assessment_id)
            raise InvalidRequestError(f"Cannot update completed assessment: {assessment_id}")
        
        # Update assessment data
        assessment["data"].update(data)
        assessment["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Update status if all required fields are filled
        template = self._form_templates.get(assessment["template_id"])
        if template:
            completion_percentage = self._calculate_completion_percentage(assessment, template)
            if completion_percentage == 100 and assessment["status"] == "created":
                assessment["status"] = "in_progress"
        
        # Check for flags based on data
        self._update_assessment_flags(assessment)
        
        logger.info("Updated assessment: %s", assessment_id)
        
        return {
            "assessment_id": assessment["id"],
            "patient_id": assessment["patient_id"],
            "status": assessment["status"],
            "updated_at": assessment["updated_at"],
            "completion_percentage": self._calculate_completion_percentage(assessment, template),
            "flags": assessment["flags"]
        }
    
    def complete_assessment(
        self,
        assessment_id: str,
        completion_data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Complete an assessment."""
        self._ensure_initialized()
        
        if not assessment_id:
            logger.error("Invalid request: assessment_id is required")
            raise InvalidRequestError("Invalid request: assessment_id is required")
        
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            logger.error("Assessment not found: %s", assessment_id)
            raise ModelNotFoundError(f"Assessment not found: {assessment_id}")
        
        # Ensure assessment is not already completed
        if assessment["status"] == "completed":
            logger.error("Assessment already completed: %s", assessment_id)
            raise InvalidRequestError(f"Assessment already completed: {assessment_id}")
        
        completion_data = completion_data or {}
        
        # Update assessment data with completion data
        if completion_data:
            assessment["data"].update(completion_data)
        
        # Update assessment status
        assessment["status"] = "completed"
        assessment["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        assessment["updated_at"] = assessment["completed_at"]
        
        # Calculate scores
        assessment["scores"] = self._calculate_scores(assessment)
        
        # Update flags
        self._update_assessment_flags(assessment)
        
        logger.info("Completed assessment: %s", assessment_id)
        
        # Get template
        template = self._form_templates.get(assessment["template_id"])
        
        return {
            "assessment_id": assessment["id"],
            "patient_id": assessment["patient_id"],
            "clinician_id": assessment["clinician_id"],
            "assessment_type": assessment["assessment_type"],
            "status": "completed",
            "completed_at": assessment["completed_at"],
            "scores": assessment["scores"],
            "flags": assessment["flags"],
            "summary": self._generate_assessment_summary(assessment, template),
            "recommendations": self._generate_recommendations(assessment, template)
        }
    
    def analyze_assessment(
        self,
        assessment_id: str,
        analysis_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Analyze an assessment."""
        self._ensure_initialized()
        
        if not assessment_id:
            logger.error("Invalid request: assessment_id is required")
            raise InvalidRequestError("Invalid request: assessment_id is required")
        
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            logger.error("Assessment not found: %s", assessment_id)
            raise ModelNotFoundError(f"Assessment not found: {assessment_id}")
        
        analysis_type = analysis_type or "general"
        options = options or {}
        
        # Get template
        template = self._form_templates.get(assessment["template_id"])
        
        # Perform analysis based on type
        if analysis_type == "general":
            analysis_result = self._perform_general_analysis(assessment, template, options)
        elif analysis_type == "clinical":
            analysis_result = self._perform_clinical_analysis(assessment, template, options)
        elif analysis_type == "temporal":
            analysis_result = self._perform_temporal_analysis(assessment, options)
        elif analysis_type == "comparative":
            analysis_result = self._perform_comparative_analysis(assessment, options)
        else:
            logger.error("Invalid analysis type: %s", analysis_type)
            raise InvalidRequestError(f"Invalid analysis type: {analysis_type}")
        
        logger.info(
            "Analyzed assessment: %s, analysis type: %s",
            assessment_id, analysis_type
        )
        
        return {
            "assessment_id": assessment["id"],
            "patient_id": assessment["patient_id"],
            "assessment_type": assessment["assessment_type"],
            "analysis_type": analysis_type,
            "status": assessment["status"],
            "analyzed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "result": analysis_result,
            "options_used": options
        }
    
    def get_assessment_history(
        self,
        patient_id: str,
        assessment_type: str | None = None,
        limit: int | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Get assessment history for a patient."""
        self._ensure_initialized()
        
        if not patient_id:
            logger.error("Invalid request: patient_id is required")
            raise InvalidRequestError("Invalid request: patient_id is required")
        
        options = options or {}
        
        # Filter assessments by patient ID and assessment type
        assessments = []
        for assessment in self._assessments.values():
            if assessment["patient_id"] == patient_id:
                if assessment_type and assessment["assessment_type"] != assessment_type:
                    continue
                assessments.append(assessment)
        
        # Sort assessments by created_at in descending order
        assessments.sort(key=lambda a: a["created_at"], reverse=True)
        
        # Apply limit if specified
        if limit and limit > 0:
            assessments = assessments[:limit]
        
        # Extract summary information
        history = []
        for assessment in assessments:
            template = self._form_templates.get(assessment["template_id"])
            history.append({
                "assessment_id": assessment["id"],
                "assessment_type": assessment["assessment_type"],
                "status": assessment["status"],
                "created_at": assessment["created_at"],
                "updated_at": assessment["updated_at"],
                "completed_at": assessment["completed_at"],
                "scores": assessment["scores"],
                "flags": assessment["flags"],
                "template_name": template["name"] if template else None,
                "completion_percentage": self._calculate_completion_percentage(assessment, template)
            })
        
        logger.info(
            "Retrieved assessment history for patient: %s, found %d assessments",
            patient_id, len(history)
        )
        
        return {
            "patient_id": patient_id,
            "assessment_type": assessment_type,
            "history": history,
            "count": len(history),
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "options_used": options
        }
    
    def create_form_template(
        self,
        name: str,
        form_type: str,
        fields: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a new assessment form template."""
        self._ensure_initialized()
        
        if not name or not form_type or not fields:
            logger.error("Invalid request: name, form_type, and fields are required")
            raise InvalidRequestError("Invalid request: name, form_type, and fields are required")
        
        template_id = str(uuid.uuid4())
        metadata = metadata or {}
        
        # Create template
        template = {
            "id": template_id,
            "name": name,
            "form_type": form_type,
            "fields": fields,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metadata": metadata
        }
        
        # Store template
        self._form_templates[template_id] = template
        
        logger.info(
            "Created form template: %s, type: %s, fields: %d",
            template_id, form_type, len(fields)
        )
        
        return {
            "template_id": template_id,
            "name": name,
            "form_type": form_type,
            "field_count": len(fields),
            "created_at": template["created_at"]
        }
    
    def get_form_template(
        self,
        template_id: str
    ) -> dict[str, Any]:
        """Get a form template."""
        self._ensure_initialized()
        
        if not template_id:
            logger.error("Invalid request: template_id is required")
            raise InvalidRequestError("Invalid request: template_id is required")
        
        template = self._form_templates.get(template_id)
        if not template:
            logger.error("Form template not found: %s", template_id)
            raise ModelNotFoundError(f"Form template not found: {template_id}")
        
        return template
    
    def list_form_templates(
        self,
        form_type: str | None = None,
        limit: int | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """List available form templates."""
        self._ensure_initialized()
        
        options = options or {}
        
        # Filter templates by form type
        templates = []
        for template in self._form_templates.values():
            if form_type and template["form_type"] != form_type:
                continue
            
            # Include summary information, not full template
            templates.append({
                "id": template["id"],
                "name": template["name"],
                "form_type": template["form_type"],
                "field_count": len(template["fields"]),
                "created_at": template["created_at"]
            })
        
        # Sort templates by name
        templates.sort(key=lambda t: t["name"])
        
        # Apply limit if specified
        if limit and limit > 0:
            templates = templates[:limit]
        
        logger.info("Listed form templates, found %d templates", len(templates))
        
        return {
            "templates": templates,
            "count": len(templates),
            "form_type": form_type,
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "options_used": options
        }
    
    def calculate_score(
        self,
        assessment_id: str,
        scoring_method: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Calculate score for an assessment."""
        self._ensure_initialized()
        
        if not assessment_id:
            logger.error("Invalid request: assessment_id is required")
            raise InvalidRequestError("Invalid request: assessment_id is required")
        
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            logger.error("Assessment not found: %s", assessment_id)
            raise ModelNotFoundError(f"Assessment not found: {assessment_id}")
        
        scoring_method = scoring_method or "standard"
        options = options or {}
        
        # Calculate scores based on method
        if scoring_method == "standard":
            scores = self._calculate_standard_scores(assessment, options)
        elif scoring_method == "clinical":
            scores = self._calculate_clinical_scores(assessment, options)
        elif scoring_method == "custom":
            scores = self._calculate_custom_scores(assessment, options)
        else:
            logger.error("Invalid scoring method: %s", scoring_method)
            raise InvalidRequestError(f"Invalid scoring method: {scoring_method}")
        
        # Update assessment scores
        assessment["scores"] = scores
        assessment["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        logger.info(
            "Calculated scores for assessment: %s, method: %s",
            assessment_id, scoring_method
        )
        
        return {
            "assessment_id": assessment["id"],
            "patient_id": assessment["patient_id"],
            "scoring_method": scoring_method,
            "scores": scores,
            "calculated_at": assessment["updated_at"],
            "options_used": options
        }
    
    def generate_report(
        self,
        assessment_id: str,
        report_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Generate a report for an assessment."""
        self._ensure_initialized()
        
        if not assessment_id:
            logger.error("Invalid request: assessment_id is required")
            raise InvalidRequestError("Invalid request: assessment_id is required")
        
        assessment = self._assessments.get(assessment_id)
        if not assessment:
            logger.error("Assessment not found: %s", assessment_id)
            raise ModelNotFoundError(f"Assessment not found: {assessment_id}")
        
        report_type = report_type or "summary"
        options = options or {}
        
        # Ensure assessment is completed for certain report types
        if report_type in ["detailed", "clinical"] and assessment["status"] != "completed":
            logger.error("Assessment not completed for report type: %s", report_type)
            raise InvalidRequestError(f"Assessment not completed for report type: {report_type}")
        
        # Get template
        template = self._form_templates.get(assessment["template_id"])
        
        # Generate report based on type
        if report_type == "summary":
            report_data = self._generate_summary_report(assessment, template, options)
        elif report_type == "detailed":
            report_data = self._generate_detailed_report(assessment, template, options)
        elif report_type == "clinical":
            report_data = self._generate_clinical_report(assessment, template, options)
        elif report_type == "progress":
            report_data = self._generate_progress_report(assessment, options)
        else:
            logger.error("Invalid report type: %s", report_type)
            raise InvalidRequestError(f"Invalid report type: {report_type}")
        
        logger.info(
            "Generated report for assessment: %s, type: %s",
            assessment_id, report_type
        )
        
        return {
            "assessment_id": assessment["id"],
            "patient_id": assessment["patient_id"],
            "report_type": report_type,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "report": report_data,
            "options_used": options
        }
    
    def _init_default_templates(self) -> None:
        """Initialize default assessment templates."""
        # PHQ-9 Depression Scale
        phq9_fields = [
            {
                "id": "phq9_1",
                "type": "choice",
                "question": "Little interest or pleasure in doing things",
                "choices": [
                    {"value": 0, "label": "Not at all"},
                    {"value": 1, "label": "Several days"},
                    {"value": 2, "label": "More than half the days"},
                    {"value": 3, "label": "Nearly every day"}
                ],
                "required": True
            },
            {
                "id": "phq9_2",
                "type": "choice",
                "question": "Feeling down, depressed, or hopeless",
                "choices": [
                    {"value": 0, "label": "Not at all"},
                    {"value": 1, "label": "Several days"},
                    {"value": 2, "label": "More than half the days"},
                    {"value": 3, "label": "Nearly every day"}
                ],
                "required": True
            },
            # Additional PHQ-9 fields would be defined here...
            {
                "id": "phq9_9",
                "type": "choice",
                "question": "Thoughts that you would be better off dead, or of hurting yourself",
                "choices": [
                    {"value": 0, "label": "Not at all"},
                    {"value": 1, "label": "Several days"},
                    {"value": 2, "label": "More than half the days"},
                    {"value": 3, "label": "Nearly every day"}
                ],
                "required": True,
                "flag": True
            }
        ]
        
        phq9_template = {
            "id": str(uuid.uuid4()),
            "name": "PHQ-9 Depression Scale",
            "form_type": "depression",
            "fields": phq9_fields,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metadata": {
                "description": "Patient Health Questionnaire-9 for depression screening",
                "scoring": {
                    "ranges": [
                        {"min": 0, "max": 4, "label": "Minimal depression"},
                        {"min": 5, "max": 9, "label": "Mild depression"},
                        {"min": 10, "max": 14, "label": "Moderate depression"},
                        {"min": 15, "max": 19, "label": "Moderately severe depression"},
                        {"min": 20, "max": 27, "label": "Severe depression"}
                    ]
                }
            }
        }
        
        # GAD-7 Anxiety Scale
        gad7_fields = [
            {
                "id": "gad7_1",
                "type": "choice",
                "question": "Feeling nervous, anxious, or on edge",
                "choices": [
                    {"value": 0, "label": "Not at all"},
                    {"value": 1, "label": "Several days"},
                    {"value": 2, "label": "More than half the days"},
                    {"value": 3, "label": "Nearly every day"}
                ],
                "required": True
            },
            # Additional GAD-7 fields would be defined here...
        ]
        
        gad7_template = {
            "id": str(uuid.uuid4()),
            "name": "GAD-7 Anxiety Scale",
            "form_type": "anxiety",
            "fields": gad7_fields,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metadata": {
                "description": "Generalized Anxiety Disorder 7-item scale",
                "scoring": {
                    "ranges": [
                        {"min": 0, "max": 4, "label": "Minimal anxiety"},
                        {"min": 5, "max": 9, "label": "Mild anxiety"},
                        {"min": 10, "max": 14, "label": "Moderate anxiety"},
                        {"min": 15, "max": 21, "label": "Severe anxiety"}
                    ]
                }
            }
        }
        
        # Store templates
        self._form_templates[phq9_template["id"]] = phq9_template
        self._form_templates[gad7_template["id"]] = gad7_template
    
    def _calculate_completion_percentage(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None
    ) -> float:
        """Calculate the completion percentage of an assessment."""
        if not template:
            return 0
        
        required_fields = [field for field in template["fields"] if field.get("required", False)]
        if not required_fields:
            return 100
        
        completed_fields = 0
        for field in required_fields:
            if field["id"] in assessment["data"]:
                completed_fields += 1
        
        return (completed_fields / len(required_fields)) * 100
    
    def _update_assessment_flags(self, assessment: dict[str, Any]) -> None:
        """Update flags based on assessment data."""
        flags = []
        template = self._form_templates.get(assessment["template_id"])
        
        if not template:
            assessment["flags"] = flags
            return
        
        # Check for flag fields in template
        for field in template["fields"]:
            if field.get("flag", False) and field["id"] in assessment["data"]:
                value = assessment["data"][field["id"]]
                
                # Suicide risk check
                if field["id"] == "phq9_9" and isinstance(value, (int, float)) and value > 1:
                    flags.append({
                        "type": "suicide_risk",
                        "severity": "moderate" if value == 2 else "high",
                        "field": field["id"],
                        "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    })
        
        # Check PHQ-9 total score if available
        if "phq9_total" in assessment.get("scores", {}):
            phq9_score = assessment["scores"]["phq9_total"]
            if phq9_score >= 20:
                flags.append({
                    "type": "severe_depression",
                    "severity": "high",
                    "score": phq9_score,
                    "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                })
        
        assessment["flags"] = flags
    
    def _calculate_scores(self, assessment: dict[str, Any]) -> dict[str, Any]:
        """Calculate scores for an assessment."""
        scores = {}
        template = self._form_templates.get(assessment["template_id"])
        
        if not template:
            return scores
        
        # PHQ-9 scoring
        if template["form_type"] == "depression":
            phq9_total = 0
            for i in range(1, 10):  # PHQ-9 has 9 questions
                field_id = f"phq9_{i}"
                if field_id in assessment["data"]:
                    value = assessment["data"][field_id]
                    if isinstance(value, (int, float)):
                        phq9_total += value
            
            scores["phq9_total"] = phq9_total
            
            # Determine severity
            if phq9_total >= 20:
                scores["phq9_severity"] = "severe"
            elif phq9_total >= 15:
                scores["phq9_severity"] = "moderately_severe"
            elif phq9_total >= 10:
                scores["phq9_severity"] = "moderate"
            elif phq9_total >= 5:
                scores["phq9_severity"] = "mild"
            else:
                scores["phq9_severity"] = "minimal"
        
        # GAD-7 scoring
        elif template["form_type"] == "anxiety":
            gad7_total = 0
            for i in range(1, 8):  # GAD-7 has 7 questions
                field_id = f"gad7_{i}"
                if field_id in assessment["data"]:
                    value = assessment["data"][field_id]
                    if isinstance(value, (int, float)):
                        gad7_total += value
            
            scores["gad7_total"] = gad7_total
            
            # Determine severity
            if gad7_total >= 15:
                scores["gad7_severity"] = "severe"
            elif gad7_total >= 10:
                scores["gad7_severity"] = "moderate"
            elif gad7_total >= 5:
                scores["gad7_severity"] = "mild"
            else:
                scores["gad7_severity"] = "minimal"
        
        return scores
    
    def _calculate_standard_scores(
        self,
        assessment: dict[str, Any],
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate standard scores for an assessment."""
        return self._calculate_scores(assessment)
    
    def _calculate_clinical_scores(
        self,
        assessment: dict[str, Any],
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate clinical scores for an assessment."""
        scores = self._calculate_scores(assessment)
        
        # Add clinical risk assessment
        template = self._form_templates.get(assessment["template_id"])
        
        if template and template["form_type"] == "depression":
            # Suicide risk assessment based on PHQ-9 item 9
            suicide_risk = "none"
            if "phq9_9" in assessment["data"]:
                phq9_9_value = assessment["data"]["phq9_9"]
                if phq9_9_value == 1:
                    suicide_risk = "low"
                elif phq9_9_value == 2:
                    suicide_risk = "moderate"
                elif phq9_9_value == 3:
                    suicide_risk = "high"
            
            scores["clinical_risk"] = {
                "suicide_risk": suicide_risk,
                "treatment_urgency": "high" if suicide_risk in ["moderate", "high"] else "routine"
            }
        
        return scores
    
    def _calculate_custom_scores(
        self,
        assessment: dict[str, Any],
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate custom scores for an assessment based on provided options."""
        scores = self._calculate_scores(assessment)
        
        # Custom scoring based on options can be implemented here
        
        return scores
    
    def _generate_assessment_summary(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Generate a summary of an assessment."""
        summary = {
            "assessment_type": assessment["assessment_type"],
            "completion_status": assessment["status"],
            "completion_time": None
        }
        
        if assessment["created_at"] and assessment.get("completed_at"):
            # Calculate completion time in minutes
            start_time = datetime.datetime.fromisoformat(assessment["created_at"])
            end_time = datetime.datetime.fromisoformat(assessment["completed_at"])
            completion_time = (end_time - start_time).total_seconds() / 60
            summary["completion_time"] = round(completion_time, 1)
        
        # Add score summaries
        if assessment.get("scores"):
            summary["scores"] = assessment["scores"]
        
        # Add flags
        if assessment.get("flags"):
            summary["flags"] = assessment["flags"]
        
        # Add template information
        if template:
            summary["template_name"] = template["name"]
        
        return summary
    
    def _generate_recommendations(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Generate recommendations based on assessment results."""
        recommendations = {
            "follow_up": None,
            "interventions": [],
            "resources": [],
            "clinical_considerations": []
        }
        
        if not template:
            return recommendations
        
        # PHQ-9 recommendations
        if template["form_type"] == "depression" and "scores" in assessment:
            severity = assessment["scores"].get("phq9_severity")
            
            if severity == "minimal":
                recommendations["follow_up"] = "4_weeks"
                recommendations["interventions"] = ["supportive_care", "lifestyle_changes"]
            elif severity == "mild":
                recommendations["follow_up"] = "2_weeks"
                recommendations["interventions"] = ["psychotherapy", "lifestyle_changes"]
            elif severity == "moderate":
                recommendations["follow_up"] = "1_week"
                recommendations["interventions"] = ["psychotherapy", "consider_medication"]
            elif severity in ["moderately_severe", "severe"]:
                recommendations["follow_up"] = "immediate"
                recommendations["interventions"] = ["medication", "psychotherapy"]
                
            # Special considerations for suicide risk
            for flag in assessment.get("flags", []):
                if flag["type"] == "suicide_risk":
                    recommendations["follow_up"] = "immediate"
                    recommendations["interventions"].append("safety_planning")
                    recommendations["clinical_considerations"].append("Conduct comprehensive suicide risk assessment")
        
        return recommendations
    
    def _perform_general_analysis(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Perform general analysis of an assessment."""
        result = {
            "summary": self._generate_assessment_summary(assessment, template),
            "completion_percentage": self._calculate_completion_percentage(assessment, template),
            "flags": assessment.get("flags", [])
        }
        
        # Add recommendations if assessment is completed
        if assessment["status"] == "completed":
            result["recommendations"] = self._generate_recommendations(assessment, template)
        
        return result
    
    def _perform_clinical_analysis(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Perform clinical analysis of an assessment."""
        # Start with general analysis
        result = self._perform_general_analysis(assessment, template, options)
        
        # Add clinical-specific analysis
        result["clinical"] = {
            "severity_assessment": {},
            "risk_factors": [],
            "differential_considerations": []
        }
        
        # Additional clinical analysis would be implemented here
        
        return result
    
    def _perform_temporal_analysis(
        self,
        assessment: dict[str, Any],
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Perform temporal analysis of an assessment, comparing with previous assessments."""
        result = {
            "trend": "stable",
            "comparison": {},
            "significant_changes": []
        }
        
        # Temporal analysis would be implemented here
        
        return result
    
    def _perform_comparative_analysis(
        self,
        assessment: dict[str, Any],
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Perform comparative analysis, comparing with population norms or other patients."""
        result = {
            "population_comparison": {},
            "similar_patients": {},
            "percentile_ranks": {}
        }
        
        # Comparative analysis would be implemented here
        
        return result
    
    def _generate_summary_report(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a summary report for an assessment."""
        report = {
            "title": f"{template['name'] if template else 'Assessment'} Summary Report",
            "patient_id": assessment["patient_id"],
            "date": assessment.get("completed_at", assessment["updated_at"]),
            "status": assessment["status"],
            "summary": self._generate_assessment_summary(assessment, template)
        }
        
        # Add scores if available
        if assessment.get("scores"):
            report["scores"] = assessment["scores"]
        
        # Add recommendations if completed
        if assessment["status"] == "completed":
            report["recommendations"] = self._generate_recommendations(assessment, template)
        
        return report
    
    def _generate_detailed_report(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a detailed report for an assessment."""
        # Start with summary report
        report = self._generate_summary_report(assessment, template, options)
        
        # Additional detailed report sections would be implemented here
        
        return report
    
    def _generate_clinical_report(
        self,
        assessment: dict[str, Any],
        template: dict[str, Any] | None,
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a clinical report for an assessment."""
        # Start with detailed report
        report = self._generate_detailed_report(assessment, template, options)
        
        # Additional clinical report sections would be implemented here
        
        return report
    
    def _generate_progress_report(
        self,
        assessment: dict[str, Any],
        options: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a progress report showing changes over time."""
        report = {
            "title": "Treatment Progress Report",
            "patient_id": assessment["patient_id"],
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "current_assessment": {
                "assessment_id": assessment["id"],
                "assessment_type": assessment["assessment_type"],
                "date": assessment.get("completed_at", assessment["updated_at"])
            }
        }
        
        # Additional progress report sections would be implemented here
        
        return report
