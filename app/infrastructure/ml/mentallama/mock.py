"""
Mock ML Service Implementation.

This module provides mock implementations of ML services for testing purposes.
These mock implementations follow the interfaces defined in interface.py
and provide realistic responses for testing without requiring actual ML models.
"""

import random
import re
from datetime import datetime
from typing import Any
import uuid

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ModelNotFoundError,
    ServiceUnavailableError,
)
from app.core.services.ml.interface import MentaLLaMAInterface, PHIDetectionInterface
from app.core.utils.logging import get_logger
from app.domain.utils.datetime_utils import UTC

# Create logger (no PHI logging)
logger = get_logger(__name__)


# REMOVE: Legacy MockMentaLLaMA from core.services.ml.mentallama.mock. Use infrastructure layer only.
class MockMentaLLaMA(MentaLLaMAInterface): # Uncommented class definition
    """
    Mock MentaLLaMA implementation.

    This class provides a mock implementation of MentaLLaMA services for testing.
    It simulates responses from various mental health analysis models and 
    implements Digital Twin functionality for patient simulation.
    """
    
    def __init__(self) -> None:
        """Initialize MockMentaLLaMA instance."""
        self._initialized = False
        self._config = None
        self._model_types = [
            "general", "depression_detection", "risk_assessment", 
            "sentiment_analysis", "wellness_dimensions", "digital_twin"
        ]
        self._mock_responses = {}
        self._sessions = {}
        self._digital_twins = {}
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            self._config = config or {}
            
            # Load mock responses
            custom_responses = self._config.get("mock_responses")
            if custom_responses is not None:
                if not isinstance(custom_responses, dict):
                    raise InvalidConfigurationError("mock_responses must be a dictionary")
                self._mock_responses = custom_responses
            else:
                self._load_default_mock_responses()
            
            self._initialized = True
            logger.info("Mock MentaLLaMA service initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize mock MentaLLaMA service: {e!s}")
            self._initialized = False
            self._config = None
            raise InvalidConfigurationError(f"Failed to initialize mock MentaLLaMA service: {e!s}")
    
    def _load_default_mock_responses(self) -> None:
        """Load default mock responses for various model types."""
        self._mock_responses = {
            "general": self._create_general_response(),
            "depression_detection": self._create_depression_detection_response(),
            "risk_assessment": self._create_risk_assessment_response(),
            "sentiment_analysis": self._create_sentiment_analysis_response(),
            "wellness_dimensions": self._create_wellness_dimensions_response(),
            "digital_twin": self._create_digital_twin_response(),
        }
    
    def _create_general_response(self) -> dict[str, Any]:
        """Create a default mock response for general model type."""
        return {
            "content": """Based on the provided text, I've identified several patterns that may be clinically relevant:

1. **Emotional Presentation**: The text shows a mix of anxiety and low mood, with significant worry about the future.

2. **Cognitive Patterns**: There appears to be some catastrophic thinking and overgeneralization, particularly around work performance.

3. **Behavioral Indicators**: Mentions of sleep disruption and reduced engagement in previously enjoyed activities.

4. **Relational Context**: References to strained interpersonal connections, particularly with family members.

These patterns would warrant further professional assessment to determine clinical significance. This analysis is meant to support, not replace, clinical judgment.

Remember that this is a preliminary analysis based solely on the language patterns in the text provided. A comprehensive evaluation would include a structured clinical interview, standardized assessments, and consideration of medical, developmental, and psychosocial history.""",
            "model": "mock-gpt-4",
            "model_type": "general",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def _create_depression_detection_response(self) -> dict[str, Any]:
        """Create a default mock response for depression detection model type."""
        return {
            "depression_signals": {
                "severity": "moderate",
                "confidence": 0.78,
                "key_indicators": [
                    {
                        "type": "linguistic",
                        "description": "Negative self-referential language",
                        "evidence": "I'm not good enough to handle this"
                    },
                    {
                        "type": "behavioral",
                        "description": "Sleep disruption",
                        "evidence": "I've been having trouble sleeping most nights"
                    },
                    {
                        "type": "cognitive",
                        "description": "Hopelessness",
                        "evidence": "I don't see how things will get better"
                    }
                ]
            },
            "analysis": {
                "summary": "Multiple moderate depression indicators present, including negative self-evaluation, sleep disruption, and hopelessness about the future",
                "warning_signs": ["Explicit statements of worthlessness", "Disrupted sleep pattern", "Expressions of hopelessness"],
                "protective_factors": ["Seeking help/awareness of difficulties", "References to previously enjoyed activities"],
                "limitations": ["Analysis based only on text without clinical interview", "Cannot assess duration of symptoms"]
            },
            "recommendations": {
                "suggested_assessments": ["PHQ-9", "Beck Depression Inventory-II", "Clinical interview focusing on mood and neurovegetative symptoms"],
                "discussion_points": ["Timeline of symptom development", "Impact on daily functioning", "Exploration of cognitive distortions"]
            },
            "model": "mock-gpt-4",
            "model_type": "depression_detection",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def _create_risk_assessment_response(self) -> dict[str, Any]:
        """Create a default mock response for risk assessment model type."""
        return {
            "risk_assessment": {
                "overall_risk_level": "low",
                "confidence": 0.82,
                "identified_risks": [
                    {
                        "risk_type": "self-harm",
                        "severity": "low",
                        "evidence": "I don't care what happens to me anymore",
                        "temporality": "current"
                    }
                ]
            },
            "analysis": {
                "summary": "Mild risk indicators present but no explicit statements of intent or plan for self-harm or suicide",
                "critical_factors": ["Expressions of hopelessness", "Passive indifference to wellbeing"],
                "protective_factors": ["Help-seeking behavior", "No explicit expressions of intent to harm self"],
                "context_considerations": ["Current stressors may be temporary", "Social support not clearly evaluated"],
                "limitations": ["Risk assessment requires direct clinical evaluation", "Text analysis cannot determine intent or access to means"]
            },
            "recommendations": {
                "immediate_actions": [],
                "clinical_follow_up": ["Direct assessment of self-harm/suicidal ideation", "Safety planning if risk increases", "Evaluation of support system"],
                "screening_tools": ["Columbia-Suicide Severity Rating Scale", "Safety Planning Intervention"]
            },
            "model": "mock-gpt-4",
            "model_type": "risk_assessment",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def _create_sentiment_analysis_response(self) -> dict[str, Any]:
        """Create a default mock response for sentiment analysis model type."""
        return {
            "sentiment": {
                "overall_score": -0.65,
                "intensity": 0.72,
                "dominant_valence": "negative"
            },
            "emotions": {
                "primary_emotions": [
                    {
                        "emotion": "sadness",
                        "intensity": 0.76,
                        "evidence": "I feel so down all the time"
                    },
                    {
                        "emotion": "anxiety",
                        "intensity": 0.68,
                        "evidence": "I'm constantly worried about everything"
                    },
                    {
                        "emotion": "hopelessness",
                        "intensity": 0.72,
                        "evidence": "I don't see how things will improve"
                    }
                ],
                "emotional_range": "narrow",
                "emotional_stability": "relatively stable"
            },
            "analysis": {
                "summary": "Predominantly negative emotional tone with consistent expressions of sadness, anxiety, and hopelessness",
                "notable_patterns": ["Persistent negative valence throughout", "Limited positive emotional expression", "Significant intensity of negative emotions"],
                "emotional_themes": ["Sadness related to self-perception", "Anxiety about the future", "General sense of defeat"],
                "clinical_relevance": "Emotional pattern consistent with depressive presentation, with significant anxiety component",
                "limitations": ["Point-in-time assessment only", "Cannot determine baseline emotional state"]
            },
            "model": "mock-gpt-4",
            "model_type": "sentiment_analysis",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def _create_wellness_dimensions_response(self) -> dict[str, Any]:
        """Create a default mock response for wellness dimensions model type."""
        return {
            "wellness_dimensions": [
                {
                    "dimension": "emotional",
                    "score": 0.35,
                    "summary": "Significant emotional distress indicated",
                    "strengths": ["Emotional awareness", "Ability to articulate feelings"],
                    "challenges": ["Persistent negative emotions", "Difficulty regulating emotional state"],
                    "evidence": ["I feel overwhelmed by sadness", "I can't seem to shake these feelings"]
                },
                {
                    "dimension": "social",
                    "score": 0.42,
                    "summary": "Moderate challenges in social connections",
                    "strengths": ["References to existing relationships"],
                    "challenges": ["Withdrawal from social interaction", "Feeling disconnected from others"],
                    "evidence": ["I've been avoiding my friends", "Nobody really understands what I'm going through"]
                },
                {
                    "dimension": "physical",
                    "score": 0.40,
                    "summary": "Physical wellness concerns present",
                    "strengths": ["Awareness of physical health impact"],
                    "challenges": ["Sleep disruption", "Low energy", "Changes in appetite"],
                    "evidence": ["I'm exhausted all the time", "I've been having trouble sleeping"]
                }
            ],
            "analysis": {
                "summary": "Multiple wellness dimensions show significant challenges, with emotional wellness most impacted",
                "patterns": ["Interconnected challenges across dimensions", "Emotional state affecting physical and social wellness"],
                "priorities": ["Addressing emotional distress", "Improving sleep quality", "Rebuilding social connections"]
            },
            "recommendations": {
                "emotional": ["Consider counseling or therapy", "Mindfulness practices", "Emotional awareness journaling"],
                "social": ["Gradual reengagement with supportive relationships", "Communication skills development"],
                "physical": ["Sleep hygiene practices", "Gentle physical activity", "Regular meal schedule"]
            },
            "model": "mock-gpt-4",
            "model_type": "wellness_dimensions",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def _create_digital_twin_response(self) -> dict[str, Any]:
        """Create a default mock response for digital twin model type."""
        return {
            "digital_twin_id": f"dt-{random.randint(1000, 9999)}",
            "creation_timestamp": datetime.now(UTC).isoformat(),
            "model_version": "1.0.0",
            "summary": "Digital twin created based on provided textual data. The twin represents a cognitive-behavioral model of the individual with emphasis on response patterns, thought structures, and clinical implications.",
            "model": "mock-gpt-4",
            "model_type": "digital_twin",
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        return self._initialized
    
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        logger.info("Mock MentaLLaMA service shut down")
    
    def process(
        self, 
        text: str,
        model_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Process text using the MentaLLaMA model.
        
        Args:
            text: Text to process
            model_type: Type of model to use
            options: Additional processing options
            
        Returns:
            Processing results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
            ModelNotFoundError: If model type is not found
        """
        # Validate service state and input
        self._validate_service_and_input(text)
        
        # Set default model type if not provided
        if model_type is None:
            model_type = "general"
        
        # Validate model type
        model_type = model_type.lower()
        if model_type not in [
            "general", 
            "depression_detection", 
            "risk_assessment",
            "analysis",  # Alias for general
            "conditions",  # Alias for depression_detection
            "therapeutic",  # Alias for general with formatting
            "risk",  # Alias for risk_assessment
            "wellness",  # Alias for wellness_dimensions
            "sentiment_analysis",
            "wellness_dimensions",
            "digital_twin"
        ]:
            raise ModelNotFoundError(model_type)
        
        # Handle model type aliases for API compatibility
        if model_type == "analysis":
            model_type = "general"
        elif model_type == "conditions":
            model_type = "depression_detection"
        elif model_type == "therapeutic":
            model_type = "general"
        elif model_type == "risk":
            model_type = "risk_assessment"
        elif model_type == "wellness":
            model_type = "wellness_dimensions"
        
        # Initialize options if not provided
        if options is None:
            options = {}
        
        # Get the appropriate mock response
        if model_type in self._mock_responses:
            response = self._mock_responses[model_type].copy()
        else:
            # Fallback to general model if specific type not found in mock responses
            response = self._mock_responses["general"].copy()
            response["model_type"] = model_type
        
        # Update timestamp to current
        response["timestamp"] = datetime.now(UTC).isoformat()
        
        # Add request options to response metadata
        if "metadata" not in response:
            response["metadata"] = {}
        response["metadata"]["options"] = options
        
        return response
    
    def _validate_service_and_input(self, text: str) -> None:
        """
        Validate service state and input text.
        
        Args:
            text: Input text to validate
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock MentaLLaMA service is not initialized")
        
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
    
    def detect_depression(
        self, 
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Detect depression signals in text.
        
        Args:
            text: Text to analyze
            options: Additional processing options
            
        Returns:
            Depression detection results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._validate_service_and_input(text)
        
        # Process with depression detection model
        return self.process(text, "depression_detection", options)
    
    def assess_risk(
        self, 
        text: str,
        risk_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Assess risk in text.
        
        Args:
            text: Text to analyze
            risk_type: Type of risk to assess (suicide, self-harm, violence, etc.)
            options: Additional processing options
            
        Returns:
            Risk assessment results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._validate_service_and_input(text)
        
        # Get mock response
        response = self.process(text, "risk_assessment", options)
        
        # Customize response based on risk type if provided
        if risk_type and isinstance(response, dict) and "risk_assessment" in response:
            filtered_risks = []
            for risk in response["risk_assessment"].get("identified_risks", []):
                if risk.get("risk_type") == risk_type:
                    filtered_risks.append(risk)
            
            # If we found matching risks, replace the identified risks
            if filtered_risks:
                response["risk_assessment"]["identified_risks"] = filtered_risks
        
        return response
    
    def analyze_sentiment(
        self, 
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Analyze sentiment in text.
        
        Args:
            text: Text to analyze
            options: Additional processing options
            
        Returns:
            Sentiment analysis results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._validate_service_and_input(text)
        
        # Process with sentiment analysis model
        return self.process(text, "sentiment_analysis", options)
    
    def analyze_wellness_dimensions(
        self, 
        text: str,
        dimensions: list[str] | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Analyze wellness dimensions in text.
        
        Args:
            text: Text to analyze
            dimensions: List of dimensions to analyze
            options: Additional processing options
            
        Returns:
            Wellness dimensions analysis results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._validate_service_and_input(text)
        
        # Get mock response
        response = self.process(text, "wellness_dimensions", options)
        
        # Filter dimensions if requested
        if dimensions and isinstance(response, dict) and "wellness_dimensions" in response:
            filtered_dimensions = []
            for dim in response["wellness_dimensions"]:
                if dim.get("dimension") in dimensions:
                    filtered_dimensions.append(dim)
            
            # If we found matching dimensions, replace the wellness dimensions
            if filtered_dimensions:
                response["wellness_dimensions"] = filtered_dimensions
        
        return response
    
    # Digital Twin methods
    
    def generate_digital_twin(
        self,
        patient_id: str | None = None,
        text_data: list[str] | None = None,
        patient_data: dict[str, Any] | None = None,
        demographic_data: dict[str, Any] | None = None,
        medical_history: dict[str, Any] | None = None,
        treatment_history: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Generate a digital twin for a patient.
        
        Args:
            patient_id: ID of the patient
            text_data: List of text samples for analysis
            patient_data: General patient data
            demographic_data: Patient demographic information
            medical_history: Patient medical history
            treatment_history: Patient treatment history
            options: Additional options
            
        Returns:
            Digital twin details
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If required data is missing
        """
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service is not initialized")
        
        # Validate input data
        if not patient_id and not text_data and not patient_data:
            raise InvalidRequestError("At least one of patient_id, text_data, or patient_data must be provided")
        
        # Generate a default patient ID if not provided
        if not patient_id:
            patient_id = f"patient-{uuid.uuid4()}"
        
        # Generate a twin ID
        twin_id = f"twin-{uuid.uuid4()}"
        
        # Normalize input data
        text_data = text_data or []
        patient_data = patient_data or {}
        demographic_data = demographic_data or {}
        medical_history = medical_history or {}
        treatment_history = treatment_history or {}
        options = options or {}
        
        # Create digital twin
        twin = {
            "id": twin_id,
            "patient_id": patient_id,
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "status": "active",
            "model_version": "1.0",
            "input_data": {
                "text_samples_count": len(text_data),
                "demographic_data": demographic_data,
                "medical_history": medical_history,
                "treatment_history": treatment_history
            },
            "parameters": options,
            "metadata": {
                "provider": "mock",
                "creation_time": datetime.now(UTC).isoformat()
            }
        }
        
        # Store twin
        self._digital_twins[twin_id] = twin
        
        # Return twin details
        return {
            "digital_twin_id": twin_id,
            "patient_id": patient_id,
            "status": "created",
            "creation_time": twin["created_at"],
            "model_version": twin["model_version"]
        }
    
    def create_digital_twin_session(
        self,
        twin_id: str,
        session_type: str | None = None,
        therapist_id: str | None = None,
        patient_id: str | None = None,
        session_params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Create a new digital twin session.
        
        Args:
            twin_id: ID of the digital twin
            session_type: Type of session (therapy, assessment, etc.)
            therapist_id: ID of therapist
            patient_id: ID of patient
            session_params: Additional session parameters
            
        Returns:
            Session details
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If twin ID is invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service is not initialized")
        
        # Validate twin ID
        if not twin_id or not isinstance(twin_id, str):
            raise InvalidRequestError("Invalid twin ID")
        
        # Check if twin exists
        if twin_id not in self._digital_twins:
            # Auto-create a twin for testing purposes
            patient_id = patient_id or f"auto-patient-{random.randint(1000, 9999)}"
            self._digital_twins[twin_id] = {
                "id": twin_id,
                "patient_id": patient_id,
                "created_at": datetime.now(UTC).isoformat(),
                "status": "active",
                "metadata": {}
            }
        
        # Use default session type if not provided
        session_type = session_type or "therapy"
        
        # Create unique session ID
        session_id = f"session-{uuid.uuid4()}"
        
        # Set up session parameters
        session_params = session_params or {}
        
        # Create session
        session = {
            "id": session_id,
            "twin_id": twin_id,
            "session_type": session_type,
            "therapist_id": therapist_id,
            "patient_id": patient_id or self._digital_twins[twin_id].get("patient_id"),
            "start_time": datetime.now(UTC).isoformat(),
            "end_time": None,
            "status": "active",
            "messages": [],
            "params": session_params,
            "metadata": {
                "creator": "mock_service",
                "created_at": datetime.now(UTC).isoformat()
            }
        }
        
        # Store session
        self._sessions[session_id] = session
        
        # Return session details
        return {
            "session_id": session_id,
            "twin_id": twin_id,
            "session_type": session_type,
            "status": "active",
            "start_time": session["start_time"],
            "message_count": 0
        }
    
    def get_digital_twin_session(self, session_id: str) -> dict[str, Any]:
        """
        Get information about a digital twin session.
        
        Args:
            session_id: ID of the session
            
        Returns:
            Dict containing session information
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If session ID is invalid
            ModelNotFoundError: If session not found
        """
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service is not initialized")
        
        # Validate session ID
        if not session_id or not isinstance(session_id, str):
            raise InvalidRequestError("Invalid session ID")
        
        # Check if session exists
        if session_id not in self._sessions:
            raise InvalidRequestError(f"Session not found: {session_id}")
        
        # Get session
        session = self._sessions[session_id]
        
        # Return session info (including messages)
        result = {
            "session_id": session_id,
            "twin_id": session["twin_id"],
            "therapist_id": session.get("therapist_id"),
            "patient_id": session.get("patient_id"),
            "session_type": session["session_type"],
            "status": session["status"],
            "start_time": session["start_time"],
            "end_time": session.get("end_time"),
            "message_count": len(session["messages"]),
            "messages": session["messages"],
            "params": session.get("params", {})
        }
        
        return result
    
    def send_message_to_session(
        self,
        session_id: str,
        message: str,
        sender_type: str | None = None,
        sender_id: str | None = None,
        message_params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Send a message to a digital twin session.
        
        Args:
            session_id: ID of the session
            message: Message content
            sender_type: Type of sender (user, therapist, system)
            sender_id: ID of the sender
            message_params: Additional message parameters
            
        Returns:
            Dict containing message information and digital twin's response
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If request is invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service is not initialized")
        
        # Validate session ID and message
        if not session_id or not isinstance(session_id, str):
            raise InvalidRequestError("Invalid session ID")
        if not message or not isinstance(message, str):
            raise InvalidRequestError("Message must be a non-empty string")
        
        # Set default sender type
        sender_type = sender_type or "user"
        
        # Check if session exists
        if session_id not in self._sessions:
            raise InvalidRequestError(f"Session not found: {session_id}")
        
        # Get session
        session = self._sessions[session_id]
        
        # Check if session is active
        if session["status"] != "active":
            raise InvalidRequestError(f"Session is not active: {session_id}")
        
        # Create message
        message_id = f"msg-{uuid.uuid4()}"
        message_obj = {
            "id": message_id,
            "session_id": session_id,
            "content": message,
            "sender_type": sender_type,
            "sender_id": sender_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "params": message_params or {}
        }
        
        # Add message to session
        session["messages"].append(message_obj)
        
        # Generate digital twin response
        dt_message_id = f"msg-{uuid.uuid4()}"
        dt_response = self._generate_dt_response(message, session["session_type"])
        dt_message = {
            "id": dt_message_id,
            "session_id": session_id,
            "content": dt_response,
            "sender_type": "digital_twin",
            "sender_id": f"dt-{session.get('patient_id', 'anonymous')}",
            "timestamp": datetime.now(UTC).isoformat(),
            "params": {}
        }
        
        # Add digital twin response to session
        session["messages"].append(dt_message)
        
        # Return response
        result = {
            "message": message_obj,
            "response": dt_message,
            "session_status": session["status"],
            "messages": session["messages"]
        }
        
        return result
    
    def _generate_dt_response(self, message: str, session_type: str) -> str:
        """
        Generate a mock Digital Twin response based on message and session type.
        
        Args:
            message: The message to respond to
            session_type: Type of session (therapy, assessment, coaching)
            
        Returns:
            Generated response
        """
        # Simple responses based on session type
        if session_type == "therapy":
            responses = [
                "I understand what you're saying. Can you tell me more about how that made you feel?",
                "That sounds challenging. How have you been coping with these feelings?",
                "I'm hearing that this has been difficult for you. What support do you feel would be most helpful right now?",
                "It's common to feel that way in such situations. Have you noticed any patterns in when these feelings arise?",
                "Thank you for sharing that with me. Let's explore some coping strategies that might help in these moments."
            ]
        elif session_type == "assessment":
            responses = [
                "I'd like to understand your experience better. On a scale of 1-10, how would you rate the intensity of what you're describing?",
                "Could you share more about how frequently you've been experiencing this?",
                "I'm gathering important information to help understand your situation. When did you first notice these symptoms?",
                "How has this been affecting your daily functioning, such as work, relationships, or self-care?",
                "Have you noticed any factors that seem to improve or worsen these experiences?"
            ]
        elif session_type == "coaching":
            responses = [
                "Let's focus on what specific goal you'd like to work toward based on what you've shared.",
                "What one small step could you take this week to address this situation?",
                "I hear your concern. Let's break this down into manageable actions you can take.",
                "That's an important insight. How might you apply this awareness to your current challenges?",
                "Let's identify what resources or support would help you move forward with this goal."
            ]
        else:  # Default responses
            responses = [
                "Thank you for sharing that with me. Could you tell me more?",
                "I appreciate your openness. Let's explore this further.",
                "That's helpful information. How does this affect your daily life?",
                "I understand. What would be most helpful for us to focus on today?",
                "I'm here to support you. What would you like to discuss next?"
            ]
        
        # Return random response
        return random.choice(responses)
    
    def end_digital_twin_session(
        self,
        session_id: str,
        end_reason: str | None = None
    ) -> dict[str, Any]:
        """
        End a digital twin session.
        
        Args:
            session_id: ID of the session
            end_reason: Reason for ending the session
            
        Returns:
            Session summary
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If session ID is invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("MentaLLaMA service is not initialized")
        
        # Validate session ID
        if not session_id or not isinstance(session_id, str):
            raise InvalidRequestError("Invalid session ID")
        
        # Check if session exists
        if session_id not in self._sessions:
            raise InvalidRequestError(f"Session not found: {session_id}")
        
        # Get session
        session = self._sessions[session_id]
        
        # Check if session is already ended
        if session["status"] != "active":
            return {
                "session_id": session_id,
                "status": session["status"],
                "message": f"Session already in {session['status']} state",
                "summary": self._generate_session_summary(session)
            }
        
        # Set session end time and status
        session["end_time"] = datetime.now(UTC).isoformat()
        session["status"] = "completed"
        session["end_reason"] = end_reason or "completed_normally"
        
        # Generate session summary
        summary = self._generate_session_summary(session)
        
        # Update session in store
        self._sessions[session_id] = session
        
        # Return session summary
        return {
            "session_id": session_id,
            "twin_id": session["twin_id"],
            "status": "completed",
            "message_count": len(session["messages"]),
            "start_time": session["start_time"],
            "end_time": session["end_time"],
            "duration_seconds": random.randint(300, 3600),  # Mock duration between 5-60 minutes
            "summary": summary
        }
    
    def _generate_session_summary(self, session: dict[str, Any]) -> dict[str, Any]:
        """
        Generate a mock session summary.
        
        Args:
            session: The session to generate a summary for
            
        Returns:
            Generated session summary
        """
        # Extract basic session info
        session_type = session.get("session_type", "therapy")
        message_count = len(session.get("messages", []))
        duration_seconds = 0
        
        # Calculate session duration if timestamps are available
        if "created_at" in session and "ended_at" in session:
            try:
                start_time = datetime.fromisoformat(session["created_at"].replace("Z", "+00:00"))
                end_time = datetime.fromisoformat(session["ended_at"].replace("Z", "+00:00"))
                duration_seconds = (end_time - start_time).total_seconds()
            except (ValueError, TypeError):
                duration_seconds = random.randint(900, 3600)  # Fallback: 15-60 minutes
        else:
            duration_seconds = random.randint(900, 3600)  # Fallback: 15-60 minutes
        
        # Generate appropriate summary based on session type
        if session_type == "therapy":
            themes = [
                "anxiety about work performance",
                "relationship difficulties",
                "sleep disruption",
                "feelings of inadequacy",
                "social withdrawal"
            ]
            # Select 1-3 random themes
            selected_themes = random.sample(themes, min(len(themes), random.randint(1, 3)))
            
            summary = {
                "key_themes": selected_themes,
                "emotional_patterns": {
                    "primary_emotions": ["anxiety", "sadness"],
                    "emotional_volatility": "moderate",
                    "emotional_awareness": "good"
                },
                "therapeutic_insights": [
                    "Client shows good engagement and self-reflection",
                    "Cognitive restructuring techniques may be beneficial",
                    "Sleep hygiene interventions recommended"
                ],
                "progress_indicators": {
                    "engagement": random.uniform(0.7, 0.9),
                    "insight_development": random.uniform(0.5, 0.8),
                    "coping_skills_application": random.uniform(0.4, 0.7)
                },
                "suggested_focus_areas": [
                    "Develop structured sleep routine",
                    "Practice cognitive reframing techniques",
                    "Gradual increase in social activities"
                ]
            }
            
        elif session_type == "assessment":
            summary = {
                "assessment_areas": [
                    "emotional functioning",
                    "cognitive patterns",
                    "behavioral tendencies",
                    "social support",
                    "coping mechanisms"
                ],
                "provisional_impressions": {
                    "possible_conditions": ["Moderate Anxiety", "Mild Depression"],
                    "confidence": "moderate",
                    "differential_considerations": ["Adjustment Disorder", "Sleep Disorder"]
                },
                "risk_factors": {
                    "suicide_risk": "low",
                    "self_harm_risk": "low",
                    "harm_to_others_risk": "not detected"
                },
                "recommended_assessments": [
                    "PHQ-9",
                    "GAD-7",
                    "Sleep Quality Assessment"
                ],
                "treatment_considerations": [
                    "CBT might be beneficial for identified thought patterns",
                    "Sleep hygiene protocol recommended",
                    "Consider supportive therapy focused on building coping skills"
                ]
            }
            
        elif session_type == "coaching":
            summary = {
                "focus_areas": [
                    "work-life balance",
                    "stress management",
                    "communication skills"
                ],
                "goals_identified": [
                    "Establish consistent sleep schedule",
                    "Develop assertive communication strategies",
                    "Implement daily mindfulness practice"
                ],
                "strengths_leveraged": [
                    "Self-awareness",
                    "Commitment to personal growth",
                    "Problem-solving abilities"
                ],
                "action_steps": [
                    "Create evening wind-down routine",
                    "Practice 'I' statements in challenging conversations",
                    "Start with 5-minute daily meditation"
                ],
                "progress_metrics": {
                    "goal_clarity": random.uniform(0.7, 0.9),
                    "action_plan_development": random.uniform(0.6, 0.8),
                    "commitment_level": random.uniform(0.7, 0.95)
                }
            }
            
        else:  # Default summary
            summary = {
                "key_points": [
                    "Exploration of current challenges",
                    "Discussion of coping strategies",
                    "Identification of support resources"
                ],
                "engagement_level": "good",
                "notable_patterns": [
                    "Self-reflective communication style",
                    "Focus on practical solutions",
                    "Openness to feedback and suggestions"
                ],
                "follow_up_considerations": [
                    "Continue exploring identified themes",
                    "Develop more specific action plans",
                    "Monitor progress on implemented strategies"
                ]
            }
        
        # Add general metrics
        summary["session_metrics"] = {
            "message_count": message_count,
            "average_response_time_seconds": random.uniform(2.5, 5.0),
            "engagement_score": random.uniform(0.7, 0.9),
            "session_duration_minutes": int(duration_seconds / 60)
        }
        
        return summary
    
    def get_session_insights(
        self,
        session_id: str,
        insight_type: str | None = None
    ) -> dict[str, Any]:
        """
        Get insights from a Digital Twin session.
        
        Args:
            session_id: ID of the session
            insight_type: Type of insights to retrieve
            
        Returns:
            Dict containing session insights
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If session ID is invalid
            ModelNotFoundError: If session not found
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock MentaLLaMA service is not initialized")
        
        if not session_id or not isinstance(session_id, str):
            raise InvalidRequestError("Session ID must be a non-empty string")
        
        # Get session
        session = self._sessions.get(session_id)
        if not session:
            raise ModelNotFoundError(f"Session not found: {session_id}")
        
        # Generate insights based on session and insight type
        insights = {}
        
        # Basic insights (always included)
        insights["session_id"] = session_id
        insights["generated_at"] = datetime.now(UTC).isoformat() + "Z"
        insights["session_type"] = session.get("session_type", "therapy")
        insights["message_count"] = len(session.get("messages", []))
        insights["session_status"] = session.get("status", "unknown")
        
        # Add specific insights based on type
        insights["insights"] = {
            "themes": [],
            "recommendations": []
        }
        
        # Linguistic insights
        if not insight_type or insight_type == "linguistic":
            linguistic_insight = {
                "type": "linguistic",
                "data": {
                    "emotional_tone": "primarily anxious with elements of sadness",
                    "communication_style": "reflective and detail-oriented",
                    "narrative_themes": [
                        "work-related stress",
                        "interpersonal difficulties",
                        "sleep disturbances"
                    ],
                    "language_complexity": "moderate to high",
                    "self_references": "frequent negative self-evaluation"
                },
                "timestamp": datetime.now(UTC).isoformat() + "Z",
                "confidence": 0.82
            }
            insights["insights"]["themes"].append(linguistic_insight)
        
        # Clinical insights
        if not insight_type or insight_type == "clinical":
            clinical_insight = {
                "type": "clinical",
                "data": {
                    "symptom_patterns": {
                        "anxiety": {
                            "severity": "moderate",
                            "confidence": 0.82,
                            "evidence": ["excessive worry", "difficulty concentrating", "sleep disturbance"]
                        },
                        "depression": {
                            "severity": "mild",
                            "confidence": 0.68,
                            "evidence": ["low mood", "reduced interest", "fatigue"]
                        }
                    },
                    "risk_assessment": {
                        "self_harm": "low",
                        "suicide": "low",
                        "harm_to_others": "not detected"
                    },
                    "functional_impact": {
                        "work": "moderate",
                        "relationships": "moderate",
                        "self_care": "mild"
                    },
                    "treatment_implications": [
                        "CBT techniques for anxiety management",
                        "Sleep hygiene protocol",
                        "Mindfulness-based stress reduction"
                    ]
                },
                "timestamp": datetime.now(UTC).isoformat() + "Z",
                "confidence": 0.78
            }
            insights["insights"]["recommendations"].append(clinical_insight)
        
        # Therapeutic insights
        if not insight_type or insight_type == "therapeutic":
            therapeutic_insight = {
                "type": "therapeutic",
                "data": {
                    "rapport": {
                        "quality": "good",
                        "development": "progressive improvement through session"
                    },
                    "response_to_interventions": {
                        "cognitive_techniques": "positive engagement",
                        "behavioral_suggestions": "receptive but hesitant",
                        "emotional_processing": "moderate depth"
                    },
                    "resistance_patterns": [
                        "some avoidance of difficult emotions",
                        "occasional minimization of challenges"
                    ],
                    "readiness_for_change": {
                        "awareness": "high",
                        "motivation": "moderate",
                        "self_efficacy": "variable"
                    },
                    "therapeutic_alliance_strength": 0.76
                },
                "timestamp": datetime.now(UTC).isoformat() + "Z",
                "confidence": 0.76
            }
            insights["insights"]["themes"].append(therapeutic_insight)
        
        # Progress insights
        if not insight_type or insight_type == "progress":
            progress_insight = {
                "type": "progress",
                "data": {
                    "symptom_change": {
                        "anxiety": "slight improvement",
                        "mood": "stabilizing",
                        "sleep": "beginning to implement recommendations"
                    },
                    "skill_development": {
                        "emotion_regulation": "early progress",
                        "cognitive_restructuring": "increasing awareness",
                        "communication": "practicing new strategies"
                    },
                    "goal_progress": [
                        {"goal": "Improve sleep quality", "status": "initial steps taken", "progress": 0.3},
                        {"goal": "Reduce workplace anxiety", "status": "implementing techniques", "progress": 0.45},
                        {"goal": "Enhance self-care routine", "status": "plan developed", "progress": 0.25}
                    ],
                    "overall_trajectory": "positive with expected fluctuations"
                },
                "timestamp": datetime.now(UTC).isoformat() + "Z",
                "confidence": 0.71
            }
            insights["insights"]["recommendations"].append(progress_insight)
        
        return insights


class MockPHIDetection(PHIDetectionInterface):
    """
    Mock PHI detection implementation.
    
    This class provides a mock implementation of PHI detection services for testing.
    It simulates the detection and redaction of Protected Health Information (PHI)
    to support HIPAA compliance testing.
    """
    
    def __init__(self) -> None:
        """Initialize MockPHIDetection instance."""
        self._initialized = False
        self._config = None
        self.PHI_PATTERNS = [
            ("NAME", re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")),
            ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
            ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
            ("PHONE", re.compile(r"\(\d{3}\) \d{3}-\d{4}\b|\b\d{3}-\d{3}-\d{4}\b")),
            ("ADDRESS", re.compile(r"\b\d+ [A-Z][a-z]+ (Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b")),
            ("DATE", re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b|\b\d{1,2}-\d{1,2}-\d{2,4}\b|\b[A-Z][a-z]{2,8} \d{1,2}, \d{4}\b")),
        ]
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            self._config = config or {}
            self._initialized = True
            logger.info("Mock PHI detection service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize mock PHI detection service: {e!s}")
            self._initialized = False
            self._config = None
            raise InvalidConfigurationError(f"Failed to initialize mock PHI detection service: {e!s}")
    
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        return self._initialized
    
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        logger.info("Mock PHI detection service shut down")
    
    def detect_phi(
        self,
        text: str,
        detection_level: str | None = None
    ) -> dict[str, Any]:
        """
        Detect PHI in text.
        
        Args:
            text: Text to analyze
            detection_level: Detection level (strict, moderate, relaxed)
            
        Returns:
            Dict containing detection results with PHI locations and types
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock PHI detection service is not initialized")
        if not text or not isinstance(text, str):
            return {
                "phi_instances": [],
                "confidence_score": 0.0,
                "has_phi": False,
                "detection_level": detection_level or "strict",
                "model": "mock-phi-detection",
                "analysis_time_ms": 1,
                "timestamp": datetime.now(UTC).isoformat() + "Z"
            }
        phi_instances = []
        for phi_type, pattern in self.PHI_PATTERNS:
            for match in pattern.finditer(text):
                phi_instances.append({
                    "type": phi_type,
                    "text": match.group(0),
                    "start_pos": match.start(),
                    "end_pos": match.end(),
                    "confidence": 0.99 if phi_type != "DATE" else 0.98
                })
        has_phi = len(phi_instances) > 0
        confidence_score = 0.0
        if has_phi:
            confidence_score = 0.95
        elif text.strip():
            confidence_score = 0.1
        return {
            "phi_instances": phi_instances,
            "confidence_score": confidence_score,
            "has_phi": has_phi,
            "detection_level": detection_level or "strict",
            "model": "mock-phi-detection",
            "analysis_time_ms": 1,
            "timestamp": datetime.now(UTC).isoformat() + "Z"
        }
    
    def redact_phi(
        self,
        text: str,
        replacement: str = "[REDACTED]",
        detection_level: str | None = None
    ) -> dict[str, Any]:
        """
        Redact PHI from text.
        
        Args:
            text: Text to redact
            replacement: Replacement text for redacted PHI
            detection_level: Detection level (strict, moderate, relaxed)
            
        Returns:
            Dict containing redacted text and metadata
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock PHI detection service is not initialized")
        if not text or not isinstance(text, str):
            return {
                "original_length": 0,
                "redacted_length": 0,
                "redacted_text": "",
                "redaction_count": 0,
                "redacted_types": [],
                "detection_level": detection_level or "strict",
                "replacement_used": replacement,
                "timestamp": datetime.now(UTC).isoformat() + "Z"
            }
        detection_result = self.detect_phi(text, detection_level)
        redacted_text = text
        redaction_count = 0
        redacted_types = set()
        # Sort matches by start_pos descending to avoid offset issues
        matches = sorted(detection_result["phi_instances"], key=lambda m: m["start_pos"], reverse=True)
        for match in matches:
            start, end = match["start_pos"], match["end_pos"]
            redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
            redaction_count += 1
            redacted_types.add(match["type"])
        return {
            "original_length": len(text),
            "redacted_length": len(redacted_text),
            "redacted_text": redacted_text,
            "redaction_count": redaction_count,
            "redacted_types": list(redacted_types),
            "detection_level": detection_result["detection_level"],
            "replacement_used": replacement,
            "timestamp": datetime.now(UTC).isoformat() + "Z"
        }