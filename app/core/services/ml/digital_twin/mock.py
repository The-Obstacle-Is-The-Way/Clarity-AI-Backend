"""
Mock Digital Twin Implementation.

This module provides a mock implementation of Digital Twin services for development and testing.
No actual patient simulation is performed; instead, predefined responses are returned.
"""

import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError,
)
from app.core.services.ml.interface import DigitalTwinInterface  # Corrected interface name
from app.core.utils.logging import get_logger
from app.domain.utils.datetime_utils import UTC

# Create logger (no PHI logging)
logger = get_logger(__name__)


class MockDigitalTwinService(DigitalTwinInterface): # Corrected base class
    """
    Mock implementation of Digital Twin service.
    
    This implementation simulates a Digital Twin without any actual modeling,
    returning predefined responses for development and testing.
    """
    
    def __init__(self) -> None:
        """Initialize MockDigitalTwinService instance."""
        self._initialized = False
        self._config = None
        self._patient_sessions = {}
    
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            if not config or not isinstance(config, dict):
                raise InvalidConfigurationError("Invalid configuration: must be a non-empty dictionary")
            
            self._config = config
            self._initialized = True
            logger.info("Mock Digital Twin service initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize mock Digital Twin service: {e!s}")
            self._initialized = False
            self._config = None
            raise InvalidConfigurationError(f"Failed to initialize mock Digital Twin service: {e!s}")
    
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
        self._patient_sessions = {}
        logger.info("Mock Digital Twin service shut down")
    
    def create_session(
        self,
        patient_id: str,
        context: dict[str, Any] | None = None,
        **kwargs
    ) -> dict[str, Any]:
        """
        Create a new Digital Twin session.
        
        Args:
            patient_id: Patient ID
            context: Optional context for the session
            **kwargs: Additional parameters
            
        Returns:
            Dict containing session information
            
        Raises:
            ServiceUnavailableError: If service is not initialized
        """
        if not self._initialized:
            raise ServiceUnavailableError("Digital Twin service is not initialized")
        
        logger.info(f"Creating mock Digital Twin session for patient {patient_id}")
        
        # Simulate processing time
        start_time = time.time()
        # processing_delay = random.uniform(0.1, 0.3) # Reduced delay
        # time.sleep(processing_delay) # Remove blocking sleep
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Create session
        session = {
            "session_id": session_id,
            "patient_id": patient_id,
            "created_at": datetime.now(UTC).isoformat() + "Z",
            "expires_at": (datetime.now(UTC) + timedelta(hours=24)).isoformat() + "Z",
            "context": context or {},
            "history": [],
            "metadata": {
                "provider": "mock",
                "mock": True,
            }
        }
        
        # Store session
        self._patient_sessions[session_id] = session
        
        # Calculate processing time
        elapsed = time.time() - start_time
        
        # Create result
        result = {
            "session_id": session_id,
            "patient_id": patient_id,
            "created_at": session["created_at"],
            "expires_at": session["expires_at"],
            "processing_time": elapsed,
            "metadata": session["metadata"]
        }
        
        return result
    
    def get_session(
        self,
        session_id: str,
        **kwargs
    ) -> dict[str, Any]:
        """
        Get Digital Twin session information.
        
        Args:
            session_id: Session ID
            **kwargs: Additional parameters
            
        Returns:
            Dict containing session information
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If session does not exist
        """
        if not self._initialized:
            raise ServiceUnavailableError("Digital Twin service is not initialized")
        
        logger.info(f"Getting mock Digital Twin session {session_id}")
        
        # Check if session exists
        if session_id not in self._patient_sessions:
            # Create a new session with a random patient ID if not found
            # This is just for mocking purposes
            patient_id = f"mock-patient-{random.randint(1000, 9999)}"
            session = self.create_session(patient_id)
            session_id = session["session_id"]
        
        # Get session
        session = self._patient_sessions[session_id]
        
        # Create result
        result = {
            "session_id": session_id,
            "patient_id": session["patient_id"],
            "created_at": session["created_at"],
            "expires_at": session["expires_at"],
            "history": session.get("history", []),
            "context": session.get("context", {}),
            "metadata": session["metadata"]
        }
        
        return result
    
    def send_message(
        self,
        session_id: str,
        message: str,
        **kwargs
    ) -> dict[str, Any]:
        """
        Send a message to the Digital Twin.
        
        Args:
            session_id: Session ID
            message: Message to send
            **kwargs: Additional parameters
            
        Returns:
            Dict containing Digital Twin response
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If session does not exist
        """
        if not self._initialized:
            raise ServiceUnavailableError("Digital Twin service is not initialized")
        
        # Don't log the message content as it might contain PHI
        logger.info(f"Sending message to mock Digital Twin session {session_id}")
        
        # Check if session exists
        if session_id not in self._patient_sessions:
            # Create a new session with a random patient ID if not found
            # This is just for mocking purposes
            patient_id = f"mock-patient-{random.randint(1000, 9999)}"
            session = self.create_session(patient_id)
            session_id = session["session_id"]
        
        # Get session
        session = self._patient_sessions[session_id]
        
        # Simulate processing time
        start_time = time.time()
        # processing_delay = random.uniform(0.1, 0.5) # Reduced delay
        # time.sleep(processing_delay) # Remove blocking sleep
        
        # Determine response based on message
        response = self._get_response_for_message(message, session)
        
        # Add to history
        timestamp = datetime.now(UTC).isoformat() + "Z"
        session["history"].append({
            "role": "user",
            "content": message,
            "timestamp": timestamp
        })
        session["history"].append({
            "role": "assistant",
            "content": response,
            "timestamp": timestamp
        })
        
        # Calculate processing time
        elapsed = time.time() - start_time
        
        # Create result
        result = {
            "session_id": session_id,
            "patient_id": session["patient_id"],
            "message": message,
            "response": response,
            "timestamp": timestamp,
            "processing_time": elapsed,
            "metadata": {
                "provider": "mock",
                "confidence": random.uniform(0.7, 0.95),
                "mood": random.choice(["neutral", "positive", "concerned", "professional"]),
                "mock": True,
            }
        }
        
        return result
    
    def _get_response_for_message(self, message: str, session: dict[str, Any]) -> str:
        """
        Get a response for a message based on its content.
        
        Args:
            message: Message to respond to
            session: Session information
            
        Returns:
            Response message
        """
        # Get patient ID for personalization
        patient_id = session.get("patient_id", "")
        
        # Simple keyword matching for common message types
        message_lower = message.lower()
        
        # Greeting
        if any(word in message_lower for word in ["hello", "hi", "hey", "greetings"]):
            return "Hello! I'm your digital twin health assistant. How can I help you today?"
        
        # How are you
        elif "how are you" in message_lower:
            return "I'm here to support you. More importantly, how are you feeling today?"
        
        # Medication
        elif any(word in message_lower for word in ["medication", "meds", "pills", "prescription"]):
            return "I understand you have a question about medication. It's important to follow your prescribed regimen. Have you been experiencing any side effects we should discuss with your doctor?"
        
        # Appointment
        elif any(word in message_lower for word in ["appointment", "schedule", "visit", "doctor"]):
            next_date = (datetime.now() + timedelta(days=random.randint(3, 14))).strftime("%A, %B %d")
            return f"Your next appointment is scheduled for {next_date} at 2:00 PM. Would you like me to remind you the day before?"
        
        # Symptoms
        elif any(word in message_lower for word in ["symptom", "feeling", "pain", "hurt", "sick"]):
            return "I'm sorry to hear you're not feeling well. Can you tell me more about your symptoms so I can help better?"
        
        # Wellness
        elif any(word in message_lower for word in ["wellness", "exercise", "diet", "sleep", "stress"]):
            return "Maintaining overall wellness is important for mental health. Have you been able to maintain your sleep schedule and exercise routine lately?"
        
        # Therapy
        elif any(word in message_lower for word in ["therapy", "therapist", "counseling", "counselor"]):
            return "Therapy can be a valuable part of your treatment plan. How have your recent therapy sessions been going?"
        
        # Default response
        else:
            responses = [
                "I understand. Can you tell me more about that?",
                "Thank you for sharing. How does that make you feel?",
                "I'm here to support you. What other concerns do you have?",
                "Let's discuss this further so I can better understand how to help.",
                "That's important information. How has this been affecting your daily life?"
            ]
            return random.choice(responses)
    
    def end_session(
        self,
        session_id: str,
        **kwargs
    ) -> dict[str, Any]:
        """
        End a Digital Twin session.
        
        Args:
            session_id: Session ID
            **kwargs: Additional parameters
            
        Returns:
            Dict containing session end confirmation
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If session does not exist
        """
        if not self._initialized:
            raise ServiceUnavailableError("Digital Twin service is not initialized")
        
        logger.info(f"Ending mock Digital Twin session {session_id}")
        
        # Check if session exists
        if session_id not in self._patient_sessions:
            logger.warning(f"Attempted to end non-existent session: {session_id}")
            raise InvalidRequestError(f"Session {session_id} does not exist")
        
        # Get session
        session = self._patient_sessions[session_id]
        
        # Remove session
        del self._patient_sessions[session_id]
        
        # Create result
        result = {
            "session_id": session_id,
            "patient_id": session["patient_id"],
            "ended_at": datetime.now(UTC).isoformat() + "Z",
            "metadata": {
                "provider": "mock",
                "status": "ended",
                "mock": True,
            }
        }
        
        return result
    
    def get_insights(
        self,
        patient_id: str,
        insight_type: str | None = None,
        time_period: str | None = None,
        **kwargs
    ) -> dict[str, Any]:
        """
        Get Digital Twin insights for a patient.
        
        Args:
            patient_id: Patient ID
            insight_type: Optional type of insights to retrieve
            time_period: Optional time period for insights
            **kwargs: Additional parameters
            
        Returns:
            Dict containing Digital Twin insights
            
        Raises:
            ServiceUnavailableError: If service is not initialized
        """
        if not self._initialized:
            raise ServiceUnavailableError("Digital Twin service is not initialized")
        
        logger.info(f"Getting mock Digital Twin insights for patient {patient_id}")
        
        # Simulate processing time
        start_time = time.time()
        # processing_delay = random.uniform(0.5, 1.5)
        # time.sleep(processing_delay) # Remove blocking sleep
        
        # Default insights
        insights = {}
        
        # Generate insights based on type
        if not insight_type or insight_type == "all":
            insights = self._generate_all_insights(patient_id, time_period)
        elif insight_type == "mood":
            insights = self._generate_mood_insights(patient_id, time_period)
        elif insight_type == "activity":
            insights = self._generate_activity_insights(patient_id, time_period)
        elif insight_type == "sleep":
            insights = self._generate_sleep_insights(patient_id, time_period)
        elif insight_type == "medication":
            insights = self._generate_medication_insights(patient_id, time_period)
        elif insight_type == "treatment":
            insights = self._generate_treatment_insights(patient_id, time_period)
        else:
            insights = self._generate_default_insights(patient_id, time_period)
        
        # Calculate processing time
        elapsed = time.time() - start_time
        
        # Create result
        result = {
            "patient_id": patient_id,
            "insight_type": insight_type or "all",
            "time_period": time_period or "last_30_days",
            "generated_at": datetime.now(UTC).isoformat() + "Z",
            "insights": insights,
            "processing_time": elapsed,
            "metadata": {
                "provider": "mock",
                "confidence": random.uniform(0.7, 0.95),
                "mock": True,
            }
        }
        
        return result
    
    def _generate_all_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate all types of insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing all insights
        """
        return {
            "mood": self._generate_mood_insights(patient_id, time_period)["data"],
            "activity": self._generate_activity_insights(patient_id, time_period)["data"],
            "sleep": self._generate_sleep_insights(patient_id, time_period)["data"],
            "medication": self._generate_medication_insights(patient_id, time_period)["data"],
            "treatment": self._generate_treatment_insights(patient_id, time_period)["data"],
            "summary": {
                "overall_status": random.choice(["stable", "improving", "needs_attention"]),
                "key_observations": [
                    "Patient shows consistent engagement with treatment plan",
                    "Sleep patterns have been improving over the past two weeks",
                    "Medication adherence remains high, but some side effects reported",
                    "Activity levels have decreased slightly in the past week"
                ],
                "recommendations": [
                    "Continue current medication regimen",
                    "Consider increasing physical activity",
                    "Schedule follow-up appointment in 2 weeks",
                    "Monitor sleep quality changes"
                ]
            }
        }
    
    def _generate_mood_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate mood insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing mood insights
        """
        days = 30 if not time_period or time_period == "last_30_days" else 7
        
        # Generate random mood data
        mood_data = []
        base_value = random.uniform(0.4, 0.7)
        
        for i in range(days):
            date = (datetime.now() - timedelta(days=days-i-1)).strftime("%Y-%m-%d")
            value = min(1.0, max(0.0, base_value + random.uniform(-0.15, 0.15)))
            base_value = value  # Slight correlation between days
            
            mood_data.append({
                "date": date,
                "value": round(value, 2),
                "label": self._map_mood_value_to_label(value)
            })
        
        # Calculate trends
        current_week_avg = sum(item["value"] for item in mood_data[-7:]) / 7
        prev_week_avg = sum(item["value"] for item in mood_data[-14:-7]) / 7
        change = round(current_week_avg - prev_week_avg, 2)
        
        return {
            "type": "mood",
            "data": {
                "daily_values": mood_data,
                "average": round(sum(item["value"] for item in mood_data) / len(mood_data), 2),
                "trend": {
                    "direction": "up" if change > 0.05 else "down" if change < -0.05 else "stable",
                    "change_percentage": round(change * 100, 1)
                },
                "observations": [
                    "Mood has been relatively stable over the period",
                    "Slight improvement noted in the past week",
                    "Mood correlates with reported activity levels"
                ]
            }
        }
    
    def _map_mood_value_to_label(self, value: float) -> str:
        """
        Map mood value to label.
        
        Args:
            value: Mood value (0.0-1.0)
            
        Returns:
            Mood label
        """
        if value < 0.2:
            return "very low"
        elif value < 0.4:
            return "low"
        elif value < 0.6:
            return "moderate"
        elif value < 0.8:
            return "good"
        else:
            return "very good"
    
    def _generate_activity_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate activity insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing activity insights
        """
        days = 30 if not time_period or time_period == "last_30_days" else 7
        
        # Generate random activity data
        activity_data = []
        base_value = random.uniform(30, 60)
        
        for i in range(days):
            date = (datetime.now() - timedelta(days=days-i-1)).strftime("%Y-%m-%d")
            value = max(0, base_value + random.uniform(-15, 15))
            base_value = value  # Slight correlation between days
            
            activity_data.append({
                "date": date,
                "value": round(value),
                "unit": "minutes"
            })
        
        # Calculate trends
        current_week_avg = sum(item["value"] for item in activity_data[-7:]) / 7
        prev_week_avg = sum(item["value"] for item in activity_data[-14:-7]) / 7
        change = round(current_week_avg - prev_week_avg, 2)
        
        return {
            "type": "activity",
            "data": {
                "daily_values": activity_data,
                "average": round(sum(item["value"] for item in activity_data) / len(activity_data), 2),
                "trend": {
                    "direction": "up" if change > 5 else "down" if change < -5 else "stable",
                    "change_percentage": round((change / prev_week_avg) * 100 if prev_week_avg > 0 else 0, 1)
                },
                "observations": [
                    "Activity levels have been consistent",
                    f"Average daily activity: {round(current_week_avg)} minutes",
                    "Activity correlates positively with mood metrics"
                ]
            }
        }
    
    def _generate_sleep_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate sleep insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing sleep insights
        """
        days = 30 if not time_period or time_period == "last_30_days" else 7
        
        # Generate random sleep data
        sleep_data = []
        base_hours = random.uniform(6, 8)
        
        for i in range(days):
            date = (datetime.now() - timedelta(days=days-i-1)).strftime("%Y-%m-%d")
            hours = max(3, min(10, base_hours + random.uniform(-1, 1)))
            base_hours = hours  # Slight correlation between days
            
            quality = random.uniform(0.3, 0.9)
            if hours < 5:
                quality = max(0.1, quality - 0.2)
            elif hours > 8:
                quality = min(1.0, quality + 0.2)
            
            sleep_data.append({
                "date": date,
                "hours": round(hours, 1),
                "quality": round(quality, 2),
                "quality_label": "good" if quality > 0.6 else "fair" if quality > 0.4 else "poor"
            })
        
        # Calculate trends
        current_week_avg = sum(item["hours"] for item in sleep_data[-7:]) / 7
        prev_week_avg = sum(item["hours"] for item in sleep_data[-14:-7]) / 7
        change = round(current_week_avg - prev_week_avg, 1)
        
        return {
            "type": "sleep",
            "data": {
                "daily_values": sleep_data,
                "average_hours": round(sum(item["hours"] for item in sleep_data) / len(sleep_data), 1),
                "average_quality": round(sum(item["quality"] for item in sleep_data) / len(sleep_data), 2),
                "trend": {
                    "direction": "up" if change > 0.5 else "down" if change < -0.5 else "stable",
                    "change_hours": change
                },
                "observations": [
                    f"Average sleep duration: {round(current_week_avg, 1)} hours per night",
                    "Sleep quality correlates with next-day mood",
                    "Weekend sleep patterns show improved quality"
                ]
            }
        }
    
    def _generate_medication_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate medication insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing medication insights
        """
        days = 30 if not time_period or time_period == "last_30_days" else 7
        
        # Generate random medication data
        adherence_data = []
        medications = ["Medication A", "Medication B"]
        
        for i in range(days):
            date = (datetime.now() - timedelta(days=days-i-1)).strftime("%Y-%m-%d")
            
            day_data = {
                "date": date,
                "medications": {}
            }
            
            for med in medications:
                adherence = random.random() > 0.1  # 90% adherence rate
                day_data["medications"][med] = {
                    "taken": adherence,
                    "scheduled_time": "08:00 AM" if med == "Medication A" else "08:00 PM",
                    "actual_time": "08:15 AM" if adherence and med == "Medication A" else "08:10 PM" if adherence else None
                }
            
            adherence_data.append(day_data)
        
        # Calculate overall adherence
        total_doses = len(medications) * days
        taken_doses = sum(
            1 for day in adherence_data 
            for med, data in day["medications"].items() 
            if data["taken"]
        )
        adherence_rate = round((taken_doses / total_doses) * 100, 1)
        
        return {
            "type": "medication",
            "data": {
                "daily_values": adherence_data,
                "adherence_rate": adherence_rate,
                "adherence_label": "excellent" if adherence_rate >= 90 else "good" if adherence_rate >= 80 else "needs improvement",
                "reported_side_effects": [
                    {
                        "medication": "Medication A",
                        "effects": ["Mild drowsiness", "Dry mouth"],
                        "severity": "mild"
                    }
                ],
                "observations": [
                    f"Overall medication adherence rate: {adherence_rate}%",
                    "Morning dose more consistently taken than evening dose",
                    "Side effects appear to be mild and tolerable"
                ]
            }
        }
    
    def _generate_treatment_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate treatment insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing treatment insights
        """
        # Generate random treatment data
        engagement_score = random.uniform(0.7, 0.95)
        
        return {
            "type": "treatment",
            "data": {
                "engagement_score": round(engagement_score, 2),
                "engagement_label": "high" if engagement_score > 0.8 else "moderate",
                "completed_tasks": random.randint(5, 10),
                "total_tasks": 12,
                "appointments": [
                    {
                        "date": (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d"),
                        "type": "Psychiatrist",
                        "attended": True
                    },
                    {
                        "date": (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"),
                        "type": "Therapist",
                        "attended": True
                    },
                    {
                        "date": (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d"),
                        "type": "Psychiatrist",
                        "attended": None
                    }
                ],
                "treatment_modules": [
                    {
                        "name": "CBT Module 1",
                        "completion": 100,
                        "feedback_score": 4.5
                    },
                    {
                        "name": "CBT Module 2",
                        "completion": 75,
                        "feedback_score": 4.2
                    },
                    {
                        "name": "Mindfulness",
                        "completion": 50,
                        "feedback_score": 4.0
                    }
                ],
                "observations": [
                    "Consistent engagement with treatment plan",
                    "All scheduled appointments attended",
                    "Good progress in CBT modules",
                    "Positive feedback on treatment efficacy"
                ]
            }
        }
    
    def _generate_default_insights(self, patient_id: str, time_period: str | None = None) -> dict[str, Any]:
        """
        Generate default insights.
        
        Args:
            patient_id: Patient ID
            time_period: Optional time period for insights
            
        Returns:
            Dict containing default insights
        """
        return {
            "summary": {
                "overall_status": random.choice(["stable", "improving", "needs_attention"]),
                "observations": [
                    "Patient shows consistent engagement with treatment plan",
                    "Regular attendance at scheduled appointments",
                    "Mood has been relatively stable"
                ],
                "recommendations": [
                    "Continue current treatment plan",
                    "Schedule follow-up appointment",
                    "Consider additional support resources"
                ]
            }
        }