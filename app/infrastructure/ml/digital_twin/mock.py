"""
Mock Digital Twin Service Implementation.

This module provides a mock implementation of the Digital Twin service
for development and testing purposes.
"""

import datetime
import uuid
from typing import Any

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from app.core.services.ml.interface import DigitalTwinInterface
from app.core.utils.logging import get_logger
from app.domain.utils.datetime_utils import UTC, format_iso8601, now_utc

logger = get_logger(__name__)

class MockDigitalTwinService(DigitalTwinInterface):
    """
    Mock implementation of the Digital Twin service.
    Simulates twin creation, status checks, updates, insights, and interactions.
    """

    def __init__(self) -> None:
        """Initialize the mock service."""
        self._initialized = False
        self._config: dict[str, Any] = {}
        self._twins: dict[str, dict[str, Any]] = {}  # Store mock twin data
        self._sessions: dict[str, dict[str, Any]] = {}  # Store mock sessions

    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the mock service with configuration.

        Args:
            config: Configuration dictionary (can be empty for mock).
        """
        # Validate configuration parameters
        if config is None:
            config = {}
        if "response_style" in config and not isinstance(config["response_style"], str):
            raise InvalidConfigurationError("response_style must be a string.")
        if "session_duration_minutes" in config and not isinstance(config["session_duration_minutes"], (int, float)):
            raise InvalidConfigurationError("session_duration_minutes must be a number.")
        try:
            self._config = config
            self._initialized = True
            logger.info("Mock Digital Twin service initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize mock Digital Twin service: {e}", exc_info=True)
            self._initialized = False
            raise InvalidConfigurationError(f"Failed to initialize mock Digital Twin service: {e}")

    def is_healthy(self) -> bool:
        """Check if the service is healthy."""
        return self._initialized

    def shutdown(self) -> None:
        """Shutdown the mock service."""
        self._initialized = False
        self._twins.clear()
        logger.info("Mock Digital Twin service shut down.")

    def create_digital_twin(self, initial_data: dict[str, Any]) -> dict[str, Any]:
        """
        Mock creation of a new digital twin for a patient.

        Args:
            patient_id: The ID of the patient.
            initial_data: Initial data to populate the twin.

        Returns:
            A dictionary containing the status and ID of the created twin.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        if not isinstance(initial_data, dict) or not initial_data.get("patient_id"):
            raise InvalidRequestError("Initial data must include 'patient_id'.")
        patient_id = initial_data["patient_id"]

        twin_id = f"mock_twin_{uuid.uuid4()}"
        self._twins[twin_id] = {
            "patient_id": patient_id,
            "status": "active",
            "data": initial_data,
            "insights_cache": {},
            "interaction_history": []
        }
        logger.info(f"Mock digital twin created for patient {patient_id} with ID {twin_id}")
        return {"twin_id": twin_id, "status": "created"}

    def get_twin_status(self, twin_id: str) -> dict[str, Any]:
        """
        Get the mock status of a digital twin.

        Args:
            twin_id: The ID of the digital twin.

        Returns:
            A dictionary containing the status information.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")

        twin = self._twins.get(twin_id)
        if not twin:
            raise ResourceNotFoundError(f"Mock digital twin with ID {twin_id} not found.")

        return {"twin_id": twin_id, "status": twin.get("status", "unknown"), "patient_id": twin.get("patient_id")}

    def update_twin_data(self, twin_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        Mock update of the data associated with a digital twin.

        Args:
            twin_id: The ID of the digital twin.
            data: The data to update.

        Returns:
            A dictionary confirming the update status.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        if not data:
            raise InvalidRequestError("Update data cannot be empty.")

        twin = self._twins.get(twin_id)
        if not twin:
            raise ResourceNotFoundError(f"Mock digital twin with ID {twin_id} not found.")

        twin["data"].update(data)
        # Invalidate cache on update
        twin["insights_cache"] = {}
        logger.info(f"Mock digital twin data updated for twin ID {twin_id}")
        return {"twin_id": twin_id, "status": "updated"}
    
    def create_session(self, twin_id: str, session_type: str) -> dict[str, Any]:
        """
        Create a new therapy session for a digital twin.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        if twin_id not in self._twins:
            raise ResourceNotFoundError(f"Mock digital twin with ID {twin_id} not found.")

        session_id = f"mock_session_{uuid.uuid4()}"
        start_time = format_iso8601(now_utc())
        session = {
            "session_id": session_id,
            "twin_id": twin_id,
            "session_type": session_type,
            "start_time": start_time,
            "status": "active",
            "messages": []
        }
        self._sessions[session_id] = session
        return {
            "session_id": session_id,
            "twin_id": twin_id,
            "session_type": session_type,
            "start_time": start_time,
            "status": "active"
        }
    
    def get_session(self, session_id: str) -> dict[str, Any]:
        """
        Retrieve an existing session by ID.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        session = self._sessions.get(session_id)
        if not session:
            raise ResourceNotFoundError(f"Session with ID {session_id} not found.")
        return session.copy()
    
    def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        """
        Send a user message to the session and generate a mock twin response.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        session = self._sessions.get(session_id)
        if not session:
            raise ResourceNotFoundError(f"Session with ID {session_id} not found.")

        # Append user message
        session["messages"].append({"content": message, "sender": "user"})
        # Determine topic
        msg_lower = message.lower()
        if "hopeless" in msg_lower:
            topic = "depression"
        elif "worried" in msg_lower:
            topic = "anxiety"
        elif "medication" in msg_lower:
            topic = "medication"
        elif "sleep" in msg_lower:
            topic = "sleep"
        elif "walk" in msg_lower or "exercise" in msg_lower:
            topic = "exercise"
        else:
            topic = "general"

        response_text = f"Mock response relevant to {topic}"
        # Append twin response
        session["messages"].append({"content": response_text, "sender": "twin"})
        return {"response": response_text, "messages": session["messages"].copy()}
    
    def end_session(self, session_id: str) -> dict[str, Any]:
        """
        End an active session, mark as completed, and return summary.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        session = self._sessions.get(session_id)
        if not session:
            raise ResourceNotFoundError(f"Session with ID {session_id} not found.")

        # Compute duration
        start_time_str = session["start_time"]
        start_dt = datetime.datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
        duration_delta = datetime.datetime.now(UTC) - start_dt
        duration_minutes = int(duration_delta.total_seconds() / 60)

        # Mark completed
        session["status"] = "completed"
        summary = f"Session completed with {len(session['messages'])} messages."
        return {
            "session_id": session_id,
            "status": "completed",
            "duration": f"{duration_minutes} minutes",
            "summary": summary
        }

    def get_insights(self, twin_id: str, insight_types: list[str] | None = None) -> dict[str, Any]:
        """
        Generate mock insights from the digital twin's data.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        twin = self._twins.get(twin_id)
        if not twin:
            raise ResourceNotFoundError(f"Mock digital twin with ID {twin_id} not found.")

        insights: dict[str, Any] = {}
        # Default summary if no specific types requested
        if not insight_types:
            insights["summary"] = f"General mock insights summary for twin {twin_id}."
            return {"twin_id": twin_id, "insights": insights}

        for insight_type in insight_types:
            if insight_type == "mood":
                insights["mood"] = {
                    "overall_mood": "neutral",
                    "mood_trend": "stable",
                    "key_factors": ["stress", "sleep"]
                }
            elif insight_type == "sleep":
                insights["sleep"] = {
                    "average_duration": 7.0,
                    "sleep_quality_trend": "improving",
                    "recommendations": ["Maintain consistent bedtime", "Reduce caffeine intake"]
                }
            elif insight_type == "medication":
                insights["medication"] = {
                    "adherence_estimate": "85%",
                    "potential_side_effects": ["nausea", "dizziness"]
                }
            elif insight_type == "treatment":
                insights["treatment"] = {
                    "effectiveness_assessment": "effective",
                    "suggestions_for_adjustment": ["Increase therapy frequency", "Consider group sessions"]
                }
            else:
                insights[insight_type] = {"summary": f"Mock insight for {insight_type}"}

        return {"twin_id": twin_id, "insights": insights}

    def interact(self, twin_id: str, query: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Mock interaction with the digital twin.

        Args:
            twin_id: The ID of the digital twin.
            query: The interaction query or command.
            context: Optional context for the interaction.

        Returns:
            A dictionary containing the mock result of the interaction.
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock Digital Twin service is not initialized.")
        if not query:
            raise InvalidRequestError("Query cannot be empty.")

        twin = self._twins.get(twin_id)
        if not twin:
            raise ResourceNotFoundError(f"Mock digital twin with ID {twin_id} not found.")

        # Generate a simple mock response based on the query
        response_text = f"Mock response to query: '{query}'. Context provided: {bool(context)}"
        mock_result = {
            "response": response_text,
            "confidence": 0.95,
            "metadata": {"interaction_type": "query_response"}
        }

        # Log interaction
        twin["interaction_history"].append({"query": query, "response": response_text})
        logger.info(f"Mock interaction with twin ID {twin_id}. Query: '{query}'")

        return {"twin_id": twin_id, "interaction_result": mock_result}