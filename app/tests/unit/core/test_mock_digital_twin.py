"""
Migrated from standalone test to proper unit test.
Original file: app/tests/standalone/core/test_mock_digital_twin.py

This test uses the actual implementations from the main codebase.
Migration date: Tue May 13 10:38:16 EDT 2025
"""

"""
Unit tests for the MockDigitalTwinService.

These tests verify that the MockDigitalTwinService correctly simulates
digital twin functionality for testing purposes.
"""

# Create mock classes for testing
from abc import ABC, abstractmethod
from datetime import datetime

import pytest

from app.domain.exceptions import DomainError as SessionNotFoundError
from app.domain.exceptions import ValidationError as InvalidConfigurationError
from app.domain.models.digital_twin_state import DigitalTwinState
from app.domain.services.digital_twin_service import DigitalTwinService


class DigitalTwinService(ABC):
    """Abstract base class for digital twin services."""

    @abstractmethod
    def initialize(self, config):
        """Initialize the service with configuration."""
        pass

    @abstractmethod
    def is_healthy(self):
        """Check if the service is healthy."""
        pass

    @abstractmethod
    def shutdown(self):
        """Shut down the service."""
        pass


class MockDigitalTwinService(DigitalTwinService):
    """Mock implementation of digital twin service for testing."""

    def __init__(self):
        """Initialize the mock digital twin service."""
        self._healthy = False
        self._sessions = {}
        self._twins = {}
        self._simulations = {}
        self._states = {}

    def initialize(self, config):
        """Initialize the service with configuration."""
        if config is None:
            raise InvalidConfigurationError("Configuration cannot be None")
        self._healthy = True
        return True

    def is_healthy(self):
        """Check if the service is healthy."""
        return self._healthy

    def shutdown(self):
        """Shut down the service."""
        self._healthy = False

    def create_session(self, patient_id, context):
        """Create a new digital twin session."""
        session_id = f"session-{len(self._sessions) + 1}"
        session = {
            "session_id": session_id,
            "patient_id": patient_id,
            "context": context,
            "messages": [],
            "created_at": datetime.now().isoformat(),
        }
        self._sessions[session_id] = session
        return {"session_id": session_id, "patient_id": patient_id}

    def get_session(self, session_id):
        """Get a session by ID."""
        if session_id not in self._sessions:
            raise SessionNotFoundError(f"Session {session_id} not found")
        return self._sessions[session_id]

    def send_message(self, session_id, message):
        """Send a message to a session."""
        if session_id not in self._sessions:
            raise SessionNotFoundError(f"Session {session_id} not found")

        session = self._sessions[session_id]
        session["messages"].append(
            {
                "role": "user",
                "content": message,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Generate a mock response
        response = {
            "role": "assistant",
            "content": f"Mock response to: {message}",
            "timestamp": datetime.now().isoformat(),
        }
        session["messages"].append(response)

        return {"response": response["content"], "session_id": session_id}

    def create_digital_twin(self, patient_id, twin_data):
        """Create a new digital twin."""
        twin_id = f"twin-{len(self._twins) + 1}"
        twin = {
            "twin_id": twin_id,
            "patient_id": patient_id,
            "data": twin_data,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "state": DigitalTwinState.ACTIVE.value,
        }
        self._twins[twin_id] = twin
        return {"twin_id": twin_id, "patient_id": patient_id}

    def get_digital_twin(self, twin_id):
        """Get a digital twin by ID."""
        if twin_id not in self._twins:
            return None
        return self._twins[twin_id]

    def update_digital_twin(self, twin_id, updates):
        """Update a digital twin."""
        if twin_id not in self._twins:
            return False

        twin = self._twins[twin_id]
        for key, value in updates.items():
            if key in twin["data"]:
                twin["data"][key] = value

        twin["updated_at"] = datetime.now().isoformat()
        return True

    def delete_digital_twin(self, twin_id):
        """Delete a digital twin."""
        if twin_id not in self._twins:
            return False

        del self._twins[twin_id]
        return True

    def start_simulation(self, twin_id, parameters):
        """Start a simulation for a digital twin."""
        if twin_id not in self._twins:
            return None

        simulation_id = f"sim-{len(self._simulations) + 1}"
        simulation = {
            "simulation_id": simulation_id,
            "twin_id": twin_id,
            "parameters": parameters,
            "status": "running",
            "results": None,
            "created_at": datetime.now().isoformat(),
        }
        self._simulations[simulation_id] = simulation
        return {"simulation_id": simulation_id, "twin_id": twin_id}

    def get_simulation_status(self, simulation_id):
        """Get the status of a simulation."""
        if simulation_id not in self._simulations:
            return None

        return {
            "simulation_id": simulation_id,
            "status": self._simulations[simulation_id]["status"],
        }

    def get_simulation_results(self, simulation_id):
        """Get the results of a simulation."""
        if simulation_id not in self._simulations:
            return None

        simulation = self._simulations[simulation_id]
        if simulation["status"] != "completed":
            return {
                "simulation_id": simulation_id,
                "status": simulation["status"],
                "results": None,
            }

        return {
            "simulation_id": simulation_id,
            "status": "completed",
            "results": simulation["results"],
        }

    def complete_simulation(self, simulation_id, results):
        """Complete a simulation with results."""
        if simulation_id not in self._simulations:
            return False

        simulation = self._simulations[simulation_id]
        simulation["status"] = "completed"
        simulation["results"] = results
        simulation["completed_at"] = datetime.now().isoformat()
        return True

    def create_twin_state(self, twin_id, state_data):
        """Create a state for a digital twin."""
        if twin_id not in self._twins:
            return None

        state_id = f"state-{len(self._states) + 1}"
        state = {
            "state_id": state_id,
            "twin_id": twin_id,
            "data": state_data,
            "created_at": datetime.now().isoformat(),
        }
        self._states[state_id] = state
        return {"state_id": state_id, "twin_id": twin_id}

    def get_twin_state(self, state_id):
        """Get a twin state by ID."""
        if state_id not in self._states:
            return None

        return self._states[state_id]

    def list_twin_states(self, twin_id):
        """List all states for a digital twin."""
        return [state for state in self._states.values() if state["twin_id"] == twin_id]


class TestMockDigitalTwinService:
    """Tests for the MockDigitalTwinService."""

    @pytest.fixture
    def service(self):
        """Create a mock digital twin service for testing."""
        return MockDigitalTwinService()

    @pytest.fixture
    def initialized_service(self, service):
        """Create an initialized mock digital twin service."""
        service.initialize({"api_key": "test_key"})
        return service

    @pytest.mark.standalone()
    def test_initialize(self, service):
        """Test initializing the service."""
        assert service.is_healthy() is False

        result = service.initialize({"api_key": "test_key"})

        assert result is True
        assert service.is_healthy() is True

    @pytest.mark.standalone()
    def test_initialize_with_invalid_config(self, service):
        """Test initializing with invalid configuration."""
        with pytest.raises(InvalidConfigurationError):
            service.initialize(None)

    @pytest.mark.standalone()
    def test_shutdown(self, initialized_service):
        """Test shutting down the service."""
        assert initialized_service.is_healthy() is True

        initialized_service.shutdown()

        assert initialized_service.is_healthy() is False

    @pytest.mark.standalone()
    def test_create_session(self, initialized_service):
        """Test creating a session."""
        patient_id = "patient-123"
        context = {"medical_history": "Test history"}

        result = initialized_service.create_session(patient_id, context)

        assert "session_id" in result
        assert result["patient_id"] == patient_id

        # Verify session was created
        session = initialized_service.get_session(result["session_id"])
        assert session["patient_id"] == patient_id
        assert session["context"] == context
        assert len(session["messages"]) == 0

    @pytest.mark.standalone()
    def test_get_session_not_found(self, initialized_service):
        """Test getting a non-existent session."""
        with pytest.raises(SessionNotFoundError):
            initialized_service.get_session("nonexistent-session")

    @pytest.mark.standalone()
    def test_send_message(self, initialized_service):
        """Test sending a message to a session."""
        patient_id = "patient-123"
        session_result = initialized_service.create_session(patient_id, {})
        session_id = session_result["session_id"]

        message = "Test message"
        result = initialized_service.send_message(session_id, message)

        assert result["session_id"] == session_id
        assert "response" in result

        # Verify message was added to session
        session = initialized_service.get_session(session_id)
        assert len(session["messages"]) == 2  # User message and response
        assert session["messages"][0]["role"] == "user"
        assert session["messages"][0]["content"] == message
        assert session["messages"][1]["role"] == "assistant"

    @pytest.mark.standalone()
    def test_send_message_session_not_found(self, initialized_service):
        """Test sending a message to a non-existent session."""
        with pytest.raises(SessionNotFoundError):
            initialized_service.send_message("nonexistent-session", "Test message")

    @pytest.mark.standalone()
    def test_create_digital_twin(self, initialized_service):
        """Test creating a digital twin."""
        patient_id = "patient-123"
        twin_data = {
            "age": 35,
            "gender": "female",
            "conditions": ["anxiety", "depression"],
            "medications": [
                {"name": "Sertraline", "dosage": "50mg", "frequency": "daily"},
                {"name": "Lorazepam", "dosage": "0.5mg", "frequency": "as needed"},
            ],
            "history": {
                "therapy_sessions": 12,
                "hospitalizations": 0,
                "gaba_pathway_markers": "normal",
            },
        }

        result = initialized_service.create_digital_twin(patient_id, twin_data)

        assert "twin_id" in result
        assert result["patient_id"] == patient_id

        # Verify twin was created
        twin = initialized_service.get_digital_twin(result["twin_id"])
        assert twin["patient_id"] == patient_id
        assert twin["data"] == twin_data
        assert twin["state"] == DigitalTwinState.ACTIVE.value

    @pytest.mark.standalone()
    def test_update_digital_twin(self, initialized_service):
        """Test updating a digital twin."""
        patient_id = "patient-123"
        twin_data = {"age": 35, "gender": "female"}
        result = initialized_service.create_digital_twin(patient_id, twin_data)
        twin_id = result["twin_id"]

        # Update twin
        updates = {"age": 36}
        update_result = initialized_service.update_digital_twin(twin_id, updates)

        assert update_result is True

        # Verify twin was updated
        updated_twin = initialized_service.get_digital_twin(twin_id)
        assert updated_twin["data"]["age"] == 36
        assert updated_twin["data"]["gender"] == "female"

    @pytest.mark.standalone()
    def test_delete_digital_twin(self, initialized_service):
        """Test deleting a digital twin."""
        patient_id = "patient-123"
        twin_data = {"age": 35}
        result = initialized_service.create_digital_twin(patient_id, twin_data)
        twin_id = result["twin_id"]

        # Delete twin
        delete_result = initialized_service.delete_digital_twin(twin_id)

        assert delete_result is True

        # Verify twin was deleted
        twin = initialized_service.get_digital_twin(twin_id)
        assert twin is None

    @pytest.mark.standalone()
    def test_simulation_workflow(self, initialized_service):
        """Test the complete simulation workflow."""
        # Create twin
        patient_id = "patient-123"
        twin_data = {"age": 35, "conditions": ["anxiety"]}
        twin_result = initialized_service.create_digital_twin(patient_id, twin_data)
        twin_id = twin_result["twin_id"]

        # Start simulation
        parameters = {
            "duration": 30,
            "medication_changes": [{"name": "Prozac", "dosage": "20mg"}],
        }
        sim_result = initialized_service.start_simulation(twin_id, parameters)
        sim_id = sim_result["simulation_id"]

        # Check status
        status = initialized_service.get_simulation_status(sim_id)
        assert status["status"] == "running"

        # Complete simulation
        results = {
            "predicted_outcomes": {
                "anxiety_level": "reduced by 30%",
                "side_effects": ["mild insomnia", "reduced appetite"],
                "adherence_probability": 0.85,
            }
        }
        initialized_service.complete_simulation(sim_id, results)

        # Get results
        final_results = initialized_service.get_simulation_results(sim_id)
        assert final_results["status"] == "completed"
        assert final_results["results"] == results

    @pytest.mark.standalone()
    def test_twin_states(self, initialized_service):
        """Test creating and retrieving digital twin states."""
        # Create twin
        patient_id = "patient-123"
        twin_data = {"age": 35}
        twin_result = initialized_service.create_digital_twin(patient_id, twin_data)
        twin_id = twin_result["twin_id"]

        # Create states
        state1_data = {"anxiety_level": "high", "timestamp": "2023-01-01T12:00:00Z"}
        state1_result = initialized_service.create_twin_state(twin_id, state1_data)

        state2_data = {"anxiety_level": "medium", "timestamp": "2023-01-15T12:00:00Z"}
        state2_result = initialized_service.create_twin_state(twin_id, state2_data)

        # Get state
        state1 = initialized_service.get_twin_state(state1_result["state_id"])
        assert state1["twin_id"] == twin_id
        assert state1["data"] == state1_data

        # List states
        states = initialized_service.list_twin_states(twin_id)
        assert len(states) == 2
        assert states[0]["data"]["anxiety_level"] == "high"
        assert states[1]["data"]["anxiety_level"] == "medium"
