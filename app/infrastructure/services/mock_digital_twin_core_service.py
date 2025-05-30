"""
Mock Digital Twin Core Service - Infrastructure Implementation

This module provides a mock implementation of the Digital Twin Core service
for testing purposes, maintaining clean architecture principles.
"""

from typing import Any
from uuid import UUID, uuid4


class MockDigitalTwinCoreService:
    """
    Mock implementation of the Digital Twin Core service interface.
    Used for testing and development without requiring external dependencies.
    """

    def __init__(
        self,
        digital_twin_repository=None,
        patient_repository=None,
        xgboost_service=None,
        pat_service=None,
        mentalllama_service=None,
        config: dict[str, Any] | None = None,
    ):
        """
        Initialize the mock Digital Twin Core service.

        Args:
            digital_twin_repository: Optional repository for digital twin data
            patient_repository: Optional repository for patient data
            xgboost_service: Optional XGBoost service
            pat_service: Optional PAT service
            mentalllama_service: Optional MentalLLaMA service
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self._digital_twin_repository = digital_twin_repository
        self._patient_repository = patient_repository
        self._xgboost_service = xgboost_service
        self._pat_service = pat_service
        self._mentalllama_service = mentalllama_service
        self._initialized = True
        self._digital_twins: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}

    async def initialize(self) -> bool:
        """
        Initialize the service.

        Returns:
            True if initialization is successful
        """
        self._initialized = True
        return True

    async def initialize_digital_twin(
        self,
        patient_id: UUID,
        include_genetic_data: bool = False,
        include_biomarkers: bool = True,
    ):
        """
        Initialize a new digital twin for a patient.

        Args:
            patient_id: The UUID of the patient
            include_genetic_data: Whether to include genetic data in the twin
            include_biomarkers: Whether to include biomarker data in the twin

        Returns:
            The initialized digital twin state
        """
        # Create a mock state for the digital twin
        state_id = uuid4()

        # Example state structure that matches what the test expects
        state: Any = type(  # type: ignore[misc]
            "DigitalTwinState",
            (),
            {
                "id": state_id,
                "patient_id": patient_id,
                "version": 1,
                "data": {
                    "brain_state": {
                        "neurotransmitter_levels": {
                            "serotonin": 0.7,
                            "dopamine": 0.8,
                            "gaba": 0.6,
                            "glutamate": 0.9,
                            "norepinephrine": 0.75,
                        },
                        "brain_regions": {
                            "prefrontal_cortex": {
                                "activity": 0.8,
                                "connectivity": 0.75,
                            },
                            "amygdala": {"activity": 0.9, "connectivity": 0.7},
                            "hippocampus": {"activity": 0.7, "connectivity": 0.8},
                        },
                    },
                    "treatment_history": [],
                },
                "with_updates": lambda clinical_insights=None, metadata_updates=None: state,
            },
        )

        # If we have a repository, store the state
        if self._digital_twin_repository:
            await self._digital_twin_repository.save(state)

        return state

    async def shutdown(self) -> bool:
        """
        Shut down the service and release resources.

        Returns:
            True if shutdown is successful
        """
        self._initialized = False
        return True

    async def create_digital_twin(self, user_data: dict[str, Any]) -> dict[str, Any]:
        """
        Create a new digital twin based on user data.

        Args:
            user_data: User profile and clinical data

        Returns:
            Digital twin data
        """
        twin_id = str(uuid4())

        digital_twin = {
            "id": twin_id,
            "created_at": "2025-05-14T15:00:00Z",
            "user_profile": user_data.get("user_profile", {}),
            "clinical_data": user_data.get("clinical_data", {}),
            "status": "active",
            "version": "1.0.0",
        }

        self._digital_twins[twin_id] = digital_twin
        return digital_twin

    async def get_digital_twin(self, twin_id: str) -> dict[str, Any] | None:
        """
        Retrieve a digital twin by ID.

        Args:
            twin_id: The ID of the digital twin

        Returns:
            Digital twin data if found, None otherwise
        """
        return self._digital_twins.get(twin_id)

    async def create_session(
        self, twin_id: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Create a new session with a digital twin.

        Args:
            twin_id: The ID of the digital twin
            context: Optional session context

        Returns:
            Session data
        """
        if twin_id not in self._digital_twins:
            raise ValueError(f"Digital twin with ID {twin_id} not found")

        session_id = str(uuid4())

        session = {
            "id": session_id,
            "twin_id": twin_id,
            "created_at": "2025-05-14T15:00:00Z",
            "context": context or {},
            "status": "active",
            "messages": [],
        }

        self._sessions[session_id] = session
        return session

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        """
        Retrieve a session by ID.

        Args:
            session_id: The ID of the session

        Returns:
            Session data if found, None otherwise
        """
        return self._sessions.get(session_id)

    async def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        """
        Send a message to a digital twin session.

        Args:
            session_id: The ID of the session
            message: The message to send

        Returns:
            Response from the digital twin
        """
        if session_id not in self._sessions:
            raise ValueError(f"Session with ID {session_id} not found")

        session = self._sessions[session_id]

        # Create mock response
        response = {
            "id": str(uuid4()),
            "session_id": session_id,
            "timestamp": "2025-05-14T15:01:00Z",
            "input": message,
            "response": f"Mock response to: {message}",
            "metadata": {
                "processing_time_ms": 150,
                "sentiment": "neutral",
                "model_version": "1.0.0",
            },
        }

        # Add to session messages
        session["messages"].append(
            {"role": "user", "content": message, "timestamp": "2025-05-14T15:00:30Z"}
        )

        session["messages"].append(
            {
                "role": "assistant",
                "content": response["response"],
                "timestamp": "2025-05-14T15:01:00Z",
            }
        )

        return response

    async def end_session(self, session_id: str) -> dict[str, Any]:
        """
        End a digital twin session.

        Args:
            session_id: The ID of the session

        Returns:
            Session summary
        """
        if session_id not in self._sessions:
            raise ValueError(f"Session with ID {session_id} not found")

        session = self._sessions[session_id]
        session["status"] = "ended"
        session["ended_at"] = "2025-05-14T15:10:00Z"

        return {
            "session_id": session_id,
            "status": "ended",
            "duration_seconds": 600,
            "message_count": len(session["messages"]) // 2,
            "summary": "Mock session ended successfully",
        }

    async def process_treatment_event(self, patient_id: UUID, event_data: dict[str, Any]) -> Any:
        """
        Process a treatment event and update the digital twin state.

        Args:
            patient_id: Patient UUID
            event_data: Treatment event data

        Returns:
            Updated digital twin state
        """
        # Get the latest state
        current_state = None
        if self._digital_twin_repository:
            current_state = await self._digital_twin_repository.get_latest_state(patient_id)

        if not current_state:
            current_state = await self.initialize_digital_twin(patient_id)

        # Create a new state with incremented version
        state_id = uuid4()
        new_state: Any = type(  # type: ignore[misc]
            "DigitalTwinState",
            (),
            {
                "id": state_id,
                "patient_id": patient_id,
                "version": current_state.version + 1,
                "data": {
                    "brain_state": current_state.data.get("brain_state", {}),
                    "treatment_history": [
                        *current_state.data.get("treatment_history", []),
                        event_data,
                    ],
                },
                "with_updates": lambda clinical_insights=None, metadata_updates=None: new_state,
            },
        )

        # Store the new state
        if self._digital_twin_repository:
            await self._digital_twin_repository.save(new_state)

        return new_state

    async def generate_treatment_recommendations(
        self,
        patient_id: UUID,
        consider_current_medications: bool = True,
        include_therapy_options: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Generate treatment recommendations based on the digital twin.

        Args:
            patient_id: Patient UUID
            consider_current_medications: Whether to consider current medications
            include_therapy_options: Whether to include therapy options

        Returns:
            List of treatment recommendations
        """
        recommendations = []

        # Add medication recommendations
        recommendations.append(
            {
                "id": str(uuid4()),
                "type": "medication",
                "name": "Sertraline",
                "dosage": "50mg",
                "schedule": "once daily in the morning",
                "rationale": "Based on neurotransmitter analysis showing low serotonin levels",
                "confidence": 0.85,
                "side_effects": ["nausea", "insomnia", "dry mouth"],
                "interactions": ["MAOIs", "other SSRIs"],
            }
        )

        # Add therapy recommendations if requested
        if include_therapy_options:
            recommendations.append(
                {
                    "id": str(uuid4()),
                    "type": "therapy",
                    "name": "Cognitive Behavioral Therapy",
                    "frequency": "weekly",
                    "duration": "45 minutes",
                    "focus_areas": ["thought patterns", "behavioral activation"],
                    "rationale": "Effective for both depression and anxiety management",
                    "confidence": 0.9,
                    "expected_outcomes": [
                        "reduced rumination",
                        "improved coping strategies",
                    ],
                }
            )

        return recommendations

    async def get_visualization_data(
        self, patient_id: UUID, visualization_type: str = "brain_model"
    ) -> dict[str, Any]:
        """
        Get visualization data for the digital twin.

        Args:
            patient_id: Patient UUID
            visualization_type: Type of visualization to generate

        Returns:
            Visualization data
        """
        if visualization_type == "brain_model":
            return {
                "visualization_type": "brain_model_3d",
                "patient_id": str(patient_id),
                "timestamp": "2025-05-14T15:00:00Z",
                "brain_regions": [
                    {
                        "name": "prefrontal_cortex",
                        "activity": 0.8,
                        "color": "#ff7700",
                        "size": 1.2,
                        "connections": ["amygdala", "hippocampus"],
                    },
                    {
                        "name": "amygdala",
                        "activity": 0.9,
                        "color": "#ff0000",
                        "size": 1.5,
                        "connections": ["hippocampus"],
                    },
                    {
                        "name": "hippocampus",
                        "activity": 0.7,
                        "color": "#ffaa00",
                        "size": 1.0,
                        "connections": [],
                    },
                ],
                "neurotransmitters": {
                    "serotonin": 0.7,
                    "dopamine": 0.8,
                    "gaba": 0.6,
                    "glutamate": 0.9,
                    "norepinephrine": 0.75,
                },
            }
        else:
            return {
                "visualization_type": visualization_type,
                "patient_id": str(patient_id),
                "timestamp": "2025-05-14T15:00:00Z",
                "message": "Visualization type not fully supported in mock implementation",
            }

    async def compare_states(
        self, patient_id: UUID, state_id_1: UUID, state_id_2: UUID
    ) -> dict[str, Any]:
        """
        Compare two digital twin states.

        Args:
            patient_id: Patient UUID
            state_id_1: First state UUID
            state_id_2: Second state UUID

        Returns:
            Comparison data
        """
        return {
            "patient_id": str(patient_id),
            "state_1": {"id": str(state_id_1), "timestamp": "2025-05-14T15:00:00Z"},
            "state_2": {"id": str(state_id_2), "timestamp": "2025-05-14T15:05:00Z"},
            "brain_state_changes": {
                "serotonin": {"before": 0.7, "after": 0.75, "change": "+0.05"},
                "dopamine": {"before": 0.8, "after": 0.85, "change": "+0.05"},
            },
            "new_insights": [
                {
                    "id": str(uuid4()),
                    "title": "Medication Response",
                    "description": "Initial positive response to new medication",
                    "confidence": 0.8,
                }
            ],
            "summary": "Modest improvement in neurotransmitter levels after medication change.",
        }

    async def generate_clinical_summary(
        self,
        patient_id: UUID,
        include_treatment_history: bool = True,
        include_predictions: bool = True,
    ) -> dict[str, Any]:
        """
        Generate a clinical summary for the patient.

        Args:
            patient_id: Patient UUID
            include_treatment_history: Whether to include treatment history
            include_predictions: Whether to include predictions

        Returns:
            Clinical summary data
        """
        # Get patient data if available
        patient_data = {}
        if self._patient_repository:
            patient = await self._patient_repository.get_patient(patient_id)
            if patient:
                patient_data = {
                    "id": str(patient_id),
                    "name": f"{patient.get('first_name', '')} {patient.get('last_name', '')}".strip(),
                }
        else:
            # Mock patient data
            patient_data = {"id": str(patient_id), "name": "Jane Doe"}

        # Generate summary
        summary = {
            "patient": patient_data,
            "digital_twin_state": {
                "neurotransmitter_levels": {"serotonin": 0.75, "dopamine": 0.85},
                "significant_brain_regions": [
                    {"name": "amygdala", "activity": "elevated"},
                    {"name": "prefrontal_cortex", "activity": "normal"},
                ],
            },
            "significant_insights": [
                {
                    "id": str(uuid4()),
                    "title": "Anxiety Pattern",
                    "description": "Elevated amygdala activity consistent with anxiety presentation",
                    "confidence": 0.85,
                },
                {
                    "id": str(uuid4()),
                    "title": "Treatment Response",
                    "description": "Positive response to SSRI with 7% increase in serotonin levels",
                    "confidence": 0.8,
                },
            ],
            "treatment_recommendations": await self.generate_treatment_recommendations(
                patient_id,
                consider_current_medications=True,
                include_therapy_options=True,
            ),
        }

        # Add treatment history if requested
        if include_treatment_history:
            summary["treatment_history"] = [
                {
                    "date": "2025-05-01T10:00:00Z",
                    "type": "medication_started",
                    "name": "Sertraline",
                    "dosage": "25mg",
                    "notes": "Initial dose for depression",
                },
                {
                    "date": "2025-05-10T10:00:00Z",
                    "type": "medication_adjusted",
                    "name": "Sertraline",
                    "dosage": "50mg",
                    "notes": "Increased after good initial tolerance",
                },
            ]

        # Add predictions if requested
        if include_predictions:
            summary["predictions"] = {
                "treatment_response": {
                    "current_trajectory": "positive",
                    "expected_improvement": "moderate to significant within 4-6 weeks",
                    "confidence": 0.75,
                },
                "risk_factors": {"relapse": "low", "side_effects": "moderate"},
            }

        return summary
