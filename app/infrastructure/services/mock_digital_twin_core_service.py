"""
Mock Digital Twin Core Service - Infrastructure Implementation

This module provides a mock implementation of the Digital Twin Core service
for testing purposes, maintaining clean architecture principles.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from app.core.exceptions import InvalidConfigurationError


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
        config: Optional[Dict[str, Any]] = None
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
        self._digital_twins = {}
        self._sessions = {}
    
    async def initialize(self) -> bool:
        """
        Initialize the service.
        
        Returns:
            True if initialization is successful
        """
        self._initialized = True
        return True
    
    async def shutdown(self) -> bool:
        """
        Shut down the service and release resources.
        
        Returns:
            True if shutdown is successful
        """
        self._initialized = False
        return True
    
    async def create_digital_twin(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
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
            "version": "1.0.0"
        }
        
        self._digital_twins[twin_id] = digital_twin
        return digital_twin
    
    async def get_digital_twin(self, twin_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a digital twin by ID.
        
        Args:
            twin_id: The ID of the digital twin
            
        Returns:
            Digital twin data if found, None otherwise
        """
        return self._digital_twins.get(twin_id)
    
    async def create_session(self, twin_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
            "messages": []
        }
        
        self._sessions[session_id] = session
        return session
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a session by ID.
        
        Args:
            session_id: The ID of the session
            
        Returns:
            Session data if found, None otherwise
        """
        return self._sessions.get(session_id)
    
    async def send_message(self, session_id: str, message: str) -> Dict[str, Any]:
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
                "model_version": "1.0.0"
            }
        }
        
        # Add to session messages
        session["messages"].append({
            "role": "user",
            "content": message,
            "timestamp": "2025-05-14T15:00:30Z"
        })
        
        session["messages"].append({
            "role": "assistant",
            "content": response["response"],
            "timestamp": "2025-05-14T15:01:00Z"
        })
        
        return response
    
    async def end_session(self, session_id: str) -> Dict[str, Any]:
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
            "summary": "Mock session ended successfully"
        }