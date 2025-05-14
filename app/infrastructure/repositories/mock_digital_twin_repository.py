"""
Mock Digital Twin Repository - Test Implementation

This module provides a mock implementation of the Digital Twin repository
for testing purposes. It follows clean architecture principles.
"""

from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from app.core.interfaces.repositories.digital_twin_repository_interface import IDigitalTwinRepository


class MockDigitalTwinRepository(IDigitalTwinRepository):
    """
    Mock implementation of the Digital Twin repository interface.
    Used for testing and development without requiring external dependencies.
    """

    def __init__(self):
        """Initialize the mock repository with in-memory storage."""
        self._digital_twins = {}
        self._sessions = {}
    
    async def create_digital_twin(self, twin_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new digital twin.
        
        Args:
            twin_data: Data for the digital twin
            
        Returns:
            The created digital twin with ID
        """
        twin_id = str(uuid4())
        
        # Create the digital twin with an ID
        digital_twin = {
            "id": twin_id,
            **twin_data,
            "created_at": "2025-05-14T15:00:00Z",
            "updated_at": "2025-05-14T15:00:00Z",
            "status": "active",
            "version": "1.0.0"
        }
        
        # Store in memory
        self._digital_twins[twin_id] = digital_twin
        
        return digital_twin
    
    async def get_digital_twin(self, twin_id: Union[str, UUID]) -> Optional[Dict[str, Any]]:
        """
        Get a digital twin by ID.
        
        Args:
            twin_id: Digital twin ID
            
        Returns:
            Digital twin data if found, None otherwise
        """
        twin_id_str = str(twin_id)
        return self._digital_twins.get(twin_id_str)
    
    async def update_digital_twin(self, twin_id: Union[str, UUID], twin_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update a digital twin.
        
        Args:
            twin_id: Digital twin ID
            twin_data: Updated data
            
        Returns:
            Updated digital twin if found, None otherwise
        """
        twin_id_str = str(twin_id)
        
        if twin_id_str not in self._digital_twins:
            return None
        
        # Update the digital twin
        digital_twin = self._digital_twins[twin_id_str]
        digital_twin.update(twin_data)
        digital_twin["updated_at"] = "2025-05-14T15:05:00Z"
        
        return digital_twin
    
    async def delete_digital_twin(self, twin_id: Union[str, UUID]) -> bool:
        """
        Delete a digital twin.
        
        Args:
            twin_id: Digital twin ID
            
        Returns:
            True if deleted, False if not found
        """
        twin_id_str = str(twin_id)
        
        if twin_id_str not in self._digital_twins:
            return False
        
        # Remove from storage
        del self._digital_twins[twin_id_str]
        
        return True
    
    async def list_digital_twins(self, user_id: Optional[Union[str, UUID]] = None) -> List[Dict[str, Any]]:
        """
        List all digital twins, optionally filtered by user ID.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            List of digital twins
        """
        if user_id is None:
            return list(self._digital_twins.values())
        
        user_id_str = str(user_id)
        
        # Filter by user ID
        return [
            twin for twin in self._digital_twins.values()
            if twin.get("user_id") == user_id_str
        ]
    
    async def create_session(self, twin_id: Union[str, UUID], session_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new session for a digital twin.
        
        Args:
            twin_id: Digital twin ID
            session_data: Session data
            
        Returns:
            Created session with ID
        """
        twin_id_str = str(twin_id)
        
        if twin_id_str not in self._digital_twins:
            raise ValueError(f"Digital twin with ID {twin_id_str} not found")
        
        session_id = str(uuid4())
        
        # Create the session
        session = {
            "id": session_id,
            "twin_id": twin_id_str,
            "created_at": "2025-05-14T15:00:00Z",
            "updated_at": "2025-05-14T15:00:00Z",
            "status": "active",
            **session_data,
            "messages": []
        }
        
        # Store in memory
        self._sessions[session_id] = session
        
        return session
    
    async def get_session(self, session_id: Union[str, UUID]) -> Optional[Dict[str, Any]]:
        """
        Get a session by ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Session data if found, None otherwise
        """
        session_id_str = str(session_id)
        return self._sessions.get(session_id_str)
    
    async def update_session(self, session_id: Union[str, UUID], session_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update a session.
        
        Args:
            session_id: Session ID
            session_data: Updated data
            
        Returns:
            Updated session if found, None otherwise
        """
        session_id_str = str(session_id)
        
        if session_id_str not in self._sessions:
            return None
        
        # Update the session
        session = self._sessions[session_id_str]
        session.update(session_data)
        session["updated_at"] = "2025-05-14T15:05:00Z"
        
        return session
    
    async def add_message_to_session(self, session_id: Union[str, UUID], message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add a message to a session.
        
        Args:
            session_id: Session ID
            message: Message data
            
        Returns:
            Updated session with the new message
        """
        session_id_str = str(session_id)
        
        if session_id_str not in self._sessions:
            raise ValueError(f"Session with ID {session_id_str} not found")
        
        # Get the session
        session = self._sessions[session_id_str]
        
        # Add message to session
        session["messages"].append(message)
        session["updated_at"] = "2025-05-14T15:05:00Z"
        
        return session
    
    async def end_session(self, session_id: Union[str, UUID]) -> Optional[Dict[str, Any]]:
        """
        End a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Updated session if found, None otherwise
        """
        session_id_str = str(session_id)
        
        if session_id_str not in self._sessions:
            return None
        
        # End the session
        session = self._sessions[session_id_str]
        session["status"] = "ended"
        session["ended_at"] = "2025-05-14T15:10:00Z"
        
        return session