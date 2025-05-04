"""
Mock implementation of DigitalTwinRepository for testing.
Uses in-memory storage rather than actual database.
"""
from datetime import datetime
from uuid import UUID, uuid4

from app.domain.entities.digital_twin import DigitalTwinState
from app.domain.entities.digital_twin_enums import ClinicalSignificance  # Corrected import path
from app.domain.repositories.digital_twin_repository import DigitalTwinRepository


class MockDigitalTwinRepository(DigitalTwinRepository):
    """
    Mock implementation of DigitalTwinRepository using in-memory storage.
    Suitable for testing and development without a database dependency.
    """
    
    def __init__(self):
        """Initialize the mock repository with empty storage."""
        self._storage: dict[UUID, list[DigitalTwinState]] = {}
    
    async def get_by_id(self, digital_twin_id: UUID) -> DigitalTwinState | None:
        """
        Retrieve a Digital Twin state by its ID.
        
        Args:
            digital_twin_id: The ID of the Digital Twin state
            
        Returns:
            The Digital Twin state if found, None otherwise
        """
        for patient_states in self._storage.values():
            for state in patient_states:
                if hasattr(state, 'id') and state.id == digital_twin_id:
                    return state
        return None
    
    async def get_latest_for_patient(self, patient_id: UUID) -> DigitalTwinState | None:
        """
        Retrieve the latest Digital Twin state for a patient.
        
        Args:
            patient_id: The ID of the patient
            
        Returns:
            The latest Digital Twin state if found, None otherwise
        """
        # Return the most recently saved state (append order)
        if patient_id not in self._storage or not self._storage[patient_id]:
            return None
        return self._storage[patient_id][-1]
    
    async def get_history_for_patient(
        self, 
        patient_id: UUID, 
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ) -> list[DigitalTwinState]:
        """
        Retrieve historical Digital Twin states for a patient.
        
        Args:
            patient_id: The ID of the patient
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            limit: Maximum number of records to return
            
        Returns:
            List of Digital Twin states ordered by timestamp (newest first)
        """
        if patient_id not in self._storage:
            return []
        
        # Apply date filters if provided
        filtered_states = self._storage[patient_id]
        
        if start_date:
            filtered_states = [
                state for state in filtered_states
                if state.timestamp >= start_date
            ]
        
        if end_date:
            filtered_states = [
                state for state in filtered_states
                if state.timestamp <= end_date
            ]
        
        # Sort by timestamp (newest first) and apply limit
        sorted_states = sorted(
            filtered_states,
            key=lambda state: state.timestamp,
            reverse=True
        )
        
        return sorted_states[:limit]
    
    async def save(self, digital_twin_state: DigitalTwinState) -> DigitalTwinState:
        """
        Save a Digital Twin state.
        
        Args:
            digital_twin_state: The Digital Twin state to save
            
        Returns:
            The saved Digital Twin state with any updates (e.g., generated IDs)
        """
        patient_id = digital_twin_state.patient_id
        
        # Initialize patient storage if it doesn't exist
        if patient_id not in self._storage:
            self._storage[patient_id] = []
        
        # Store a copy of the state to prevent external modification
        state_copy = digital_twin_state  # In a real impl, we'd deep copy
        
        # Add ID if not provided
        if not hasattr(state_copy, 'id'):
            # In a real implementation, we'd use proper attribute setting
            # This is just for the mock
            state_copy.id = uuid4()
        
        self._storage[patient_id].append(state_copy)
        return state_copy
    
    # Alias for non-enhanced tests
    async def get_latest_state(self, patient_id: UUID) -> DigitalTwinState | None:
        """
        Retrieve the latest Digital Twin state for a patient (alias for get_latest_for_patient).
        """
        return await self.get_latest_for_patient(patient_id)
    
    async def find_by_clinical_significance(
        self,
        significance_level: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ) -> list[tuple[UUID, DigitalTwinState]]:
        """
        Find Digital Twin states with specified clinical significance.
        
        Args:
            significance_level: The clinical significance level to search for
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            limit: Maximum number of records to return
            
        Returns:
            List of tuples containing patient ID and Digital Twin state
        """
        results = []
        
        # Convert string to enum value
        try:
            sig_level = ClinicalSignificance(significance_level.lower())
        except ValueError:
            return []
        
        # Search all patients
        for patient_id, states in self._storage.items():
            for state in states:
                # Apply date filters
                if start_date and state.timestamp < start_date:
                    continue
                if end_date and state.timestamp > end_date:
                    continue
                
                # Check for insights with matching significance
                matching_insights = [
                    insight for insight in state.clinical_insights
                    if insight.clinical_significance == sig_level
                ]
                
                if matching_insights:
                    results.append((patient_id, state))
                    
                    # Break early if we've reached the limit
                    if len(results) >= limit:
                        return results
        
        return results
    
    # Implement abstract interface methods for compatibility
    async def get_by_patient_id(self, patient_id: UUID) -> DigitalTwinState | None:  # type: ignore
        """Alias for retrieving the latest Digital Twin state by patient ID."""
        return await self.get_latest_for_patient(patient_id)

    async def create(self, twin: DigitalTwinState) -> DigitalTwinState:
        """Create a new Digital Twin state (alias for save)."""
        return await self.save(twin)

    async def update(self, twin: DigitalTwinState) -> DigitalTwinState | None:
        """Update an existing Digital Twin state (alias for save)."""
        return await self.save(twin)

    async def delete(self, twin_id: UUID) -> bool:
        """Delete a Digital Twin state by its ID."""
        removed = False
        for patient_id, states in list(self._storage.items()):
            filtered = [s for s in states if not (hasattr(s, 'id') and s.id == twin_id)]
            if len(filtered) < len(states):
                self._storage[patient_id] = filtered
                removed = True
        return removed