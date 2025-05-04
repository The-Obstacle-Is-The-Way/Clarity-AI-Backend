"""
Mock implementation of PatientRepository for testing.
Uses in-memory storage rather than actual database.
"""
from uuid import UUID, uuid4

from app.domain.entities.patient import Patient  # Removed Gender import
from app.domain.repositories.patient_repository import PatientRepository


class MockPatientRepository(PatientRepository):
    """
    Mock implementation of PatientRepository using in-memory storage.
    Suitable for testing and development without a database dependency.
    """
    
    def __init__(self):
        """Initialize the mock repository with empty storage."""
        self._storage: dict[UUID, Patient] = {}
    
    async def get_by_id(self, patient_id: UUID) -> Patient | None:
        """
        Retrieve a patient by ID.
        
        Args:
            patient_id: The ID of the patient
            
        Returns:
            The patient if found, None otherwise
        """
        return self._storage.get(patient_id)
    
    async def get_all(self, limit: int = 100, offset: int = 0) -> list[Patient]:
        """
        Retrieve all patients with pagination.
        
        Args:
            limit: Maximum number of patients to retrieve
            offset: Number of patients to skip
            
        Returns:
            List of patients
        """
        patients = list(self._storage.values())
        return patients[offset:offset + limit]
    
    async def save(self, patient: Patient) -> Patient:
        """
        Save a patient (create or update).
        
        Args:
            patient: The patient to save
            
        Returns:
            The saved patient with any updates (e.g., generated IDs)
        """
        # Generate ID if not provided
        if not patient.id:
            # In a real implementation, we'd use proper attribute setting
            # This is just for the mock
            patient.id = uuid4()
        
        # Store a copy of the patient
        patient_copy = patient  # In a real impl, we'd deep copy
        self._storage[patient.id] = patient_copy
        return patient_copy
    
    async def delete(self, patient_id: UUID) -> bool:
        """
        Delete a patient by ID.
        
        Args:
            patient_id: The ID of the patient to delete
            
        Returns:
            True if successful, False otherwise
        """
        if patient_id in self._storage:
            del self._storage[patient_id]
            return True
        return False
    
    async def find_by_name(self, name: str) -> list[Patient]:
        """
        Find patients by name (partial match).
        
        Args:
            name: The name to search for
            
        Returns:
            List of matching patients
        """
        name_lower = name.lower()
        matching_patients = []
        
        for patient in self._storage.values():
            if (name_lower in patient.first_name.lower() or 
                    name_lower in patient.last_name.lower() or
                    name_lower in patient.full_name.lower()):
                matching_patients.append(patient)
        
        return matching_patients
    
    async def find_by_diagnosis(self, diagnosis_code: str) -> list[Patient]:
        """
        Find patients by diagnosis code.
        
        Args:
            diagnosis_code: The diagnosis code to search for
            
        Returns:
            List of patients with the specified diagnosis
        """
        matching_patients = []
        
        for patient in self._storage.values():
            for diagnosis in patient.diagnoses:
                if diagnosis.code == diagnosis_code and diagnosis.is_active:
                    matching_patients.append(patient)
                    break  # Found a match, no need to check other diagnoses
        
        return matching_patients
    
    async def find_by_medication(self, medication_name: str) -> list[Patient]:
        """
        Find patients by medication name.
        
        Args:
            medication_name: The medication name to search for
            
        Returns:
            List of patients with the specified medication
        """
        medication_name_lower = medication_name.lower()
        matching_patients = []
        
        for patient in self._storage.values():
            for medication in patient.medications:
                if (medication_name_lower in medication.name.lower() and 
                        medication.is_active):
                    matching_patients.append(patient)
                    break  # Found a match, no need to check other medications
        
        return matching_patients
    
    # Implement abstract methods for compatibility
    async def create(self, patient: Patient) -> Patient:
        """Create a new patient record (alias for save)."""
        return await self.save(patient)

    async def update(self, patient: Patient) -> Patient | None:
        """Update an existing patient record (alias for save)."""
        return await self.save(patient)

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Patient]:
        """List all patients with pagination (alias for get_all)."""
        return await self.get_all(limit=limit, offset=offset)