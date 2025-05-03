"""
Digital Twin Domain Entity Module.

This module defines the core domain entities for digital twins,
representing computational models of patients for simulation and prediction.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional


class TwinType(str, Enum):
    """Types of digital twins available in the system."""
    PSYCHIATRIC = "psychiatric"
    PHYSIOLOGICAL = "physiological"
    BEHAVIORAL = "behavioral"
    INTEGRATED = "integrated"
    TREATMENT_RESPONSE = "treatment_response"
    COGNITIVE = "cognitive"


class SimulationType(str, Enum):
    """Types of simulations that can be run on digital twins."""
    TREATMENT_RESPONSE = "treatment_response"
    SYMPTOM_PROGRESSION = "symptom_progression"
    RISK_PROJECTION = "risk_projection"
    WHAT_IF_ANALYSIS = "what_if_analysis"
    COMORBIDITY_INTERACTION = "comorbidity_interaction"
    BEHAVIORAL_FEEDBACK = "behavioral_feedback"


class DigitalTwin:
    """
    Digital Twin domain entity representing a computational model of a patient.
    
    Digital twins enable simulation and prediction of patient responses
    to various treatments and conditions, enhancing clinical decision making.
    
    Attributes:
        id: Unique identifier for the digital twin
        twin_type: Type of digital twin
        name: Name of the digital twin
        description: Description of the digital twin
        created_at: When the digital twin was created
        updated_at: When the digital twin was last updated
        version: Version of the digital twin
        data: Model data for the digital twin
        user_id: ID of the patient this digital twin represents
    """
    
    def __init__(
        self,
        id: Optional[str],
        twin_type: TwinType,
        name: str,
        description: Optional[str],
        created_at: Optional[datetime],
        updated_at: Optional[datetime],
        version: str,
        data: Dict[str, Any],
        user_id: str
    ):
        """
        Initialize a new DigitalTwin entity.
        
        Args:
            id: Unique identifier (None for new twins)
            twin_type: Type of digital twin
            name: Name of the digital twin
            description: Description of the digital twin
            created_at: When the digital twin was created
            updated_at: When the digital twin was last updated
            version: Version of the digital twin
            data: Model data for the digital twin
            user_id: ID of the patient this digital twin represents
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        self.id = id
        self.twin_type = twin_type
        self.name = name
        self.description = description
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.version = version
        self.data = data
        self.user_id = user_id
        
        # Validate entity state
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate the entity state.
        
        Raises:
            ValueError: If entity state is invalid
        """
        if not self.name:
            raise ValueError("Digital twin name cannot be empty")
            
        if not self.user_id:
            raise ValueError("Digital twin must be associated with a user")
    
    def update(self, 
               name: Optional[str] = None, 
               description: Optional[str] = None,
               version: Optional[str] = None,
               data: Optional[Dict[str, Any]] = None) -> None:
        """
        Update the digital twin.
        
        Args:
            name: New name (if provided)
            description: New description (if provided)
            version: New version (if provided)
            data: New model data (if provided)
        """
        if name:
            self.name = name
        if description is not None:  # Allow empty description
            self.description = description
        if version:
            self.version = version
        if data:
            self.data = data
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert entity to dictionary.
        
        Returns:
            Dictionary representation of the entity
        """
        return {
            "id": self.id,
            "twin_type": self.twin_type.value if isinstance(self.twin_type, TwinType) else self.twin_type,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "version": self.version,
            "data": self.data,
            "user_id": self.user_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DigitalTwin":
        """
        Create entity from dictionary.
        
        Args:
            data: Dictionary representation of entity
            
        Returns:
            DigitalTwin entity
        """
        # Convert string enum values to enum instances
        twin_type = TwinType(data["twin_type"]) if isinstance(data["twin_type"], str) else data["twin_type"]
        
        # Parse timestamps
        created_at = datetime.fromisoformat(data["created_at"]) if isinstance(data["created_at"], str) else data["created_at"]
        updated_at = datetime.fromisoformat(data["updated_at"]) if isinstance(data["updated_at"], str) else data["updated_at"]
        
        return cls(
            id=data.get("id"),
            twin_type=twin_type,
            name=data["name"],
            description=data.get("description"),
            created_at=created_at,
            updated_at=updated_at,
            version=data["version"],
            data=data.get("data", {}),
            user_id=data["user_id"]
        )
