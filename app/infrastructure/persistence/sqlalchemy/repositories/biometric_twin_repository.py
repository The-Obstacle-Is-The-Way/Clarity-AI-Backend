"""
SQLAlchemy implementation of the BiometricTwinStateRepository.

This module provides a concrete implementation of the BiometricTwinRepository
interface using SQLAlchemy ORM for database operations.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.domain.entities.biometric_twin import BiometricDataPoint, BiometricTwinState
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository
from app.infrastructure.persistence.sqlalchemy.models.biometric_twin_model import (
    BiometricDataPointModel,
    BiometricTwinModel,
)


class SQLAlchemyBiometricTwinRepository(BiometricTwinRepository):
    """
    SQLAlchemy implementation of the BiometricTwinRepository interface.
    
    This class provides concrete implementations of the repository methods
    using SQLAlchemy ORM for database operations.
    """
    
    def __init__(self, session: Session) -> None:
        """
        Initialize the repository with a SQLAlchemy session.
        
        Args:
            session: SQLAlchemy database session
        """
        self.session = session
    
    def get_by_id(self, twin_id: UUID) -> BiometricTwinState | None:
        """
        Retrieve a BiometricTwin by its ID.
        
        Args:
            twin_id: The unique identifier of the BiometricTwin
            
        Returns:
            The BiometricTwin if found, None otherwise
        """
        twin_model = self.session.query(BiometricTwinModel).filter(
            BiometricTwinModel.twin_id == str(twin_id)
        ).first()
        
        if not twin_model:
            return None
        
        return self._map_to_entity(twin_model)
    
    def get_by_patient_id(self, patient_id: UUID) -> BiometricTwinState | None:
        """
        Retrieve a BiometricTwin by the associated patient ID.
        
        Args:
            patient_id: The unique identifier of the patient
            
        Returns:
            The BiometricTwin if found, None otherwise
        """
        twin_model = self.session.query(BiometricTwinModel).filter(
            BiometricTwinModel.patient_id == str(patient_id)
        ).first()
        
        if not twin_model:
            return None
        
        return self._map_to_entity(twin_model)
    
    def save(self, biometric_twin: BiometricTwinState) -> BiometricTwinState:
        """
        Save a BiometricTwin entity.
        
        This method handles both creation of new entities and updates to existing ones.
        
        Args:
            biometric_twin: The BiometricTwin entity to save
            
        Returns:
            The saved BiometricTwin with any repository-generated fields updated
        """
        # Check if the twin already exists
        existing_model = self.session.query(BiometricTwinModel).filter(
            BiometricTwinModel.twin_id == str(biometric_twin.twin_id)
        ).first()
        
        if existing_model:
            # Update existing twin
            self._update_model(existing_model, biometric_twin)
            twin_model = existing_model
        else:
            # Create new twin
            twin_model = self._map_to_model(biometric_twin)
            self.session.add(twin_model)
        
        # Save data points
        self._save_data_points(biometric_twin)
        
        # Commit changes
        self.session.commit()
        
        # Refresh the model to get any database-generated values
        self.session.refresh(twin_model)
        
        # Return the updated entity
        return self._map_to_entity(twin_model)
    
    def delete(self, twin_id: UUID) -> bool:
        """
        Delete a BiometricTwin by its ID.
        
        Args:
            twin_id: The unique identifier of the BiometricTwin to delete
            
        Returns:
            True if the entity was successfully deleted, False otherwise
        """
        # Delete associated data points first
        data_points_deleted = self.session.query(BiometricDataPointModel).filter(
            BiometricDataPointModel.twin_id == str(twin_id)
        ).delete()
        
        # Delete the twin
        twin_deleted = self.session.query(BiometricTwinModel).filter(
            BiometricTwinModel.twin_id == str(twin_id)
        ).delete()
        
        self.session.commit()
        
        return twin_deleted > 0
    
    def list_by_connected_device(self, device_id: str) -> list[BiometricTwinState]:
        """
        List all BiometricTwin entities connected to a specific device.
        
        Args:
            device_id: The unique identifier of the connected device
            
        Returns:
            List of BiometricTwin entities connected to the specified device
        """
        # Query twins with the specified device in their connected_devices array
        twin_models = self.session.query(BiometricTwinModel).filter(
            BiometricTwinModel.connected_devices.contains([device_id])
        ).all()
        
        return [self._map_to_entity(model) for model in twin_models]
    
    def list_all(self, limit: int = 100, offset: int = 0) -> list[BiometricTwinState]:
        """
        List all BiometricTwin entities with pagination.
        
        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip
            
        Returns:
            List of BiometricTwin entities
        """
        twin_models = self.session.query(BiometricTwinModel).order_by(
            BiometricTwinModel.created_at.desc()
        ).limit(limit).offset(offset).all()
        
        return [self._map_to_entity(model) for model in twin_models]
    
    def count(self) -> int:
        """
        Count the total number of BiometricTwin entities.
        
        Returns:
            The total count of BiometricTwin entities
        """
        return self.session.query(func.count(BiometricTwinModel.twin_id)).scalar()
    
    def _map_to_entity(self, model: BiometricTwinModel) -> BiometricTwinState:
        """
        Map a BiometricTwinModel to a BiometricTwin entity.
        
        Args:
            model: The database model to map
            
        Returns:
            The corresponding domain entity
        """
        # Get data points for this twin
        data_point_models = self.session.query(BiometricDataPointModel).filter(
            BiometricDataPointModel.twin_id == model.twin_id
        ).all()
        
        # Map data points to entities
        data_points = [self._map_data_point_to_entity(dp_model) 
                      for dp_model in data_point_models]
        
        # Create the BiometricTwin entity
        return BiometricTwinState(
            patient_id=UUID(model.patient_id),
            twin_id=UUID(model.twin_id),
            data_points=data_points,
            created_at=model.created_at,
            updated_at=model.updated_at,
            baseline_established=model.baseline_established,
            connected_devices=set(model.connected_devices) if model.connected_devices else set()
        )
    
    def _map_to_model(self, entity: BiometricTwinState) -> BiometricTwinModel:
        """
        Map a BiometricTwin entity to a BiometricTwinModel.
        
        Args:
            entity: The domain entity to map
            
        Returns:
            The corresponding database model
        """
        return BiometricTwinModel(
            twin_id=str(entity.twin_id),
            patient_id=str(entity.patient_id),
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            baseline_established=entity.baseline_established,
            connected_devices=list(entity.connected_devices) if entity.connected_devices else []
        )
    
    def _update_model(self, model: BiometricTwinModel, entity: BiometricTwinState) -> None:
        """
        Update a BiometricTwinModel with values from a BiometricTwin entity.
        
        Args:
            model: The database model to update
            entity: The domain entity with updated values
        """
        model.updated_at = entity.updated_at
        model.baseline_established = entity.baseline_established
        model.connected_devices = list(entity.connected_devices) if entity.connected_devices else []
    
    def _map_data_point_to_entity(self, model: BiometricDataPointModel) -> BiometricDataPoint:
        """
        Map a BiometricDataPointModel to a BiometricDataPoint entity.
        
        Args:
            model: The database model to map
            
        Returns:
            The corresponding domain entity
        """
        return BiometricDataPoint(
            data_type=model.data_type,
            value=self._deserialize_value(model.value, model.value_type),
            timestamp=model.timestamp,
            source=model.source,
            metadata=model.metadata_json,
            confidence=model.confidence,
            data_id=UUID(model.data_id)
        )
    
    def _map_data_point_to_model(
        self, 
        data_point: BiometricDataPoint, 
        twin_id: UUID
    ) -> BiometricDataPointModel:
        """
        Map a BiometricDataPoint entity to a BiometricDataPointModel.
        
        Args:
            data_point: The domain entity to map
            twin_id: The ID of the associated BiometricTwin
            
        Returns:
            The corresponding database model
        """
        value, value_type = self._serialize_value(data_point.value)
        
        return BiometricDataPointModel(
            data_id=str(data_point.data_id),
            twin_id=str(twin_id),
            data_type=data_point.data_type,
            value=value,
            value_type=value_type,
            timestamp=data_point.timestamp,
            source=data_point.source,
            metadata_json=data_point.metadata,
            confidence=data_point.confidence
        )
    
    def _save_data_points(self, entity: BiometricTwinState) -> None:
        """
        Save all data points for a BiometricTwin.
        
        Args:
            entity: The BiometricTwin entity containing data points to save
        """
        # Get existing data point IDs
        existing_data_point_ids = set(
            str(dp_id) for dp_id, in self.session.query(BiometricDataPointModel.data_id).filter(
                BiometricDataPointModel.twin_id == str(entity.twin_id)
            ).all()
        )
        
        # Process each data point
        for data_point in entity.data_points:
            data_point_id = str(data_point.data_id)
            
            if data_point_id in existing_data_point_ids:
                # Data point already exists, remove from set to track processed points
                existing_data_point_ids.remove(data_point_id)
            else:
                # New data point, add to database
                data_point_model = self._map_data_point_to_model(data_point, entity.twin_id)
                self.session.add(data_point_model)
        
        # Any remaining IDs in the set are data points that were removed from the entity
        # We don't delete them here as that should be handled explicitly
    
    def _serialize_value(self, value: Any) -> tuple[str, str]:
        """
        Serialize a value for storage in the database.
        
        Args:
            value: The value to serialize
            
        Returns:
            Tuple of (serialized_value, value_type)
        """
        import json
        
        if isinstance(value, (int, float)):
            return str(value), "number"
        elif isinstance(value, str):
            return value, "string"
        elif isinstance(value, dict):
            return json.dumps(value), "json"
        else:
            # Convert to string as fallback
            return str(value), "string"
    
    def _deserialize_value(self, value: str, value_type: str) -> str | float | int | dict:
        """
        Deserialize a value from the database.
        
        Args:
            value: The serialized value
            value_type: The type of the value
            
        Returns:
            The deserialized value
        """
        import json
        
        if value_type == "number":
            # Try to convert to int first, then float if that fails
            try:
                return int(value)
            except ValueError:
                return float(value)
        elif value_type == "json":
            return json.loads(value)
        else:
            return value