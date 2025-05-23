"""
SQLAlchemy implementation of the BiometricTwinRepository.

This module provides a concrete implementation of the BiometricTwinRepository
interface using SQLAlchemy ORM for database operations with proper Data Mapper pattern.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.domain.entities.biometric_twin_enhanced import (
    BiometricDataPoint,
    BiometricSource,
    BiometricTimeseriesData,
    BiometricTwin,
    BiometricType,
)
from app.domain.repositories.biometric_twin_repository import BiometricTwinRepository
from app.infrastructure.persistence.sqlalchemy.models.biometric_twin_model import (
    BiometricDataPointModel,
    BiometricTwinModel,
)


class SQLAlchemyBiometricTwinRepository(BiometricTwinRepository):
    """
    SQLAlchemy implementation of the BiometricTwinRepository interface.

    This class provides concrete implementations of the repository methods
    using SQLAlchemy ORM for database operations with proper Clean Architecture
    Data Mapper pattern to convert between domain entities and persistence models.
    """

    def __init__(self, session: Session) -> None:
        """
        Initialize the repository with a SQLAlchemy session.

        Args:
            session: SQLAlchemy database session
        """
        self.session = session

    def get_by_id(self, twin_id: UUID) -> BiometricTwin | None:
        """
        Retrieve a BiometricTwin by its ID.

        Args:
            twin_id: The unique identifier of the BiometricTwin

        Returns:
            The BiometricTwin if found, None otherwise
        """
        twin_model = (
            self.session.query(BiometricTwinModel).filter(BiometricTwinModel.id == twin_id).first()
        )

        if not twin_model:
            return None

        return self._map_to_entity(twin_model)

    def get_by_patient_id(self, patient_id: UUID) -> BiometricTwin | None:
        """
        Retrieve a BiometricTwin by the associated patient ID.

        Args:
            patient_id: The unique identifier of the patient

        Returns:
            The BiometricTwin if found, None otherwise
        """
        twin_model = (
            self.session.query(BiometricTwinModel)
            .filter(BiometricTwinModel.patient_id == patient_id)
            .first()
        )

        if not twin_model:
            return None

        return self._map_to_entity(twin_model)

    def save(self, biometric_twin: BiometricTwin) -> BiometricTwin:
        """
        Save a BiometricTwin entity.

        This method handles both creation of new entities and updates to existing ones.

        Args:
            biometric_twin: The BiometricTwin entity to save

        Returns:
            The saved BiometricTwin with any repository-generated fields updated
        """
        # Check if the twin already exists
        existing_model = (
            self.session.query(BiometricTwinModel)
            .filter(BiometricTwinModel.id == biometric_twin.id)
            .first()
        )

        if existing_model:
            # Update existing twin
            self._update_model(existing_model, biometric_twin)
            twin_model = existing_model
        else:
            # Create new twin
            twin_model = self._map_to_model(biometric_twin)
            self.session.add(twin_model)

        # Save timeseries data
        self._save_timeseries_data(biometric_twin)

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
        data_points_deleted = (
            self.session.query(BiometricDataPointModel)
            .filter(BiometricDataPointModel.twin_id == twin_id)
            .delete()
        )

        # Delete the twin
        twin_deleted = (
            self.session.query(BiometricTwinModel).filter(BiometricTwinModel.id == twin_id).delete()
        )

        self.session.commit()

        return twin_deleted > 0

    def list_by_connected_device(self, device_id: str) -> list[BiometricTwin]:
        """
        List all BiometricTwin entities connected to a specific device.

        Args:
            device_id: The unique identifier of the connected device

        Returns:
            List of BiometricTwin entities connected to the specified device
        """
        # Query twins with the specified device in their connected_devices array
        twin_models = (
            self.session.query(BiometricTwinModel)
            .filter(BiometricTwinModel.connected_devices.contains([device_id]))
            .all()
        )

        return [self._map_to_entity(model) for model in twin_models]

    def list_all(self, limit: int = 100, offset: int = 0) -> list[BiometricTwin]:
        """
        List all BiometricTwin entities with pagination.

        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip

        Returns:
            List of BiometricTwin entities
        """
        twin_models = (
            self.session.query(BiometricTwinModel)
            .order_by(BiometricTwinModel.created_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )

        return [self._map_to_entity(model) for model in twin_models]

    def count(self) -> int:
        """
        Count the total number of BiometricTwin entities.

        Returns:
            The total count of BiometricTwin entities
        """
        result = self.session.query(func.count(BiometricTwinModel.id)).scalar()
        return int(result) if result is not None else 0

    def _map_to_entity(self, model: BiometricTwinModel) -> BiometricTwin:
        """
        Map a BiometricTwinModel to a BiometricTwin entity using Data Mapper pattern.

        Args:
            model: The database model to map

        Returns:
            The corresponding domain entity
        """
        # Get data points for this twin
        data_point_models = (
            self.session.query(BiometricDataPointModel)
            .filter(BiometricDataPointModel.twin_id == model.id)
            .order_by(BiometricDataPointModel.timestamp)
            .all()
        )

        # Group data points by biometric type to create timeseries
        timeseries_data: dict[BiometricType, BiometricTimeseriesData] = {}
        data_points_by_type: dict[BiometricType, list[BiometricDataPoint]] = {}

        for dp_model in data_point_models:
            try:
                biometric_type = BiometricType(dp_model.data_type)
            except ValueError:
                # Skip unknown biometric types for forward compatibility
                continue

            if biometric_type not in data_points_by_type:
                data_points_by_type[biometric_type] = []

            # Map data point model to domain entity
            # Note: MyPy sees Column descriptors, but at runtime these are actual values
            data_point = BiometricDataPoint(
                timestamp=dp_model.timestamp,  # type: ignore[arg-type]
                value=self._deserialize_value(dp_model.value, dp_model.value_type),  # type: ignore[arg-type]
                source=BiometricSource(dp_model.source) if dp_model.source else BiometricSource.CLINICAL,  # type: ignore[arg-type]
                metadata=dp_model.metadata_json or {},  # type: ignore[arg-type]
            )

            data_points_by_type[biometric_type].append(data_point)

        # Create timeseries for each biometric type
        for biometric_type, data_points in data_points_by_type.items():
            # Get appropriate unit for this biometric type
            unit = self._get_unit_for_biometric_type(biometric_type)

            timeseries = BiometricTimeseriesData(
                biometric_type=biometric_type,
                unit=unit,
                data_points=data_points,
            )
            timeseries_data[biometric_type] = timeseries

        # Create the BiometricTwin entity
        # Note: MyPy sees Column descriptors, but at runtime these are actual values
        return BiometricTwin(
            id=str(model.id),
            patient_id=str(model.patient_id),  # type: ignore[arg-type]
            timeseries_data=timeseries_data,
            created_at=model.created_at,  # type: ignore[arg-type]
            updated_at=model.updated_at,  # type: ignore[arg-type]
        )

    def _map_to_model(self, entity: BiometricTwin) -> BiometricTwinModel:
        """
        Map a BiometricTwin entity to a BiometricTwinModel using Data Mapper pattern.

        Args:
            entity: The domain entity to map

        Returns:
            The corresponding database model
        """
        # Extract connected devices from timeseries metadata if any
        connected_devices = set()
        for timeseries in entity.timeseries_data.values():
            for data_point in timeseries.data_points:
                if "device_id" in data_point.metadata:
                    connected_devices.add(data_point.metadata["device_id"])

        return BiometricTwinModel(
            id=entity.id,
            patient_id=entity.patient_id,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            baseline_established=True,  # Assume baseline is established if we have data
            connected_devices=list(connected_devices),
        )

    def _update_model(self, model: BiometricTwinModel, entity: BiometricTwin) -> None:
        """
        Update a BiometricTwinModel with values from a BiometricTwin entity.

        Args:
            model: The database model to update
            entity: The domain entity with updated values
        """
        # Note: MyPy sees Column descriptors, but at runtime these are actual attributes
        model.updated_at = entity.updated_at  # type: ignore[assignment]

        # Update connected devices
        connected_devices = set()
        for timeseries in entity.timeseries_data.values():
            for data_point in timeseries.data_points:
                if "device_id" in data_point.metadata:
                    connected_devices.add(data_point.metadata["device_id"])

        model.connected_devices = list(connected_devices)  # type: ignore[assignment]
        model.baseline_established = bool(entity.timeseries_data)  # type: ignore[assignment]

    def _save_timeseries_data(self, entity: BiometricTwin) -> None:
        """
        Save all timeseries data for a BiometricTwin.

        Args:
            entity: The BiometricTwin entity containing timeseries data to save
        """
        # Get existing data point IDs to avoid duplicates
        existing_data_points = set(
            str(dp_id)
            for dp_id, in self.session.query(BiometricDataPointModel.data_id)
            .filter(BiometricDataPointModel.twin_id == entity.id)
            .all()
        )

        # Process each timeseries
        for biometric_type, timeseries in entity.timeseries_data.items():
            for data_point in timeseries.data_points:
                # Generate a unique ID for the data point if needed
                data_point_id = (
                    f"{entity.id}_{biometric_type.value}_{int(data_point.timestamp.timestamp())}"
                )

                if data_point_id not in existing_data_points:
                    # New data point, add to database
                    data_point_model = self._map_data_point_to_model(
                        data_point, entity.id, biometric_type, data_point_id
                    )
                    self.session.add(data_point_model)

    def _map_data_point_to_model(
        self,
        data_point: BiometricDataPoint,
        twin_id: str,
        biometric_type: BiometricType,
        data_point_id: str,
    ) -> BiometricDataPointModel:
        """
        Map a BiometricDataPoint entity to a BiometricDataPointModel.

        Args:
            data_point: The domain entity to map
            twin_id: The ID of the associated BiometricTwin
            biometric_type: The type of biometric data
            data_point_id: Unique identifier for the data point

        Returns:
            The corresponding database model
        """
        value, value_type = self._serialize_value(data_point.value)

        return BiometricDataPointModel(
            data_id=data_point_id,
            twin_id=twin_id,
            data_type=biometric_type.value,
            value=value,
            value_type=value_type,
            timestamp=data_point.timestamp,
            source=data_point.source.value,
            metadata_json=data_point.metadata,
            confidence=1.0,  # Default confidence if not specified
        )

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

    def _deserialize_value(self, value: str, value_type: str) -> str | float | int | dict[Any, Any]:
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
            result: dict[str, Any] = json.loads(value)
            return result
        else:
            return value

    def _get_unit_for_biometric_type(self, biometric_type: BiometricType) -> str:
        """
        Get the appropriate unit for a biometric type.

        Args:
            biometric_type: The biometric type

        Returns:
            The unit string for the biometric type
        """
        unit_map = {
            BiometricType.HEART_RATE: "bpm",
            BiometricType.BLOOD_PRESSURE: "mmHg",
            BiometricType.TEMPERATURE: "°C",
            BiometricType.RESPIRATORY_RATE: "breaths/min",
            BiometricType.BLOOD_GLUCOSE: "mg/dL",
            BiometricType.OXYGEN_SATURATION: "%",
            BiometricType.WEIGHT: "kg",
            BiometricType.HRV: "ms",
            BiometricType.SLEEP: "hours",
            BiometricType.ACTIVITY: "steps",
            BiometricType.STRESS: "score",
            BiometricType.MOOD: "score",
        }
        return unit_map.get(biometric_type, "")


# Export alias to maintain backward compatibility with names used in UnitOfWorkFactory
BiometricTwinRepositoryImpl = SQLAlchemyBiometricTwinRepository
