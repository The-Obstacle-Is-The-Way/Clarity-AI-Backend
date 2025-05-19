"""
Digital Twin Repository implementation.

This module provides the repository implementation for digital twin entities,
bridging between the domain model and the database.
"""

import logging
import uuid
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from app.domain.entities.biometric_twin_enhanced import (
    BiometricDataPoint,
    BiometricSource,
    BiometricTimeseriesData,
    BiometricTwin,
    BiometricType,
)
from app.domain.value_objects.physiological_ranges import PhysiologicalRange
from app.infrastructure.persistence.sqlalchemy.models.digital_twin import (
    BiometricDataPointModel,
    BiometricTimeseriesModel,
    DigitalTwinModel,
)

logger = logging.getLogger(__name__)


class DigitalTwinRepository:
    """
    Repository for Digital Twin persistence.

    This repository provides methods to create, retrieve, and update
    digital twin data in the database.
    """

    def __init__(self, session: Session):
        """
        Initialize the repository.

        Args:
            session: SQLAlchemy database session
        """
        self.session = session

    async def get_by_id(self, twin_id: str) -> BiometricTwin | None:
        """
        Get a digital twin by ID.

        Args:
            twin_id: ID of the digital twin

        Returns:
            BiometricTwin entity or None if not found
        """
        try:
            # Query with eager loading of related entities
            model = (
                self.session.query(DigitalTwinModel)
                .filter(DigitalTwinModel.id == twin_id)
                .options(
                    joinedload(DigitalTwinModel.timeseries).joinedload(
                        BiometricTimeseriesModel.data_points
                    )
                )
                .first()
            )

            if not model:
                return None

            # Convert to domain entity
            return self._model_to_entity(model)
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving digital twin by ID {twin_id}: {e}")
            return None

    async def get_by_patient_id(self, patient_id: str) -> BiometricTwin | None:
        """
        Get a digital twin by patient ID.

        Args:
            patient_id: ID of the patient

        Returns:
            BiometricTwin entity or None if not found
        """
        try:
            # Query with eager loading of related entities
            model = (
                self.session.query(DigitalTwinModel)
                .filter(DigitalTwinModel.patient_id == patient_id)
                .options(
                    joinedload(DigitalTwinModel.timeseries).joinedload(
                        BiometricTimeseriesModel.data_points
                    )
                )
                .first()
            )

            if not model:
                return None

            # Convert to domain entity
            return self._model_to_entity(model)
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving digital twin for patient {patient_id}: {e}")
            return None

    async def create(self, twin: BiometricTwin) -> bool:
        """
        Create a new digital twin.

        Args:
            twin: BiometricTwin entity

        Returns:
            True on success, False on failure
        """
        try:
            # Convert domain entity to model
            model = self._entity_to_model(twin)

            # Add to session
            self.session.add(model)
            self.session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(
                f"Error creating digital twin for patient {twin.patient_id}: {e}"
            )
            self.session.rollback()
            return False

    async def update(self, twin: BiometricTwin) -> bool:
        """
        Update an existing digital twin.

        Args:
            twin: BiometricTwin entity

        Returns:
            True on success, False on failure
        """
        try:
            # Check if exists
            existing = (
                self.session.query(DigitalTwinModel)
                .filter(DigitalTwinModel.id == twin.id)
                .first()
            )

            if not existing:
                logger.error(f"Digital twin with ID {twin.id} not found for update")
                return False

            # Update twin attributes
            existing.updated_at = datetime.now()

            # Handle timeseries data - update existing or add new
            self._update_timeseries_data(existing, twin)

            self.session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(
                f"Error updating digital twin for patient {twin.patient_id}: {e}"
            )
            self.session.rollback()
            return False

    async def delete(self, twin_id: str) -> bool:
        """
        Delete a digital twin.

        Args:
            twin_id: ID of the digital twin

        Returns:
            True on success, False on failure
        """
        try:
            # Find the model
            model = (
                self.session.query(DigitalTwinModel)
                .filter(DigitalTwinModel.id == twin_id)
                .first()
            )

            if not model:
                logger.error(f"Digital twin with ID {twin_id} not found for deletion")
                return False

            # Delete the model (cascade will remove related timeseries and data points)
            self.session.delete(model)
            self.session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(f"Error deleting digital twin with ID {twin_id}: {e}")
            self.session.rollback()
            return False

    def _model_to_entity(self, model: DigitalTwinModel) -> BiometricTwin:
        """
        Convert an ORM model to a domain entity.

        Args:
            model: DigitalTwinModel instance

        Returns:
            BiometricTwin domain entity
        """
        # Build timeseries data
        timeseries_data = {}
        for ts_model in model.timeseries:
            # Convert to correct BiometricType
            try:
                biometric_type = BiometricType(ts_model.biometric_type)
            except ValueError:
                # Fallback for unknown types
                biometric_type = ts_model.biometric_type

            # Create data points
            data_points = []
            for dp_model in ts_model.data_points:
                try:
                    source = BiometricSource(dp_model.source)
                except ValueError:
                    source = dp_model.source

                data_points.append(
                    BiometricDataPoint(
                        timestamp=dp_model.timestamp,
                        value=dp_model.value,
                        source=source,
                        metadata=dp_model.metadata,
                    )
                )

            # Create physiological range
            range_data = None
            if ts_model.physiological_range:
                range_data = PhysiologicalRange.from_dict(ts_model.physiological_range)

            # Create timeseries
            timeseries_data[biometric_type] = BiometricTimeseriesData(
                biometric_type=biometric_type,
                unit=ts_model.unit,
                data_points=data_points,
                physiological_range=range_data,
            )

        # Create digital twin entity
        return BiometricTwin(
            id=model.id,
            patient_id=model.patient_id,
            timeseries_data=timeseries_data,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    def _entity_to_model(self, entity: BiometricTwin) -> DigitalTwinModel:
        """
        Convert a domain entity to an ORM model.

        Args:
            entity: BiometricTwin domain entity

        Returns:
            DigitalTwinModel instance
        """
        # Create twin model
        twin_model = DigitalTwinModel(
            id=entity.id,
            patient_id=entity.patient_id,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )

        # Add timeseries data
        for biometric_type, timeseries in entity.timeseries_data.items():
            # Convert to string type if needed
            type_str = (
                biometric_type.value
                if isinstance(biometric_type, BiometricType)
                else str(biometric_type)
            )

            # Create timeseries model
            ts_model = BiometricTimeseriesModel(
                id=str(uuid.uuid4()),
                biometric_type=type_str,
                unit=timeseries.unit,
                created_at=entity.created_at,
                updated_at=entity.updated_at,
            )

            # Set physiological range
            if timeseries.physiological_range:
                ts_model.physiological_range = timeseries.physiological_range.to_dict()

            # Add data points
            for data_point in timeseries.data_points:
                source_str = (
                    data_point.source.value
                    if isinstance(data_point.source, BiometricSource)
                    else str(data_point.source)
                )

                dp_model = BiometricDataPointModel(
                    id=str(uuid.uuid4()),
                    timestamp=data_point.timestamp,
                    source=source_str,
                    created_at=entity.created_at,
                )

                # Set value and metadata
                dp_model.value = data_point.value
                dp_model.metadata = data_point.metadata

                # Add to timeseries
                ts_model.data_points.append(dp_model)

            # Add to twin
            twin_model.timeseries.append(ts_model)

        return twin_model

    def _update_timeseries_data(
        self, model: DigitalTwinModel, entity: BiometricTwin
    ) -> None:
        """
        Update timeseries data in the ORM model.

        Args:
            model: DigitalTwinModel to update
            entity: BiometricTwin with new data
        """
        # Map existing timeseries by type for easy lookup
        existing_timeseries = {ts.biometric_type: ts for ts in model.timeseries}

        # Process each timeseries in the entity
        for biometric_type, timeseries in entity.timeseries_data.items():
            # Convert to string type if needed
            type_str = (
                biometric_type.value
                if isinstance(biometric_type, BiometricType)
                else str(biometric_type)
            )

            # Check if exists
            if type_str in existing_timeseries:
                # Update existing timeseries
                ts_model = existing_timeseries[type_str]
                ts_model.unit = timeseries.unit
                ts_model.updated_at = datetime.now()

                # Update physiological range
                if timeseries.physiological_range:
                    ts_model.physiological_range = (
                        timeseries.physiological_range.to_dict()
                    )
                else:
                    ts_model.physiological_range = None

                # Map existing data points by timestamp for lookup
                existing_data_points = {
                    dp.timestamp.isoformat(): dp for dp in ts_model.data_points
                }

                # Process each data point
                for data_point in timeseries.data_points:
                    timestamp_str = data_point.timestamp.isoformat()
                    source_str = (
                        data_point.source.value
                        if isinstance(data_point.source, BiometricSource)
                        else str(data_point.source)
                    )

                    if timestamp_str in existing_data_points:
                        # Update existing data point
                        dp_model = existing_data_points[timestamp_str]
                        dp_model.source = source_str
                        dp_model.value = data_point.value
                        dp_model.metadata = data_point.metadata
                    else:
                        # Add new data point
                        dp_model = BiometricDataPointModel(
                            id=str(uuid.uuid4()),
                            timestamp=data_point.timestamp,
                            source=source_str,
                            created_at=datetime.now(),
                        )
                        dp_model.value = data_point.value
                        dp_model.metadata = data_point.metadata
                        ts_model.data_points.append(dp_model)
            else:
                # Create new timeseries
                ts_model = BiometricTimeseriesModel(
                    id=str(uuid.uuid4()),
                    biometric_type=type_str,
                    unit=timeseries.unit,
                    created_at=datetime.now(),
                    updated_at=datetime.now(),
                )

                # Set physiological range
                if timeseries.physiological_range:
                    ts_model.physiological_range = (
                        timeseries.physiological_range.to_dict()
                    )

                # Add data points
                for data_point in timeseries.data_points:
                    source_str = (
                        data_point.source.value
                        if isinstance(data_point.source, BiometricSource)
                        else str(data_point.source)
                    )

                    dp_model = BiometricDataPointModel(
                        id=str(uuid.uuid4()),
                        timestamp=data_point.timestamp,
                        source=source_str,
                        created_at=datetime.now(),
                    )
                    dp_model.value = data_point.value
                    dp_model.metadata = data_point.metadata
                    ts_model.data_points.append(dp_model)

                # Add to twin
                model.timeseries.append(ts_model)
