"""
SQL Alchemy implementation of the temporal sequence repository.

This module provides a SQLAlchemy-based implementation of the
TemporalSequenceRepository interface for time-series data storage and retrieval.
"""

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.temporal_sequence import TemporalSequence, TimePoint
from app.domain.repositories.temporal_repository import TemporalSequenceRepository
from app.infrastructure.persistence.sqlalchemy.models.temporal_sequence_model import (
    TemporalDataPointModel,
    TemporalSequenceModel,
)


class SqlAlchemyTemporalSequenceRepository(TemporalSequenceRepository):
    """
    SQLAlchemy implementation of the temporal sequence repository.
    
    This repository handles the persistence of temporal sequences, including
    serialization/deserialization between domain entities and database models.
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize with a SQLAlchemy session."""
        self.session = session
    
    async def save(self, sequence: TemporalSequence) -> UUID:
        """
        Persist a temporal sequence.
        
        Args:
            sequence: The domain entity to persist
            
        Returns:
            UUID of the saved sequence
        """
        # Convert domain entity to ORM models
        
        # Create sequence model
        sequence_model = TemporalSequenceModel(
            sequence_id=sequence.sequence_id,
            patient_id=sequence.patient_id,
            feature_names=sequence.feature_names,
            sequence_metadata=sequence.metadata
        )
        
        # Create data point models for each time point
        data_points = []
        for i, tp in enumerate(sequence.time_points):
            data_point = TemporalDataPointModel(
                sequence_id=sequence.sequence_id,
                position=i,
                timestamp=tp.time_value,
                values=tp.data
            )
            data_points.append(data_point)
        
        # Save to database
        self.session.add(sequence_model)
        self.session.add_all(data_points)
        await self.session.flush()
        
        return sequence.sequence_id
    
    async def get_by_id(self, sequence_id: UUID) -> TemporalSequence | None:
        """
        Retrieve a temporal sequence by ID.
        
        Args:
            sequence_id: UUID of the sequence to retrieve
            
        Returns:
            TemporalSequence if found, None otherwise
        """
        # Get sequence model
        result = await self.session.execute(
            sa.select(TemporalSequenceModel).where(
                TemporalSequenceModel.sequence_id == sequence_id
            )
        )
        sequence_model = result.scalars().first()
        
        if not sequence_model:
            return None
        
        # Get data points
        result = await self.session.execute(
            sa.select(TemporalDataPointModel)
            .where(TemporalDataPointModel.sequence_id == sequence_id)
            .order_by(TemporalDataPointModel.position)
        )
        data_points = result.scalars().all()
        
        # Convert to domain entity
        time_points = [
            TimePoint(time_value=dp.timestamp, data=dp.values)
            for dp in data_points
        ]
        
        return TemporalSequence(
            sequence_id=sequence_model.sequence_id,
            patient_id=sequence_model.patient_id,
            feature_names=sequence_model.feature_names,
            time_points=time_points,
            metadata=sequence_model.sequence_metadata
        )
    
    async def get_by_patient_id(self, patient_id: UUID) -> list[TemporalSequence]:
        """
        Get all temporal sequences for a patient.
        
        Args:
            patient_id: UUID of the patient
            
        Returns:
            List of temporal sequences
        """
        # Get sequence models
        result = await self.session.execute(
            sa.select(TemporalSequenceModel).where(
                TemporalSequenceModel.patient_id == patient_id
            )
        )
        sequence_models = result.scalars().all()
        
        # Build list of domain entities
        sequences = []
        for seq_model in sequence_models:
            # Get data points for this sequence
            result = await self.session.execute(
                sa.select(TemporalDataPointModel)
                .where(TemporalDataPointModel.sequence_id == seq_model.sequence_id)
                .order_by(TemporalDataPointModel.position)
            )
            data_points = result.scalars().all()
            
            # Convert to domain entity
            time_points = [
                TimePoint(time_value=dp.timestamp, data=dp.values)
                for dp in data_points
            ]
            
            sequence = TemporalSequence(
                sequence_id=seq_model.sequence_id,
                patient_id=seq_model.patient_id,
                feature_names=seq_model.feature_names,
                time_points=time_points,
                metadata=seq_model.sequence_metadata
            )
            sequences.append(sequence)
        
        return sequences
    
    async def delete(self, sequence_id: UUID) -> bool:
        """
        Delete a temporal sequence.
        
        Args:
            sequence_id: UUID of the sequence to delete
            
        Returns:
            True if deletion was successful
        """
        # Delete data points first (foreign key constraint)
        await self.session.execute(
            sa.delete(TemporalDataPointModel).where(
                TemporalDataPointModel.sequence_id == sequence_id
            )
        )
        
        # Delete sequence
        result = await self.session.execute(
            sa.delete(TemporalSequenceModel).where(
                TemporalSequenceModel.sequence_id == sequence_id
            )
        )
        
        return result.rowcount > 0
    
    async def get_latest_by_feature(
        self, 
        patient_id: UUID, 
        feature_name: str,
        limit: int = 10
    ) -> TemporalSequence | None:
        """
        Get the most recent temporal sequence containing a specific feature.
        
        Args:
            patient_id: UUID of the patient
            feature_name: Name of the feature to find
            limit: Maximum number of entries to return
            
        Returns:
            The most recent temporal sequence containing the feature
        """
        # Find sequences containing the feature
        result = await self.session.execute(
            sa.select(TemporalSequenceModel)
            .where(
                TemporalSequenceModel.patient_id == patient_id,
                TemporalSequenceModel.feature_names.contains([feature_name])
            )
            .order_by(sa.desc(TemporalSequenceModel.created_at))
            .limit(limit)
        )
        sequence_models = result.scalars().all()
        
        if not sequence_models:
            return None
        
        # Get the most recent sequence
        latest_model = sequence_models[0]
        
        # Get data points
        result = await self.session.execute(
            sa.select(TemporalDataPointModel)
            .where(TemporalDataPointModel.sequence_id == latest_model.sequence_id)
            .order_by(TemporalDataPointModel.position)
        )
        data_points = result.scalars().all()
        
        # Convert to domain entity
        time_points = [
            TimePoint(time_value=dp.timestamp, data=dp.values)
            for dp in data_points
        ]
        
        return TemporalSequence(
            sequence_id=latest_model.sequence_id,
            patient_id=latest_model.patient_id,
            feature_names=latest_model.feature_names,
            time_points=time_points,
            metadata=latest_model.sequence_metadata
        ) 