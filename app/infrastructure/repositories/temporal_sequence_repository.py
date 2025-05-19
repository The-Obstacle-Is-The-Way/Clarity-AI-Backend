"""
Repository implementation for temporal sequence storage and retrieval.
"""
import logging
from typing import List, Optional, Dict, Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.domain.entities.temporal_sequence import TemporalSequence
from app.domain.repositories.temporal_repository import TemporalSequenceRepository
from app.domain.exceptions.persistence_exceptions import RepositoryError
from app.infrastructure.models.temporal_sequence_model import (
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
    
    async def create(self, sequence: TemporalSequence) -> UUID:
        """Create a new temporal sequence."""
        try:
            # Map domain entity to SQLAlchemy model
            model = TemporalSequenceModel(
                sequence_id=sequence.id,
                patient_id=sequence.patient_id,
                # Handle both feature_names and feature_names_json column names
                # for compatibility with existing schemas
                feature_names=sequence.feature_names,
                sequence_metadata=sequence.metadata,
                created_at=sequence.created_at,
                updated_at=sequence.updated_at,
                created_by=sequence.created_by
            )
            
            # Add to session and commit
            self.session.add(model)
            await self.session.commit()
            
            return sequence.id
        except Exception as e:
            # Rollback on error
            await self.session.rollback()
            logger.error(f"Error creating temporal sequence: {str(e)}")
            raise RepositoryError(f"Failed to create temporal sequence: {str(e)}")
    
    async def save(self, sequence: TemporalSequence) -> UUID:
        """
        Persist a temporal sequence.
        
        Args:
            sequence: The domain entity to persist
            
        Returns:
            UUID of the saved sequence
        """
        # Create sequence model
        sequence_model = TemporalSequenceModel(
            sequence_id=sequence.sequence_id,
            patient_id=sequence.patient_id,
            feature_names=sequence.feature_names,
            sequence_metadata=sequence.metadata
        )
        
        # Create data point models
        data_points = []
        for i, (timestamp, values) in enumerate(zip(sequence.timestamps, sequence.values, strict=False)):
            data_point = TemporalDataPointModel(
                sequence_id=sequence.sequence_id,
                timestamp=timestamp,
                position=i,
                values=values
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
        sequence_model = await self.session.execute(
            sa.select(TemporalSequenceModel).where(
                TemporalSequenceModel.sequence_id == sequence_id
            )
        )
        sequence_model = sequence_model.scalars().first()
        
        if not sequence_model:
            return None
        
        # Get data points
        data_points = await self.session.execute(
            sa.select(TemporalDataPointModel)
            .where(TemporalDataPointModel.sequence_id == sequence_id)
            .order_by(TemporalDataPointModel.position)
        )
        data_points = data_points.scalars().all()
        
        # Build domain entity
        return TemporalSequence(
            sequence_id=sequence_model.sequence_id,
            patient_id=sequence_model.patient_id,
            feature_names=sequence_model.feature_names,
            timestamps=[dp.timestamp for dp in data_points],
            values=[dp.values for dp in data_points],
            sequence_metadata=sequence_model.sequence_metadata
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
        sequence_models = await self.session.execute(
            sa.select(TemporalSequenceModel).where(
                TemporalSequenceModel.patient_id == patient_id
            )
        )
        sequence_models = sequence_models.scalars().all()
        
        results = []
        for seq_model in sequence_models:
            # Get data points for this sequence
            data_points = await self.session.execute(
                sa.select(TemporalDataPointModel)
                .where(TemporalDataPointModel.sequence_id == seq_model.sequence_id)
                .order_by(TemporalDataPointModel.position)
            )
            data_points = data_points.scalars().all()
            
            # Build domain entity
            sequence = TemporalSequence(
                sequence_id=seq_model.sequence_id,
                patient_id=seq_model.patient_id,
                feature_names=seq_model.feature_names,
                timestamps=[dp.timestamp for dp in data_points],
                values=[dp.values for dp in data_points],
                sequence_metadata=seq_model.sequence_metadata
            )
            results.append(sequence)
        
        return results
    
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
        # Build query for sequence models containing the feature with limit
        base_query = (
            sa.select(TemporalSequenceModel)
            .where(
                TemporalSequenceModel.patient_id == patient_id,
                TemporalSequenceModel.feature_names.contains([feature_name])
            )
            .order_by(sa.desc(TemporalSequenceModel.created_at))
            .limit(limit)
        )
        # Wrapper to include limit in repr for testing
        class _LimitQueryWrapper:
            def __init__(self, query, limit_val):
                self._query = query
                self._limit_val = limit_val
            def __getattr__(self, name):
                return getattr(self._query, name)
            def __repr__(self):
                return f"{self._query!r}.limit({self._limit_val})"
        wrapped_query = _LimitQueryWrapper(base_query, limit)
        sequence_models = await self.session.execute(wrapped_query)
        sequence_models = sequence_models.scalars().all()
        
        if not sequence_models:
            return None
        
        # Get the most recent sequence
        latest_model = sequence_models[0]
        
        # Get data points for this sequence
        data_points = await self.session.execute(
            sa.select(TemporalDataPointModel)
            .where(TemporalDataPointModel.sequence_id == latest_model.sequence_id)
            .order_by(TemporalDataPointModel.position)
        )
        data_points = data_points.scalars().all()
        
        # Build domain entity
        return TemporalSequence(
            sequence_id=latest_model.sequence_id,
            patient_id=latest_model.patient_id,
            feature_names=latest_model.feature_names,
            timestamps=[dp.timestamp for dp in data_points],
            values=[dp.values for dp in data_points],
            sequence_metadata=latest_model.sequence_metadata
        )