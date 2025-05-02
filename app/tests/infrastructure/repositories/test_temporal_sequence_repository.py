"""
Tests for the SQL Alchemy implementation of the temporal sequence repository.
"""
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.temporal_sequence import TemporalSequence
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.models.temporal_sequence_model import (
    TemporalDataPointModel,
    TemporalSequenceModel,
)
from app.infrastructure.repositories.temporal_sequence_repository import (
    SqlAlchemyTemporalSequenceRepository,
)


@pytest.fixture
def mock_session():
    """Create a mock SQLAlchemy session for testing."""
    session = AsyncMock(spec=AsyncSession)

    # Mock for execute that will be customized in tests
    session.execute = AsyncMock()

    # Mock for add and add_all
    session.add = MagicMock()
    session.add_all = MagicMock()

    # Mock for flush
    session.flush = AsyncMock()

    return session


@pytest.fixture
@pytest.mark.db_required()
def test_sequence():
    """Create a test temporal sequence for tests."""
    now = datetime.now(UTC)
    sequence_id = uuid4()
    patient_id = uuid4()

    # Create sequence with three time points
    sequence = TemporalSequence(
        sequence_id=sequence_id,
        patient_id=patient_id,
        feature_names=["dopamine", "serotonin", "gaba"],
        timestamps=[
            now,
            now + timedelta(hours=1),
            now + timedelta(hours=2)
        ],
        values=[
            [0.5, 0.3, 0.7],
            [0.6, 0.4, 0.6],
            [0.7, 0.5, 0.5]
        ],
        sequence_metadata={"source": "test", "type": "neurotransmitter_levels"}  # Renamed
    )

    return sequence


@pytest.fixture
def mock_sequence_model():
    """Create a mock sequence model for tests."""
    now = datetime.now(UTC)
    sequence_id = uuid4()

    model = MagicMock(spec=TemporalSequenceModel)
    model.sequence_id = sequence_id
    model.patient_id = uuid4()
    model.feature_names = ["dopamine", "serotonin", "gaba"]
    model.sequence_metadata = {"source": "test", "type": "neurotransmitter_levels"}  # Renamed
    model.created_at = now

    return model


@pytest.fixture
def mock_data_points(mock_sequence_model):
    """Create mock data points for tests."""
    now = datetime.now(UTC)

    data_points = []
    for i in range(3):
        point = MagicMock(spec=TemporalDataPointModel)
        point.sequence_id = mock_sequence_model.sequence_id
        point.position = i
        point.timestamp = now + timedelta(hours=i)
        point.values = [0.5 + (i * 0.1), 0.3 + (i * 0.1), 0.7 - (i * 0.1)]
        data_points.append(point)

    return data_points


class TestSqlAlchemyTemporalSequenceRepository:
    """Tests for SqlAlchemyTemporalSequenceRepository."""

    def test_init(self, mock_session):
        """Test repository initialization."""
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)
        assert repo.session == mock_session

    @pytest.mark.asyncio()
    async def test_save(self, mock_session, test_sequence):
        """Test saving a temporal sequence."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Execute
        result = await repo.save(test_sequence)

        # Verify
        assert result == test_sequence.sequence_id
        mock_session.add.assert_called_once()
        mock_session.add_all.assert_called_once()
        mock_session.flush.assert_awaited_once()

        # Verify model creation
        added_model = mock_session.add.call_args[0][0]
        assert isinstance(added_model, TemporalSequenceModel)
        assert added_model.sequence_id == test_sequence.sequence_id
        assert added_model.patient_id == test_sequence.patient_id
        assert added_model.feature_names == test_sequence.feature_names
        assert added_model.sequence_metadata == test_sequence.sequence_metadata  # Renamed

        # Verify data points creation
        data_points = mock_session.add_all.call_args[0][0]
        assert len(data_points) == len(test_sequence.timestamps)
        for i, point in enumerate(data_points):
            assert isinstance(point, TemporalDataPointModel)
            assert point.sequence_id == test_sequence.sequence_id
            assert point.position == i
            assert point.timestamp == test_sequence.timestamps[i]
            assert point.values == test_sequence.values[i]

    @pytest.mark.asyncio()
    async def test_get_by_id_found(self, mock_session, mock_sequence_model, mock_data_points):
        """Test getting a sequence by ID when found."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock the query results
        mock_sequence_result = MagicMock()
        mock_sequence_result.scalars = MagicMock(return_value=mock_sequence_result)
        mock_sequence_result.first = MagicMock(return_value=mock_sequence_model)

        mock_data_points_result = MagicMock()
        mock_data_points_result.scalars = MagicMock(return_value=mock_data_points_result)
        mock_data_points_result.all = MagicMock(return_value=mock_data_points)

        mock_session.execute.side_effect = [mock_sequence_result, mock_data_points_result]

        # Execute
        result = await repo.get_by_id(mock_sequence_model.sequence_id)

        # Verify
        assert result is not None
        assert result.sequence_id == mock_sequence_model.sequence_id
        assert result.patient_id == mock_sequence_model.patient_id
        assert result.feature_names == mock_sequence_model.feature_names
        assert result.sequence_metadata == mock_sequence_model.sequence_metadata  # Renamed
        assert len(result.timestamps) == len(mock_data_points)
        assert len(result.values) == len(mock_data_points)

        # Verify that execute was called twice
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio()
    async def test_get_by_id_not_found(self, mock_session):
        """Test getting a sequence by ID when not found."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock the query results for sequence not found
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_result)
        mock_result.first = MagicMock(return_value=None)

        mock_session.execute.return_value = mock_result

        # Execute
        result = await repo.get_by_id(uuid4())

        # Verify
        assert result is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio()
    async def test_get_by_patient_id(self, mock_session, mock_sequence_model, mock_data_points):
        """Test getting sequences by patient ID."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock the query results
        mock_sequence_result = MagicMock()
        mock_sequence_result.scalars = MagicMock(return_value=mock_sequence_result)
        mock_sequence_result.all = MagicMock(return_value=[mock_sequence_model])

        mock_data_points_result = MagicMock()
        mock_data_points_result.scalars = MagicMock(return_value=mock_data_points_result)
        mock_data_points_result.all = MagicMock(return_value=mock_data_points)

        mock_session.execute.side_effect = [mock_sequence_result, mock_data_points_result]

        # Execute
        results = await repo.get_by_patient_id(mock_sequence_model.patient_id)

        # Verify
        assert len(results) == 1
        assert results[0].sequence_id == mock_sequence_model.sequence_id
        assert results[0].patient_id == mock_sequence_model.patient_id
        assert len(results[0].timestamps) == len(mock_data_points)

        # Verify that execute was called twice
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio()
    async def test_delete_success(self, mock_session):
        """Test deleting a sequence successfully."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock successful deletion (rowcount > 0)
        mock_result1 = MagicMock()
        mock_result1.rowcount = 2  # Deleted data points

        mock_result2 = MagicMock()
        mock_result2.rowcount = 1  # Deleted sequence

        mock_session.execute.side_effect = [mock_result1, mock_result2]

        # Execute
        result = await repo.delete(uuid4())

        # Verify
        assert result is True
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio()
    async def test_delete_not_found(self, mock_session):
        """Test deleting a sequence that doesn't exist."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock unsuccessful deletion (rowcount = 0)
        mock_result1 = MagicMock()
        mock_result1.rowcount = 0  # No data points deleted

        mock_result2 = MagicMock()
        mock_result2.rowcount = 0  # No sequence deleted

        mock_session.execute.side_effect = [mock_result1, mock_result2]

        # Execute
        result = await repo.delete(uuid4())

        # Verify
        assert result is False
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio()
    async def test_get_latest_by_feature(self, mock_session, mock_sequence_model, mock_data_points):
        """Test getting the latest sequence containing a specific feature."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock the query results
        mock_sequence_result = MagicMock()
        mock_sequence_result.scalars = MagicMock(return_value=mock_sequence_result)
        mock_sequence_result.all = MagicMock(return_value=[mock_sequence_model])

        mock_data_points_result = MagicMock()
        mock_data_points_result.scalars = MagicMock(return_value=mock_data_points_result)
        mock_data_points_result.all = MagicMock(return_value=mock_data_points)

        mock_session.execute.side_effect = [mock_sequence_result, mock_data_points_result]

        # Execute
        result = await repo.get_latest_by_feature(patient_id=mock_sequence_model.patient_id, feature_name="dopamine", limit=5)

        # Verify
        assert result is not None
        assert result.sequence_id == mock_sequence_model.sequence_id
        assert result.patient_id == mock_sequence_model.patient_id
        assert len(result.timestamps) == len(mock_data_points)

        # Verify that execute was called twice
        assert mock_session.execute.call_count == 2

        # Verify the limit parameter was used
        assert "limit(5)" in str(mock_session.execute.call_args_list[0])

    @pytest.mark.asyncio()
    async def test_get_latest_by_feature_not_found(self, mock_session):
        """Test getting the latest sequence by feature when not found."""
        # Setup
        repo = SqlAlchemyTemporalSequenceRepository(session=mock_session)

        # Mock the query results for sequence not found
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_result)
        mock_result.all = MagicMock(return_value=[])

        mock_session.execute.return_value = mock_result

        # Execute
        result = await repo.get_latest_by_feature(patient_id=uuid4(), feature_name="nonexistent_feature")

        # Verify
        assert result is None
        mock_session.execute.assert_called_once()
