"""
Tests for the SQL Alchemy implementation of the temporal event repository.
"""
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.temporal_events import CorrelatedEvent, EventChain
from app.infrastructure.models.temporal_sequence_model import EventModel
from app.infrastructure.repositories.temporal_event_repository import SqlAlchemyEventRepository


@pytest.fixture
def mock_session():

    """Create a mock SQLAlchemy session for testing."""
    session = AsyncMock(spec=AsyncSession)
    
    # Mock for execute that will be customized in tests
    session.execute = AsyncMock()
    
    # Mock for add and add_all
    session.add = MagicMock()
    
    # Mock for flush
    session.flush = AsyncMock()    
    return session

@pytest.fixture
@pytest.mark.db_required()
def test_event():

    """Create a test correlated event for tests."""
    now = datetime.now()
    event_id = uuid4()
    correlation_id = uuid4()
    patient_id = uuid4()
    
    event = CorrelatedEvent()
    event.event_id = event_id
    event.correlation_id = correlation_id
    event.parent_event_id = None  # Root event
    event.patient_id = patient_id
    event.event_type = "neurotransmitter_change"
    event.timestamp = now
    event.event_metadata = {"region": "prefrontal_cortex", "neurotransmitter": "serotonin", "value_change": 0.2} # Renamed
    return event

@pytest.fixture
def test_child_event(test_event):

    """Create a test child event."""
    child_id = uuid4()
    
    child_event = CorrelatedEvent()
    child_event.event_id = child_id
    child_event.correlation_id = test_event.correlation_id
    child_event.parent_event_id = test_event.event_id
    child_event.patient_id = test_event.patient_id
    child_event.event_type = "brain_region_activation"
    child_event.timestamp = test_event.timestamp + timedelta(seconds=30)
    child_event.event_metadata = {"region": "amygdala", "activation_level": 0.3} # Renamed
    return child_event

@pytest.fixture
def mock_event_model():

    """Create a mock event model for tests."""
    now = datetime.now()
    event_id = uuid4()
    correlation_id = uuid4()
    
    model = MagicMock(spec=EventModel)
    model.id = event_id
    model.correlation_id = correlation_id
    model.parent_event_id = None
    model.patient_id = uuid4()
    model.event_type = "neurotransmitter_change"
    model.timestamp = now
    model.event_metadata = {"region": "prefrontal_cortex", "neurotransmitter": "serotonin", "value_change": 0.2} # Renamed
    return model

@pytest.fixture
def mock_child_event_model(mock_event_model):

    """Create a mock child event model."""
    child_id = uuid4()
    
    model = MagicMock(spec=EventModel)
    model.id = child_id
    model.correlation_id = mock_event_model.correlation_id
    model.parent_event_id = mock_event_model.id
    model.patient_id = mock_event_model.patient_id
    model.event_type = "brain_region_activation"
    model.timestamp = mock_event_model.timestamp + timedelta(seconds=30)
    model.event_metadata = {"region": "amygdala", "activation_level": 0.3} # Renamed
    return model

class TestSqlAlchemyEventRepository:
    """Tests for SqlAlchemyEventRepository."""
    def test_init(self, mock_session):

        """Test repository initialization."""
        repo = SqlAlchemyEventRepository(session=mock_session)
        assert repo.session == mock_session

    @pytest.mark.asyncio()
    async def test_save_event(self, mock_session, test_event):
        """Test saving a correlated event."""
        # Setup
        repo = SqlAlchemyEventRepository(session=mock_session)
    
        # Execute
        result = await repo.save_event(test_event)
    
        # Verify
        assert result == test_event.event_id
        mock_session.add.assert_called_once()
        mock_session.flush.assert_awaited_once()
    
        # Verify model creation
        added_model = mock_session.add.call_args[0][0]
        assert isinstance(added_model, EventModel)
        assert added_model.id == test_event.event_id
        assert added_model.correlation_id == test_event.correlation_id
        assert added_model.parent_event_id == test_event.parent_event_id
        assert added_model.patient_id == test_event.patient_id
        assert added_model.event_type == test_event.event_type
        assert added_model.timestamp == test_event.timestamp
        assert added_model.event_metadata == test_event.event_metadata # Renamed

    @pytest.mark.asyncio()
    async def test_get_event_by_id_found(self, mock_session, mock_event_model):
        """Test getting an event by ID when found."""
        # Setup
        repo = SqlAlchemyEventRepository(session=mock_session)
    
        # Mock the query results
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_result)
        mock_result.first = MagicMock(return_value=mock_event_model)
    
        mock_session.execute.return_value = mock_result
    
        # Execute
        result = await repo.get_event_by_id(mock_event_model.id)
    
        # Verify
        assert result is not None
        assert result.event_id == mock_event_model.id
        assert result.correlation_id == mock_event_model.correlation_id
        assert result.parent_event_id == mock_event_model.parent_event_id
        assert result.patient_id == mock_event_model.patient_id
        assert result.event_type == mock_event_model.event_type
        assert result.timestamp == mock_event_model.timestamp
        assert result.event_metadata == mock_event_model.event_metadata # Renamed
    
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio()
    async def test_get_event_by_id_not_found(self, mock_session):
        """Test getting an event by ID when not found."""
        # Setup
        repo = SqlAlchemyEventRepository(session=mock_session)
    
        # Mock the query results for event not found
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_result)
        mock_result.first = MagicMock(return_value=None)
    
        mock_session.execute.return_value = mock_result
    
        # Execute
        result = await repo.get_event_by_id(uuid4())
    
        # Verify
        assert result is None
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio()
    async def test_get_events_by_correlation_id(self, mock_session, mock_event_model, mock_child_event_model):
        """Test getting events by correlation ID."""
        # Setup
        repo = SqlAlchemyEventRepository(session=mock_session)
    
        # Mock the query results
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_result)
        mock_result.all = MagicMock(return_value=[mock_event_model, mock_child_event_model])
    
        mock_session.execute.return_value = mock_result
    
        # Execute
        results = await repo.get_events_by_correlation_id(mock_event_model.correlation_id)
    
        # Verify
        assert len(results) == 2
        assert results[0].event_id == mock_event_model.id
        assert results[1].event_id == mock_child_event_model.id
    
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio()
    async def test_get_event_chain(self, mock_session, mock_event_model, mock_child_event_model):
        """Test getting an event chain by correlation ID."""
        # Setup
        repo = SqlAlchemyEventRepository(session=mock_session)
    
        # Mock the get_events_by_correlation_id method
        with patch.object(repo, 'get_events_by_correlation_id', return_value=[self._model_to_entity(mock_event_model), self._model_to_entity(mock_child_event_model)]):
            
            # Execute
            chain = await repo.get_event_chain(mock_event_model.correlation_id)
        
            # Verify
            assert isinstance(chain, EventChain)
            assert len(chain.events) == 2
        
            # Verify the hierarchy was set up correctly (root event has child)
            root_event = next((e for e in chain.events if e.parent_event_id is None), None)
            assert root_event is not None
        
            # In a real implementation, rebuild_hierarchy would link events properly
            # but we mock this here by verifying that get_events_by_correlation_id was called
            repo.get_events_by_correlation_id.assert_called_once_with(mock_event_model.correlation_id)

    @pytest.mark.asyncio()
    async def test_get_patient_events(self, mock_session, mock_event_model, mock_child_event_model):
        """Test getting events associated with a patient."""
        # Setup
        repo = SqlAlchemyEventRepository(session=mock_session)
    
        # Mock the query results
        mock_result = MagicMock()
        mock_result.scalars = MagicMock(return_value=mock_result)
        mock_result.all = MagicMock(return_value=[mock_event_model, mock_child_event_model])
    
        mock_session.execute.return_value = mock_result
    
        # Execute
        results = await repo.get_patient_events(patient_id=mock_event_model.patient_id, event_type="neurotransmitter_change", limit=10)
    
        # Verify
        assert len(results) == 2
        assert results[0].event_id == mock_event_model.id
        assert results[1].event_id == mock_child_event_model.id
    
        # Verify the query parameters were used
        mock_session.execute.assert_called_once()
        assert "event_type" in str(mock_session.execute.call_args)
        assert "limit(10)" in str(mock_session.execute.call_args)

    @staticmethod
    def _model_to_entity(model):

        """
        Convert a model to an entity for testing purposes.
    
        Args:
            model: The mock model
        
        Returns:
            The corresponding CorrelatedEvent entity
        """
        return CorrelatedEvent(
            event_id=model.id,
            correlation_id=model.correlation_id,
            parent_event_id=model.parent_event_id,
            patient_id=model.patient_id,
            event_type=model.event_type,
            timestamp=model.timestamp,
            event_metadata=model.event_metadata # Renamed
        )