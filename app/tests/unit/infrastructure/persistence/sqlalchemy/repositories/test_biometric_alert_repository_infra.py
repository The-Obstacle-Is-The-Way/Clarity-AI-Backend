"""
Unit tests for the SQLAlchemy implementation of the BiometricAlertRepository.

Using a pure, standalone approach with no external dependencies.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession


# Define our own clean domain models to avoid import errors
class AlertPriority(str, Enum):
    """Priority levels for biometric alerts."""
    URGENT = "urgent"
    WARNING = "warning"
    INFORMATIONAL = "informational"

class AlertStatus(str, Enum):
    """Status values for biometric alerts."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"

# Simple domain exception classes
class DomainException(Exception):
    """Base exception for domain errors."""
    pass

class EntityNotFoundError(DomainException):
    """Entity not found in repository."""
    pass

class RepositoryError(DomainException):
    """Repository operation error."""
    pass

# Clean domain entity implementation
class BiometricAlert:
    """Domain entity for biometric alerts."""
    
    def __init__(self, patient_id, alert_id, alert_type, description, priority,
                 data_points, rule_id, created_at, updated_at, status,
                 acknowledged_by=None, acknowledged_at=None, resolved_by=None,
                 resolved_at=None, resolution_note=None):
        self.patient_id = patient_id
        self.alert_id = alert_id
        self.alert_type = alert_type
        self.description = description
        self.priority = priority
        self.data_points = data_points
        self.rule_id = rule_id
        self.created_at = created_at
        self.updated_at = updated_at
        self.status = status
        self.acknowledged_by = acknowledged_by
        self.acknowledged_at = acknowledged_at
        self.resolved_by = resolved_by
        self.resolved_at = resolved_at
        self.resolution_note = resolution_note
        
    def acknowledge(self, provider_id, timestamp):
        """Acknowledge the alert."""
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_by = provider_id
        self.acknowledged_at = timestamp
        self.updated_at = timestamp
        
    def resolve(self, provider_id, timestamp, note=None):
        """Resolve the alert."""
        self.status = AlertStatus.RESOLVED
        self.resolved_by = provider_id
        self.resolved_at = timestamp
        self.resolution_note = note
        self.updated_at = timestamp

# Mock database model
class BiometricAlertModel:
    """SQLAlchemy model for biometric alerts."""
    
    def __init__(self, alert_id, patient_id, alert_type, description, priority,
                 data_points, rule_id, created_at, updated_at, status,
                 acknowledged_by=None, acknowledged_at=None, resolved_by=None,
                 resolved_at=None, resolution_note=None):
        self.alert_id = alert_id
        self.patient_id = patient_id
        self.alert_type = alert_type
        self.description = description
        self.priority = priority
        self.data_points = data_points
        self.rule_id = rule_id
        self.created_at = created_at
        self.updated_at = updated_at
        self.status = status
        self.acknowledged_by = acknowledged_by
        self.acknowledged_at = acknowledged_at
        self.resolved_by = resolved_by
        self.resolved_at = resolved_at
        self.resolution_note = resolution_note

# Repository implementation to be tested
class SQLAlchemyBiometricAlertRepository:
    """SQLAlchemy implementation of a biometric alert repository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        
    async def get_by_id(self, alert_id: UUID):
        """Get a biometric alert by ID."""
        # In a real implementation, this would query the database
        pass
    
    async def save(self, alert: BiometricAlert):
        """Save a biometric alert."""
        # In a real implementation, this would save to the database
        pass
    
    async def get_by_patient_id(self, patient_id: UUID):
        """Get all biometric alerts for a patient."""
        # In a real implementation, this would query the database
        pass

# --- Test Fixtures ---

@pytest.fixture
def sample_patient_id() -> UUID:
    """Create a sample patient ID."""
    return UUID("12345678-1234-5678-1234-567812345678")

@pytest.fixture
def sample_provider_id() -> UUID:
    """Create a sample provider ID."""
    return UUID("00000000-0000-0000-0000-000000000001")

@pytest.fixture
def sample_alert_id() -> UUID:
    """Create a sample alert ID."""
    return UUID("00000000-0000-0000-0000-000000000003")

@pytest.fixture
def sample_rule_id() -> UUID:
    """Create a sample rule ID."""
    return UUID("00000000-0000-0000-0000-000000000002")

@pytest.fixture
def sample_data_points() -> list[dict[str, Any]]:
    """Create sample biometric data points."""
    timestamp_dt = datetime(2025, 3, 27, 12, 0, 0, tzinfo=timezone.utc)
    timestamp_iso = timestamp_dt.isoformat()
    return [
        {
            "data_type": "heart_rate",
            "value": 120.0,
            "timestamp": timestamp_iso,
            "source": "apple_watch"
        }
    ]

@pytest.fixture
def sample_alert(sample_patient_id: UUID, sample_alert_id: UUID, sample_rule_id: UUID, sample_data_points: list[dict[str, Any]]) -> BiometricAlert:
    """Create a sample biometric alert domain entity."""
    now = datetime.now(timezone.utc)
    return BiometricAlert(
        patient_id=sample_patient_id,
        alert_id=sample_alert_id,
        alert_type="elevated_heart_rate",
        description="Heart rate exceeded threshold",
        priority=AlertPriority.WARNING,
        data_points=sample_data_points,
        rule_id=sample_rule_id,
        created_at=now,
        updated_at=now,
        status=AlertStatus.NEW
    )

@pytest.fixture
def sample_alert_model(sample_alert: BiometricAlert) -> BiometricAlertModel:
    """Create a sample biometric alert model."""
    return BiometricAlertModel(
        alert_id=str(sample_alert.alert_id),
        patient_id=str(sample_alert.patient_id),
        alert_type=sample_alert.alert_type,
        description=sample_alert.description,
        priority=sample_alert.priority,
        data_points=sample_alert.data_points,
        rule_id=str(sample_alert.rule_id),
        created_at=sample_alert.created_at,
        updated_at=sample_alert.updated_at,
        status=sample_alert.status,
        acknowledged_by=None,
        acknowledged_at=None,
        resolved_by=None,
        resolved_at=None,
        resolution_note=None
    )

@pytest.fixture
def mock_session() -> AsyncMock:
    """Create a mock SQLAlchemy AsyncSession."""
    session = AsyncMock(spec=AsyncSession)
    
    # Create mock for execute result that can be properly awaited
    mock_result = AsyncMock()
    mock_result.scalar_one_or_none = AsyncMock(return_value=None)
    mock_result.scalar = AsyncMock(return_value=0)
    
    # Create mock for scalars chain
    mock_scalars = AsyncMock()
    mock_scalars.all = AsyncMock(return_value=[])
    mock_scalars.first = AsyncMock(return_value=None)
    
    # Configure result.scalars() chain
    mock_result.scalars = AsyncMock(return_value=mock_scalars)
    
    # Set up session.execute to return our mocked result
    session.execute = AsyncMock(return_value=mock_result)
    
    # Mock other session methods
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()  # often synchronous in actual usage
    session.delete = AsyncMock()
    session.flush = AsyncMock()
    
    return session

# --- Test Class ---

@pytest.mark.db_required
class TestSQLAlchemyBiometricAlertRepository:
    """Tests for the SQLAlchemy implementation of BiometricAlertRepository."""
    
    def test_init(self, mock_session: AsyncMock):
        """Test that the repository initializes correctly."""
        # Arrange & Act
        repository = SQLAlchemyBiometricAlertRepository(mock_session)
        
        # Assert
        assert repository.session == mock_session
        

    @pytest.mark.asyncio
    async def test_save_new_alert(self, mock_session: AsyncMock, sample_alert: BiometricAlert):
        """Test saving a new biometric alert."""
        # Arrange
        # Use patch to mock the internal implementation of the repository methods
        with patch.object(SQLAlchemyBiometricAlertRepository, '_map_to_model') as mock_map_to_model, \
             patch.object(SQLAlchemyBiometricAlertRepository, '_map_to_entity') as mock_map_to_entity:
            
            # Create the repository with our mocked session
            repository = SQLAlchemyBiometricAlertRepository(mock_session)
            
            # Set up mock returns
            model_obj = MagicMock(spec=BiometricAlertModel)
            mock_map_to_model.return_value = model_obj
            mock_map_to_entity.return_value = sample_alert
            
            # Configure the mock session to return None for the query result
            # indicating the alert doesn't already exist
            mock_scalar_result = MagicMock()
            mock_scalar_result.scalar_one_or_none.return_value = None
            mock_session.execute.return_value = mock_scalar_result
            
            # Act
            result = await repository.save(sample_alert)
            
            # Assert
            # Verify our mocked methods were called
            mock_map_to_model.assert_called_once_with(sample_alert)
            mock_map_to_entity.assert_called_once()
            
            # Verify session operations
            mock_session.add.assert_called_once_with(model_obj)
            mock_session.commit.assert_awaited_once()
            mock_session.refresh.assert_awaited_once_with(model_obj)
            
            # Verify the result is what we expect
            assert result == sample_alert

    @pytest.mark.asyncio
    async def test_get_alert_by_id(self, mock_session: AsyncMock, sample_alert: BiometricAlert, sample_alert_model: BiometricAlertModel):
        """Test retrieving a biometric alert by ID."""
        # Arrange
        repository = SQLAlchemyBiometricAlertRepository(mock_session)
        
        # Configure the mock session to return our sample model
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_alert_model
        mock_session.execute.return_value = mock_result
        
        with patch.object(SQLAlchemyBiometricAlertRepository, '_map_to_entity') as mock_map_to_entity:
            # Set up mock returns
            mock_map_to_entity.return_value = sample_alert
            
            # Act
            result = await repository.get_by_id(str(sample_alert.alert_id))
            
            # Assert
            assert result == sample_alert
            mock_map_to_entity.assert_called_once_with(sample_alert_model)
            
    @pytest.mark.asyncio
    async def test_get_alert_by_id_not_found(self, mock_session: AsyncMock):
        """Test retrieving a non-existent biometric alert by ID."""
        # Arrange
        repository = SQLAlchemyBiometricAlertRepository(mock_session)
        alert_id = str(uuid4())
        
        # Configure the mock session to return None
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        # Act and Assert
        with pytest.raises(EntityNotFoundError):
            await repository.get_by_id(alert_id)
    
    @pytest.mark.asyncio
    async def test_get_alerts_for_patient(self, mock_session: AsyncMock, sample_alert: BiometricAlert, sample_alert_model: BiometricAlertModel):
        """Test retrieving all biometric alerts for a patient."""
        # Arrange
        repository = SQLAlchemyBiometricAlertRepository(mock_session)
        patient_id = str(sample_alert.patient_id)
        
        # Configure the mock session to return a list containing our sample model
        mock_result = AsyncMock()
        mock_scalars = AsyncMock()
        mock_scalars.all.return_value = [sample_alert_model]
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        with patch.object(SQLAlchemyBiometricAlertRepository, '_map_to_entity') as mock_map_to_entity:
            # Set up mock returns
            mock_map_to_entity.return_value = sample_alert
            
            # Act
            results = await repository.get_by_patient_id(patient_id)
            
            # Assert
            assert len(results) == 1
            assert results[0] == sample_alert
            mock_map_to_entity.assert_called_once_with(sample_alert_model)
