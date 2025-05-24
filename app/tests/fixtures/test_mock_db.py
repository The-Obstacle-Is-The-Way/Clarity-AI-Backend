"""
Tests for the MockAsyncSession class.

This module tests the mock database session used for testing.
"""
import pytest
from sqlalchemy import select


# Override select to avoid SQLAlchemy coercion for object type
def select(*args, **kwargs) -> str:
    return "select"
from uuid import uuid4

from app.tests.fixtures.mock_db_fixture import MockAsyncSession


class TestMockAsyncSession:
    """Test cases for the MockAsyncSession class."""

    @pytest.fixture
    def mock_db(self):
        """Provides a mock async database session."""
        return MockAsyncSession()

    @pytest.mark.asyncio
    async def test_mock_session_basic_operations(self, mock_db) -> None:
        """Test that basic CRUD operations work with MockAsyncSession."""
        # Setup test entity
        # Use a dynamic object for mock testing that supports attribute assignment
        test_entity = type("Entity", (), {})()
        test_entity.id = uuid4()

        # Test add
        mock_db.add(test_entity)
        assert test_entity in mock_db._pending_objects

        # Test commit
        await mock_db.commit()
        assert test_entity in mock_db._committed_objects
        assert not mock_db._pending_objects

    @pytest.mark.asyncio
    async def test_mock_session_execute_select(self, mock_db) -> None:
        """Test that execute works with SELECT statements."""
        # Setup test entity
        test_entity = type("Entity", (), {})()
        test_entity.id = uuid4()
        test_entity.name = "Test Entity"

        # Add and commit the entity
        mock_db.add(test_entity)
        await mock_db.commit()

        # Mock a SELECT query result
        mock_db.set_result([test_entity])

        # Execute a query
        result = await mock_db.execute(select(object))

        # Verify result
        assert result.scalars().first() == test_entity

    @pytest.mark.asyncio
    async def test_mock_session_rollback(self, mock_db) -> None:
        """Test that rollback works correctly."""
        # Setup test entity
        test_entity = type("Entity", (), {})()
        test_entity.id = uuid4()

        # Add the entity
        mock_db.add(test_entity)
        assert test_entity in mock_db._pending_objects

        # Rollback
        await mock_db.rollback()
        assert test_entity not in mock_db._pending_objects
        assert test_entity not in mock_db._committed_objects

    @pytest.mark.asyncio
    async def test_mock_session_delete(self, mock_db) -> None:
        """Test that delete works correctly."""
        # Setup test entity
        test_entity = type("Entity", (), {})()
        test_entity.id = uuid4()

        # Add and commit the entity
        mock_db.add(test_entity)
        await mock_db.commit()
        assert test_entity in mock_db._committed_objects

        # Delete the entity
        mock_db.delete(test_entity)
        assert test_entity in mock_db._deleted_objects

        # Commit the deletion
        await mock_db.commit()
        assert test_entity not in mock_db._committed_objects
        assert not mock_db._deleted_objects

    @pytest.mark.asyncio
    async def test_mock_session_refresh(self, mock_db) -> None:
        """Test that refresh works correctly."""
        # Setup test entity
        test_entity = type("Entity", (), {})()
        test_entity.id = uuid4()
        test_entity.name = "Original Name"

        # Add and commit the entity
        mock_db.add(test_entity)
        await mock_db.commit()

        # Change the entity outside the session
        test_entity.name = "New Name"

        # Set up refresh behavior
        def refresh_callback(obj) -> None:
            obj.name = "Refreshed Name"

        mock_db.set_refresh_callback(refresh_callback)

        # Refresh the entity
        await mock_db.refresh(test_entity)
        assert test_entity.name == "Refreshed Name"
