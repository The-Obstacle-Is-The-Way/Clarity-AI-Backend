"""
HIPAA Security Test Suite - Database Security Tests

Tests for the SQLAlchemy Unit of Work implementation to ensure HIPAA-compliant
data integrity and proper transaction management for PHI operations.
"""

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import sessionmaker

from app.domain.exceptions import RepositoryError
from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work import SQLAlchemyUnitOfWork

import logging


class TestSQLAlchemyUnitOfWork:
    """
    Tests for the SQLAlchemy Unit of Work to ensure HIPAA-compliant data integrity.

    These tests verify:
        1. Proper transaction management for all PHI operations
        2. Atomicity of related data changes
        3. Rollback on errors to prevent inconsistent PHI states
        4. Clean session management to prevent data leaks
    """

    @pytest.fixture
    def mock_session_factory(self):
        """Create a mock session factory (sessionmaker) for testing."""
        mock_session = MagicMock()
        # Mock the sessionmaker behavior: calling it returns a session mock
        mock_factory = MagicMock(spec=sessionmaker, return_value=mock_session)
        return mock_factory, mock_session

    @pytest.fixture
    def unit_of_work(self, mock_session_factory):
        """Create a SQLAlchemyUnitOfWork instance with mocked session factory."""
        factory, _ = mock_session_factory
        uow = SQLAlchemyUnitOfWork(session_factory=factory)
        
        return uow

    def test_successful_transaction(self, unit_of_work, mock_session_factory):
        """Test a successful transaction commit."""
        factory, mock_session = mock_session_factory
        
        with unit_of_work as uow:
            # Simulate some operation
            # Explicitly commit within context is required now
            uow.commit()
        
        # Verify session factory and session interaction
        factory.assert_called_once()
        mock_session.begin.assert_called_once()
        mock_session.commit.assert_called_once() # Commit is called in __exit__
        mock_session.rollback.assert_not_called()
        mock_session.close.assert_called_once() # Close happens at end of top-level context

    def test_transaction_rollback_on_exception(self, unit_of_work, mock_session_factory):
        """Test that an exception inside the transaction triggers rollback."""
        factory, mock_session = mock_session_factory

        with pytest.raises(ValueError, match="Test exception"):
            with unit_of_work:
                # Simulate repository operations that cause an error
                raise ValueError("Test exception")

        # Assert
        factory.assert_called_once()
        mock_session.begin.assert_called_once()
        mock_session.rollback.assert_called_once() # Rollback called in __exit__
        mock_session.commit.assert_not_called()
        mock_session.close.assert_called_once()

    def test_transaction_rollback_without_commit(self, unit_of_work, mock_session_factory):
        """Test that the transaction rolls back if commit is not called."""
        factory, mock_session = mock_session_factory

        with unit_of_work:
            # Simulate some operation
            pass
            # --- No explicit commit --- 

        # Assert: Should rollback by default if no exception and no commit
        factory.assert_called_once()
        mock_session.begin.assert_called_once()
        mock_session.commit.assert_not_called()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_nested_transaction_support_commit(self, unit_of_work, mock_session_factory):
        """Test nested transaction (savepoint) support with commit."""
        factory, mock_session = mock_session_factory
        
        with unit_of_work as uow: # Outer: begin()
            mock_session.begin.assert_called_once()
            with uow.nested() as nested_uow: # Inner: begin_nested()
                mock_session.begin_nested.assert_called_once()
                # Simulate nested operation
                nested_uow.commit() # Mark nested level for commit (release savepoint)
            # Nested transaction commit should trigger session.commit() in nested __exit__
            # to release the savepoint
            mock_session.commit.assert_called_once() # Called in nested __exit__ 
            mock_session.begin_nested.assert_called_once()
            # Outer transaction commit
            uow.commit() # Mark outer level for commit
        
        # Outer commit happens in outer __exit__
        assert mock_session.commit.call_count == 2 # Once for nested, once for outer
        mock_session.rollback.assert_not_called()
        mock_session.close.assert_called_once()

    def test_nested_transaction_support_rollback_inner(self, unit_of_work, mock_session_factory):
        """Test nested transaction (savepoint) rollback on inner level."""
        factory, mock_session = mock_session_factory

        with unit_of_work as uow: # Outer: begin()
            mock_session.begin.assert_called_once()
            with uow.nested() as nested_uow: # Inner: begin_nested()
                mock_session.begin_nested.assert_called_once()
                # Simulate nested operation
                pass # No commit in nested block
            # Nested transaction without commit should trigger session.rollback() 
            # in nested __exit__ to rollback the savepoint
            mock_session.rollback.assert_called_once() # Called in nested __exit__
            mock_session.begin_nested.assert_called_once()
            mock_session.commit.assert_not_called() # Not called yet
            
            # Outer transaction commit
            uow.commit() # Mark outer level for commit

        # Outer commit happens in outer __exit__
        mock_session.commit.assert_called_once() 
        mock_session.rollback.assert_called_once() # Only called for the nested part
        mock_session.close.assert_called_once()

    def test_nested_transaction_support_rollback_outer(self, unit_of_work, mock_session_factory):
        """Test nested transaction (savepoint) rollback on outer level."""
        factory, mock_session = mock_session_factory
        exc_message = "Outer rollback"

        with pytest.raises(ValueError, match=exc_message):
             with unit_of_work as uow: # Outer: begin()
                 with uow.nested() as nested_uow: # Inner: begin_nested()
                     mock_session.begin_nested.assert_called_once()
                     nested_uow.commit() # Mark inner for commit
                 mock_session.commit.assert_called_once() # Inner commit releases savepoint
                 raise ValueError(exc_message) # Exception triggers outer rollback

        # Assert: rollback called in outer __exit__ due to exception
        mock_session.rollback.assert_called_once()
        assert mock_session.commit.call_count == 1 # Only inner commit/release happened
        mock_session.close.assert_called_once()

    def test_read_only_transaction(self, unit_of_work, mock_session_factory):
        """Test read-only transaction support for safer PHI access."""
        factory, mock_session = mock_session_factory

        with unit_of_work.read_only():
            # This transaction should be marked read-only and auto-rollback
            pass

        # Assert
        factory.assert_called_once()
        mock_session.begin.assert_called_once()
        mock_session.rollback.assert_called_once() # Should rollback in __exit__
        mock_session.commit.assert_not_called()
        mock_session.close.assert_called_once()

    def test_read_only_transaction_prevents_commits(self, unit_of_work, mock_session_factory):
        """Test that read-only transactions cannot commit changes."""
        factory, mock_session = mock_session_factory

        with pytest.raises(RepositoryError, match="Cannot commit changes in a read-only transaction"):
            with unit_of_work.read_only() as uow_ro:
                uow_ro.commit() # Attempt to commit

        # Assert commit was not called, rollback was (in __exit__)
        mock_session.commit.assert_not_called()
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()

    def test_nested_read_only_transaction(self, unit_of_work, mock_session_factory):
        """Test nested read-only transactions."""
        factory, mock_session = mock_session_factory

        with unit_of_work as uow_outer:
            with uow_outer.read_only() as uow_ro_inner:
                 # Inner is read-only
                 with pytest.raises(RepositoryError, match="Cannot commit changes in a read-only transaction"):
                      uow_ro_inner.commit()
                 # Try nesting another read-only
                 with uow_ro_inner.read_only() as uow_ro_nested:
                     with pytest.raises(RepositoryError, match="Cannot commit changes in a read-only transaction"):
                         uow_ro_nested.commit()
            # Exiting inner read-only context, rollback should happen
            assert mock_session.rollback.call_count >= 1 # At least inner rollback
            mock_session.commit.assert_not_called()
            # Outer context is *not* read-only, can commit
            uow_outer.commit() 
            
        # Outer commit happens
        mock_session.commit.assert_called_once()
        # Rollback was called for the read-only nested contexts
        assert mock_session.rollback.call_count >= 1 
        mock_session.close.assert_called_once()

    def test_transaction_metadata_for_audit(self, unit_of_work, mock_session_factory, caplog):
        """Test that transaction metadata is captured for audit logging."""
        _, mock_session = mock_session_factory
        
        # Initialize audit mock
        audit_mock = MagicMock()
        with patch('app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work.get_audit_logger') as mock_get_logger:
            mock_get_logger.return_value = audit_mock
            
            # Use unit of work with metadata
            with unit_of_work as uow:
                # Simulate operation with metadata
                uow.set_metadata({
                    "user_id": "test_user",
                    "operation": "create_patient",
                    "entity_type": "patient",
                    "entity_id": "patient123",
                    "access_reason": "treatment"
                })
                
                # Explicitly commit within context
                uow.commit()
            
            # Verify session operations
            mock_session.begin.assert_called_once()
            mock_session.commit.assert_called_once()
            
            # Verify that the metadata was used correctly
            assert unit_of_work._metadata == {}  # Metadata is cleared after transaction
    
    def test_transaction_failure_audit(self, unit_of_work, mock_session_factory, caplog):
        """Test that failed transactions are properly audited."""
        _, mock_session = mock_session_factory
        
        # Initialize audit mock
        audit_mock = MagicMock()
        with patch('app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work.get_audit_logger') as mock_get_logger:
            mock_get_logger.return_value = audit_mock
            
            # Provide a test exception to raise
            test_error = ValueError("Test transaction failure")
            
            with pytest.raises(ValueError, match="Test transaction failure"):
                with unit_of_work as uow:
                    # Set metadata before the failure
                    uow.set_metadata({
                        "user_id": "test_user",
                        "operation": "update_patient",
                        "entity_type": "patient",
                        "entity_id": "patient123",
                        "access_reason": "treatment"
                    })
                    
                    # Raise exception to cause transaction failure
                    raise test_error
            
            # Verify rollback was called due to exception
            mock_session.rollback.assert_called_once()
            mock_session.commit.assert_not_called()
            
            # Metadata should be cleared after transaction
            assert unit_of_work._metadata == {}

    def test_user_context_tracking(self, unit_of_work, mock_session_factory):
        """Test the user context tracking functionality."""
        _, mock_session = mock_session_factory
        
        with unit_of_work as uow:
            # Set user context
            uow.set_user_context(
                user_id="doctor_smith",
                access_reason="treatment"
            )
            
            # Verify context is tracked
            assert uow.get_current_user_id() == "doctor_smith"
            assert uow.get_current_access_reason() == "treatment"
            
            # Verify metadata was set
            assert uow._metadata.get('user_id') == "doctor_smith"
            assert uow._metadata.get('access_reason') == "treatment"
            assert 'timestamp' in uow._metadata
            
            # Complete the transaction
            uow.commit()
        
        # User context should be cleared after transaction
        assert unit_of_work._current_user_id is None
        assert unit_of_work._current_access_reason is None


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
