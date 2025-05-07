"""Unit tests for the enhanced SQLAlchemy database module."""
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import Column, Integer, String, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base

# Assuming Base is correctly defined elsewhere or use declarative_base
Base = declarative_base()

# Correct import - Assuming these are the intended imports
from app.infrastructure.persistence.sqlalchemy.database import (
    Database,
    DatabaseFactory,
    EnhancedDatabase,
    get_database,
    get_db_session,
)


# Define a test model for database operations
class SampleModel(Base):
    """Test model for database operations."""
    __tablename__ = "test_models"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    value = Column(String(100), nullable=True)

@pytest.fixture(scope="module")
def mock_settings_module():
    """Mock application settings for the module."""
    settings = MagicMock()
    settings.DATABASE_URL = "sqlite:///:memory:"
    settings.DATABASE_ECHO = False
    settings.DATABASE_POOL_SIZE = 5
    settings.DATABASE_MAX_OVERFLOW = 10  # Explicitly set
    settings.DATABASE_POOL_TIMEOUT = 30  # Explicitly set
    settings.DATABASE_POOL_RECYCLE = 3600 # Explicitly set
    settings.DATABASE_SSL_MODE = None      # Explicitly set
    settings.DATABASE_SSL_CA = None        # Explicitly set
    settings.DATABASE_SSL_VERIFY = None    # Explicitly set
    settings.DATABASE_SSL_ENABLED = False
    settings.DATABASE_ENCRYPTION_ENABLED = True
    settings.DATABASE_AUDIT_ENABLED = True
    settings.ENVIRONMENT = "test" # Ensure environment is test
    
    # Patch the get_settings function where it's used by the database module
    with patch("app.infrastructure.persistence.sqlalchemy.database.get_settings", return_value=settings) as p1:
        # Also patch the canonical get_settings in core.config.settings, as it might be imported
        # directly by other modules or even the database module if imports are complex.
        with patch("app.core.config.settings.get_settings", return_value=settings) as p2:
            yield settings

@pytest.fixture(scope="function") # Use function scope for isolation
def in_memory_db(mock_settings_module):
    """Create an in-memory SQLite database."""
    # Use the mocked settings URL
    db = Database(db_url=mock_settings_module.DATABASE_URL)
    Base.metadata.create_all(db.engine)
    yield db
    Base.metadata.drop_all(db.engine)
    db.engine.dispose() # Dispose engine after test

@pytest.fixture(scope="function") # Use function scope for isolation
def enhanced_db(mock_settings_module):
    """Create an enhanced in-memory SQLite database."""
    # Use the mocked settings URL and enable features explicitly for testing
    db = EnhancedDatabase(
        db_url=mock_settings_module.DATABASE_URL,
        enable_encryption=True,
        enable_audit=True
    )
    Base.metadata.create_all(db.engine)
    yield db
    Base.metadata.drop_all(db.engine)
    db.engine.dispose() # Dispose engine after test

class TestDatabase:
    """Tests for the base Database class."""

    def test_init(self, mock_settings_module):
        """Test database initialization."""
        # Use mocked settings for initialization test
        db = Database(db_url=mock_settings_module.DATABASE_URL, echo=False, pool_size=5)

        assert db.db_url == mock_settings_module.DATABASE_URL
        assert db.echo is False
        assert db.pool_size == 5
        assert db.engine is not None
        assert db.SessionLocal is not None

    def test_get_session(self, in_memory_db):
        """Test getting a database session."""
        session = None
        try:
            session = in_memory_db.get_session()
            assert isinstance(session, Session)
        finally:
            if session:
                session.close()

    def test_create_tables(self, in_memory_db):
        """Test creating database tables."""
        # Tables are created in the fixture. Verify by inserting data.
        with in_memory_db.session_scope() as session:
            test_model = SampleModel(name="test_create", value="created")
            session.add(test_model)
            session.commit() # Commit needed to save

        # Verify the record exists
        with in_memory_db.session_scope() as session:
            result = session.query(SampleModel).filter_by(name="test_create").first()
            assert result is not None
            assert result.name == "test_create"
            assert result.value == "created"

    def test_drop_tables(self, in_memory_db):
        """Test dropping database tables."""
        # Insert a test record
        with in_memory_db.session_scope() as session:
            test_model = SampleModel(name="test_drop", value="to_be_dropped")
            session.add(test_model)
            session.commit()

        # Drop tables
        in_memory_db.drop_tables()

        # Attempt to query - should fail if tables are dropped
        with pytest.raises(SQLAlchemyError): # Expect an error (e.g., NoSuchTableError)
             with in_memory_db.session_scope() as session:
                 session.query(SampleModel).first()

        # Re-create tables for subsequent tests if needed (handled by fixture scope)
        # in_memory_db.create_tables()


    def test_session_scope(self, in_memory_db):
        """Test session scope context manager."""
        # Use context manager to add a record
        with in_memory_db.session_scope() as session:
            test_model = SampleModel(name="test_scope", value="context_manager")
            session.add(test_model)
            # Commit happens automatically on exit if no exception

        # Verify record was committed
        with in_memory_db.session_scope() as session:
            result = session.query(SampleModel).filter_by(name="test_scope").first()
            assert result is not None
            assert result.value == "context_manager"

    def test_session_scope_rollback(self, in_memory_db):
        """Test session scope rollback on exception."""
        try:
            with in_memory_db.session_scope() as session:
                test_model = SampleModel(name="should_rollback", value="value")
                session.add(test_model)
                raise ValueError("Test exception") # Force rollback
        except ValueError:
            pass # Expected exception

        # Verify record was not committed
        with in_memory_db.session_scope() as session:
            result = session.query(SampleModel).filter_by(name="should_rollback").first()
            assert result is None

    @patch("app.infrastructure.persistence.sqlalchemy.database.logger")
    def test_execute_query(self, mock_logger, in_memory_db):
        """Test executing a raw SQL query."""
        # Insert test data
        with in_memory_db.session_scope() as session:
            test_model = SampleModel(name="query_test", value="raw_sql")
            session.add(test_model)
            session.commit()

        # Execute raw query using text() for parameter binding
        results = in_memory_db.execute_query(
            text("SELECT * FROM test_models WHERE name = :name"), {"name": "query_test"}
        )

        assert len(results) == 1
        # Access by index or key depending on execute_query implementation
        # Assuming it returns dict-like rows or RowProxy
        assert results[0].name == "query_test"
        assert results[0].value == "raw_sql"
        # mock_logger.debug.assert_called() # Verify logging if implemented

class TestEnhancedDatabase:
    """Tests for the EnhancedDatabase class."""

    def test_init(self, mock_settings_module):
        """Test enhanced database initialization."""
        db = EnhancedDatabase(
            db_url=mock_settings_module.DATABASE_URL,
            enable_encryption=True,
            enable_audit=True
        )

        assert db.db_url == mock_settings_module.DATABASE_URL
        assert db.echo is False # Assuming default or from settings
        assert db.pool_size == 5 # Assuming default or from settings
        assert db.enable_encryption is True
        assert db.enable_audit is True
        assert db.engine is not None

    @patch("app.infrastructure.persistence.sqlalchemy.database.logger")
    def test_session_scope_with_audit(self, mock_logger, enhanced_db):
        """Test session scope with audit logging."""
        with enhanced_db.session_scope() as session:
            test_model = SampleModel(name="audit_test", value="logged")
            session.add(test_model)
            # Commit happens automatically

        # Verify audit logging calls (adjust count based on implementation)
        assert mock_logger.info.call_count >= 2 # Start, Commit/Close
        log_calls = [c.args[0] for c in mock_logger.info.call_args_list]
        assert any("Starting transaction" in log for log in log_calls)
        # assert any("Committing transaction" in log for log in log_calls) # Might be debug
        assert any("Closing session" in log for log in log_calls) # Or similar message

    @patch("app.infrastructure.persistence.sqlalchemy.database.logger")
    def test_session_scope_rollback_with_audit(self, mock_logger, enhanced_db):
        """Test session scope rollback with audit logging."""
        try:
            with enhanced_db.session_scope() as session:
                test_model = SampleModel(name="audit_rollback", value="should_log")
                session.add(test_model)
                raise ValueError("Test exception")
        except ValueError:
            pass # Expected

        # Verify error logging
        mock_logger.error.assert_called_once()
        error_msg = mock_logger.error.call_args[0][0]
        assert "Rolling back transaction" in error_msg # Or similar message
        assert "ValueError" in error_msg # Check if exception type is logged

    def test_get_protected_engine(self, enhanced_db):
        """Test getting a protected database engine (if implemented differently)."""
        protected_engine = enhanced_db.get_protected_engine()
        # If it's just returning the same engine:
        assert protected_engine is enhanced_db.engine
        # If it returns a proxy or different object, add specific tests here.

class TestDatabaseFactory:
    """Tests for the database factory functions."""
    
    @pytest.fixture(autouse=True)
    def reset_factory(self):
        """Reset the DatabaseFactory singleton instance before and after each test."""
        DatabaseFactory.reset()
        yield
        DatabaseFactory.reset()

    def test_database_factory_singleton(self, mock_settings_module):
        """Test DatabaseFactory creates a singleton EnhancedDatabase instance."""
        from app.infrastructure.persistence.sqlalchemy.database import EnhancedDatabase
        
        # Initialize with test settings
        DatabaseFactory.initialize(lambda: mock_settings_module)
        
        # First call should create a new instance
        db1 = DatabaseFactory.get_database()
        
        # Verify we got an instance of the right type
        assert isinstance(db1, EnhancedDatabase)
        
        # Second call should return the same instance
        db2 = DatabaseFactory.get_database()
        assert db1 is db2, "Singleton behavior violated: got different instances"
    
    def test_legacy_get_database_function(self, mock_settings_module):
        """Test that the legacy get_database function uses the DatabaseFactory."""
        from app.infrastructure.persistence.sqlalchemy.database import EnhancedDatabase
        
        # Initialize with test settings
        DatabaseFactory.initialize(lambda: mock_settings_module)
        
        # Get database from factory directly
        factory_db = DatabaseFactory.get_database()
        
        # Get database from legacy function
        legacy_db = get_database()
        
        # Both should be the same instance
        assert factory_db is legacy_db, "Legacy function returned different instance than factory"
        assert isinstance(legacy_db, EnhancedDatabase)

    def test_get_db_session(self, mock_settings_module):
        """Test get_db_session dependency injection function."""
        from app.infrastructure.persistence.sqlalchemy.database import EnhancedDatabase
        
        # Create mock database instance
        mock_db_instance = MagicMock(spec=EnhancedDatabase)
        mock_session = MagicMock(spec=Session)
        
        # Mock the session_scope context manager
        mock_db_instance.session_scope.return_value.__enter__.return_value = mock_session
        
        # Mock database provider function
        mock_db_provider = MagicMock(return_value=mock_db_instance)

        # Create a generator from the function, passing our custom provider
        session_gen = get_db_session(db_provider=mock_db_provider)

        # Get the session from the generator
        retrieved_session = next(session_gen)
        assert retrieved_session is mock_session # Should be the mocked session
        mock_db_instance.session_scope.assert_called_once() # Verify session_scope was entered

        # Simulate closing the session by exhausting the generator
        with pytest.raises(StopIteration):
            next(session_gen)
        # Verify the context manager exit was called (which should close the session)
        mock_db_instance.session_scope.return_value.__exit__.assert_called_once()
    
    def test_thread_safety(self, mock_settings_module):
        """Test that the DatabaseFactory is thread-safe."""
        import concurrent.futures
        
        # Initialize with test settings
        DatabaseFactory.initialize(lambda: mock_settings_module)
        DatabaseFactory.reset()
        
        # Track the instances created in each thread
        instances = []
        instance_ids = set()
        thread_count = 10
        
        def get_db_in_thread():
            db = DatabaseFactory.get_database()
            instances.append(db)
            instance_ids.add(id(db))
            # Small sleep to increase chance of race conditions
            time.sleep(0.01)
            return id(db)

        # Run get_database concurrently in multiple threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(get_db_in_thread) for _ in range(thread_count)]
            concurrent.futures.wait(futures)
            
        # All threads should have the same database instance
        assert len(instance_ids) == 1, "Multiple database instances were created"
        assert len(instances) == thread_count, "Not all threads created a database instance"
