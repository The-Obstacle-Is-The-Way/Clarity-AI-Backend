"""
Unit tests for the GUID cross-database compatibility type.

This module tests the SQLAlchemy TypeDecorator implementation that handles
UUIDs consistently across different database dialects (PostgreSQL and SQLite).
"""

import uuid
import pytest
from sqlalchemy import Column, create_engine, MetaData, Table
from sqlalchemy.orm import Session, registry

from app.infrastructure.persistence.sqlalchemy.types import GUID


class TestGUIDTypeDecorator:
    """Tests for the GUID SQLAlchemy TypeDecorator."""

    def setup_method(self):
        """Set up a fresh metadata and engine for each test."""
        self.metadata = MetaData()
        self.mapper_registry = registry()
        
        # Create a test table with a GUID column
        self.test_table = Table(
            'test_guid',
            self.metadata,
            Column('id', GUID, primary_key=True),
            Column('optional_id', GUID, nullable=True),
        )

    def test_guid_postgresql_dialect(self):
        """Test GUID type with PostgreSQL dialect."""
        # Create a PostgreSQL-compatible in-memory database
        engine = create_engine('postgresql://', strategy='mock', executor=self._mock_execute)
        self.metadata.create_all(engine)
        
        # Generate a test UUID
        test_uuid = uuid.uuid4()
        
        # Validate that GUID produces the correct DDL for PostgreSQL
        ddl = str(self.test_table.columns.id.type.compile(dialect=engine.dialect))
        assert 'UUID' in ddl, "Should use native UUID type for PostgreSQL"

    def test_guid_sqlite_dialect(self):
        """Test GUID type with SQLite dialect."""
        # Create a SQLite in-memory database
        engine = create_engine('sqlite:///:memory:')
        self.metadata.create_all(engine)
        
        # Generate a test UUID
        test_uuid = uuid.uuid4()
        
        # Validate that GUID produces the correct DDL for SQLite
        ddl = str(self.test_table.columns.id.type.compile(dialect=engine.dialect))
        assert 'VARCHAR' in ddl or 'String' in ddl, "Should use String(36) type for SQLite"
        
        # Test inserting and retrieving UUID values
        with Session(engine) as session:
            # Execute raw SQL to insert a UUID
            session.execute(
                self.test_table.insert().values(
                    id=test_uuid,
                    optional_id=None
                )
            )
            session.commit()
            
            # Query the UUID back
            result = session.execute(self.test_table.select()).fetchone()
            
            # Verify the UUID was stored and retrieved correctly
            assert isinstance(result.id, uuid.UUID), "Should retrieve as UUID object"
            assert result.id == test_uuid, "Should retrieve the same UUID value"
            assert result.optional_id is None, "Should handle NULL/None values correctly"

    def _mock_execute(self, sql, *args, **kwargs):
        """Mock executor for the PostgreSQL engine to prevent actual DB connections."""
        return None
