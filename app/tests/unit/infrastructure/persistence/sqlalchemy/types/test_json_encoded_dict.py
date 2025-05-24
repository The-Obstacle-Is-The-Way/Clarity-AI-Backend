"""
Unit tests for the JSONEncodedDict type decorator.

Tests the ability to store and retrieve dictionary data through SQLAlchemy
with JSON serialization for different database dialects.
"""

from sqlalchemy import Column, Integer, MetaData, Table, create_engine
from sqlalchemy.orm import Session, registry

from app.infrastructure.persistence.sqlalchemy.types import JSONEncodedDict


class TestJSONEncodedDict:
    """Tests for the JSONEncodedDict SQLAlchemy TypeDecorator."""

    def setup_method(self) -> None:
        """Set up a fresh metadata and engine for each test."""
        self.metadata = MetaData()
        self.mapper_registry = registry()

        # Create a test table with a JSONEncodedDict column
        self.test_table = Table(
            "test_json",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("data", JSONEncodedDict, nullable=True),
        )

    def test_json_sqlite_dialect(self) -> None:
        """Test JSONEncodedDict with SQLite dialect."""
        # Create a SQLite in-memory database
        engine = create_engine("sqlite:///:memory:")
        self.metadata.create_all(engine)

        # Test dictionary to store
        test_dict = {"key1": "value1", "key2": 123, "nested": {"a": 1, "b": 2}}

        # Test inserting and retrieving JSON values
        with Session(engine) as session:
            # Execute raw SQL to insert data
            session.execute(self.test_table.insert().values(id=1, data=test_dict))
            session.commit()

            # Query the data back
            result = session.execute(self.test_table.select()).fetchone()

            # Verify the dictionary was stored and retrieved correctly
            assert isinstance(result.data, dict), "Should retrieve as dict object"
            assert result.data == test_dict, "Should retrieve the same dict values"
