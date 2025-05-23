from contextlib import asynccontextmanager

import pytest
from sqlalchemy import Column, Integer, String, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

# Create a dedicated declarative base for our tests
TestBase = declarative_base()


# Define a simple model for testing
class SampleModel(TestBase):
    """Test model for database operations."""

    __tablename__ = "test_models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    value = Column(String(100), nullable=True)


# Create our own test database wrapper
class TestDatabase:
    def __init__(self, connection_string="sqlite+aiosqlite:///:memory:"):
        self.connection_string = connection_string
        self.engine = create_async_engine(self.connection_string, echo=False, future=True)
        self.session_factory = async_sessionmaker(
            bind=self.engine, autocommit=False, autoflush=False, expire_on_commit=False
        )

    @asynccontextmanager
    async def session(self):
        """Get an async session as a context manager."""
        session = self.session_factory()
        try:
            yield session
        finally:
            await session.close()

    async def create_tables(self) -> None:
        """Create all the defined tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(TestBase.metadata.create_all)

    async def drop_tables(self) -> None:
        """Drop all the defined tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(TestBase.metadata.drop_all)

    async def dispose(self) -> None:
        """Dispose of the engine."""
        await self.engine.dispose()


@pytest.fixture(scope="function")
@pytest.mark.asyncio
async def test_db():
    """Create an in-memory test database."""
    db = TestDatabase()
    await db.create_tables()
    yield db
    await db.drop_tables()
    await db.dispose()


class TestDatabaseOperations:
    """Tests for basic database operations."""

    @pytest.mark.asyncio
    async def test_create_tables(self, test_db) -> None:
        """Test that tables can be created."""
        # Create a new record
        async with test_db.session() as session:
            record = SampleModel(name="test_create", value="test_value")
            session.add(record)
            await session.commit()

            # Query the record
            result = await session.execute(select(SampleModel).filter_by(name="test_create"))
            retrieved_record = result.scalar_one_or_none()

            # Verify it's there
            assert retrieved_record is not None
            assert retrieved_record.name == "test_create"
            assert retrieved_record.value == "test_value"

    @pytest.mark.asyncio
    async def test_session_operations(self, test_db) -> None:
        """Test session operations (add, commit, query)."""
        # Create a new record
        async with test_db.session() as session:
            record = SampleModel(name="test_session", value="session_ops")
            session.add(record)
            await session.commit()

            # Query it back
            result = await session.execute(select(SampleModel).filter_by(name="test_session"))
            retrieved_record = result.scalar_one_or_none()

            # Verify it exists
            assert retrieved_record is not None
            assert retrieved_record.name == "test_session"

    @pytest.mark.asyncio
    async def test_rollback(self, test_db) -> None:
        """Test session rollback."""
        async with test_db.session() as session:
            # Add a record
            record = SampleModel(name="rollback_test", value="will_be_rolled_back")
            session.add(record)

            # Roll back the transaction
            await session.rollback()

            # Try to query it - should not exist
            result = await session.execute(select(SampleModel).filter_by(name="rollback_test"))
            retrieved_record = result.scalar_one_or_none()

            # Should be None since we rolled back
            assert retrieved_record is None

    @pytest.mark.asyncio
    async def test_drop_tables(self, test_db) -> None:
        """Test dropping tables."""
        # First add a record
        async with test_db.session() as session:
            record = SampleModel(name="drop_test", value="will_be_dropped")
            session.add(record)
            await session.commit()

        # Drop all tables
        await test_db.drop_tables()

        # Recreate tables and verify they're empty
        await test_db.create_tables()

        # Query for the record - should be gone
        async with test_db.session() as session:
            result = await session.execute(select(SampleModel))
            records = result.scalars().all()
            assert len(records) == 0

    @pytest.mark.asyncio
    async def test_execute_query(self, test_db) -> None:
        """Test executing a raw SQL query."""
        # Use the engine directly for raw SQL
        async with test_db.engine.begin() as conn:
            await conn.execute(text("SELECT 1"))

        # If we reach here without error, the test passes
        assert True
