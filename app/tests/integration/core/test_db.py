"""
Tests for the database utilities using the standardized test_db_initializer.

This module verifies that our core database functionality works correctly
with the standardized test database infrastructure.
"""
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout_asyncio
from sqlalchemy import Column, String, text
from sqlalchemy.ext.asyncio import AsyncSession

# Import REAL application Base
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Import standardized test database components
from app.tests.integration.utils.test_db_initializer import get_test_db_session, verify_table_exists


@pytest.mark.asyncio
async def test_database_connection(db_session: AsyncSession):
    """Test basic database connectivity with standardized session."""
    # Simple query to verify connection
    result = await db_session.execute(text("SELECT 1"))
    value = result.scalar()
    assert value == 1, "Database connection failed"


@pytest.mark.asyncio
async def test_table_creation(db_session: AsyncSession):
    """Test that tables are properly created in the test database."""
    # Verify our standard tables exist
    assert await verify_table_exists(db_session, "users"), "Users table missing"
    assert await verify_table_exists(db_session, "patients"), "Patients table missing"

    # Verify core table structure
    result = await db_session.execute(text("PRAGMA table_info(users)"))
    columns = {col[1] for col in result.fetchall()}
    required_columns = {"id", "email", "username", "password_hash"}
    assert required_columns.issubset(columns), f"Missing columns in users table: {required_columns - columns}"


# Test model for custom table creation tests
class TestCustomModel(Base):
    __tablename__ = "test_custom_models"
    __table_args__ = {"extend_existing": True}

    id = Column(String(36), primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500))


@pytest_asyncio.fixture
async def setup_custom_model():
    """Setup and teardown for the custom model test."""
    # Use the standardized session
    async for session in get_test_db_session():
        # Create custom table
        await session.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {TestCustomModel.__tablename__} (
            id VARCHAR(36) PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description VARCHAR(500)
        )
        """))
        await session.commit()

        yield session

        # Cleanup: drop the custom table
        await session.execute(text(f"DROP TABLE IF EXISTS {TestCustomModel.__tablename__}"))
        await session.commit()


@pytest.mark.asyncio
async def test_custom_table_operations(setup_custom_model: AsyncSession):
    """Test operations on a custom table."""
    session = setup_custom_model

    # Verify table exists
    assert await verify_table_exists(session, TestCustomModel.__tablename__), \
    "Custom table was not created"

    # Insert test data
    await session.execute(text(f"""
    INSERT INTO {TestCustomModel.__tablename__} (id, name, description)
    VALUES ('test-id-1', 'Test Model', 'A test model for the database')
    """))
    await session.commit()

    # Query the data
    result = await session.execute(text(f"""
    SELECT id, name, description FROM {TestCustomModel.__tablename__}
    WHERE id = 'test-id-1'
    """))
    row = result.fetchone()

    # Verify data was properly inserted and retrieved
    assert row is not None, "Failed to retrieve inserted test data"
    assert row[0] == "test-id-1", "ID mismatch in retrieved data"
    assert row[1] == "Test Model", "Name mismatch in retrieved data"
