"""
Test Module for Database Connectivity in Docker Environment.

This module provides comprehensive validation of database connectivity
in the Docker container test environment, following clean architecture principles
and ensuring proper interface segregation between test components.
"""

import logging
import os
import uuid
from typing import Any

import pytest
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    insert,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.domain.utils.datetime_utils import now_utc

# Configure logging
logger = logging.getLogger(__name__)


class DatabaseConnectionValidator:
    """
    Domain service that validates database connectivity following clean architecture.

    This class embodies the single responsibility principle by focusing solely on
    validating database connections without mixing concerns.
    """

    def __init__(self, connection_url: str):
        """
        Initialize with a connection URL following dependency injection principles.

        Args:
            connection_url: Database connection URL to test
        """
        self.connection_url = connection_url
        self._engine: AsyncEngine | None = None

    async def create_engine(self) -> AsyncEngine:
        """
        Create a SQLAlchemy engine with mathematically optimal connection parameters.

        Returns:
            Configured AsyncEngine instance
        """
        self._engine = create_async_engine(
            self.connection_url,
            pool_size=2,  # Minimal pool for testing
            max_overflow=2,
            pool_timeout=10,
            pool_recycle=300,
            pool_pre_ping=True,
            echo=False,
        )
        return self._engine

    async def validate_connection(self) -> tuple[bool, str]:
        """
        Validate database connection with proper error handling.

        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self._engine:
            await self.create_engine()

        try:
            async with self._engine.connect() as connection:
                # Simple validation query
                result = await connection.execute(text("SELECT 1"))
                value = result.scalar()

                if value == 1:
                    return True, "Database connection successful"
                else:
                    return False, f"Unexpected result: {value}"

        except SQLAlchemyError as e:
            return False, f"Database connection error: {e!s}"
        except Exception as e:
            return False, f"Unexpected error: {e!s}"

    async def validate_table_operations(self) -> tuple[bool, str, list[dict[str, Any]]]:
        """
        Validate table operations with proper transaction management.

        This method tests more advanced database operations including:
        - Table creation
        - Data insertion
        - Data retrieval
        - Proper cleanup

        Returns:
            Tuple of (success: bool, message: str, results: List[Dict])
        """
        if not self._engine:
            await self.create_engine()

        # Define test table using SQLAlchemy metadata
        metadata = MetaData()
        test_table = Table(
            "test_docker_table",
            metadata,
            Column("id", UUID, primary_key=True),
            Column("name", String(50), nullable=False),
            Column("value", Integer, nullable=False),
            Column("created_at", DateTime, nullable=False),
        )

        results = []

        try:
            # Create table in a transaction
            async with self._engine.begin() as conn:
                await conn.run_sync(
                    lambda sync_conn: metadata.create_all(sync_conn, tables=[test_table])
                )

                # Insert test data
                test_id = uuid.uuid4()
                current_time = now_utc()
                stmt = insert(test_table).values(
                    id=test_id, name="test_record", value=42, created_at=current_time
                )
                await conn.execute(stmt)

                # Query data back
                query = select(test_table).where(test_table.c.id == test_id)
                result = await conn.execute(query)
                row = result.first()

                if row:
                    results.append(
                        {
                            "id": str(row.id),
                            "name": row.name,
                            "value": row.value,
                            "created_at": row.created_at.isoformat(),
                        }
                    )

                # Explicitly drop the table to clean up
                await conn.run_sync(lambda sync_conn: test_table.drop(sync_conn))

            return True, "Table operations successful", results

        except SQLAlchemyError as e:
            # Try to clean up the table even after error
            try:
                async with self._engine.begin() as conn:
                    await conn.run_sync(
                        lambda sync_conn: test_table.drop(sync_conn, checkfirst=True)
                    )
            except:
                pass
            return False, f"Table operation error: {e!s}", results

    async def dispose(self) -> None:
        """
        Clean up resources following RAII principles.
        """
        if self._engine:
            await self._engine.dispose()
            self._engine = None


@pytest.mark.asyncio
async def test_docker_database_connection_basic() -> None:
    """Test basic Docker database connectivity with clean error handling."""
    # Get database URL from environment
    db_url = os.environ.get("TEST_DATABASE_URL")

    # If not running in Docker, skip test
    if not db_url:
        pytest.skip("Not running in Docker environment (TEST_DATABASE_URL not set)")

    # Create validator following dependency injection principles
    validator = DatabaseConnectionValidator(db_url)

    try:
        # Test basic connectivity
        success, message = await validator.validate_connection()
        assert success, message
        logger.info(f"✅ Database connection test passed: {message}")
    finally:
        # Clean up resources
        await validator.dispose()


@pytest.mark.asyncio
async def test_docker_database_table_operations() -> None:
    """Test Docker database table operations with proper domain modeling."""
    # Get database URL from environment
    db_url = os.environ.get("TEST_DATABASE_URL")

    # If not running in Docker, skip test
    if not db_url:
        pytest.skip("Not running in Docker environment (TEST_DATABASE_URL not set)")

    # Create validator following dependency injection principles
    validator = DatabaseConnectionValidator(db_url)

    try:
        # Test table operations
        success, message, results = await validator.validate_table_operations()
        assert success, message

        # Validate results
        assert len(results) == 1, "Expected one test record"
        assert results[0]["name"] == "test_record", "Incorrect record name"
        assert results[0]["value"] == 42, "Incorrect record value"

        logger.info(f"✅ Database table operations test passed: {message}")
        logger.info(f"Test record: {results[0]}")
    finally:
        # Clean up resources
        await validator.dispose()
