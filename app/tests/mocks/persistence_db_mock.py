"""
Mock implementation of persistence.db for testing.

This module provides mock versions of the database classes and functions
to allow tests to run without actual database connections.
"""
from unittest.mock import AsyncMock, MagicMock

# Mock SQLAlchemy AsyncSession
class AsyncSession(MagicMock):
    """Mock AsyncSession for testing without database connections."""
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
        
    async def commit(self):
        pass
        
    async def rollback(self):
        pass
        
    async def close(self):
        pass


# Mock DatabaseEngine
class DatabaseEngine(MagicMock):
    """Mock DatabaseEngine for testing."""
    async def dispose(self):
        pass
        
    async def create_all(self):
        pass


# Mock session factory function
def get_db_session():
    """Return a mock database session."""
    return AsyncMock(spec=AsyncSession)


# Mock database instance getter
def get_db_instance():
    """Return a mock database engine."""
    return MagicMock(spec=DatabaseEngine) 