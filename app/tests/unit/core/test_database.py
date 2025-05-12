"""
Unit tests for database connection and session management.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

# Updated imports from app.core.db
import app.core.dependencies.database as dbmod

# Assuming settings are correctly loaded
from app.config.settings import Settings, get_settings
from app.core.dependencies.database import get_engine, get_session, get_session_local

# Test settings (override if necessary for testing environment)
TEST_DATABASE_URL = "postgresql+asyncpg://test_user:test_password@test_host:5432/test_db"
# Define a dummy Base for testing if the actual one isn't available/needed here
# from sqlalchemy.orm import declarative_base
# Base = declarative_base()

@pytest.fixture(scope="module")
def test_settings() -> Settings:
    """Overrides settings for testing, specifically the database URL."""
    settings = get_settings()
    # Override DATABASE_URL for isolated testing
    settings.DATABASE_URL = TEST_DATABASE_URL
    # Ensure other DB settings that might affect engine creation are consistent if needed
    settings.DATABASE_ECHO = False # Usually false for tests
    return settings

@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    # The loop should be closed at the end of the test
    loop.close()

@pytest.mark.asyncio
@patch.object(dbmod, 'create_async_engine')  # Patch the underlying engine creation
async def test_get_engine(mock_create_engine, test_settings: Settings):
    """Test the get_engine function."""
    # Ensure the test_settings fixture provides the DATABASE_URL
    assert test_settings.DATABASE_URL is not None, "DATABASE_URL must be set in test_settings"

    # Mock the return value of create_async_engine
    mock_engine_instance = AsyncMock()
    mock_engine_instance.url = test_settings.DATABASE_URL # Set mock url
    mock_engine_instance.pool.size = MagicMock(return_value=test_settings.DB_POOL_SIZE) # Mock pool size
    mock_engine_instance.pool.overflow = MagicMock(return_value=test_settings.DB_MAX_OVERFLOW) # Mock pool overflow
    mock_create_engine.return_value = mock_engine_instance

    # Reset the global _engine variable in db.py before calling get_engine
    with patch.object(dbmod, '_engine', None):
        engine = get_engine(test_settings)

    assert engine is mock_engine_instance
    # Verify create_async_engine was called with expected args
    mock_create_engine.assert_called_once()
    call_args = mock_create_engine.call_args[0]
    call_kwargs = mock_create_engine.call_args[1]
    assert call_args[0] == test_settings.DATABASE_URL # Check URL passed correctly
    assert call_kwargs.get('echo') == test_settings.DATABASE_ECHO
    assert call_kwargs.get('pool_size') == test_settings.DB_POOL_SIZE
    assert call_kwargs.get('max_overflow') == test_settings.DB_MAX_OVERFLOW

    # Dispose of the mock engine (important for async mocks)
    await engine.dispose()
    mock_engine_instance.dispose.assert_awaited_once()

@pytest.mark.asyncio
@patch.object(dbmod, 'sessionmaker')  # Patch sessionmaker creation
async def test_get_session_local(mock_sessionmaker, test_settings: Settings):
    """Test the creation of the sessionmaker via get_session_local."""
    mock_engine = AsyncMock()
    with patch.object(dbmod, 'get_engine', return_value=mock_engine):
        with patch.object(dbmod, '_async_session_local', None):
            SessionLocalFactory = get_session_local(engine=mock_engine)

    assert SessionLocalFactory is not None
    mock_sessionmaker.assert_called_once()
    call_kwargs = mock_sessionmaker.call_args[1]
    assert call_kwargs.get('bind') == mock_engine
    assert call_kwargs.get('class_') == AsyncSession
    assert call_kwargs.get('expire_on_commit') is False
    assert call_kwargs.get('autoflush') is False

@pytest.mark.asyncio
async def test_get_session_context_manager():
    """Test the get_session context manager yields and closes a session."""
    mock_session_factory = MagicMock(spec=sessionmaker)
    mock_session_instance = AsyncMock(spec=AsyncSession)
    mock_session_factory.return_value.__aenter__.return_value = mock_session_instance

    with patch.object(dbmod, 'get_session_local', return_value=mock_session_factory):
        async with get_session() as session:
            assert session is mock_session_instance
            await session.execute("SELECT 1")

    mock_session_factory.assert_called_once()
    mock_session_instance.close.assert_awaited_once()
    mock_session_factory.return_value.__aexit__.assert_awaited_once()

@pytest.mark.asyncio
async def test_get_session_context_manager_exception():
    """Test the get_session context manager handles exceptions correctly."""
    mock_session_factory = MagicMock(spec=sessionmaker)
    mock_session_instance = AsyncMock(spec=AsyncSession)
    mock_session_factory.return_value.__aenter__.return_value = mock_session_instance

    test_exception = ValueError("Something went wrong")

    with patch.object(dbmod, 'get_session_local', return_value=mock_session_factory):
        with pytest.raises(ValueError, match="Something went wrong"):
            async with get_session() as session:
                assert session is mock_session_instance
                raise test_exception

    mock_session_factory.assert_called_once()
    # mock_session_instance.rollback.assert_awaited_once() # Uncomment if rollback is implemented
    mock_session_instance.close.assert_awaited_once()
    mock_session_factory.return_value.__aexit__.assert_awaited_once()


# Example test demonstrating how to use the dependency with a mock request if needed
# async def test_route_using_get_db():
#     mock_session = AsyncMock(spec=AsyncSession)
#     async def override_get_db():
#         yield mock_session
#         await mock_session.close() # Simulate close
#
#     app.dependency_overrides[get_db_dependency()] = override_get_db # Assuming get_db_dependency exists
#     async with AsyncClient(app=app, base_url="http://test") as client:
#         response = await client.get("/some_route_using_db")
#     # Assertions...
#     app.dependency_overrides.clear() # Clean up override 