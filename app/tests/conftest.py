"""
Global test configuration for the entire test suite.

This module contains fixtures and configurations that should be available
to all tests in the application. It is automatically loaded by pytest.
"""

import logging
import sys
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Import the create_application function
from app.factory import create_application

# Make the module available to be imported by tests
sys.modules["pytest_asyncio"] = pytest_asyncio

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def base_test_config() -> dict[str, Any]:
    """
    Returns a basic configuration dictionary for tests.
    This can be used as a base for other fixtures.
    """
    return {
        "testing": True,
        "debug": True,
    }


@pytest.fixture(scope="session")
def test_settings():
    """
    Create test application settings.

    This fixture provides a configuration that can be used for testing
    without connecting to real external services.
    """
    from app.core.config.settings import Settings

    # Create test settings with safe defaults
    return Settings(
        # Database settings
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        # Security settings
        JWT_SECRET_KEY="test_secret_key_for_testing_only",
        JWT_ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        JWT_REFRESH_TOKEN_EXPIRE_DAYS=7,
        # API settings
        API_V1_STR="/api/v1",
        PROJECT_NAME="Clarity AI Backend Test",
        # Environment
        ENVIRONMENT="test",
        TESTING=True,
        # Redis settings
        REDIS_URL="redis://localhost:6379/0",
        # JWT settings
        JWT_ISSUER="clarity-auth",
        JWT_AUDIENCE="clarity-api",
        # Other settings as needed
        PHI_ENCRYPTION_KEY="test_encryption_key_for_phi_data_testing_only",
    )


@pytest.fixture(scope="session")
def encryption_service():
    """
    Create a test encryption service.

    This fixture provides a consistent encryption service for tests.
    """
    from app.infrastructure.security.encryption import create_encryption_service

    # Use a fixed test key for consistent test results
    test_key = "test_encryption_key_for_phi_data_testing_only"
    test_salt = "test_salt_value_for_encryption_tests_only"

    return create_encryption_service(secret_key=test_key, salt=test_salt)


@pytest.fixture(autouse=True)
def disable_audit_logging_for_tests(request):
    """
    Automatically disable audit logging for all tests.

    This fixture runs automatically for all tests and disables audit logging
    to avoid database transaction errors in tests.
    """
    # Skip disabling for certain tests if needed
    if request.node.get_closest_marker("enable_audit_logging"):
        yield
        return

    # Override setup for FastAPI applications in the test
    fixture_names = dir(request)
    for name in ["app", "app_instance", "test_app", "fastapi_app"]:
        if name in fixture_names:
            app = request.getfixturevalue(name)
            if isinstance(app, FastAPI):
                app.state.disable_audit_middleware = True
                logger.debug(f"Disabled audit middleware for app fixture: {name}")

    yield


@pytest_asyncio.fixture
async def with_disabled_audit_middleware(request, app_instance):
    """
    Fixture that explicitly disables audit middleware for FastAPI app instances.

    This is useful for tests that directly create FastAPI applications or when
    the autouse fixture doesn't work.
    """
    if hasattr(app_instance, "state"):
        app_instance.state.disable_audit_middleware = True
        logger.debug("Explicitly disabled audit middleware for test app")

    yield app_instance

    # Restore state if needed
    if hasattr(app_instance, "state"):
        app_instance.state.disable_audit_middleware = False


@pytest.fixture(scope="function")
async def client_app_tuple_func_scoped(
    test_settings,
) -> Generator[tuple[AsyncClient, FastAPI], None, None]:
    """
    Provides a tuple of (AsyncClient, FastAPI) with function scope.

    This fixture is more efficient for tests that need both the client and app instance,
    as it avoids creating them separately.
    """
    # Create application with explicit flags to disable middleware that might cause hangs
    app = create_application(
        settings_override=test_settings,
        include_test_routers=True,
        disable_audit_middleware=True,  # Explicitly disable audit middleware
        skip_auth_middleware=False,  # Keep auth middleware for auth tests
    )

    # Explicitly mark as test mode
    app.state.testing = True
    app.state.disable_audit_middleware = True

    # Ensure session factory is properly set up for tests
    async_engine = create_async_engine(
        test_settings.ASYNC_DATABASE_URL,
        echo=False,
        # For SQLite, important to enable check_same_thread=False for tests
        connect_args={"check_same_thread": False}
        if test_settings.ASYNC_DATABASE_URL.startswith("sqlite")
        else {},
    )

    # Create an async session factory
    async_session_factory = async_sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    # Set session factory on app state
    app.state.actual_session_factory = async_session_factory
    app.state.db_engine = async_engine

    # Create test tables if using SQLite in-memory
    if test_settings.ASYNC_DATABASE_URL.startswith("sqlite"):
        from app.infrastructure.persistence.sqlalchemy.models.base import Base

        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        app.state.db_schema_created = True

    # Create test client with non-default timeout
    async with AsyncClient(
        app=app,
        base_url="http://test",
        timeout=3.0,  # Add global timeout for all requests
    ) as client:
        yield client, app

    # Clean up resources
    await async_engine.dispose()


# Add fixtures for JWT testing with in-memory token blacklist
@pytest.fixture
def test_jwt_secret_key() -> str:
    """Fixture to provide a consistent JWT secret key for tests."""
    return "test_jwt_secret_key_that_is_sufficiently_long_for_testing_purposes_only"


@pytest.fixture
def test_jwt_settings(test_jwt_secret_key):
    """Fixture to provide JWT settings for tests."""
    from unittest.mock import MagicMock

    from app.core.config.settings import Settings

    # Create a mock settings object with JWT configuration
    settings = MagicMock(spec=Settings)
    settings.JWT_SECRET_KEY = test_jwt_secret_key
    settings.JWT_ALGORITHM = "HS256"
    settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30
    settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
    settings.JWT_ISSUER = "clarity-ai-test"
    settings.JWT_AUDIENCE = "test-audience"
    settings.ENVIRONMENT = "test"

    return settings


@pytest.fixture
def test_token_blacklist_repository():
    """Fixture to provide an in-memory token blacklist repository for tests."""
    from app.infrastructure.security.token.in_memory_token_blacklist_repository import (
        InMemoryTokenBlacklistRepository,
    )

    return InMemoryTokenBlacklistRepository()


@pytest.fixture
def jwt_service(mock_token_blacklist_repository):
    """Fixture for a configured JWT service for testing."""
    from app.infrastructure.security.jwt.jwt_service import JWTService
    from app.tests.utils.jwt_helpers import get_test_jwt_service_config

    config = get_test_jwt_service_config()
    jwt_service = JWTService(
        secret_key=config["secret_key"],
        algorithm=config["algorithm"],
        access_token_expire_minutes=config["access_token_expire_minutes"],
        refresh_token_expire_days=config["refresh_token_expire_days"],
        token_blacklist_repository=mock_token_blacklist_repository,
        issuer=config["issuer"],
        audience=config["audience"],
    )

    return jwt_service


@pytest.fixture
def mock_redis_service():
    """Fixture to provide a mock Redis service for tests."""
    from app.tests.mocks.mock_redis_service import MockRedisService

    return MockRedisService()


@pytest.fixture
def mock_redis_cache_service(mock_redis_service):
    """Fixture to provide a mock Redis cache service for tests."""
    from unittest.mock import MagicMock

    # Create a mock that wraps the MockRedisService for additional methods
    mock_cache = MagicMock()

    # Forward basic Redis operations to the MockRedisService
    mock_cache.get = mock_redis_service.get
    mock_cache.set = mock_redis_service.set
    mock_cache.delete = mock_redis_service.delete
    mock_cache.exists = mock_redis_service.exists
    mock_cache.expire = mock_redis_service.expire
    mock_cache.ttl = mock_redis_service.ttl
    mock_cache.incr = mock_redis_service.incr
    mock_cache.decr = mock_redis_service.decr
    mock_cache.hset = mock_redis_service.hset
    mock_cache.hget = mock_redis_service.hget
    mock_cache.hdel = mock_redis_service.hdel

    # Additional methods for CacheService
    mock_cache.get_json = mock_redis_service.get
    mock_cache.set_json = mock_redis_service.set

    return mock_cache


@pytest.fixture
def mock_token_blacklist_repository():
    """
    Fixture to provide an in-memory token blacklist repository.

    This implementation doesn't rely on Redis and is suitable for unit tests.
    """
    from app.core.interfaces.repositories.token_blacklist_repository_interface import (
        ITokenBlacklistRepository,
    )

    class InMemoryTokenBlacklistRepository(ITokenBlacklistRepository):
        """In-memory implementation for testing."""

        def __init__(self):
            self._token_blacklist = {}  # token hash -> jti
            self._jti_blacklist = {}  # jti -> details

        async def add_to_blacklist(
            self, token: str, jti: str, expires_at: datetime, reason: str | None = None
        ) -> None:
            """Add a token to the blacklist."""
            from hashlib import sha256

            token_hash = sha256(token.encode()).hexdigest()
            self._token_blacklist[token_hash] = jti
            self._jti_blacklist[jti] = {
                "expires_at": expires_at,
                "reason": reason or "test_blacklist",
            }

        async def is_blacklisted(self, token: str) -> bool:
            """Check if a token is blacklisted."""
            from hashlib import sha256

            token_hash = sha256(token.encode()).hexdigest()
            return token_hash in self._token_blacklist

        async def is_jti_blacklisted(self, token_id: str) -> bool:
            """Check if a JTI is blacklisted."""
            return token_id in self._jti_blacklist

        async def clear_expired_tokens(self) -> int:
            """Remove expired tokens from the blacklist."""
            now = datetime.now(timezone.utc)
            expired_jtis = [
                jti
                for jti, details in self._jti_blacklist.items()
                if details.get("expires_at") and details.get("expires_at") <= now
            ]

            for jti in expired_jtis:
                del self._jti_blacklist[jti]

                # Also remove from token blacklist
                for token_hash, token_jti in list(self._token_blacklist.items()):
                    if token_jti == jti:
                        del self._token_blacklist[token_hash]

            return len(expired_jtis)

    return InMemoryTokenBlacklistRepository()


@pytest.fixture
def mock_settings():
    """Fixture to provide mock settings for tests."""
    from app.tests.mocks.mock_settings import MockSettings

    return MockSettings()


# Setup ML model service fixture
@pytest.fixture
def mock_model_service():
    """
    Fixture to provide a mock model service for tests.

    This mock service allows tests requiring ML model functionality to run
    without actual ML models or inference operations. It provides predictable
    responses for testing purposes.

    Returns:
        IModelService: A mock implementation of the model service interface
    """
    from app.tests.utils.mock_model_service import create_mock_model_service

    return create_mock_model_service()


from app.core.schemas.users import UserCreateRequest

@pytest.fixture
def provider_user():
    """Fixture to provide a provider user for tests."""
    return UserCreateRequest(
        email="provider@example.com",
        password="test_password",
        first_name="Provider",
        last_name="User",
        role="provider",
    )


@pytest.fixture
def provider_auth_headers(provider_user, jwt_service):
    """Fixture to provide provider authentication headers for tests."""
    token = jwt_service.create_access_token_for_user(provider_user)
    return {"Authorization": f"Bearer {token}"}


# Setup other global fixtures if needed
