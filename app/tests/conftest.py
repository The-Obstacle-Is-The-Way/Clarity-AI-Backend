"""
Pytest configuration file for the application.

This module provides fixtures and configuration for testing the application.
"""

import asyncio
import logging
import uuid
from collections.abc import AsyncGenerator, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from typing import Any

# --- Core App/Config Imports ---
from app.core.config.settings import Settings, get_settings
from app.core.interfaces.repositories.user_repository import IUserRepository

# --- Domain Imports ---


# --- Infrastructure Imports ---
from app.infrastructure.persistence.sqlalchemy.database import Base
from app.infrastructure.security.password.hashing import pwd_context
from app.domain.services.pat_service import PATService

# --- Presentation Layer Imports ---
from app.main import create_application
from app.presentation.api.dependencies.user_repository import get_user_repository_provider
from app.presentation.api.dependencies.auth_service import get_auth_service_provider
from app.presentation.api.dependencies.auth import get_jwt_service
from app.core.dependencies.database import get_db_session
from app.presentation.api.dependencies.services import get_pat_service
from app.presentation.api.v1.endpoints import auth as auth_router
from app.presentation.middleware.authentication_middleware import (
    AuthenticationMiddleware,
)

# --- Test Utility Imports ---


# Setup logging for tests
logger = logging.getLogger(__name__)

# --- Global Test Constants ---
TEST_USERNAME = "testuser@example.com"
TEST_PASSWORD = "testpassword" 
TEST_INVALID_PASSWORD = "wrongpassword" 
TEST_INTEGRATION_USER_ID = uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
TEST_PROVIDER_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")

# --- Helper Functions --- 

def create_test_application(settings: Settings) -> FastAPI:
    """
    Create a minimal FastAPI application instance for testing.
    
    This function is a simplified version of the real create_application 
    function in app_factory.py, bypassing problematic imports and dependencies
    that aren't needed for testing.
    
    Args:
        settings: Application settings
        
    Returns:
        FastAPI application instance configured for testing
    """
    # Create a minimal FastAPI app with test-appropriate settings
    app = FastAPI(
        title=settings.PROJECT_NAME if hasattr(settings, "PROJECT_NAME") else "Test API",
        description="Test API for automated testing",
        version=settings.VERSION if hasattr(settings, "VERSION") else "0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    return app

# --- Settings Fixtures --- 

@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Load test settings once per session by calling the core get_settings.
    The core get_settings function now handles test environment detection.
    """
    logger.info("Loading test settings via core get_settings()...")
    # Call the correct get_settings from app.core.config.settings
    settings = get_settings()
    logger.info(
        f"Test Settings Loaded: {settings.model_dump(exclude={'JWT_SECRET_KEY'})}" 
    )
    return settings

# --- Mock Service Fixtures --- 

@pytest.fixture(scope="function")
def mock_jwt_service() -> AsyncMock:
    """Provides a function-scoped AsyncMock for JWTService."""
    mock = AsyncMock()
    # Example config (tests can override):
    # mock.create_access_token = AsyncMock(return_value="mock_access_token") 
    # mock.verify_token = AsyncMock(
    #     return_value={"sub": str(TEST_INTEGRATION_USER_ID), "roles": ["patient"]}
    # )
    return mock

@pytest.fixture(scope="function")
def mock_auth_service() -> AsyncMock:
    """Provides a function-scoped AsyncMock for AuthService."""
    mock = AsyncMock()
    return mock

@pytest.fixture(scope="function")
def mock_pat_service() -> AsyncMock:
    """Provides a function-scoped AsyncMock for PATService."""
    mock = AsyncMock()
    return mock

@pytest.fixture(scope="function")
def mock_analytics_service() -> AsyncMock:
    """Provides a basic AsyncMock for the Analytics Service."""
    mock = AsyncMock()
    mock.process_event = AsyncMock(return_value=None)
    mock.process_batch_events = AsyncMock(return_value=None)
    mock.get_event_summary = AsyncMock(return_value={"total_events": 10})
    return mock

# --- Mock Repository/DB Fixtures --- 

@pytest_asyncio.fixture(scope="function")
async def test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Creates an isolated in-memory SQLite database session for each test function.
    Ensures schema is created and rolled back after the test.
    """
    database_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(
        database_url,
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False}
    )

    async with engine.begin() as conn:
        logger.info("Creating all tables in test database...")
        await conn.run_sync(Base.metadata.create_all)

    testing_session_local = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
        expire_on_commit=False,
        class_=AsyncSession
    )

    async with testing_session_local() as session:
        logger.info("Yielding test database session.")
        yield session
        logger.info("Rolling back test database session transaction.")
        await session.rollback()

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def mock_db_session_override(
    test_db_session: AsyncSession
) -> Callable[[], AsyncGenerator[AsyncSession, None]]:
    """Provides a fixture yielding the test_db_session for overriding get_db_session."""
    async def _override() -> AsyncGenerator[AsyncSession, None]:
        yield test_db_session
    return _override

@pytest_asyncio.fixture(scope="function")
def mock_user_repository_override(
) -> Callable[[], IUserRepository]: 
    """Provides a factory function returning a mock IUserRepository."""
    def factory() -> IUserRepository: 
        mock_repo = AsyncMock()
        # Configure get_user_by_username mock
        async def mock_get_by_username(username: str) -> MagicMock | None:
            if username == TEST_USERNAME:
                mock_user = MagicMock()
                mock_user.id = TEST_INTEGRATION_USER_ID
                mock_user.username = TEST_USERNAME
                mock_user.hashed_password = pwd_context.hash(TEST_PASSWORD)
                mock_user.role = "patient"
                mock_user.is_active = True
                return mock_user
            return None
        mock_repo.get_user_by_username = AsyncMock(side_effect=mock_get_by_username)
        mock_repo.get_user_by_id = AsyncMock(return_value=None)
        mock_repo.create_user = AsyncMock(return_value=None)
        # Add other necessary mock methods from IUserRepository if needed
        # Example: mock_repo.get_by_id = AsyncMock(return_value=None) 
        return mock_repo

@pytest_asyncio.fixture(scope="function")
def mock_pat_service_override(
    mock_pat_service: AsyncMock
) -> Callable[[], PATService]: 
    """Provides a factory function returning the mock PATService."""
    def factory() -> PATService:
        return mock_pat_service
    return factory

# --- Application Fixture --- 

@pytest_asyncio.fixture(scope="function")
async def initialized_app(
    test_settings: Settings, 
    mock_db_session_override: Callable[[], AsyncGenerator[AsyncSession, None]], 
    mock_user_repository_override: Callable[[], IUserRepository],
    mock_pat_service_override: Callable[[], PATService], 
    mock_jwt_service: AsyncMock,
    mock_auth_service: AsyncMock,
    mock_analytics_service: AsyncMock,
) -> AsyncGenerator[FastAPI, None]:
    """
    Creates a MINIMAL FastAPI app configured for endpoint tests, 
    INCLUDING AuthenticationMiddleware and necessary overrides.
    Scope is function to ensure isolation.
    
    Yields the app instance for use in tests.
    """
    dependency_overrides = {
        get_settings: lambda: test_settings,
        get_db_session: mock_db_session_override, 
        get_pat_service: mock_pat_service_override, 
        get_jwt_service: lambda: mock_jwt_service, 
        get_auth_service_provider: lambda: mock_auth_service, 
        get_user_repository_provider: mock_user_repository_override,
        # get_analytics_service_provider: lambda: mock_analytics_service, 
    }

    app_instance = create_application(
        settings=test_settings, 
        dependency_overrides=dependency_overrides
    )

    public_paths = getattr(
        test_settings, 
        'AUTH_PUBLIC_PATHS', 
        ['/docs', '/openapi.json', '/api/v1/auth/login', '/public']
    )
    app_instance.add_middleware(
        AuthenticationMiddleware,
        public_paths=public_paths
    )

    app_instance.include_router(
        auth_router.router, 
        prefix="/api/v1/auth", 
        tags=["auth"]
    )

    # Optionally include other routers needed by specific test suites
    # Example: 
    # from app.presentation.api.v1.routers import analytics as analytics_router
    # app_instance.include_router(
    #     analytics_router.router, 
    #     prefix="/api/v1/analytics", 
    #     tags=["analytics"]
    # )

    yield app_instance

# --- Async Client Fixture --- 

@pytest_asyncio.fixture(scope="function")
async def async_client(
    initialized_app: FastAPI,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Create a new httpx AsyncClient instance for tests using the initialized_app.
    Ensures proper async context management.
    """
    async with AsyncClient(
        app=initialized_app, base_url="http://testserver"
    ) as client:
        yield client

# --- Authentication Header Fixture ---

@pytest_asyncio.fixture(scope="function")
async def auth_headers(
    async_client: AsyncClient, 
    test_settings: Settings 
) -> dict[str, str]:
    """Perform login and return authentication headers for test requests."""
    login_data = {
        "username": TEST_USERNAME, 
        "password": TEST_PASSWORD,
    }
    # Use the API prefix from settings
    login_url = f"{test_settings.API_V1_STR}/auth/login"
    logger.info(f"Attempting login for auth_headers fixture via URL: {login_url}")
    
    response = await async_client.post(login_url, data=login_data)
    
    # Log response status and content for debugging
    logger.info(f"Login response status: {response.status_code}")
    try:
        response_json = response.json()
        logger.info(f"Login response JSON: {response_json}") 
    except Exception as e:
        logger.error(f"Failed to parse login response JSON: {e}")
        logger.error(f"Login response text: {response.text}")
        response_json = {}

    if response.status_code != 200:
        logger.error(f"Login failed with status {response.status_code}. Response: {response.text}")
        # Optionally raise an error or return empty dict depending on test needs
        pytest.fail(f"Login failed for auth_headers fixture: {response.status_code} - {response.text}")

    access_token = response_json.get("access_token")
    if not access_token:
        pytest.fail("Access token not found in login response for auth_headers fixture.")
        
    headers = {"Authorization": f"Bearer {access_token}"}
    logger.info("auth_headers fixture generated successfully.")
    return headers
