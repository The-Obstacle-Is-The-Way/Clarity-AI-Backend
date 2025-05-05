# Standard Library Imports
import asyncio
import datetime
import logging
import os
import sqlite3
import uuid
from collections.abc import AsyncGenerator, Callable

# Third Party Imports
import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import AsyncClient
from httpx import AsyncClient
from pydantic_settings import BaseSettings
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import AsyncMock, MagicMock

# Application-specific Imports
from app.app_factory import create_application # Presentation
from app.core.config import Settings # Core
from app.core.interfaces.repositories.user_repository_interface import IUserRepository # Core
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface # Core
from app.core.domain.entities.user import User, UserRole # Core
from app.core.security.auth import get_current_user # Core
from app.application.security.jwt_service import JWTService # Application
from app.infrastructure.database.base_class import Base # Infrastructure
from app.infrastructure.database.session import get_async_session # Infrastructure

logger = logging.getLogger(__name__)

# --- Constants for Test Data ---
# Use descriptive variable names
TEST_USERNAME = "testuser@example.com"
TEST_PASSWORD = "testpassword123"
TEST_INVALID_PASSWORD = "wrongpassword"

TEST_PROVIDER_EMAIL = "provider@clinic.com"
TEST_PROVIDER_PASSWORD = "providerPass123"

# --- Core Fixtures ---


@pytest.fixture(scope="session")
def event_loop() -> Callable[[], asyncio.AbstractEventLoop]:
    """Create an instance of the default event loop for the session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Override settings to use test database and disable certain features."""
    # Load base settings and override specifics for testing
    # Use environment variables for overrides if possible, fallback to defaults
    original_db_url = os.getenv("DATABASE_URL")
    original_redis_url = os.getenv("REDIS_URL")

    settings = Settings(
        _env_file=".env.test",  # Load test env if exists
        ENVIRONMENT="test",
        # Set default test values if not in .env.test
        DATABASE_URL=original_db_url or "postgresql+asyncpg://test:test@localhost:5433/testdb",
        REDIS_URL=original_redis_url or "redis://localhost:6380/0",
        SECRET_KEY="test_secret_key_for_jwt_testing_only_12345",
        ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=1,
        DB_ECHO_LOG=False,  # Keep DB logs quiet during tests unless debugging
        SENTRY_DSN=None,  # Disable Sentry for tests
        RATE_LIMIT_REQUESTS=1000,  # Allow high rate limit for tests
        RATE_LIMIT_PERIOD_SECONDS=60,
        # Add other test-specific settings as needed
    )
    db_url_display = settings.DATABASE_URL
    if "@" in db_url_display:
        db_url_display = db_url_display[: db_url_display.find("@")] + "@..."
    logger.info(f"Using test settings with DB: {db_url_display}")
    logger.info(f"Using test settings with Redis: {settings.REDIS_URL}")
    return settings


# --- Database Fixtures ---


@pytest_asyncio.fixture(scope="session")
async def test_db_engine(
    test_settings: Settings,
) -> AsyncGenerator[AsyncEngine, None]:
    """Creates a test database engine and enables foreign keys synchronously."""
    db_url = str(test_settings.DATABASE_URL)
    # Use StaticPool for SQLite in tests to simplify connection management
    # Also, ensure check_same_thread=False is passed for SQLite
    engine = create_async_engine(
        db_url,
        echo=test_settings.DB_ECHO_LOG,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False}
    )
    logger.info(f"Test DB engine created for: {engine.url}")

    # Enable Foreign Keys Synchronously before async operations
    logger.info("Attempting to enable foreign keys synchronously...")
    try:
        # Access the underlying sync engine's pool and get a connection
        sync_engine = engine.sync_engine
        with sync_engine.connect() as sync_conn:
            # Get the raw DBAPI connection
            raw_conn = sync_conn.connection.driver_connection
            if isinstance(raw_conn, sqlite3.Connection):
                 # Execute PRAGMA synchronously
                raw_conn.execute("PRAGMA foreign_keys=ON;")
                # Commit might be needed depending on SQLite/driver specifics
                raw_conn.commit()
                logger.info("Executed PRAGMA foreign_keys=ON synchronously.")
            else:
                logger.warning("Could not get raw sqlite3 connection to set PRAGMA.")
    except Exception as e:
        logger.error(f"Error enabling foreign keys synchronously: {e}", exc_info=True)
        # Decide if this should be a fatal error for the tests
        # pytest.fail(f"Failed to enable foreign keys: {e}")

    # Create tables asynchronously
    logger.info("Creating database tables...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all) # Ensure clean state
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created.")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}", exc_info=True)
        await engine.dispose() # Clean up engine if table creation fails
        pytest.fail(f"Failed to create database tables: {e}")


    yield engine # Yield the configured engine to tests

    # Drop tables
    logger.info("Dropping database tables...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.info("Database tables dropped.")
    except Exception as e:
        # Log error during teardown but don't necessarily fail the whole suite
        logger.error(f"Error dropping database tables during teardown: {e}", exc_info=True)
    finally:
        await engine.dispose()
        logger.info("Test DB engine disposed.")


@pytest_asyncio.fixture(scope="function")
async def db_session(test_db_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Provides a function-scoped database session with transaction rollback."""
    # Connect to the database
    connection = await test_db_engine.connect()
    # Begin a transaction
    trans = await connection.begin()
    # Bind an AsyncSession to the connection
    session_factory = sessionmaker(
        bind=connection, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    session = session_factory()
    logger.debug("DB session fixture started with transaction.")

    try:
        yield session
    finally:
        await session.close()
        # Rollback the transaction to ensure test isolation
        await trans.rollback()
        # Return the connection to the pool
        await connection.close()
        logger.debug("DB session fixture closed and transaction rolled back.")


# --- Application and Client Fixtures ---


@pytest.fixture(scope="function")
def override_get_settings(test_settings: Settings) -> Callable[[], Settings]:
    """Overrides the get_settings dependency to return test_settings."""
    return lambda: test_settings


# Define a mock function to replace get_current_user
async def mock_get_current_user() -> User:
    # Return a simple, valid User object for testing purposes
    return User(
        id=uuid.uuid4(),
        username="testuser",
        email="test@example.com",
        hashed_password="notarealpassword",
        role="user",
        is_active=True,
        first_name="Test",
        last_name="User",
        date_of_birth=datetime.date(1990, 1, 1),
        created_at=datetime.datetime.now(datetime.timezone.utc),
        updated_at=datetime.datetime.now(datetime.timezone.utc),
    )


@pytest_asyncio.fixture(scope="function")
async def initialized_app(
    test_settings: Settings,
    db_session: AsyncSession,  # Correctly depends on the managed session
    test_db_engine: AsyncEngine # Keep engine dependency if needed for app state
) -> FastAPI:
    """
    Provides a fully initialized FastAPI app instance for testing,
    ensuring the DB session dependency is correctly overridden with the
    transaction-managed session from the db_session fixture.
    """
    # Create the app instance directly
    app = create_application(settings=test_settings)

    # Set essential app state if needed (e.g., engine, though factory might be less relevant now)
    app.state.db_engine = test_db_engine
    # Optionally set the factory if other code relies on it, but override is key
    app.state.db_session_factory = sessionmaker(
        bind=test_db_engine, class_=AsyncSession, expire_on_commit=False
    )

    # Define the override function to yield the managed session
    async def override_get_async_session() -> AsyncGenerator[AsyncSession, None]:
        logger.debug(f"Yielding managed db_session: {id(db_session)}")
        yield db_session
        # No cleanup here, db_session fixture handles rollback/close

    # Apply necessary overrides
    app.dependency_overrides[get_async_session] = override_get_async_session
    app.dependency_overrides[get_current_user] = mock_get_current_user

    logger.info("Test FastAPI app instance created with DB session override.")
    return app


@pytest_asyncio.fixture(scope="function")
async def client(
    initialized_app: FastAPI,
) -> AsyncGenerator[AsyncClient, None]:
    """Provides an asynchronous HTTP client for making requests to the test app."""
    # Use the app provided by initialized_app fixture
    async with AsyncClient(app=initialized_app, base_url="http://testserver") as c:
        logger.debug("AsyncClient created for test app.")
        yield c


# --- Service Mocks/Fixtures ---


@pytest.fixture
def mock_jwt_service() -> MagicMock:
    """Provides a mock JWTService."""
    service = MagicMock(spec=JWTService)
    service.create_access_token = MagicMock(return_value="mock_access_token")
    service.create_refresh_token = MagicMock(return_value="mock_refresh_token")
    service.verify_token = MagicMock(
        return_value={"sub": TEST_USERNAME, "roles": [UserRole.ADMIN.value]}
    )
    service.decode_token = MagicMock(
        return_value={
            "sub": TEST_USERNAME,
            "roles": [UserRole.ADMIN.value],
            "exp": datetime.now(datetime.timezone.utc).timestamp() + 3600,
        }
    )
    return service


@pytest.fixture
def mock_auth_service(mock_jwt_service: MagicMock) -> MagicMock:
    """Provides a mock AuthService."""
    service = MagicMock(spec=AuthServiceInterface)
    service.authenticate_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(), email=TEST_USERNAME, hashed_password="hashed", roles=[UserRole.PATIENT]
        )
    )
    service.register_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(), email=TEST_USERNAME, hashed_password="hashed", roles=[UserRole.PATIENT]
        )
    )
    service.create_tokens = MagicMock(return_value=("mock_access_token", "mock_refresh_token"))
    service.refresh_access_token = AsyncMock(return_value="new_mock_access_token")
    service.get_authenticated_user = AsyncMock(
        return_value=User(id=uuid.uuid4(), email=TEST_USERNAME, roles=[UserRole.PATIENT])
    )
    service.verify_password = MagicMock(return_value=True)
    service.jwt_service = mock_jwt_service  # Assign mock JWT service
    return service


@pytest.fixture
def mock_user_service() -> MagicMock:
    """Provides a mock UserService."""
    service = MagicMock(spec=IUserRepository)
    test_user = User(
        id=uuid.uuid4(), email=TEST_USERNAME, hashed_password="hashed", roles=[UserRole.PATIENT]
    )
    service.create_user = AsyncMock(return_value=test_user)
    service.get_user_by_email = AsyncMock(return_value=test_user)
    service.get_user_by_id = AsyncMock(return_value=test_user)
    return service


# @pytest.fixture
# def mock_patient_service() -> MagicMock:
#     """Provides a mock PatientService."""
#     service = MagicMock(spec=PatientServiceInterface)
#     test_patient = Patient(
#         id=uuid.uuid4(), user_id=uuid.uuid4(), date_of_birth=datetime.date(1985, 5, 15)
#     )
#     service.create_patient = AsyncMock(return_value=test_patient)
#     service.get_patient_by_id = AsyncMock(return_value=test_patient)
#     # Add more mock methods as needed
#     return service


## TODO: Restore this fixture once InferenceResult is found/implemented
# @pytest_asyncio.fixture
# async def mock_model_service() -> MagicMock:
#     """Provides a mock ModelService."""
#     service = MagicMock(spec=ModelServiceInterface)
#     # Configure mock behavior if needed, e.g.:
#     # mock_info = ModelInfo(name="TestModel", version="1.0", description="Mocked Model")
#     # mock_result = InferenceResult(prediction=1.0, probability=0.9, metadata={"info": "mocked"})
#     # service.get_model_info.return_value = mock_info
#     # service.predict.return_value = mock_result
#     # service.load_model.return_value = None
#     logger.info("Mock ModelService created.")
#     return service

# --- Authentication Fixtures ---


@pytest_asyncio.fixture
async def authenticated_user(db_session: AsyncSession, mock_user_service: MagicMock) -> User:
    """Creates and saves a standard test user."""
    # Use the actual service logic if simple, or mock if complex setup needed
    user_service = IUserRepository(db_session)  # Use real service with test session
    user_data = UserCreateRequest(email=TEST_USERNAME, password=TEST_PASSWORD)
    created_user = await user_service.create_user(user_data)
    return created_user


# @pytest_asyncio.fixture
# async def provider_user(
#     db_session: AsyncSession, mock_user_service: MagicMock
# ) -> User:
#     """Creates and saves a provider test user."""
#     # Use the mock repository provided by the fixture
#     user_service = mock_user_service
#     # Assuming UserCreateRequest model exists or define a minimal dict/object
#     user_data = {
#         "email": TEST_PROVIDER_EMAIL, 
#         "password": TEST_PROVIDER_PASSWORD
#     }
#     # Assuming the repository's create method or a service method handles creation
#     # Adjust the call based on the actual repository/service interface if available
#     # If IUserRepository is the correct interface being mocked:
#     created_user = await user_service.create_user(user_data) 
#     # If a UserService wraps the repository:
#     # user_service_instance = UserService(user_repository=user_service)
#     # created_user = await user_service_instance.create_user(user_data, roles=[UserRole.PROVIDER])
#     # Need to clarify the actual service/repository interaction pattern
#     # For now, returning a dummy user based on mocked create
#     if (not hasattr(user_service, 'create_user')
#             or not isinstance(user_service.create_user, AsyncMock)):
#         # Fallback if mock setup is incomplete
#         user_service.create_user = AsyncMock(
#             return_value=User(
#                 id=uuid.uuid4(), 
#                 email=TEST_PROVIDER_EMAIL, 
#                 roles=[UserRole.PROVIDER]
#             )
#         )
#         created_user = await user_service.create_user(user_data)
#     else:
#         created_user = await user_service.create_user(user_data)

#     # Ensure the returned object is a User instance
#     if not isinstance(created_user, User):
#         # If the mock didn't return a User, create a default one
#         created_user = User(
#             id=uuid.uuid4(), 
#             email=TEST_PROVIDER_EMAIL, 
#             roles=[UserRole.PROVIDER]
#         )

#     return created_user


# @pytest.fixture
# def provider_auth_headers(mock_jwt_service: MagicMock, provider_user: User) -> dict[str, str]:
#     """Generates authorization headers for the provider user."""
#     access_token = mock_jwt_service.create_access_token(
#         data={"sub": provider_user.email, "roles": [UserRole.PROVIDER.value]}
#     )
#     return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def auth_headers(mock_jwt_service: MagicMock, authenticated_user: User) -> dict[str, str]:
    """Generates authorization headers for the standard authenticated user."""
    # Use the mock service to generate a token based on the created user's email
    # (or ID, depending on JWT subject strategy)
    access_token = mock_jwt_service.create_access_token(data={"sub": authenticated_user.email})
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def admin_auth_headers(mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generates authorization headers for a hypothetical admin user."""
    # Assuming admin user exists or token can be created directly for testing
    access_token = mock_jwt_service.create_access_token(
        data={"sub": "admin@clarity.ai", "roles": [UserRole.ADMIN.value]}
    )
    return {"Authorization": f"Bearer {access_token}"}


# --- Test Utility Functions ---


def override_requires_role(role: UserRole) -> Callable[[], None]:
    """Overrides the requires_role dependency to bypass actual role checking."""

    def bypass_role_check() -> None:
        # This dummy function does nothing, effectively bypassing the role check
        pass

    return bypass_role_check
