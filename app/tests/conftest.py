# Standard Library Imports
import asyncio
import logging
import os
import uuid
from collections.abc import AsyncGenerator, Callable, Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

# Third-Party Imports
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

# Application-Specific Imports
from app.app_factory import create_application
from app.core.config import Settings
from app.core.domain.entities.user import UserRole, User
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
# from app.core.domain.services.patient import PatientServiceInterface # Interface definition missing
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.infrastructure.database.base_class import Base
from app.infrastructure.database.session import get_async_session
from app.infrastructure.security.jwt import JWTService
from app.presentation.api.dependencies.auth import get_current_user
# from app.presentation.api.v1.models.users import UserCreateRequest # Model definition missing

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
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
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


@pytest.fixture(scope="session")
def postgres_container(test_settings: Settings) -> Generator[PostgresContainer, None, None]:
    """Starts a PostgreSQL container for the test session."""
    # Extract connection details from the potentially overridden DATABASE_URL
    # Basic parsing - consider a more robust URL parser if needed
    db_url = str(test_settings.DATABASE_URL)
    creds_part = db_url.split("@")[0].split("//")[1]
    db_part = db_url.split("@")[1]
    user, password = creds_part.split(":")
    host_port_db = db_part.split("/")
    dbname = host_port_db[-1]
    image = "postgres:15-alpine"  # Specify a PostgreSQL version

    logger.info(f"Starting PostgreSQL container (Image: {image}, DB: {dbname})...")
    with PostgresContainer(image=image, username=user, password=password, dbname=dbname) as pg:
        logger.info(f"PostgreSQL container started: {pg.get_connection_url()}")
        # Update settings to use the container's dynamic URL
        test_settings.DATABASE_URL = pg.get_connection_url().replace(
            "postgresql://", "postgresql+asyncpg://"
        )
        logger.info(f"Test settings DATABASE_URL updated to: {test_settings.DATABASE_URL}")
        yield pg
    logger.info("PostgreSQL container stopped.")


@pytest.fixture(scope="session")
def redis_container(test_settings: Settings) -> Generator[RedisContainer, None, None]:
    """Starts a Redis container for the test session."""
    # Basic parsing for Redis URL (assuming redis://host:port/db format)
    redis_url_parts = str(test_settings.REDIS_URL).split(":")
    port = int(redis_url_parts[2].split("/")[0])
    image = "redis:7-alpine"  # Specify a Redis version

    logger.info(f"Starting Redis container (Image: {image}, Port: {port})...")
    with RedisContainer(image=image, port=port) as redis:
        container_host = redis.get_container_host_ip()
        container_port = redis.get_exposed_port(port)
        redis_connection_url = f"redis://{container_host}:{container_port}/0"
        logger.info(f"Redis container started: {redis_connection_url}")
        # Update settings to use the container's dynamic URL
        test_settings.REDIS_URL = redis_connection_url
        logger.info(f"Test settings REDIS_URL updated to: {test_settings.REDIS_URL}")
        yield redis
    logger.info("Redis container stopped.")


# --- Database Fixtures ---


@pytest_asyncio.fixture(scope="session")
async def test_db_engine(
    test_settings: Settings, postgres_container: PostgresContainer
) -> AsyncGenerator[AsyncEngine, None]:
    """Creates a test database engine using the session-scoped Postgres container."""
    # Ensure postgres_container fixture runs first and updates the settings
    engine = create_async_engine(str(test_settings.DATABASE_URL), echo=test_settings.DB_ECHO_LOG)
    logger.info(f"Test DB engine created for: {engine.url}")

    # Create tables
    logger.info("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created.")

    yield engine

    # Drop tables
    logger.info("Dropping database tables...")
    async with engine.begin() as conn:
        # Consider CASCADE if relationships cause issues during drop
        await conn.run_sync(Base.metadata.drop_all)
    logger.info("Database tables dropped.")

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


# Renamed fixture to avoid conflict and clarify purpose
@pytest_asyncio.fixture(scope="function")
async def test_app_factory(
    test_settings: Settings, test_db_engine: AsyncEngine, redis_container: RedisContainer
) -> Callable[..., FastAPI]:
    """
    Provides a factory function to create the app instance for each test function.
    Ensures dependencies like DB engine and Redis are ready *before* app creation.
    """
    # Ensure containers are up and settings are updated before creating the app
    _ = postgres_container  # Dependency ensures it runs
    _ = redis_container  # Dependency ensures it runs

    # Create the test session factory using the test engine
    test_session_local = sessionmaker(
        bind=test_db_engine, class_=AsyncSession, expire_on_commit=False
    )

    def _create_test_app(**overrides: dict[Callable, Callable]) -> FastAPI:
        app = create_application(settings=test_settings)

        # Set up the application state correctly for tests *before* it's used
        app.state.db_engine = test_db_engine
        app.state.db_session_factory = test_session_local
        # Assuming redis client is created from pool in lifespan or middleware:
        # Need to ensure test Redis pool is available if middleware uses it directly
        app.state.redis_pool = getattr(redis_container, "pool", None)  # Or get from container
        app.state.redis = getattr(redis_container, "client", None)  # Or get from container

        # Override get_async_session to use the test factory stored in app.state
        async def override_get_async_session(
            request: Request,
        ) -> AsyncGenerator[AsyncSession, None]:
            # Access the factory stored in app.state by the test_app_factory
            session_factory = getattr(request.app.state, "db_session_factory", None)
            if not isinstance(session_factory, sessionmaker):
                # This shouldn't happen if test_app_factory sets state correctly
                logger.error("Test session factory not found in app state during override.")
                raise RuntimeError("Test session factory not found in app state during override.")

            async with session_factory() as session:
                # The transaction is managed by the db_session fixture,
                # so we just yield the session provided by the factory.
                # No explicit rollback/commit/close here.
                logger.debug(
                    "Yielding session from overridden get_async_session using app.state factory."
                )
                yield session

        app.dependency_overrides[get_async_session] = override_get_async_session  # Restore override

        # Apply any additional test-specific overrides
        app.dependency_overrides.update(overrides)

        logger.info("Test FastAPI application instance created with overrides.")
        return app

    return _create_test_app


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
    test_app_factory: Callable[..., FastAPI],
    db_session: AsyncSession,  # Ensures transaction context
) -> FastAPI:
    """
    Provides a fully initialized FastAPI app instance for testing,
    using the test factory and ensuring the DB session context is managed.
    Crucially, overrides problematic dependencies during app creation.
    """
    # Pass the override for get_current_user when creating the app
    app = test_app_factory(
        overrides={
            get_current_user: mock_get_current_user  # Add the override here
        }
    )
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
            "exp": datetime.now(timezone.utc).timestamp() + 3600,
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
#     user_data = UserCreateRequest(email=TEST_PROVIDER_EMAIL, password=TEST_PROVIDER_PASSWORD) # Missing Model
#     # Assuming the repository's create method or a service method handles creation
#     # Adjust the call based on the actual repository/service interface if available
#     # If IUserRepository is the correct interface being mocked:
#     created_user = await user_service.create_user(user_data) # Adjust based on actual create signature
#     # If a UserService wraps the repository:
#     # user_service_instance = UserService(user_repository=user_service)
#     # created_user = await user_service_instance.create_user(user_data, roles=[UserRole.PROVIDER])
#     # Need to clarify the actual service/repository interaction pattern
#     # For now, returning a dummy user based on mocked create
#     if not hasattr(user_service, 'create_user') or not isinstance(user_service.create_user, AsyncMock):
#          # Fallback if mock setup is incomplete
#          user_service.create_user = AsyncMock(return_value=User(id=uuid.uuid4(), email=TEST_PROVIDER_EMAIL, roles=[UserRole.PROVIDER]))
#          created_user = await user_service.create_user(user_data)
#     else:
#          created_user = await user_service.create_user(user_data)

#     # Ensure the returned object is a User instance
#     if not isinstance(created_user, User):
#         # If the mock didn't return a User, create a default one
#         created_user = User(id=uuid.uuid4(), email=TEST_PROVIDER_EMAIL, roles=[UserRole.PROVIDER])

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
