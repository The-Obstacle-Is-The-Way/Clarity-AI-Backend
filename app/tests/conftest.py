# Standard Library Imports
import asyncio
import datetime
import logging
import uuid
from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Third Party Imports
import pytest
import pytest_asyncio
from faker import Faker
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Application-specific Imports
from app.core.config import Settings
from app.core.domain.entities.user import User, UserRole
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.application.security.jwt_service import JWTService
from app.infrastructure.database.base_class import Base
from app.infrastructure.database.session import get_async_session

logger = logging.getLogger(__name__)

# --- Constants for Test Data ---
# Use descriptive variable names
TEST_USERNAME = "testuser@example.com"
TEST_PASSWORD = "testpassword123"  
TEST_INVALID_PASSWORD = "wrongpassword"  

TEST_PROVIDER_EMAIL = "provider@clinic.com"
TEST_PROVIDER_PASSWORD = "providerPass123"  

# --- Core Fixtures ---


@pytest_asyncio.fixture(scope="session")
def event_loop_policy() -> asyncio.DefaultEventLoopPolicy:
    """Set the asyncio event loop policy for the session."""
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture(scope="session")
def event_loop(event_loop_policy: asyncio.AbstractEventLoopPolicy) -> asyncio.AbstractEventLoop:
    """Overrides pytest default function scope event loop"""
    loop = event_loop_policy.new_event_loop()
    yield loop
    loop.close()


# --- Core Settings and Configuration Fixtures ---
@pytest_asyncio.fixture(scope="session")
def test_settings() -> Settings:
    """Load test settings, potentially overriding DATABASE_URL."""
    logger.info("Loading test settings.")
    # Load from .env.test if it exists, otherwise .env
    env_file = ".env.test" if Path(".env.test").exists() else ".env"
    settings = Settings(_env_file=env_file)

    # Override DATABASE_URL for in-memory SQLite for most tests
    settings.DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    logger.info(f"Test settings loaded. DATABASE_URL: {settings.DATABASE_URL}")
    return settings


# --- Database Fixtures ---
@pytest_asyncio.fixture(scope="function")
async def test_db_engine(test_settings: Settings) -> AsyncGenerator[AsyncEngine, None]:
    """Provides a clean SQLAlchemy engine for each test function."""
    logger.info(f"Creating test DB engine for URL: {test_settings.DATABASE_URL}")
    engine = create_async_engine(
        test_settings.DATABASE_URL,
        # echo=True, # Uncomment for SQL logging
        connect_args={"check_same_thread": False},  # Required for SQLite
        poolclass=StaticPool,  # Use StaticPool for SQLite in-memory
    )
    async with engine.begin() as conn:
        logger.debug("Dropping all tables.")
        await conn.run_sync(Base.metadata.drop_all)
        logger.debug("Creating all tables.")
        await conn.run_sync(Base.metadata.create_all)

    logger.debug(f"Yielding test DB engine: {engine}")
    yield engine

    logger.debug("Disposing test DB engine.")
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(
    test_db_engine: AsyncEngine,
) -> AsyncGenerator[AsyncSession, None]:
    """Provides a clean SQLAlchemy session with automatic rollback for each test."""
    session_factory = sessionmaker(
        bind=test_db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        logger.debug(f"DB Session created: {id(session)}")
        try:
            yield session
            await session.commit()  # Commit if test passes
            logger.debug(f"DB Session committed: {id(session)}")
        except Exception:
            logger.warning(f"DB Session rolling back due to exception: {id(session)}")
            await session.rollback()  # Rollback on any exception
            raise
        finally:
            logger.debug(f"DB Session closing: {id(session)}")
            await session.close()


@pytest_asyncio.fixture(scope="function")
async def mock_session_fixture() -> AsyncGenerator[AsyncMock, None]:
    """Provides a mock AsyncSession for dependency injection.

    Yields:
        AsyncMock: A mock object simulating AsyncSession.
    """
    session = AsyncMock(spec=AsyncSession)
    # Configure common mock methods if needed globally, or configure in tests
    session.commit = AsyncMock()
    session.add = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    session.scalar = AsyncMock()
    session.scalars = AsyncMock()
    # Add other necessary method mocks
    yield session # Use yield if you need cleanup, otherwise return


# --- Mock Service Fixtures ---
@pytest.fixture
def mock_get_current_user() -> User:
    # Return a simple, valid User object for testing purposes
    return User(
        id=uuid.uuid4(),
        username="testuser",
        email="test@example.com",
        hashed_password="notarealpassword",  
        roles=[UserRole.PATIENT.value],  
        is_active=True,
        is_verified=True,
        email_verified=True,
    )


@pytest.fixture
def mock_jwt_service() -> MagicMock:
    """Provides a MagicMock for JWTService."""
    mock = MagicMock(spec=JWTService)
    mock.create_access_token = MagicMock(return_value="mock_access_token")
    mock.create_refresh_token = MagicMock(return_value="mock_refresh_token")
    # Simulate successful token verification returning a mock user payload
    mock_payload = {
        "sub": str(uuid.uuid4()),
        "roles": ["clinician"],
        # Correctly use datetime.datetime.now()
        "exp": datetime.datetime.now(datetime.timezone.utc).timestamp() + 3600,
        "iat": datetime.datetime.now(datetime.timezone.utc).timestamp(),
    }
    # Mock get_user_from_token to return a basic User object or similar
    mock.get_user_from_token = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email="mock@example.com",
            username="mockuser",
            roles=["clinician"],
            hashed_password="mockhashedpassword",
            is_active=True,
            is_verified=True,
            email_verified=True,
        )
    )
    mock.verify_token = MagicMock(return_value=mock_payload)
    return mock


@pytest.fixture
def mock_auth_service() -> MagicMock:
    """Provides a MagicMock for AuthService based on AuthServiceInterface."""
    service = MagicMock(spec=AuthServiceInterface)
    service.authenticate_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email=TEST_USERNAME,
            username="testuser",
            full_name="Test User",
            hashed_password="hashed_password_placeholder",
            roles=[UserRole.PATIENT.value],
            is_active=True,
            is_verified=True,
            email_verified=True,
        )
    )
    service.register_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email=TEST_USERNAME,
            username="testuser",
            full_name="Test User",
            hashed_password="hashed_password_placeholder",
            roles=[UserRole.PATIENT.value],
            is_active=True,
            is_verified=True,
            email_verified=True,
        )
    )
    service.refresh_access_token = AsyncMock(return_value="new_mock_access_token")
    service.get_authenticated_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email=TEST_USERNAME,
            username="testuser",
            full_name="Test User",
            hashed_password="hashed_password_placeholder",
            roles=[UserRole.PATIENT.value],
            is_active=True,
            is_verified=True,
            email_verified=True,
        )
    )
    return service


@pytest.fixture
def mock_user_service() -> MagicMock:
    """Provides a mock UserService."""
    service = MagicMock(spec=IUserRepository)
    test_user = User(
        id=uuid.uuid4(),
        email=TEST_USERNAME,
        username="testuser",
        full_name="Test User",
        hashed_password="hashed_password_placeholder",
        roles=[UserRole.PATIENT.value],
        is_active=True,
        is_verified=True,
        email_verified=True,
    )
    service.get_by_email = AsyncMock(return_value=test_user)
    service.get_by_id = AsyncMock(return_value=test_user)
    service.create = AsyncMock(return_value=test_user)
    return service


# --- Application and Client Fixtures ---


@pytest_asyncio.fixture(scope="function")
async def initialized_app(
    mock_session_fixture: AsyncSession,
) -> AsyncGenerator[tuple[AsyncClient, AsyncSession], None]:
    """Initialize FastAPI app with mock dependencies for testing.

    Initializes the FastAPI application and overrides key dependencies
    like the database session with mock objects.

    Args:
        mock_session_fixture (AsyncSession): The mock database session.

    Yields:
        tuple[AsyncClient, AsyncSession]: A tuple containing the test client
                                           and the mock session.
    """
    # Dynamically import create_application to avoid premature app creation
    from app.main import create_application

    app = create_application()

    # Override the database session dependency using lambda
    # This ensures the override provides the mock session instance directly
    # without requiring the 'request' object, crucial for error handling tests.
    app.dependency_overrides[get_async_session] = lambda: mock_session_fixture

    # Example: Override a service dependency (adjust as per your structure)
    # mock_patient_service = AsyncMock(spec=PatientService)
    # app.dependency_overrides[get_patient_service] = lambda: mock_patient_service

    # Use httpx.AsyncClient for async testing
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        yield client, mock_session_fixture

    # Clean up overrides after the test function completes
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def test_client(initialized_app: tuple[AsyncClient, AsyncSession]) -> AsyncClient:
    """Provides just the test client from the initialized app fixture.

    Args:
        initialized_app (tuple[AsyncClient, AsyncSession]): The output of initialized_app fixture.

    Returns:
        AsyncClient: The configured test client.
    """
    client, _ = initialized_app
    return client


@pytest.fixture(scope="function")
def mock_db_session(initialized_app: tuple[AsyncClient, AsyncSession]) -> AsyncSession:
    """Provides just the mock session from the initialized app fixture.

    Args:
        initialized_app (tuple[AsyncClient, AsyncSession]): The output of initialized_app fixture.

    Returns:
        AsyncSession: The mock database session.
    """
    _, session = initialized_app
    return session


# --- User and Authentication Fixtures ---


@pytest_asyncio.fixture(scope="function")
async def authenticated_user(
    db_session: AsyncSession,
    faker: Faker,
) -> User:
    """Creates an authenticated user in the database for testing purposes."""
    # Import concrete implementation for fixture setup
    from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
        SQLAlchemyUserRepository,
    )
    from app.core.domain.entities.user import User

    user_repo = SQLAlchemyUserRepository(db_session)

    hashed_password = "hashed_password_placeholder"  
    user_email = faker.email()
    user_id = uuid.uuid4()  
    username = faker.user_name()

    # Use the imported User class directly
    domain_user_instance = User(
        id=user_id,
        username=username,
        email=user_email,
        hashed_password=hashed_password,
        roles=[UserRole.PATIENT.value],
        is_active=True,
        is_verified=True,
        email_verified=True,
        first_name=faker.first_name(),
        last_name=faker.first_name(),
        created_at=datetime.datetime.now(datetime.timezone.utc),
        updated_at=datetime.datetime.now(datetime.timezone.utc),
    )
    logger.debug(
        f"Attempting to create user in authenticated_user fixture: {domain_user_instance.id}"
    )
    try:
        # Use the repository instance created above
        created_user = await user_repo.create(user=domain_user_instance)
        logger.debug(f"User created successfully: {created_user.id}")
        # Return the created user object (which should be the DomainUser instance)
        # If user_repo.create modifies the instance in place or returns a new one,
        # adjust accordingly. Assuming it returns the created object or confirmation.
        # Let's return the instance we tried to create, assuming create confirms it.
        return domain_user_instance
    except Exception as e:
        logger.error(f"Error creating user in fixture: {e}", exc_info=True)
        raise


# @pytest_asyncio.fixture
# async def provider_user(db_session: AsyncSession, password_handler: PasswordHandler) -> User:
#     """Creates a provider user in the database."""
#     from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
#     user_repo = SQLAlchemyUserRepository(db_session)
#     hashed_password = password_handler.get_password_hash(TEST_PROVIDER_PASSWORD)
#     user_data = UserCreateRequest(
#         username="provideruser",
#         email=TEST_PROVIDER_USERNAME,
#         password=hashed_password, # Already hashed
#         roles=[UserRole.PROVIDER.value]
#     )
#     # Need a service layer or repository method that accepts UserCreateRequest or adapts it
#     # This is likely incorrect - repository should take the Domain entity
#     domain_user = User(
#         id=uuid4(),
#         username=user_data.username,
#         email=user_data.email,
#         hashed_password=hashed_password,
#         roles=user_data.roles,
#         is_active=True, is_verified=True, email_verified=True
#     )
#     created_user = await user_repo.create(user=domain_user)
#     return created_user


@pytest.fixture
def auth_headers(mock_jwt_service: MagicMock, authenticated_user: User) -> dict[str, str]:
    """Generates authorization headers for the standard authenticated user."""
    # Use the mock service to generate a token based on the created user's email
    # (or ID, depending on JWT subject strategy)
    token = mock_jwt_service.create_access_token(data={"sub": authenticated_user.email})
    return {"Authorization": f"Bearer {token}"}


# @pytest.fixture
# def provider_auth_headers(mock_jwt_service: MagicMock, provider_user: User) -> dict[str, str]:
#     """Generates authorization headers for the provider user."""
#     token = mock_jwt_service.create_access_token(data={"sub": provider_user.email})
#     return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generates authorization headers for an admin user."""
    # Create a token for a hypothetical admin user
    token = mock_jwt_service.create_access_token(
        data={"sub": "admin@example.com", "roles": [UserRole.ADMIN.value]}
    )
    return {"Authorization": f"Bearer {token}"}


# --- Utility Fixtures ---
@pytest.fixture
def patient_id() -> str:
    """Provides a valid UUID string for use as a patient ID."""
    return str(uuid.uuid4())


@pytest.fixture
def invalid_name() -> str:
    """Provides an invalid name string (e.g., empty or whitespace)."""
    return "   "


@pytest.fixture
def faker() -> Faker:
    """Provides a Faker instance for generating test data."""
    return Faker()
