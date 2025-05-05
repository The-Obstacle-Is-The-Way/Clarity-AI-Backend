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
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Application-specific Imports
from app.app_factory import create_application
from app.application.security.jwt_service import JWTService
from app.core.config import Settings
from app.core.domain.entities.user import User, UserRole
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.infrastructure.database.base_class import Base

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
    mock_user = User(
        id=uuid.uuid4(),
        email="mock@example.com",
        username="mockuser",
        roles=["clinician"],
        hashed_password="mockhashedpassword",
        is_active=True,
        is_verified=True,
        email_verified=True,
    )
    mock.get_user_from_token = AsyncMock(return_value=mock_user)
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
            email="newuser@example.com",
            username="newuser",
            full_name="New User",
            hashed_password="hashed_new_password",
            roles=[UserRole.PATIENT.value],
            is_active=True,
            is_verified=False,
            email_verified=False,
        )
    )
    return service


@pytest.fixture
def mock_user_repository() -> MagicMock:
    """Provides a MagicMock conforming to the IUserRepository interface."""
    repo = MagicMock(spec=IUserRepository)
    repo.get_by_email = AsyncMock(return_value=None) # Default to not found
    repo.create = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email="created@example.com",
            username="createduser",
            hashed_password="createdpass",
            roles=[UserRole.PATIENT.value],
            is_active=True,
        )
    )
    repo.update = AsyncMock(return_value=True)
    repo.delete = AsyncMock(return_value=True)
    return repo

@pytest.fixture
def mock_user_service() -> MagicMock:
    """Provides a mock UserService."""
    service = MagicMock()
    # Mock specific methods used in tests
    service.get_user_by_email = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email=TEST_USERNAME,
            username="testuser",
            hashed_password="hashed_password_placeholder",
            roles=[UserRole.PATIENT.value],
            is_active=True,
        )
    )
    service.create_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email="created@example.com",
            username="createduser",
            hashed_password="createdpass",
            roles=[UserRole.PATIENT.value],
            is_active=True,
        )
    )
    return service


# --- Application and Client Fixtures ---

@pytest_asyncio.fixture(scope="function")
async def test_async_client(test_settings: Settings) -> AsyncGenerator[AsyncClient, None]:
    """
    Provides an AsyncClient configured with a FastAPI app instance
    created using test settings and managing the app's lifespan.
    """
    # Create the app instance with test settings
    # Override dependencies *before* creating the client or running lifespan
    dependency_overrides = {
        # Example: Override DB session if needed for specific integration tests
        # get_async_session: lambda: mock_session_fixture() # If you need a MOCK session
        # For REAL DB interaction in integration tests, DO NOT override get_async_session here.
        # Let the app use the real one configured by test_settings.
        # Override other services as needed for isolation
    }

    from app.app_factory import create_application
    app = create_application(settings=test_settings)
    app.dependency_overrides = dependency_overrides

    # Use AsyncClient as a context manager to handle lifespan
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        logger.info("Yielding AsyncClient with managed lifespan.")
        yield client
    logger.info("AsyncClient lifespan exited.")


# --- User and Authentication Fixtures ---


@pytest_asyncio.fixture
async def authenticated_user(
    db_session: AsyncSession,
    faker: Faker,
) -> User:
    """Creates an authenticated user in the database for testing purposes."""
    user_data = {
        "id": uuid.uuid4(),
        "username": faker.user_name(),
        "email": TEST_USERNAME,
        "full_name": faker.name(),
        # Use a fixed, known password for testing logins
        "hashed_password": JWTService(settings=Settings()).get_password_hash(TEST_PASSWORD),
        "roles": [UserRole.PATIENT.value],
        "is_active": True,
        "is_verified": True,
        "email_verified": True,
        "created_at": datetime.datetime.now(datetime.timezone.utc),
        "updated_at": datetime.datetime.now(datetime.timezone.utc),
        "last_login_at": None,
        "failed_login_attempts": 0,
        "lockout_until": None,
        "mfa_enabled": False,
        "mfa_secret": None,
        "mfa_backup_codes": [],
        "timezone": "UTC",
        "preferences": {},
        "profile_picture_url": None,
        "bio": faker.text(),
        "provider_details": None,
        "patient_details": None,
        "external_auth_provider_id": None,
        "external_auth_user_id": None,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    logger.debug(f"Created authenticated test user: {user.email} (ID: {user.id})")
    return user


# @pytest_asyncio.fixture
# async def provider_user(db_session: AsyncSession, password_handler: PasswordHandler) -> User:
#     """Creates a provider user in the database."""
#     provider_data = {
#         "id": uuid.uuid4(),
#         "username": "testprovider",
#         "email": TEST_PROVIDER_EMAIL,
#         "full_name": "Test Provider",
#         "hashed_password": password_handler.get_password_hash(TEST_PROVIDER_PASSWORD),
#         "roles": [UserRole.CLINICIAN.value],
#         "is_active": True,
#         "is_verified": True,
#         "email_verified": True,
#         # Add other relevant fields...
#     }
#     # Ensure UserCreateRequest or the actual model used for creation is imported
#     # from app.presentation.schemas.user import UserCreateRequest # Example
#     user = User(**provider_data) # Adjust based on actual model
#     db_session.add(user)
#     await db_session.commit()
#     await db_session.refresh(user)
#     return user


@pytest.fixture
def auth_headers(mock_jwt_service: MagicMock, authenticated_user: User) -> dict[str, str]:
    """Generates authorization headers for the standard authenticated user."""
    access_token = mock_jwt_service.create_access_token(data={"sub": str(authenticated_user.id)})
    return {"Authorization": f"Bearer {access_token}"}


# @pytest.fixture
# def provider_auth_headers(mock_jwt_service: MagicMock, provider_user: User) -> dict[str, str]:
#     """Generates authorization headers for the provider user."""
#     access_token = mock_jwt_service.create_access_token(data={
#         "sub": str(provider_user.id),
#         "roles": [role.value for role in provider_user.roles]
#     })
#     return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def admin_auth_headers(mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generates authorization headers for an admin user."""
    # Assuming admin role needs specific identification, adjust payload as needed
    admin_id = str(uuid.uuid4())
    access_token = mock_jwt_service.create_access_token(data={"sub": admin_id, "roles": [UserRole.ADMIN.value]})
    return {"Authorization": f"Bearer {access_token}"}


# --- Utility Fixtures ---
@pytest.fixture
def patient_id() -> str:
    """Provides a valid UUID string for use as a patient ID."""
    return str(uuid.uuid4())


@pytest.fixture
def invalid_name() -> str:
    """Provides an invalid name string (e.g., empty or whitespace)."""
    return "   "


@pytest.fixture(scope="session")
def faker() -> Faker:
    """Provides a Faker instance for generating test data."""
    return Faker()
