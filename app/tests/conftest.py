# Standard Library Imports
import asyncio
import datetime
import logging
import os
from typing import AsyncGenerator, Callable
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

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
from app.core.config import Settings
from app.core.domain.entities.user import User, UserRole
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.core.security.auth import get_current_user
from app.application.security.jwt_service import JWTService
from app.infrastructure.database.base_class import Base
from app.infrastructure.database.session import get_async_session
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
from app.infrastructure.security.password_handler import PasswordHandler

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
def event_loop_policy():
    """Set the asyncio event loop policy for the session."""
    return asyncio.WindowsSelectorEventLoopPolicy() if os.name == 'nt' else asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="session")
def event_loop(event_loop_policy):
    """Overrides pytest default function scope event loop"""
    loop = event_loop_policy.new_event_loop()
    yield loop
    loop.close()


# --- Core Settings and Configuration Fixtures ---
@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Load test settings, potentially overriding DATABASE_URL."""
    logger.info("Loading test settings.")
    # Load from .env.test if it exists, otherwise .env
    env_file = ".env.test" if os.path.exists(".env.test") else ".env"
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
        connect_args={"check_same_thread": False}, # Required for SQLite
        poolclass=StaticPool, # Use StaticPool for SQLite in-memory
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
            await session.commit() # Commit if test passes
            logger.debug(f"DB Session committed: {id(session)}")
        except Exception:
            logger.warning(f"DB Session rolling back due to exception: {id(session)}")
            await session.rollback() # Rollback on any exception
            raise
        finally:
            logger.debug(f"DB Session closing: {id(session)}")
            await session.close()


@pytest.fixture(scope="function")
def override_get_async_session(
    db_session: AsyncSession,
) -> Callable[[], AsyncGenerator[AsyncSession, None]]:
    """Fixture to override the get_async_session dependency."""

    async def _override() -> AsyncGenerator[AsyncSession, None]:
        logger.debug(f"Yielding managed db_session: {id(db_session)}")
        yield db_session
        # No cleanup here, db_session fixture handles rollback/close

    return _override


# --- Mock Service Fixtures ---
@pytest.fixture
def mock_get_current_user() -> User:
    # Return a simple, valid User object for testing purposes
    return User(
        id=uuid4(),
        username="testuser",
        email="test@example.com",
        hashed_password="notarealpassword", # Keep simple for mock
        roles=[UserRole.PATIENT.value], # Example role
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
        "sub": str(uuid4()),
        "roles": ["clinician"],
        # Correctly use datetime.datetime.now()
        "exp": datetime.datetime.now(datetime.timezone.utc).timestamp() + 3600,
        "iat": datetime.datetime.now(datetime.timezone.utc).timestamp(),
    }
    # Mock get_user_from_token to return a basic User object or similar
    mock.get_user_from_token = AsyncMock(
        return_value=User(
            id=uuid4(),
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
            id=uuid4(),
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
            id=uuid4(),
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
            id=uuid4(),
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
        id=uuid4(),
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


@pytest.fixture
def override_get_settings(test_settings: Settings) -> Callable[[], Settings]:
    """Overrides the get_settings dependency to return test_settings."""
    return lambda: test_settings


@pytest_asyncio.fixture(scope="function")
async def initialized_app(
    test_settings: Settings,
    test_db_engine: AsyncEngine,
    override_get_async_session: Callable[[], AsyncGenerator[AsyncSession, None]],
) -> FastAPI:
    """
    Initialize the FastAPI application for testing, ensuring essential state
    like the database session factory is available even before the first request.
    """
    logger.info("Initializing FastAPI app for testing.")

    app = create_application(settings=test_settings)

    # Manually set essential state for direct dependency testing
    # This mimics part of the lifespan manager for test setup.
    logger.info("Manually setting app.state for test initialization.")
    app.state.db_engine = test_db_engine
    # Use the *real* session factory creator, but with the test engine
    app.state.db_session_factory = sessionmaker(
        bind=test_db_engine, class_=AsyncSession, expire_on_commit=False
    )
    logger.info(f"Manually set app.state.db_engine: {app.state.db_engine}")
    logger.info(f"Manually set app.state.db_session_factory: {app.state.db_session_factory}")

    # Apply the crucial dependency override for request handling via client
    app.dependency_overrides[get_async_session] = override_get_async_session
    logger.info(f"App dependency overrides: {app.dependency_overrides}")

    # Define the override function to yield the managed session
    async def override_get_current_user() -> User:
        logger.debug(f"Yielding managed db_session: {id(db_session)}")
        yield mock_get_current_user()
        # No cleanup here, db_session fixture handles rollback/close

    # Apply necessary overrides
    app.dependency_overrides[get_current_user] = override_get_current_user

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


# --- User and Authentication Fixtures ---


@pytest_asyncio.fixture(scope="function")
async def authenticated_user(
    db_session: AsyncSession,
    faker: Faker,
    # No, use the concrete implementation here for fixture setup
    # user_service: IUserRepository  # Use the interface type hint if needed elsewhere
) -> User:
    """Creates an authenticated user in the database for testing purposes."""
    # Import concrete implementation for fixture setup
    from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
        SQLAlchemyUserRepository,
    )
    from app.infrastructure.security.password_handler import PasswordHandler # Correct local import path

    user_repo = SQLAlchemyUserRepository(db_session)
    password_handler = PasswordHandler()

    password = faker.password()
    hashed_password = password_handler.get_password_hash(password)
    user_email = faker.email()
    user_id = uuid4() # Now defined
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
        email_verified=True
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
    return str(uuid4())


@pytest.fixture
def invalid_name() -> str:
    """Provides an invalid name string (e.g., empty or whitespace)."""
    return "   "
