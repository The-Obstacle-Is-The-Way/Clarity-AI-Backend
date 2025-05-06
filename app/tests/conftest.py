# Standard Library Imports
import asyncio
import datetime
import logging
import os
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
from app.core.domain.entities.user import User, UserRole, UserStatus
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
def test_settings() -> Settings:
    """Load test settings, potentially overriding DATABASE_URL."""
    logger.info("Loading test settings.")
    # Load from .env.test if it exists, otherwise .env
    env_file = ".env.test" if Path(".env.test").exists() else ".env"
    settings = Settings(_env_file=env_file)

    # Use test settings from the proper settings module rather than hardcoding values here
    # This ensures we reference the standardized path for test database defined in settings.py
    # In-memory database is still the default for unit tests
    # but file-based standardized path can be enabled via environment variables
    # Define the test database path following clean architecture principles
    test_db_path = Path("app/infrastructure/persistence/data/test_db.sqlite3")
    
    # If TEST_PERSISTENT_DB is set, use the file-based database
    if os.environ.get("TEST_PERSISTENT_DB"):
        settings.DATABASE_URL = f"sqlite+aiosqlite:///./app/infrastructure/persistence/data/test_db.sqlite3"
        # Ensure the directory exists using Path objects (addressing lint warnings)
        test_db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using persistent test database: {settings.DATABASE_URL}")
    else:
        # Default to in-memory for most tests (faster, isolated)
        settings.DATABASE_URL = "sqlite+aiosqlite:///:memory:"
        logger.info(f"Using in-memory test database: {settings.DATABASE_URL}")
    
    logger.info(f"Test settings loaded. DATABASE_URL: {settings.DATABASE_URL}")
    return settings


# --- Database Fixtures ---
@pytest_asyncio.fixture(scope="function")
async def test_db_engine(test_settings: Settings) -> AsyncGenerator[AsyncEngine, None]:
    """Provides a clean SQLAlchemy engine for each test function."""
    logger.info(f"Creating test DB engine for URL: {test_settings.ASYNC_DATABASE_URL or test_settings.DATABASE_URL}")
    
    # Import model validation utilities
    from app.infrastructure.persistence.sqlalchemy.models.base import ensure_all_models_loaded
    from app.infrastructure.persistence.sqlalchemy.registry import validate_models
    
    # Ensure all models are loaded before creating tables
    ensure_all_models_loaded()
    
    # Create async engine with proper configuration for testing
    engine = create_async_engine(
        test_settings.ASYNC_DATABASE_URL or test_settings.DATABASE_URL,
        echo=False,  # Set to True for SQL logging
        connect_args={"check_same_thread": False},  # Required for SQLite
        poolclass=StaticPool,  # Use StaticPool for SQLite in-memory
    )
    
    # Validate all models to ensure proper registration
    validate_models()
    
    # Create all tables in a transaction
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
    
    # Default payload. This can be overridden by specific tests or fixtures like auth_headers.
    default_user_id_for_payload = str(uuid.uuid4())
    default_mock_payload = {
        "sub": default_user_id_for_payload,
        "roles": ["clinician"],
        "username": "default_mock_jwt_user",
        "exp": datetime.datetime.now(datetime.timezone.utc).timestamp() + 3600,
        "iat": datetime.datetime.now(datetime.timezone.utc).timestamp(),
    }
    
    mock.decode_token = MagicMock(return_value=default_mock_payload)
    
    # JWTService.verify_token calls decode_token. So, if decode_token is successful,
    # verify_token effectively returns True. If decode_token raises error, it's False.
    # We can mock it to reflect this behavior based on decode_token's mock.
    # For simplicity, if decode_token returns a payload, verify_token is true.
    def _mock_verify_token(token_str):
        try:
            mock.decode_token(token_str) # Call the mocked decode_token
            return True
        except Exception:
            return False
    mock.verify_token = MagicMock(side_effect=_mock_verify_token)

    # Remove the problematic get_user_from_token default that returned SQLAUser
    # if hasattr(mock, 'get_user_from_token'):
    #     del mock.get_user_from_token

    # Ensure other interface methods are present due to 'spec'
    mock.generate_tokens_for_user = MagicMock(return_value={"access_token": "mock_access", "refresh_token": "mock_refresh"})
    mock.refresh_access_token = MagicMock(return_value="new_mock_access_token")
    mock.get_token_expiration = MagicMock(return_value=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1))
    
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
            password_hash="hashed_password_placeholder",
            roles={UserRole.PATIENT},
            status=UserStatus.ACTIVE,
        )
    )
    service.register_user = AsyncMock(
        return_value=User(
            id=uuid.uuid4(),
            email="newuser@example.com",
            username="newuser",
            full_name="New User",
            password_hash="hashed_new_password",
            roles={UserRole.PATIENT},
            status=UserStatus.PENDING_VERIFICATION,
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
    # Import PasswordHandler only when needed to avoid circular imports
    from app.infrastructure.security.password_handler import PasswordHandler
    
    # Create password handler directly - following DI principles would be better but this is a test fixture
    password_handler = PasswordHandler()
    
    # Create SQLAlchemy User model (not domain entity)
    # Import the SQLAlchemy User model and the UserRole enum it expects
    from app.infrastructure.persistence.sqlalchemy.models.user import User as SQLAUser, UserRole as SQLAUserRole
    
    # Generate a UUID for the user
    user_id = uuid.uuid4()
    
    # Create a SQLAlchemy User model instance with required fields
    user = SQLAUser(
        id=user_id,
        username=faker.user_name(),
        email=TEST_USERNAME,
        password_hash=password_handler.hash_password(TEST_PASSWORD),
        is_active=True,
        is_verified=True,
        email_verified=True,
        role=SQLAUserRole.PATIENT,  # Use the actual Enum value not string
        roles=[SQLAUserRole.PATIENT.value],  # JSON field should be a list of string values
    )
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
    """Generate authentication headers for a mock authenticated user."""
    
    # Configure the mock_jwt_service instance used by this test/fixture
    # to return a payload corresponding to the authenticated_user.
    specific_payload = {
        "sub": str(authenticated_user.id), # Use the ID from the Pydantic domain User
        "roles": authenticated_user.roles,
        "username": authenticated_user.username,
        "email": authenticated_user.email,
        "exp": datetime.datetime.now(datetime.timezone.utc).timestamp() + 3600,
        "iat": datetime.datetime.now(datetime.timezone.utc).timestamp(),
    }
    mock_jwt_service.decode_token = MagicMock(return_value=specific_payload)
    
    # The token string itself doesn't matter much as decode_token is mocked based on its input.
    # However, create_access_token is also on the mock.
    access_token_str = mock_jwt_service.create_access_token(data={"sub": str(authenticated_user.id)})

    # The get_user_from_token attribute on jwt_service is not standard.
    # get_current_user relies on user_repo.get_user_by_id(payload["sub"]).
    # So, ensure authenticated_user is in the db_session for user_repo to find.
    # The authenticated_user fixture already persists the user.

    return {"Authorization": f"Bearer {access_token_str}"}


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


# Define a new event_loop fixture with function scope for better isolation,
# adhering to pytest-asyncio best practices.
@pytest.fixture(scope="function")
async def event_loop() -> asyncio.AbstractEventLoop:
    """Provide a function-scoped event loop, managed by pytest-asyncio."""
    # This simply allows pytest-asyncio to provide its default loop.
    # No explicit creation/closing needed here; pytest-asyncio handles it.
    return asyncio.get_event_loop()
