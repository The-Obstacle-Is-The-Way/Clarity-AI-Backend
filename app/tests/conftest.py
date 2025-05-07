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
from sqlalchemy.pool import StaticPool, Pool
from sqlalchemy import event
from sqlalchemy.dialects import sqlite

# Application-specific Imports
from app.app_factory import create_application
from app.application.security.jwt_service import JWTService
from app.core.config import Settings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.registry import metadata as main_metadata
from app.presentation.api.dependencies.auth import get_current_user as app_get_current_user

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


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Load test settings, ensuring ENVIRONMENT is set to 'test'."""
    logger.info("Loading test settings for session scope.")
    # Load from .env.test if it exists, otherwise .env
    env_file = ".env.test" if Path(".env.test").exists() else None # Prefer .env.test, fallback to default load
    
    # Initialize settings, allowing .env file loading
    # We will explicitly override critical test settings afterwards
    if env_file:
        current_settings = Settings(_env_file=env_file, _env_file_encoding='utf-8')
        logger.info(f"Loaded settings from {env_file}")
    else:
        # If no .env.test, load with default .env behaviour (which might be .env or defaults)
        current_settings = Settings() 
        logger.info("Loaded settings with default .env behavior (no .env.test found).")

    # Explicitly override/ensure settings for the test environment
    current_settings.ENVIRONMENT = "test"
    current_settings.TESTING = True
    current_settings.SENTRY_DSN = None # Disable Sentry for tests

    # Logic for database URL (copied from original fixture)
    test_db_path = Path("app/infrastructure/persistence/data/test_db.sqlite3")
    if os.environ.get("TEST_PERSISTENT_DB"):
        db_url = f"sqlite+aiosqlite:///./app/infrastructure/persistence/data/test_db.sqlite3"
        test_db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using persistent test database: {db_url}")
    else:
        db_url = "sqlite+aiosqlite:///:memory:"
        logger.info(f"Using in-memory test database: {db_url}")
    
    current_settings.DATABASE_URL = db_url
    current_settings.ASYNC_DATABASE_URL = db_url # Ensure async URL is also set

    logger.info(f"Final test settings: ENVIRONMENT={current_settings.ENVIRONMENT}, DATABASE_URL={current_settings.DATABASE_URL}, ASYNC_DATABASE_URL={current_settings.ASYNC_DATABASE_URL}")
    return current_settings


# --- Database Fixtures ---
@pytest_asyncio.fixture(scope="function")
async def test_db_engine(test_settings: Settings) -> AsyncGenerator[AsyncEngine, None]:
    """Provides a clean SQLAlchemy engine for each test function."""
    logger.info(f"Creating test DB engine for URL: {test_settings.ASYNC_DATABASE_URL or test_settings.DATABASE_URL}")
    
    # Import model validation utilities
    from app.infrastructure.persistence.sqlalchemy.registry import validate_models
    
    # Ensure all models are loaded before creating tables
    # ensure_all_models_loaded() # Removed call
    
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
    import datetime
    from app.core.domain.entities.user import UserRole
    from app.infrastructure.security.jwt_service import JWTService # Correct path
    # from app.domain.exceptions.token_exceptions import InvalidTokenException # Not needed for this simplified version

    logger.info("--- mock_jwt_service FIXTURE CREATED ---") # Log fixture creation

    mock = MagicMock(spec=JWTService)

    # Simplified decode_token mock
    TEST_USER_ID_STR = "00000000-0000-0000-0000-000000000001"
    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
    default_payload = {
        "sub": TEST_USER_ID_STR, 
        "roles": [UserRole.PATIENT.value], 
        "exp": now_ts + 3600, 
        "type": "access", 
        "jti": str(uuid.uuid4())
    }

    def simple_mock_decode_token(token: str, settings_param = None):
        logger.info(f"!!! MOCK JWT DECODE CALLED (simplified) WITH TOKEN: {token} !!!")
        # Optionally, raise an exception for specific unhandled tokens if needed for a test
        # if token not in ["VALID_PATIENT_TOKEN", "VALID_PROVIDER_TOKEN", "VALID_ADMIN_TOKEN", "mock_access_token"]:
        #     raise InvalidTokenException(f"Mock JWTService (simplified): Unhandled token '{token}'")
        return default_payload

    # mock.decode_token = MagicMock(side_effect=mock_decode_token_side_effect) # OLD COMPLEX SIDE EFFECT
    mock.decode_token = MagicMock(side_effect=simple_mock_decode_token) # NEW SIMPLIFIED SIDE EFFECT

    mock.create_access_token = MagicMock(return_value="mock_access_token")
    mock.create_refresh_token = MagicMock(return_value="mock_refresh_token")
    
    # Keep other mocks if they might be incidentally called
    def _mock_verify_token(token_str):
        # logger.info(f"!!! MOCK VERIFY TOKEN (simplified) CALLED WITH: {token_str} !!!")
        try:
            mock.decode_token(token_str) # Will call the simplified, logging decode
            return True
        except Exception:
            return False
    mock.verify_token = MagicMock(side_effect=_mock_verify_token)

    mock.generate_tokens_for_user = MagicMock(return_value={"access_token": "mock_access_token_for_user", "refresh_token": "mock_refresh_token_for_user"})
    mock.refresh_access_token = MagicMock(return_value="new_mock_access_token_via_refresh")
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
async def mock_override_user() -> User:
    """Provides a mock user that can be used for overriding get_current_user."""
    # logger.info("--- mock_override_user FIXTURE CALLED ---")
    return User(
        id=uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"), # Example UUID
        email="override_user@example.com",
        username="override_user",
        roles=[UserRole.PATIENT.value], # Default to patient
        is_active=True,
        is_verified=True,
        email_verified=True,
        # Add other fields as necessary for your User model
    )

@pytest_asyncio.fixture(scope="function")
async def client_app_tuple(test_settings: Settings, mock_override_user: User) -> AsyncGenerator[tuple[AsyncClient, FastAPI], None]:
    """Creates a FastAPI app instance and an AsyncClient for it, with auth overridden.
    Uses LifespanManager for consistency with integration tests.
    """
    logger.info("Creating client_app_tuple with overridden auth and LifespanManager.")
    
    # Import LifespanManager here to keep fixture self-contained if moved
    from asgi_lifespan import LifespanManager
    from httpx import ASGITransport # Ensure ASGITransport is imported

    # Create a new app instance for this test
    app_instance = create_application(settings_override=test_settings)

    # Override the get_current_user dependency
    async def mock_get_current_user_dependency_override() -> User:
        return mock_override_user

    app_instance.dependency_overrides[app_get_current_user] = mock_get_current_user_dependency_override

    async with LifespanManager(app_instance) as manager:
        logger.info(f"client_app_tuple: LifespanManager active for app id: {id(manager.app)}")
        transport = ASGITransport(app=manager.app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client, manager.app # Yield client and the app instance from LifespanManager

    logger.info("Cleaning up client_app_tuple overrides.")
    if app_get_current_user in app_instance.dependency_overrides: # Check on original app_instance
        del app_instance.dependency_overrides[app_get_current_user]

@pytest_asyncio.fixture(scope="function")
async def unauth_async_client(test_settings: Settings) -> AsyncGenerator[AsyncClient, None]:
    """
    Provides an AsyncClient configured with a FastAPI app instance
    created using test settings, managing app lifespan, WITHOUT auth overrides.
    """
    app = create_application(settings_override=test_settings)
    
    from asgi_lifespan import LifespanManager
    async with LifespanManager(app):
        async with AsyncClient(app=app, base_url="http://testserver") as client:
            logger.info("Yielding UNAUTHENTICATED AsyncClient with managed lifespan.")
            yield client
    logger.info("UNAUTHENTICATED AsyncClient lifespan exited.")


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
@pytest.fixture(scope="session")
async def event_loop() -> asyncio.AbstractEventLoop:
    """Provide a session-scoped event loop, managed by pytest-asyncio."""
    # This simply allows pytest-asyncio to provide its default loop.
    # No explicit creation/closing needed here; pytest-asyncio handles it.
    return asyncio.get_event_loop()


# Event listener to enable foreign keys for SQLite connections
# This uses Pool.connect and bridges to async for aiosqlite
@event.listens_for(Pool, "connect", named=True)
def set_sqlite_pragma(dbapi_connection, connection_record, **kwargs):
    """Enable foreign_keys on SQLite connection for testing FK constraints."""
    # Robust check for dialect information and aiosqlite loop
    if (hasattr(connection_record, 'dialect') and 
        connection_record.dialect and 
        connection_record.dialect.name == 'sqlite' and 
        hasattr(dbapi_connection, '_loop')):
        
        loop = dbapi_connection._loop

        async def _execute_pragma(conn):
            try:
                await conn.execute("PRAGMA foreign_keys=ON")
                logger.debug("PRAGMA foreign_keys=ON executed for SQLite connection.")
            except Exception as e:
                logger.error(f"Failed to set PRAGMA foreign_keys=ON for SQLite: {e}")

        if loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_execute_pragma(dbapi_connection), loop)
            try:
                future.result(timeout=5)  # Add a timeout to prevent indefinite blocking
            except TimeoutError:
                logger.error("Timeout waiting for PRAGMA foreign_keys=ON to execute.")
            except Exception as e:
                logger.error(f"Error running PRAGMA task: {e}")
        else:
            # This case should ideally not happen if the pool is active
            # Fallback or error for non-running loop if necessary, though
            # aiosqlite connections from an async engine should have a running loop.
            logger.warning("Event loop for DBAPI connection not running, cannot set PRAGMA.")

@pytest_asyncio.fixture(scope="session")
async def test_db_engine(event_loop, test_settings: Settings) -> AsyncEngine:
    """Provides a clean SQLAlchemy engine for each test function."""
    logger.info(f"Creating test DB engine for URL: {test_settings.ASYNC_DATABASE_URL or test_settings.DATABASE_URL}")
    
    # Import model validation utilities
    from app.infrastructure.persistence.sqlalchemy.registry import validate_models
    
    # Ensure all models are loaded before creating tables
    # ensure_all_models_loaded() # Removed call
    
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
