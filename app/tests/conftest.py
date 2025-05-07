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
    from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException # Import exceptions

    logger.info("--- mock_jwt_service FIXTURE CREATED (Stateful) ---") # Log fixture creation

    mock = MagicMock(spec=JWTService)
    
    # Internal store for tokens
    issued_tokens_store = {} # token_string: {"payload": dict, "exp_timestamp": float}

    TEST_USER_ID_STR = "00000000-0000-0000-0000-000000000001" # Default, can be overridden by create_access_token data
    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
    default_payload_template = { # Used if create_access_token isn't called and decode is hit directly with an unmocked token
        "sub": TEST_USER_ID_STR, 
        "roles": [UserRole.PATIENT.value], 
        "exp": now_ts + 3600, 
        "type": "access", 
        "jti": str(uuid.uuid4())
    }

    def mock_create_access_token(data: dict, expires_delta: datetime.timedelta | None = None) -> str:
        token_string = f"mock_token_{uuid.uuid4()}"
        
        # Calculate expiry timestamp
        if expires_delta:
            expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
        else:
            # Default expiry if not provided (e.g., 15 minutes, adapt as needed)
            expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
        exp_timestamp = expire.timestamp()

        # Construct payload, ensuring 'exp' is present
        payload = data.copy()
        payload["exp"] = exp_timestamp
        payload.setdefault("type", "access") # Ensure type is set
        payload.setdefault("jti", str(uuid.uuid4())) # Ensure JTI is set

        issued_tokens_store[token_string] = {"payload": payload, "exp_timestamp": exp_timestamp}
        logger.info(f"Mock JWTService: Created token {token_string} with payload: {payload}")
        return token_string

    def mock_decode_token(token: str, settings_param = None) -> dict: # settings_param kept for signature compatibility
        logger.info(f"Mock JWTService: Attempting to decode token: {token}")
        if token not in issued_tokens_store:
            # Fallback for specific hardcoded tokens if necessary for some legacy tests,
            # but ideally all tokens come from create_access_token
            if token == "VALID_PATIENT_TOKEN": # Example of a specific known token
                 logger.warning(f"Mock JWTService: Using default payload for unmanaged token {token}")
                 return {**default_payload_template, "sub": "patient-sub-id", "roles": [UserRole.PATIENT.value]}
            logger.error(f"Mock JWTService: Invalid token - not found in store: {token}")
            raise InvalidTokenException("Mock JWTService: Token not found in store.")

        token_info = issued_tokens_store[token]
        
        # Check expiry
        if datetime.datetime.now(datetime.timezone.utc).timestamp() > token_info["exp_timestamp"]:
            logger.error(f"Mock JWTService: Token expired: {token}")
            raise TokenExpiredException("Mock JWTService: Token has expired.")
            
        logger.info(f"Mock JWTService: Decoded token {token} to payload: {token_info['payload']}")
        return token_info["payload"]

    mock.create_access_token = MagicMock(side_effect=mock_create_access_token)
    mock.decode_token = MagicMock(side_effect=mock_decode_token)
    mock.create_refresh_token = MagicMock(return_value="mock_refresh_token") # Remains simple for now
    
    def _mock_verify_token(token_str: str) -> bool:
        # logger.info(f"!!! MOCK VERIFY TOKEN (stateful) CALLED WITH: {token_str} !!!")
        try:
            mock.decode_token(token_str) # This will now use the stateful decode with expiry checks
            return True
        except (InvalidTokenException, TokenExpiredException):
            return False
        except Exception as e: # Catch any other unexpected errors during decode
            logger.error(f"Mock JWTService: Unexpected error during verify_token for {token_str}: {e}")
            return False
    mock.verify_token = MagicMock(side_effect=_mock_verify_token)

    mock.generate_tokens_for_user = MagicMock(
        return_value={"access_token": "mock_access_token_for_user", "refresh_token": "mock_refresh_token_for_user"}
    )
    mock.refresh_access_token = MagicMock(return_value="new_mock_access_token_via_refresh")
    mock.get_token_expiration = MagicMock(
        return_value=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    )
    
    # Add a way to clear the store for test isolation if needed, e.g., via a nested function or attribute
    def clear_store():
        issued_tokens_store.clear()
        logger.info("Mock JWTService: Token store cleared.")
    mock.clear_issued_tokens = MagicMock(side_effect=clear_store)

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
        full_name="Override User FullName", # Added full_name as it's required by the dataclass
        password_hash="override_hashed_password", # Added password_hash as it's required
        roles={UserRole.PATIENT}, # Use a set of Enum members
        status=UserStatus.ACTIVE, # Set status correctly
        # Removed is_active, is_verified, email_verified as they are not __init__ params for the dataclass
        # The dataclass has defaults for created_at, mfa_enabled, attempts etc.
    )

@pytest_asyncio.fixture(scope="function")
async def client_app_tuple(test_settings: Settings, mock_override_user: User) -> AsyncGenerator[tuple[AsyncClient, FastAPI], None]:
    """Creates a FastAPI app instance and an AsyncClient for it.
    Uses LifespanManager for consistency with integration tests.
    Auth is NOT globally overridden here anymore. Tests should rely on mock_jwt_service.
    The app instance yielded is the direct result from create_application, ensuring
    tests receive the actual FastAPI object, while the client still uses the
    LifespanManager-processed app for transport.
    """
    logger.info("Creating client_app_tuple. Yielding direct app_instance to tests.")
    
    from asgi_lifespan import LifespanManager
    from httpx import ASGITransport

    # Create the FastAPI application instance
    app_instance = create_application(settings_override=test_settings)
    logger.info(f"CONTEST: app_instance created. Type: {type(app_instance)}, id: {id(app_instance)}")

    # LifespanManager is used to ensure startup/shutdown events are run for the app
    # The AsyncClient's transport needs to be connected to the app *within* the LifespanManager context.
    async with LifespanManager(app_instance) as manager:
        logger.info(f"CONTEST: LifespanManager active. Type of manager.app: {type(manager.app)}, id: {id(manager.app)}")
        transport = ASGITransport(app=manager.app) # Client transport uses the app from LifespanManager
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            # Yield the original app_instance to the test, not manager.app
            logger.info(f"CONTEST: Yielding client and ORIGINAL app_instance (id: {id(app_instance)}) to test.")
            yield client, app_instance 

    logger.info("Cleaning up client_app_tuple.")

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
        "roles": authenticated_user.roles if isinstance(authenticated_user.roles, list) else list(authenticated_user.roles), # Ensure list
        "username": authenticated_user.username,
        "email": authenticated_user.email,
        # exp and iat will be set by mock_create_access_token
    }
    
    mock_jwt_service.clear_issued_tokens() # Clear if previous calls created other tokens
    access_token_str = mock_jwt_service.create_access_token(data=specific_payload)

    # The get_user_from_token attribute on jwt_service is not standard.
    # get_current_user relies on user_repo.get_user_by_id(payload["sub"]).
    # So, ensure authenticated_user is in the db_session for user_repo to find.
    # The authenticated_user fixture already persists the user.

    return {"Authorization": f"Bearer {access_token_str}"}


@pytest.fixture
def get_valid_auth_headers(mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generate patient authentication headers using the mock JWT service."""
    mock_jwt_service.clear_issued_tokens() # Ensure clean state for this specific header generation
    user_data = {
        "sub": str(uuid.uuid4()), # Use a valid UUID string
        "roles": [UserRole.PATIENT.value],
        "username": "testpatient",
        "email": "patient@example.com"
    }
    access_token = mock_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {access_token}"}

@pytest.fixture
def get_valid_provider_auth_headers(mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generate provider/clinician authentication headers using the mock JWT service."""
    mock_jwt_service.clear_issued_tokens() # Ensure clean state
    user_data = {
        "sub": str(uuid.uuid4()), # Use a valid UUID string
        "roles": [UserRole.CLINICIAN.value],
        "username": "testprovider",
        "email": "provider@example.com"
    }
    access_token = mock_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def admin_auth_headers(mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generates authorization headers for an admin user."""
    mock_jwt_service.clear_issued_tokens() # Ensure clean state
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
