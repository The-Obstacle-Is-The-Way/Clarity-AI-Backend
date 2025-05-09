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
import sys

# Application-specific Imports
from app.app_factory import create_application
from app.application.security.jwt_service import JWTService
from app.core.config.settings import Settings, get_settings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.registry import metadata as main_metadata
from app.presentation.api.dependencies.auth import get_current_user as app_get_current_user, get_jwt_service as actual_get_jwt_service_dependency
from app.presentation.api.dependencies.auth_service import get_auth_service as actual_get_auth_service_dependency
# Import Pydantic Schemas needed for mock return values
from app.presentation.api.schemas.auth import TokenResponseSchema, SessionInfoResponseSchema, UserRegistrationResponseSchema
# Import Exceptions for mocking error conditions
from app.domain.exceptions.auth_exceptions import (
    InvalidCredentialsException,
    AccountDisabledException,
    InvalidTokenException,
    TokenExpiredException,
    UserAlreadyExistsException
)
from app.infrastructure.security.password.password_handler import PasswordHandler

# Import LifespanManager
from asgi_lifespan import LifespanManager

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
    # Load settings, potentially overriding with a .env.test if it exists
    # Forcing in-memory DB for tests if not already set by .env.test
    # This ensures tests are isolated and don't affect a real DB.
    # Important: The get_settings() call itself handles .env loading.
    settings = get_settings()
    if not settings.ENVIRONMENT == "test":
        logger.warning(
            f"Test environment not explicitly 'test' ({settings.ENVIRONMENT}), forcing DATABASE_URL to in-memory for safety."
        )
        # Ensure we use the async version for ASYNC_DATABASE_URL
        settings.DATABASE_URL = "sqlite+aiosqlite:///:memory:" # For sync parts or general DB URL
        settings.ASYNC_DATABASE_URL = "sqlite+aiosqlite:///:memory:" # For async engine
    
    # Ensure DB URL implies asynchronicity for the engine
    if not settings.ASYNC_DATABASE_URL.startswith("sqlite+aiosqlite://") and \
       not settings.ASYNC_DATABASE_URL.startswith("postgresql+asyncpg://"):
        logger.warning(f"ASYNC_DATABASE_URL '{settings.ASYNC_DATABASE_URL}' might not be suitable for an async engine. Ensure it's an async dialect.")

    logger.info(f"Using in-memory test database: {settings.ASYNC_DATABASE_URL}")
    logger.info(f"Final test settings: ENVIRONMENT={settings.ENVIRONMENT}, DATABASE_URL={settings.DATABASE_URL}, ASYNC_DATABASE_URL={settings.ASYNC_DATABASE_URL}")
    return settings


# --- Database Fixtures ---
# The following function-scoped test_db_engine is REMOVED (lines 104-131 in original)
# It was causing issues by potentially re-creating tables per function.
# We will rely on the session-scoped test_db_engine defined later in this file.

@pytest_asyncio.fixture(scope="function")
async def db_session(
    test_db_engine: AsyncEngine, # This will now use the session-scoped engine
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
    """Provides a MagicMock for JWTService with stateful token handling."""
    import datetime
    import uuid
    from unittest.mock import MagicMock
    from app.core.domain.entities.user import UserRole
    from app.infrastructure.security.jwt.jwt_service import JWTService # Using updated path
    from app.domain.exceptions.token_exceptions import InvalidTokenException, TokenExpiredException

    logger.info("--- mock_jwt_service FIXTURE CREATED (Stateful, Correct Decode, WITH Spec) ---")

    mock = MagicMock(spec=JWTService) # RESTORED spec
    
    issued_tokens_store = {} # token_string: {"payload": dict, "exp_timestamp": float}

    TEST_USER_ID_STR = "00000000-0000-0000-0000-000000000001" # Default test user UUID
    DEFAULT_EXP_DELTA_MINUTES = 30

    def mock_create_access_token(data: dict, expires_delta: datetime.timedelta | None = None) -> str:
        payload = data.copy()
        user_id = payload.get("sub", TEST_USER_ID_STR)
        roles = payload.get("roles", [UserRole.PATIENT.value])
        
        if expires_delta is None:
            expires_delta = datetime.timedelta(minutes=DEFAULT_EXP_DELTA_MINUTES)
            
        expire_timestamp = (datetime.datetime.now(datetime.timezone.utc) + expires_delta).timestamp()
        
        # Ensure required claims are present
        payload["exp"] = expire_timestamp
        payload.setdefault("type", "access")
        payload.setdefault("jti", str(uuid.uuid4())) # Add unique token ID

        # Simple mock token string (doesn't need to be real JWT for mock)
        token_string = f"mock_token_{payload['jti']}"
        
        # Store the token and its data
        issued_tokens_store[token_string] = {
            "payload": payload,
            "exp_timestamp": expire_timestamp
        }
        logger.info(f"Mock JWTService: Created token {token_string} with payload: {payload}")
        return token_string

    def mock_decode_token(token: str) -> dict:
        logger.info(f"Mock JWTService: Attempting to decode token: {token}")
        stored_data = issued_tokens_store.get(token)
        
        if not stored_data:
            logger.warning(f"Mock JWTService: Token {token} not found in store.")
            raise InvalidTokenException("Token not found in mock store")
            
        # Check expiry
        now_timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if now_timestamp > stored_data["exp_timestamp"]:
            logger.warning(f"Mock JWTService: Token {token} expired at {stored_data['exp_timestamp']} (current: {now_timestamp}).")
            raise TokenExpiredException("Mock token expired")
            
        logger.info(f"Mock JWTService: Decoded token {token} to payload: {stored_data['payload']}")
        return stored_data["payload"]

    def clear_issued_tokens():
        logger.info("Mock JWTService: Token store cleared.")
        issued_tokens_store.clear()

    mock.create_access_token.side_effect = mock_create_access_token
    mock.decode_token.side_effect = mock_decode_token
    mock.clear_issued_tokens = MagicMock(side_effect=clear_issued_tokens)
    mock._issued_tokens_store = issued_tokens_store

    logger.info(f"--- mock_jwt_service FIXTURE ID: {id(mock)} ---")
    return mock


@pytest.fixture
def mock_auth_service() -> MagicMock:
    """Provides a MagicMock for AuthService based on AuthServiceInterface."""
    service = MagicMock(spec=AuthServiceInterface)
    
    # Mock login behavior
    mock_login_success_return = TokenResponseSchema(
        access_token="mock_access_token_123",
        refresh_token="mock_refresh_token_456",
        token_type="bearer",
        expires_in=3600, # Example: 1 hour
        user_id=uuid.UUID("00000000-0000-0000-0000-000000000001"), # Example UUID
        roles=[UserRole.PATIENT.value]
    )
    service.login = AsyncMock(return_value=mock_login_success_return)
    
    # Mock refresh token behavior
    mock_refresh_success_return = TokenResponseSchema(
        access_token="mock_new_access_token_789",
        refresh_token="mock_refresh_token_456", # Usually refresh token stays the same or is reissued
        token_type="bearer",
        expires_in=3600,
        user_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        roles=[UserRole.PATIENT.value]
    )
    service.refresh_access_token = AsyncMock(return_value=mock_refresh_success_return)

    # Mock register user behavior
    mock_register_success_return = UserRegistrationResponseSchema(
        id=uuid.uuid4(),
        email="newly_registered@example.com",
        is_active=True, 
        is_verified=False # Typically false after registration
    )
    service.register_user = AsyncMock(return_value=mock_register_success_return)
    
    # Mock logout behavior (often just needs to run without error, might clear cookies via response object)
    service.logout = AsyncMock(return_value=None)
    
    # Mock session info behavior
    mock_session_info_return = SessionInfoResponseSchema(
        authenticated=True,
        session_active=True,
        user_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        roles=[UserRole.PATIENT.value],
        permissions=["read:self"], # Example permissions
        exp=int(datetime.datetime.now(datetime.timezone.utc).timestamp() + 3600) # Example expiry
    )
    service.get_current_session_info = AsyncMock(return_value=mock_session_info_return)

    # --- Mocking specific failure scenarios (can be overridden in tests) ---
    # You might set up side_effects in specific tests if needed, but this provides defaults
    # Example: How to mock raising an exception for invalid login
    # service.login.side_effect = InvalidCredentialsException("Mock invalid login")
    
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

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

# This fixture will provide the FastAPI app instance configured for tests.
@pytest.fixture(scope="session")
async def app_instance_for_session(test_settings: Settings) -> FastAPI:
    logger.info("CONTEST_PY: Creating app_instance_for_session (session-scoped).")
    # Override settings for the app_factory.
    # This is a bit tricky since create_application internally calls get_settings().
    # One way is to ensure test_settings are active when create_application is called.
    # This is generally handled by how get_settings() caches or if we could pass settings.
    # For now, assuming get_settings() picks up .env.test or the forced values from test_settings fixture.
    app = create_application()
    # Store settings on the app state if not already correctly set by create_application for some reason
    # (create_application should already do this)
    app.state.settings = test_settings
    logger.info(f"CONTEST_PY: app_instance_for_session created. App state settings env: {app.state.settings.ENVIRONMENT}")
    return app

# Session-scoped fixture to manage the application lifespan
@pytest.fixture(scope="session")
async def managed_app(app_instance_for_session: FastAPI) -> AsyncGenerator[FastAPI, None]:
    logger.info("CONFTEST_PY: Entering managed_app fixture (session-scoped with LifespanManager).")
    async with LifespanManager(app_instance_for_session, startup_timeout=30, shutdown_timeout=30) as manager:
        logger.info(f"CONFTEST_PY: LifespanManager started. App instance: {manager.app}")
        # Log the state set by the lifespan manager
        # manager._state should hold what the lifespan function yielded.
        if hasattr(manager, "_state") and manager._state:
            lifespan_yielded_state_keys = list(manager._state.keys())
            logger.info(f"CONFTEST_PY: LifespanManager yielded state keys: {lifespan_yielded_state_keys}")
            if "actual_session_factory" in manager._state:
                logger.info(f"CONFTEST_PY: 'actual_session_factory' FOUND in LifespanManager._state. Type: {type(manager._state['actual_session_factory'])}")
            else:
                logger.warning("CONFTEST_PY: 'actual_session_factory' NOT FOUND in LifespanManager._state.")
        else:
            logger.warning("CONFTEST_PY: LifespanManager has no '_state' or it's empty after startup.")
        
        # The application instance to be used by the client is manager.app
        yield manager.app 
    logger.info("CONFTEST_PY: LifespanManager shut down and managed_app fixture exited.")


# This is the primary fixture tests will use to get an AsyncClient.
@pytest.fixture(scope="session")
async def client_session(managed_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    logger.info("CONFTEST_PY: Entering client_session fixture (session-scoped). Using managed_app.")
    # The AsyncClient now uses the app instance that has been processed by LifespanManager
    async with AsyncClient(app=managed_app, base_url="http://test") as ac:
        logger.info(f"CONFTEST_PY: AsyncClient created with managed_app. Client: {ac}")
        # You can inspect ac.app.state here if needed, but request.state is what matters for dependencies.
        # logger.info(f"CONFTEST_PY: client_session: ac.app.state.settings.ENVIRONMENT: {ac.app.state.settings.ENVIRONMENT if hasattr(ac.app.state, 'settings') else 'N/A'}")
        # logger.info(f"CONFTEST_PY: client_session: ac.app.state keys: {list(ac.app.state.__dict__.keys()) if hasattr(ac.app.state, '__dict__') else 'N/A'}")
        yield ac
    logger.info("CONFTEST_PY: AsyncClient closed and client_session fixture exited.")


# --- client_app_tuple fixture (original, now adapted or to be deprecated) ---
# This fixture might need to be re-evaluated.
# For tests requiring function scope (e.g. if they modify app state or DB per test),
# they might need a function-scoped client and app setup.
# The current setup is session-scoped for performance, assuming tests are isolated.

@pytest.fixture(scope="function")
async def client_app_tuple_func_scoped(test_settings: Settings) -> AsyncGenerator[tuple[AsyncClient, FastAPI], None]:
    logger.info("CONFTEST_PY: Creating client_app_tuple_func_scoped (function-scoped).")
    
    # Create a fresh app instance for each test function
    app_for_function = create_application()
    app_for_function.state.settings = test_settings # Ensure test settings are applied

    async with LifespanManager(app_for_function, startup_timeout=30, shutdown_timeout=30) as manager:
        logger.info(f"CONFTEST_PY (func): LifespanManager started. App instance: {manager.app}")
        if hasattr(manager, "_state") and manager._state:
            logger.info(f"CONFTEST_PY (func): LifespanManager yielded state keys: {list(manager._state.keys())}")
        
        functional_app_instance = manager.app # This is the app with lifespan handled

        async with AsyncClient(app=functional_app_instance, base_url="http://test") as ac:
            logger.info(f"CONFTEST_PY (func): AsyncClient for function scope created. Client: {ac}")
            yield ac, functional_app_instance # Yield client and the app instance handled by LifespanManager
            
    logger.info("CONFTEST_PY (func): AsyncClient closed, LifespanManager shut down for function scope.")


# Old client_app_tuple (session-scoped) - can be replaced by client_session or adapted
# For now, let's make it use the new session-scoped managed_app and client_session
@pytest.fixture(scope="session")
async def client_app_tuple(client_session: AsyncClient, managed_app: FastAPI) -> tuple[AsyncClient, FastAPI]:
    logger.info("CONFTEST_PY: client_app_tuple (session-scoped) is using client_session and managed_app.")
    return client_session, managed_app


# Example of a function-scoped client if some tests absolutely need it
# and cannot use the session-scoped one.
@pytest.fixture(scope="function")
async def client_function_scope(test_settings: Settings) -> AsyncGenerator[AsyncClient, None]:
    logger.info("CONFTEST_PY: Creating client_function_scope (function-scoped).")
    app_func = create_application()
    # It's crucial that this app instance also uses test_settings
    app_func.state.settings = test_settings 

    async with LifespanManager(app_func, startup_timeout=30, shutdown_timeout=30) as manager:
        the_app = manager.app
        if hasattr(manager, "_state") and manager._state:
            logger.info(f"CONFTEST_PY (client_function_scope): LifespanManager yielded state keys: {list(manager._state.keys())}")
            if "actual_session_factory" in manager._state:
                logger.info(f"CONFTEST_PY (client_function_scope): 'actual_session_factory' found in LifespanManager._state. Type: {type(manager._state['actual_session_factory'])}")

        async with AsyncClient(app=the_app, base_url="http://test") as ac:
            logger.info(f"CONFTEST_PY (client_function_scope): AsyncClient created. App settings env: {ac.app.state.settings.ENVIRONMENT if hasattr(ac.app.state, 'settings') else 'N/A'}")
            yield ac
    logger.info("CONFTEST_PY (client_function_scope): AsyncClient closed, LifespanManager shut down.")


# --- User and Authentication Fixtures ---


@pytest_asyncio.fixture
async def authenticated_user(
    db_session: AsyncSession,
    faker: Faker,
) -> User:
    """
    Creates a user (and potentially a provider), associates them,
    and saves them to the database in a single transaction.
    Returns the authenticated User model instance.
    """
    from app.infrastructure.persistence.sqlalchemy.models.user import (
        User as UserModel,
        UserRole as SQLAUserRole,
    )
    from app.infrastructure.persistence.sqlalchemy.models.provider import ProviderModel # RESTORED
    from app.infrastructure.security.password.password_handler import PasswordHandler
    import random

    pwd_handler = PasswordHandler()
    username = f"{uuid.uuid4()}-{faker.user_name()}"
    email = faker.email()
    password = faker.password()
    hashed_password = pwd_handler.hash_password(password)
    user_id = uuid.uuid4()
    selected_role = random.choice(list(SQLAUserRole))

    logger.info(
        f"Attempting to create authenticated_user with email: {email}, username: {username}, role: {selected_role.name}"
    )

    user_data = {
        "id": user_id,
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "is_active": True,
        "is_verified": True,
        "email_verified": True,
        "role": selected_role,
        "roles": [selected_role.value],
        "first_name": faker.first_name(),
        "last_name": faker.last_name(),
    }

    user = UserModel(**user_data)
    db_session.add(user)
    logger.debug(f"Added user {user.id} to session.")

    # --- PROVIDER CREATION RE-ENABLED ---
    provider_instance = None
    if user.role == SQLAUserRole.CLINICIAN:
        provider_data = {
            "id": uuid.uuid4(),
            "user_id": user.id, 
            "specialty": faker.job(),
            "license_number": faker.bothify(text="LIC-#######??"),
            "npi_number": faker.bothify(text="##########"),
            "active": True,
        }
        provider_instance = ProviderModel(**provider_data)
        user.provider = provider_instance 
        db_session.add(provider_instance)
        logger.debug(f"Added provider {provider_instance.id} for user {user.id} to session and associated.")

    # Commit transaction once after adding all objects
    try:
        await db_session.commit()
        logger.info(f"Successfully committed user {user.id} and provider {provider_instance.id if provider_instance else 'N/A'}")
        await db_session.refresh(user)
        if provider_instance:
            await db_session.refresh(provider_instance)
    except Exception as e:
        logger.error(f"Error committing user/provider transaction: {e}")
        raise e

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
    return asyncio.get_running_loop()


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

# Ensure this is the only test_db_engine fixture
@pytest_asyncio.fixture(scope="session")
async def test_db_engine(test_settings: Settings) -> AsyncEngine: # Removed event_loop dependency
    """Provides a SQLAlchemy engine for the entire test session."""
    logger.info(f"SESSION SCOPE: Creating test DB engine for URL: {test_settings.ASYNC_DATABASE_URL}")
    
    engine = create_async_engine(
        test_settings.ASYNC_DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        logger.info("SESSION SCOPE: Dropping all tables.")
        await conn.run_sync(main_metadata.drop_all) # Use main_metadata from registry
        logger.info("SESSION SCOPE: Creating all tables.")
        await conn.run_sync(main_metadata.create_all) # Use main_metadata from registry

    yield engine

    logger.info("SESSION SCOPE: Disposing test DB engine.")
    await engine.dispose()

@pytest.fixture
def mock_auth_dependency():
    """
    Creates a dependency override to bypass authentication checks in tests.
    
    This allows tests to run without requiring a valid JWT token,
    while still providing the expected user object to the endpoints.
    """
    # Import here to avoid circular imports
    from app.core.domain.entities.user import User, UserRole
    
    # Create mock users for different roles
    mock_patient = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"),  # TEST_USER_ID
        username="test_patient",
        email="test.patient@example.com",
        full_name="Test Patient",
        hashed_password="not_a_real_hash",
        roles=[UserRole.PATIENT.value],  # Use uppercase role values (PATIENT instead of patient)
        is_active=True,
        is_verified=True,
        email_verified=True,
    )
    
    mock_provider = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000002"),  # TEST_CLINICIAN_ID 
        username="test_provider",
        email="test.provider@example.com",
        full_name="Test Provider",
        hashed_password="not_a_real_hash",
        roles=[UserRole.CLINICIAN.value],  # Use uppercase role values (CLINICIAN instead of clinician)
        is_active=True,
        is_verified=True,
        email_verified=True,
    )
    
    mock_admin = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000003"),
        username="test_admin",
        email="test.admin@example.com",
        full_name="Test Admin",
        hashed_password="not_a_real_hash",
        roles=[UserRole.ADMIN.value],  # Use uppercase role values (ADMIN instead of admin)
        is_active=True,
        is_verified=True,
        email_verified=True,
    )
    
    # Store the mock users by role type
    mock_users = {
        "PATIENT": mock_patient,
        "CLINICIAN": mock_provider,
        "ADMIN": mock_admin,
        "DEFAULT": mock_provider,  # Default to provider since many endpoints require a clinician
    }
    
    # Return a function that can be used to override dependencies
    def override_dependency(role: str = "DEFAULT"):
        # Create an async function to return the appropriate user
        async def get_mock_user():
            return mock_users.get(role, mock_users["DEFAULT"])
        return get_mock_user
    
    return override_dependency

@pytest.fixture(scope="session", autouse=True)
def configure_test_logging(request):
    """
    Configures logging for the test session to ensure visibility of INFO/DEBUG logs
    from key application and framework loggers.
    """
    # Loggers to configure
    logger_names = ["app.app_factory", "fastapi", "uvicorn.error", "uvicorn.access", "app.presentation.api.dependencies.database"]
    log_level = logging.DEBUG

    # Basic formatter
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s"
    )

    # Create a stream handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)

    for name in logger_names:
        logger = logging.getLogger(name)
        # Clear any existing handlers to avoid duplicates or conflicts
        if logger.hasHandlers():
            logger.handlers.clear()
        logger.addHandler(stream_handler)
        logger.setLevel(log_level)
        logger.propagate = False # Prevent duplication if root logger also has handlers

    # Configure root logger as well, but be less aggressive with clearing
    # as pytest might have its own handlers on it.
    root_logger = logging.getLogger()
    # Check if a similar handler is already present to avoid adding multiple stdout streams
    has_stdout_handler = any(
        isinstance(h, logging.StreamHandler) and h.stream == sys.stdout
        for h in root_logger.handlers
    )
    if not has_stdout_handler:
        root_stream_handler = logging.StreamHandler(sys.stdout)
        root_stream_handler.setLevel(log_level) # Or a higher level like INFO for root
        root_stream_handler.setFormatter(formatter)
        root_logger.addHandler(root_stream_handler)
    
    # Set root logger level - be careful not to make it too verbose if not needed
    # but for debugging our app factory, DEBUG might be useful for a bit.
    root_logger.setLevel(log_level)

    # This print helps confirm the fixture ran and when
    print("\n>>> Test logging configured by custom fixture <<<\n")

    # Optionally, you can also ensure the LOG_LEVEL env var, if used by your app's
    # main config, is set to DEBUG for the test session if other parts of the
    # app rely on it directly for their own logger setup.
    # monkeypatch.setenv("LOG_LEVEL", "DEBUG") # If using monkeypatch fixture

    # Teardown (if needed, e.g., to restore original logging config)
    # For autouse session fixtures, teardown is less common unless you're
    # modifying global state in a way that needs explicit reset.
    # Here, we're just adding handlers, which pytest usually manages fine.
