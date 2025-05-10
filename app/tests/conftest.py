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
import json
import base64

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
        settings.DATABASE_URL = "sqlite+aiosqlite:///:memory:?cache=shared" 
        settings.ASYNC_DATABASE_URL = "sqlite+aiosqlite:///:memory:?cache=shared"
    
    # Ensure Redis is disabled for tests by default unless explicitly configured otherwise
    # by a specific test setup or a .env.test that wants a real Redis.
    if settings.ENVIRONMENT == "test":
        logger.info("CONFTEST_PY(test_settings): Forcing REDIS_URL to None for test environment to disable Redis connection.")
        settings.REDIS_URL = None # Disable Redis for tests

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


@pytest.fixture(scope="function")
def global_mock_jwt_service(test_settings: Settings) -> MagicMock:
    """Provides a GLOBAL MagicMock for JWTServiceInterface with specific method behaviors."""
    issued_tokens_store: dict[str, dict] = {}
    DEFAULT_EXP_DELTA_MINUTES = test_settings.ACCESS_TOKEN_EXPIRE_MINUTES

    # MODIFIED: Manually create MagicMock and attach AsyncMock/MagicMock for methods
    mock = MagicMock(spec=JWTServiceInterface, instance=True)
    # We are essentially defining the mock from scratch now, so ensure all interface methods exist.
    # The spec argument to MagicMock helps, but for attributes that are methods,
    # we need to assign callables (like AsyncMock or MagicMock instances) to them.

    async def mock_create_access_token_async(data: dict, expires_delta: datetime.timedelta | None = None) -> str:
        payload = data.copy()
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if expires_delta is None:
            expires_delta = datetime.timedelta(minutes=DEFAULT_EXP_DELTA_MINUTES)
        
        expire_at = current_time + expires_delta
        payload["exp"] = int(expire_at.timestamp())
        payload.setdefault("iat", int(current_time.timestamp()))
        payload.setdefault("type", "access")
        
        jti = str(uuid.uuid4())
        payload.setdefault("jti", jti)
        
        # Using a more JWT-like structure for the mock token string
        header = {"alg": "HS256", "typ": "JWT"}
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
        encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
        # The signature doesn't have to be real for the mock, but make it look like one part of a JWT.
        mock_signature = base64.urlsafe_b64encode(uuid.uuid4().bytes).rstrip(b'=').decode()[:10] # dummy signature part
        token_string = f"{encoded_header}.{encoded_payload}.{mock_signature}"

        issued_tokens_store[token_string] = {"payload": payload, "expire_at": expire_at}
        logger.info(f"Mock JWTService (ID: {id(mock)}, type: {type(mock).__name__}): mock_create_access_token_async executed. Created token string: '{token_string}' for sub {payload.get('sub')}")
        return token_string

    # Explicitly make create_access_token an AsyncMock with the side_effect
    mock.create_access_token = AsyncMock(side_effect=mock_create_access_token_async)

    def mock_decode_token_simplified(token: str) -> dict:
        logger.info(f"mock_decode_token_simplified CALLED with token: {token}")
        stored_info = issued_tokens_store.get(token)
        if stored_info:
            # Check expiry (optional, but good practice for a mock)
            # current_timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
            # if current_timestamp > stored_info["expire_at"].timestamp():
            #     logger.error(f"mock_decode_token_simplified: Token '{token}' is expired.")
            #     raise TokenExpiredException("Mock token expired")
            logger.info(f"mock_decode_token_simplified: Found token in store. Payload: {stored_info['payload']}")
            return stored_info["payload"]
        else:
            logger.error(f"mock_decode_token_simplified: Token '{token}' not found in issued_tokens_store. Keys: {list(issued_tokens_store.keys())}")
            # Attempt to decode if it's a 3-part JWT-like string, for debugging
            parts = token.split('.')
            if len(parts) == 3:
                try:
                    decoded_payload_bytes = base64.urlsafe_b64decode(parts[1] + '==') # Add padding for b64decode
                    payload_dict = json.loads(decoded_payload_bytes.decode())
                    logger.warning(f"mock_decode_token_simplified: Decoded unrecognized token for debugging. Payload: {payload_dict}")
                    # Still raise, as it wasn't in our store.
                except Exception as e:
                    logger.error(f"mock_decode_token_simplified: Failed to decode unrecognized 3-part token '{token}' for debugging: {e}")
            raise InvalidTokenException(f"Simplified mock: Token {token} not in store")

    # decode_token is synchronous in the interface
    mock.decode_token = MagicMock(side_effect=mock_decode_token_simplified)

    async def _clear_store_action_simplified() -> None:
        # issued_tokens_store.clear() # Keep if stateful reset is desired
        logger.info(f"Mock JWTService (ID: {id(mock)}): _clear_store_action_simplified (async no-op) called.")
        pass
    
    # clear_issued_tokens is async in the interface (IJwtService)
    mock.clear_issued_tokens = AsyncMock(side_effect=_clear_store_action_simplified)
    
    # Ensure other methods from JWTServiceInterface (if any are used by tests) are at least MagicMocks
    # For example, if JWTServiceInterface had other_sync_method and other_async_method:
    # mock.other_sync_method = MagicMock(return_value="default_sync_return")
    # mock.other_async_method = AsyncMock(return_value="default_async_return")
    # If they are not called, they don't strictly need to be defined if spec is used,
    # but explicit is often better.

    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: Mock object ID: {id(mock)}, Type: {type(mock).__name__}")
    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: create_access_token type: {type(mock.create_access_token).__name__}")
    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: create_access_token.side_effect: {getattr(mock.create_access_token, 'side_effect', 'NOT SET')}")
    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: decode_token type: {type(mock.decode_token).__name__}")
    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: decode_token.side_effect: {getattr(mock.decode_token, 'side_effect', 'NOT SET')}")
    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: clear_issued_tokens type: {type(mock.clear_issued_tokens).__name__}")
    logger.info(f"MOCK_JWT_SERVICE (Manual) PRE-RETURN: clear_issued_tokens.side_effect: {getattr(mock.clear_issued_tokens, 'side_effect', 'NOT SET')}")

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
    
    # This is the actual FastAPI instance, created fresh for each function-scoped test.
    original_fastapi_app = create_application(settings_override=test_settings)
    # Ensure settings are directly on the original app's state for its own lifecycle awareness if needed pre-LifespanManager
    original_fastapi_app.state.settings = test_settings 

    # LifespanManager will run startup/shutdown events on original_fastapi_app.
    # manager.app will be the ASGI application processed by the lifespan events.
    async with LifespanManager(original_fastapi_app, startup_timeout=30, shutdown_timeout=30) as manager:
        # manager.app is the app that has gone through lifespan startup.
        # This is what the AsyncClient should use.
        app_for_client = manager.app 
        logger.info(f"CONFTEST_PY (func): LifespanManager started. manager.app type: {type(app_for_client)}, instance: {app_for_client}")
        
        # Log the yielded state from the lifespan function for clarity
        if hasattr(manager, "_state") and manager._state and isinstance(manager._state, dict):
            logger.info(f"CONFTEST_PY (func): LifespanManager yielded state keys from manager._state: {list(manager._state.keys())}")
        # Also log what's on original_fastapi_app.state after lifespan startup, which should be populated by the lifespan function
        if hasattr(original_fastapi_app.state, "_state") and isinstance(original_fastapi_app.state._state, dict):
             logger.info(f"CONFTEST_PY (func): original_fastapi_app.state after lifespan startup: {list(original_fastapi_app.state._state.keys())}")
        else:
            logger.warning(f"CONFTEST_PY (func): original_fastapi_app.state._state not found or not a dict after lifespan.")

        async with AsyncClient(app=app_for_client, base_url="http://testserver") as ac: 
            logger.info(f"CONFTEST_PY (func): AsyncClient created with app type: {type(app_for_client)}")
            # Yield the client AND THE ORIGINAL FastAPI instance.
            # The original_fastapi_app is used for dependency_overrides.
            # The client (ac) uses app_for_client (manager.app) which has run through lifespan events.
            yield ac, original_fastapi_app 
            
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


@pytest_asyncio.fixture 
async def auth_headers( 
    global_mock_jwt_service: MagicMock, # UPDATED: Depends on global_mock_jwt_service
    authenticated_user: User, 
) -> dict[str, str]:
    """Generate authentication headers for a mock authenticated user."""
    logger.info(f"AUTH_HEADERS FIXTURE: Using global_mock_jwt_service ID: {id(global_mock_jwt_service)}")

    user_id_str = str(authenticated_user.id)
    
    # Determine scopes based on user roles
    user_scopes = set()
    role_to_scopes_map = {
        UserRole.ADMIN: ["admin:all", "user:read", "user:write"],
        UserRole.CLINICIAN: ["patient:read", "patient:write", "clinical_notes:read", "clinical_notes:write"],
        UserRole.RESEARCHER: ["patient_data:read_anonymized", "analytics:run"],
        UserRole.PATIENT: ["self_data:read", "self_data:write", "appointments:read"],
        UserRole.TECHNICIAN: ["system:monitor", "device:manage"]
    }

    primary_role_str = "unknown" # Default if no roles or single role not found
    # authenticated_user.roles is a list of role strings from the UserModel, e.g., ["clinician"]
    if authenticated_user.roles and isinstance(authenticated_user.roles, list):
        first_role_str = authenticated_user.roles[0]
        primary_role_str = first_role_str # This is already a string, e.g., "clinician"

        for role_str_from_list in authenticated_user.roles:
            try:
                # Convert string back to UserRole enum member for map lookup
                role_enum = UserRole(role_str_from_list) 
                user_scopes.update(role_to_scopes_map.get(role_enum, []))
            except ValueError:
                logger.warning(f"AUTH_HEADERS FIXTURE: Unknown role string '{role_str_from_list}' found. Skipping for scope mapping.")
    
    logger.info(f"AUTH_HEADERS FIXTURE: User ID: {user_id_str}, Roles (strings): {list(authenticated_user.roles) if authenticated_user.roles else []}, Derived Scopes: {list(user_scopes)}")

    token_data = {
        "sub": user_id_str,
        "role": primary_role_str, # Using the first role as the primary for the 'role' claim
        "scopes": list(user_scopes) # Use the derived scopes
    }
    #expires_delta = datetime.timedelta(minutes=test_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_delta = datetime.timedelta(minutes=30) # Defaulting for now

    # This call might reconfigure create_access_token if it wasn't set by configure_mock
    access_token_str = await global_mock_jwt_service.create_access_token(data=token_data, expires_delta=expires_delta)
    logger.info(f"AUTH_HEADERS FIXTURE: Token created: {access_token_str} with payload: {token_data}")
    return {"Authorization": f"Bearer {access_token_str}"}


@pytest.fixture
def get_valid_auth_headers(global_mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generate patient authentication headers using the mock JWT service."""
    global_mock_jwt_service.clear_issued_tokens() # Ensure clean state for this specific header generation
    user_data = {
        "sub": str(uuid.uuid4()), # Use a valid UUID string
        "roles": [UserRole.PATIENT.value],
        "username": "testpatient",
        "email": "patient@example.com"
    }
    access_token = global_mock_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {access_token}"}

@pytest.fixture
def get_valid_provider_auth_headers(global_mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generate provider/clinician authentication headers using the mock JWT service."""
    global_mock_jwt_service.clear_issued_tokens() # Ensure clean state
    user_data = {
        "sub": str(uuid.uuid4()), # Use a valid UUID string
        "roles": [UserRole.CLINICIAN.value],
        "username": "testprovider",
        "email": "provider@example.com"
    }
    access_token = global_mock_jwt_service.create_access_token(data=user_data)
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def admin_auth_headers(global_mock_jwt_service: MagicMock) -> dict[str, str]:
    """Generates authorization headers for an admin user."""
    global_mock_jwt_service.clear_issued_tokens() # Ensure clean state
    # Assuming admin role needs specific identification, adjust payload as needed
    admin_id = str(uuid.uuid4())
    access_token = global_mock_jwt_service.create_access_token(data={"sub": admin_id, "roles": [UserRole.ADMIN.value]})
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
