# Corrected Import Block Start
import datetime
import logging
import os
import uuid
from collections.abc import AsyncGenerator, Callable, Awaitable
from unittest.mock import AsyncMock

import boto3
import pytest
import pytest_asyncio
from fastapi import FastAPI
from jose import jwt
from moto import mock_aws
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

# --- Core App/Config Imports ---
from app.core.config.settings import Settings, get_settings
from app.core.domain.entities.user import User, UserRole, UserStatus
from app.domain.entities.user import User as DomainUser
from app.domain.services.pat_service import PATService
from app.infrastructure.security.auth_service import AuthenticationService
from app.infrastructure.security.jwt_service import JWTService
from app.infrastructure.security.password_handler import PasswordHandler

# Corrected database imports
from app.infrastructure.database.base_class import Base
from app.infrastructure.database.session import get_async_session
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import UserRepository

# --- API Layer Imports ---
from app.main import create_application
from app.presentation.api.v1.api_router import api_router as api_v1_router
from app.presentation.api.dependencies.services import get_pat_service
from app.presentation.api.v1.dependencies import (
    get_llm_service,
    get_user_repository_provider,
)

# Corrected Import Block End

# Setup logging for tests
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# --- Global Test Constants ---
TEST_USERNAME = "testuser@example.com"
TEST_PASSWORD = "testpassword"
TEST_INVALID_PASSWORD = "invalidpassword"
TEST_ADMIN_USERNAME = "admin@example.com"
TEST_PROVIDER_USERNAME = "provider@example.com"
TEST_PROVIDER_PASSWORD = "providerpassword"


# --- Helper Functions ---
def create_test_application(settings: Settings) -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME if hasattr(settings, "PROJECT_NAME") else "Test API",
        description="Test API for automated testing",
        version=settings.VERSION if hasattr(settings, "VERSION") else "0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    return app


# --- Settings Fixtures ---
@pytest.fixture(scope="session")
def test_settings() -> Settings:
    logger.info("Loading test settings via core get_settings()...")
    settings = get_settings()
    logger.info(f"Test Settings Loaded: {settings.model_dump(exclude={'JWT_SECRET_KEY'})}")
    return settings


# --- Mock Service Fixtures ---
@pytest.fixture(scope="function")
def mock_jwt_service() -> AsyncMock:
    """Provide a mock JWT service."""
    mock = AsyncMock(spec=JWTService)
    mock.create_access_token.return_value = "mock_access_token_for_test"
    mock.create_refresh_token.return_value = "mock_refresh_token_for_test"
    mock.verify_token.return_value = {"sub": str(uuid.uuid4()), "roles": ["patient"]}
    logger.info("mock_jwt_service configured with token methods.")
    return mock


@pytest.fixture(scope="function")
def mock_auth_service(
    password_handler: PasswordHandler, user_repository: UserRepository
) -> AsyncMock:
    """Provide a mock authentication service."""
    mock = AsyncMock(spec=AuthenticationService)
    mock.authenticate_user.side_effect = (
        lambda username, password: User(
            id=str(uuid.uuid4()), username=username, role="patient", is_active=True
        )
        if username == TEST_USERNAME and password == TEST_PASSWORD
        else None
    )
    mock.create_user.return_value = None
    mock.get_current_active_user.return_value = User(
        id=str(uuid.uuid4()), username=TEST_USERNAME, role="patient", is_active=True
    )
    mock.get_current_active_provider.return_value = User(
        id=str(uuid.uuid4()), username=TEST_PROVIDER_USERNAME, role="provider", is_active=True
    )
    logger.info("mock_auth_service configured.")
    return mock


@pytest.fixture(scope="function")
def mock_pat_service() -> AsyncMock:
    """Provide a mock PAT service."""
    mock = AsyncMock(spec=PATService)
    mock.process_text_phi = AsyncMock(return_value="Processed text without PHI")
    mock.process_notes = AsyncMock(return_value={"summary": "Mock summary"})
    mock.get_event_summary = AsyncMock(return_value={"total_events": 10})
    return mock


# --- Mock Repository/DB Fixtures ---
@pytest_asyncio.fixture(scope="function")
async def test_db_session() -> AsyncGenerator[AsyncSession, None]:
    database_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(
        database_url, echo=False, poolclass=StaticPool, connect_args={"check_same_thread": False}
    )

    async with engine.begin() as conn:
        logger.info("Creating all tables in test database...")
        await conn.run_sync(Base.metadata.create_all)

    testing_session_local = sessionmaker(
        autocommit=False, autoflush=False, bind=engine, expire_on_commit=False, class_=AsyncSession
    )

    async with testing_session_local() as session:
        logger.info("Yielding test database session.")
        yield session
        logger.info("Rolling back test database session transaction.")
        await session.rollback()

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def seed_test_data(test_db_session: AsyncSession) -> None:
    logger.info("Seeding test data...")

    try:
        user_check = await test_db_session.execute(
            text("SELECT 1 FROM users WHERE email = :email"), {"email": TEST_USERNAME}
        )
        if user_check.scalar_one_or_none() is None:
            await test_db_session.execute(
                text("""
                    INSERT INTO users (id, username, email, hashed_password, role, is_active, is_verified)
                    VALUES (:id, :username, :email, :password, 'patient', 1, 1)
                """),
                {
                    "id": str(uuid.uuid4()),
                    "username": TEST_USERNAME,
                    "email": TEST_USERNAME,
                    "password": "hashed_password",
                },
            )
            logger.info(f"Seeded user: {TEST_USERNAME}")

        provider_check = await test_db_session.execute(
            text("SELECT 1 FROM users WHERE email = :email"), {"email": TEST_PROVIDER_USERNAME}
        )
        if provider_check.scalar_one_or_none() is None:
            await test_db_session.execute(
                text("""
                    INSERT INTO users (id, username, email, hashed_password, role, is_active, is_verified)
                    VALUES (:id, :username, :email, :password, 'provider', 1, 1)
                """),
                {
                    "id": str(uuid.uuid4()),
                    "username": TEST_PROVIDER_USERNAME,
                    "email": TEST_PROVIDER_USERNAME,
                    "password": "hashed_password",
                },
            )
            logger.info(f"Seeded provider: {TEST_PROVIDER_USERNAME}")

        await test_db_session.commit()
        logger.info("Test data committed.")

    except Exception as e:
        logger.error(f"Error seeding test data: {e}")
        await test_db_session.rollback()
        raise

    logger.info("Seeding test data finished.")


# Helper function for token creation
def create_test_token(
    settings: Settings,
    subject: str,
    role: UserRole,
    expires_delta: datetime.timedelta | None = None,
) -> str:
    """Helper function to create a JWT token."""
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode = {"sub": subject, "role": role.value, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


# --- AWS Mock Fixtures (using moto) ---
@pytest.fixture(scope="session")
def aws_credentials() -> None:
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="session")
def s3_client(aws_credentials: None) -> "boto3.client":
    """Mocked S3 client."""
    with mock_aws():
        yield boto3.client("s3", region_name="us-east-1")


@pytest.fixture(scope="session")
def bedrock_client(aws_credentials: None) -> "boto3.client":
    """Mocked Bedrock client."""
    with mock_aws():
        yield boto3.client("bedrock", region_name="us-east-1")


@pytest.fixture(scope="session")
def bedrock_runtime_client(aws_credentials: None) -> "boto3.client":
    """Mocked Bedrock Runtime client."""
    with mock_aws():
        yield boto3.client("bedrock-runtime", region_name="us-east-1")


# If using Comprehend Medical
@pytest.fixture(scope="session")
def comprehend_medical_client(aws_credentials: None) -> "boto3.client":
    """Mocked Comprehend Medical client."""
    with mock_aws():
        yield boto3.client("comprehendmedical", region_name="us-east-1")


# Example: Create a mock S3 bucket if needed by tests
@pytest.fixture(scope="session")
def mock_s3_bucket(s3_client: "boto3.client") -> str:
    """Create a mock S3 bucket for testing."""
    bucket_name = "mock-clarity-data-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    return bucket_name


# --- Debugging Fixture ---
@pytest_asyncio.fixture
async def initialized_app_fixture(
    test_db_session: AsyncSession, 
    user_repository: UserRepository, 
    settings: Settings
) -> FastAPI:
    _app = create_application()

    _app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    test_db_url = settings.DATABASE_URL or "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(
        test_db_url, poolclass=NullPool, connect_args={"check_same_thread": False}
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_async_session() -> AsyncGenerator[AsyncSession, None]:
        async with async_session_factory() as session:
            yield session

    _app.dependency_overrides[get_async_session] = override_get_async_session

    _app.dependency_overrides[get_user_repository_provider] = lambda: user_repository
    _app.dependency_overrides[get_llm_service] = lambda: AsyncMock()
    _app.dependency_overrides[get_pat_service] = lambda: AsyncMock()

    yield _app

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# --- Test User Fixtures ---
@pytest.fixture
async def test_patient_user(
    test_db_session: AsyncSession, 
    user_repository: UserRepository
) -> DomainUser:
    """Fixture for a test patient user."""
    return await create_user_in_db(
        user_repo=user_repository,
        email="testpatient@example.com",
        password="password",
        full_name="Test Patient",
        roles={UserRole.PATIENT},
    )


@pytest.fixture
async def test_provider_user(
    test_db_session: AsyncSession, 
    user_repository: UserRepository
) -> DomainUser:
    """Fixture for a test provider user."""
    return await create_user_in_db(
        user_repo=user_repository,
        email="testprovider@example.com",
        password="providerpassword",
        full_name="Test Provider",
        roles={UserRole.CLINICIAN},  # Example provider role
    )


@pytest.fixture
async def test_admin_user(
    test_db_session: AsyncSession, 
    user_repository: UserRepository
) -> DomainUser:
    """Fixture for a test admin user."""
    return await create_user_in_db(
        user_repo=user_repository,
        email="testadmin@example.com",
        password="adminpassword",
        full_name="Test Admin",
        roles={UserRole.ADMIN},
    )


@pytest.fixture
async def user_with_custom_role(
    test_db_session: AsyncSession, 
    user_repository: UserRepository
) -> Callable[..., Awaitable[DomainUser]]:
    """Factory fixture to create users with specific roles."""
    async def _create_user(roles: set[UserRole], email_suffix: str = "custom") -> DomainUser:
        return await create_user_in_db(
            user_repo=user_repository,
            email=f"test{email_suffix}@example.com",
            password="password",
            full_name=f"Test {email_suffix.capitalize()} User",
            roles=roles,
        )
    return _create_user


# --- Test Client and App Initialization ---
@pytest.fixture(scope="session")
def initialized_app(
    settings: Settings,
    test_db_session: AsyncSession,
    user_repository: UserRepository,
    mock_pat_service: AsyncMock,
) -> FastAPI:
    """Fixture to initialize the FastAPI application for testing."""
    app = create_application()

    # Define the provider function inline for clarity
    def override_get_user_repository_provider() -> UserRepository:
        return user_repository

    # Override dependencies with test implementations or mocks
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_async_session] = lambda: test_db_session
    app.dependency_overrides[get_pat_service] = lambda: mock_pat_service
    # app.dependency_overrides[get_llm_service] = lambda: mock_llm_service # Keep commented if not needed now
    # Override with the actual repository instance via the provider function
    app.dependency_overrides[get_user_repository_provider] = override_get_user_repository_provider

    # Setup for database (ensure tables are created)
    # Note: Moved db setup logic inside test_db_session fixture usually

    return app


async def create_user_in_db(
    user_repo: UserRepository,
    email: str,
    password: str,
    full_name: str,
    roles: set[UserRole],
    user_id: uuid.UUID | None = None,
    status: UserStatus = UserStatus.ACTIVE,
    mfa_enabled: bool = False,
) -> DomainUser:
    """Create a user in the database using the repository."""
    user_id = user_id or uuid.uuid4()
    hashed_password = PasswordHandler().hash_password(password)

    domain_user = DomainUser(
        id=user_id,
        username=email.split('@')[0],  # Assuming username generation logic
        email=email,
        password_hash=hashed_password,
        full_name=full_name,
        roles=roles,
        status=status,
        mfa_enabled=mfa_enabled,
        # Add other necessary fields from DomainUser if needed
        created_at=datetime.datetime.now(datetime.timezone.utc),
        updated_at=datetime.datetime.now(datetime.timezone.utc),
        last_login_at=None,
        failed_login_attempts=0,
        locked_until=None,
        mfa_secret=None,
        mfa_backup_codes=None
    )
    return await user_repo.create(domain_user)
