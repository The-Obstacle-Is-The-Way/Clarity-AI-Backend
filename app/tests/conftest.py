# Corrected Import Block Start
import datetime
import logging
import os
import uuid
from collections.abc import AsyncGenerator, Callable
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
from app.core.domain.entities.user import User, UserRole
from app.domain.services.pat_service import PATService
from app.infrastructure.security.auth_service import AuthenticationService
from app.infrastructure.security.jwt_service import JWTService
# Corrected database imports
from app.infrastructure.database.base_class import Base
from app.infrastructure.database.session import get_db_session
from app.infrastructure.persistence.repositories.in_memory_user_repository import (
    InMemoryUserRepository,
)
from app.infrastructure.persistence.repositories.user_repository import UserRepository

# --- API Layer Imports ---
from app.main import create_application
from app.presentation.api.v1.api_router import api_router as api_v1_router
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
    mock_user_repository_override: Callable[[], UserRepository], mock_jwt_service: AsyncMock
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
    mock_user_repository: InMemoryUserRepository, settings: Settings
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

    async def override_get_db_session() -> AsyncGenerator[AsyncSession, None]:
        async with async_session_factory() as session:
            yield session

    _app.dependency_overrides[get_db_session] = override_get_db_session

    _app.dependency_overrides[get_user_repository_provider] = lambda: mock_user_repository
    _app.dependency_overrides[get_llm_service] = lambda: AsyncMock()
    _app.dependency_overrides[get_pat_service] = lambda: AsyncMock()

    yield _app

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
