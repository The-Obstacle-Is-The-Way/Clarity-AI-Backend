# Standard Library Imports
import logging
import logging.config
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

# Third-Party Imports
import sentry_sdk
from fastapi import FastAPI, Request, HTTPException, status as http_status
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

# Application-Specific Imports
from app.core.config import Settings, settings as global_settings
from app.core.config.settings import get_settings
from app.core.logging_config import LOGGING_CONFIG
from app.core.security.rate_limiting.service import get_rate_limiter_service
from app.infrastructure.database.session import create_db_engine_and_session
import app.infrastructure.persistence.sqlalchemy.models  # noqa: F401 # Ensure models register first
from app.presentation.api.v1.api_router import api_v1_router
from app.presentation.middleware.logging import LoggingMiddleware
from app.presentation.middleware.rate_limiting import RateLimitingMiddleware
from app.presentation.middleware.request_id import RequestIdMiddleware
from app.presentation.middleware.security_headers import SecurityHeadersMiddleware
from app.presentation.middleware.authentication import AuthenticationMiddleware
from app.infrastructure.security.jwt_service import get_jwt_service
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository

# Potentially import test routers conditionally or via a flag
from app.tests.routers.admin_test_router import router as admin_test_router

# Initialize logging early
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

# Removed early Sentry init, moved to factory/lifespan

# --- Helper Functions ---
def _initialize_sentry(settings: Settings) -> None:
    """Initializes Sentry if DSN is provided."""
    if settings.SENTRY_DSN:
        logger.info("Sentry DSN found, initializing Sentry.")
        try:
            sentry_sdk.init(
                dsn=str(settings.SENTRY_DSN),
                traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
                profiles_sample_rate=settings.SENTRY_PROFILES_SAMPLE_RATE,
                environment=settings.ENVIRONMENT,
                release=settings.VERSION,
                # Consider enabling performance monitoring based on settings
                enable_tracing=True,  # Adjust as needed
            )
        except Exception as e:
            logger.error(f"Failed to initialize Sentry: {e}", exc_info=True)
    else:
        logger.info("Sentry DSN not provided, skipping Sentry initialization.")


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifespan events (startup and shutdown)."""
    logger.info("Application lifespan startup sequence initiated.")
    current_settings = fastapi_app.state.settings
    logger.info(f"Lifespan using settings from app.state. ENVIRONMENT: {current_settings.ENVIRONMENT}, DB_URL: {current_settings.DATABASE_URL}")

    db_engine = None
    redis_client = None
    redis_pool = None

    try:
        # --- Test Environment Specific Setup ---
        if current_settings.ENVIRONMENT == "test":
            logger.info("Test environment: Initializing DB and creating tables directly.")
            # Ensure all models are loaded into metadata by importing the package
            import app.infrastructure.persistence.sqlalchemy.models 
            from app.infrastructure.persistence.sqlalchemy.models.base import Base
            from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
            from sqlalchemy.pool import StaticPool

            db_url = str(current_settings.ASYNC_DATABASE_URL or current_settings.DATABASE_URL)
            logger.info(f"Test environment: Creating engine for {db_url}")
            db_engine = create_async_engine(
                db_url,
                echo=False, 
                connect_args={"check_same_thread": False}, # Required for SQLite
                poolclass=StaticPool
            )
            
            async with db_engine.begin() as conn:
                logger.info("Test environment: Dropping and Creating all tables...")
                # await conn.run_sync(Base.metadata.drop_all)
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Test environment: Tables created.")

            session_factory = async_sessionmaker(
                bind=db_engine, class_=AsyncSession, expire_on_commit=False
            )
            fastapi_app.state.db_engine = db_engine
            fastapi_app.state.db_session_factory = session_factory
            logger.info("Test environment: DB Engine and Session Factory configured.")

            # Create test users
            logger.info("Test environment: Creating test users...")
            from app.tests.integration.utils.test_db_initializer import create_test_users
            async with session_factory() as session:
                try:
                    await create_test_users(session)
                    await session.commit() 
                    logger.info("Test environment: Test users created successfully.")
                except Exception as e_users:
                    logger.error(f"Test environment: Error creating test users: {e_users}", exc_info=True)
                    await session.rollback()
                    raise RuntimeError(f"Failed to create test users: {e_users}") from e_users

            # Mock Redis for tests
            logger.info("Test environment: Mocking Redis connection.")
            from redis.asyncio import ConnectionPool, Redis # Import here
            mock_redis_client = AsyncMock(spec=Redis)
            mock_redis_client.ping = AsyncMock()
            mock_redis_client.close = AsyncMock()
            mock_redis_pool = AsyncMock(spec=ConnectionPool)
            mock_redis_pool.disconnect = AsyncMock()
            redis_client = mock_redis_client
            redis_pool = mock_redis_pool
            fastapi_app.state.redis = redis_client
            fastapi_app.state.redis_pool = redis_pool

        # --- Production/Other Environment Setup ---
        else:
            logger.info("Production/Other environment: Initializing DB connection.")
            # Use the existing create_db_engine_and_session for non-test envs
            from app.infrastructure.database.session import create_db_engine_and_session # Import here
            db_url = str(current_settings.ASYNC_DATABASE_URL or current_settings.DATABASE_URL)
            db_engine, session_factory = create_db_engine_and_session(db_url)
            fastapi_app.state.db_engine = db_engine
            fastapi_app.state.db_session_factory = session_factory
            logger.info("Database connection initialized successfully.")

            # Initialize Real Redis 
            logger.info("Initializing Redis connection pool...")
            from redis.asyncio import ConnectionPool, Redis # Import here
            try:
                redis_pool = ConnectionPool.from_url(str(current_settings.REDIS_URL), decode_responses=True)
                fastapi_app.state.redis_pool = redis_pool
                redis_client = Redis(connection_pool=redis_pool)
                fastapi_app.state.redis = redis_client
                await redis_client.ping()
                logger.info("Redis connection successful.")
            except Exception as e:
                logger.error(f"Redis connection failed: {e}", exc_info=True)
                fastapi_app.state.redis_pool = None
                fastapi_app.state.redis = None
                redis_client = None # Ensure vars are None
                redis_pool = None

        # --- Common Setup (Sentry) ---
        _initialize_sentry(current_settings)

        logger.info("Application startup complete.")
        yield # Application runs here

    except Exception as startup_exc:
         logger.critical(f"Application startup failed critically: {startup_exc}", exc_info=True)
         # Re-raise to prevent app from starting in a broken state
         raise RuntimeError("Application startup failed") from startup_exc
    finally:
        # --- Shutdown Logic ---
        logger.info("Application lifespan shutdown sequence initiated.")
        if redis_client:
            try:
                await redis_client.close()
                logger.info("Redis client closed.")
            except Exception as e:
                logger.error(f"Error closing Redis client: {e}", exc_info=True)
        if redis_pool:
            try:
                await redis_pool.disconnect()
                logger.info("Redis connection pool disconnected.")
            except Exception as e:
                logger.error(f"Error disconnecting Redis pool: {e}", exc_info=True)

        if db_engine: # Use the engine created within the try block
            try:
                await db_engine.dispose()
                logger.info("Database engine disposed successfully.")
            except Exception as e:
                logger.error(f"Error disposing database engine: {e}", exc_info=True)

        logger.info("Application shutdown complete.")


# --- Application Factory ---
def create_application(
    settings_override: Settings | None = None,
    include_test_routers: bool = False
) -> FastAPI:
    """Factory function to create and configure the FastAPI application."""
    logger.info("Creating FastAPI application instance...")

    # Resolve settings: Use provided settings or load global ones
    app_settings = settings_override if settings_override is not None else global_settings

    # Configure logging early
    logging.config.dictConfig(LOGGING_CONFIG)
    logger.info(
        f"Logging configured with level: {LOGGING_CONFIG.get('loggers', {}).get('app', {}).get('level', 'UNKNOWN')}"
    )

    # Initialize Sentry if DSN is provided (moved Sentry init inside factory for clarity)
    if app_settings.SENTRY_DSN:
        logger.info(f"Initializing Sentry for environment: {app_settings.ENVIRONMENT}")
        try:
            sentry_sdk.init(
                dsn=str(app_settings.SENTRY_DSN),
                traces_sample_rate=app_settings.SENTRY_TRACES_SAMPLE_RATE,
                profiles_sample_rate=app_settings.SENTRY_PROFILES_SAMPLE_RATE,
                environment=app_settings.ENVIRONMENT,
                release=app_settings.VERSION,
                enable_tracing=True,
            )
            logger.info("Sentry initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize Sentry: {e}", exc_info=True)
    else:
        logger.warning("SENTRY_DSN not found. Sentry integration disabled.")

    # Create FastAPI app with lifespan context manager
    app_instance = FastAPI(
        title=app_settings.PROJECT_NAME,
        version=app_settings.API_VERSION,
        description=app_settings.PROJECT_DESCRIPTION,
        openapi_url=f"{app_settings.API_V1_STR}/openapi.json",
        docs_url="/docs" if app_settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if app_settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,  # Use the lifespan context manager
    )
    app_instance.state.settings = app_settings 

    logger.info(f"Factory: app.state.settings after FastAPI init and direct set: {app_instance.state.settings.ENVIRONMENT if hasattr(app_instance.state, 'settings') and app_instance.state.settings is not None else 'NOT FOUND ON app.state'}") # Diagnostic log

    # --- Middleware Configuration (Order Matters!) ---
    # 1. Security Headers Middleware
    app_instance.add_middleware(SecurityHeadersMiddleware)
    logger.info("Security headers middleware added.")

    # 2. Request ID Middleware
    app_instance.add_middleware(RequestIdMiddleware)
    logger.info("Request ID middleware added.")

    # 3. Logging Middleware
    # Temporarily commented due to import/implementation issues
    # app_instance.add_middleware(LoggingMiddleware, logger=logging.getLogger("app.access"))
    logger.warning("Logging middleware TEMPORARILY DISABLED due to implementation issue.")

    # 4. Authentication Middleware
    # Initialize and register the authentication middleware
    logger.info("Initializing and registering AuthenticationMiddleware...")
    try:
        jwt_service = get_jwt_service()
        user_repository = SQLAlchemyUserRepository(session_factory=app_instance.state.db_session_factory)
        
        # Define public paths - keep in sync with middleware defaults or settings
        public_paths = {
            "/docs", "/openapi.json", "/redoc",  # API docs
            "/health", "/metrics", "/",  # Public monitoring endpoints
            f"{app_settings.API_V1_STR}/auth/login",  # Auth endpoints
            f"{app_settings.API_V1_STR}/auth/register",
            f"{app_settings.API_V1_STR}/auth/refresh",
        }
        
        app_instance.add_middleware(
            AuthenticationMiddleware,
            jwt_service=jwt_service,
            user_repo=user_repository,
            public_paths=public_paths
        )
        logger.info("Authentication middleware added successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize AuthenticationMiddleware: {e}", exc_info=True)
        logger.warning("Authentication middleware NOT ADDED - application will not enforce authentication!")

    # 5. Rate Limiting Middleware
    # Temporarily disabled due to implementation issues
    # rate_limiter_service = get_rate_limiter_service(app_settings)
    # app_instance.add_middleware(RateLimitingMiddleware, limiter=rate_limiter_service)
    logger.warning("Rate limiting middleware TEMPORARILY DISABLED due to implementation issue.")

    # 4. CORS
    if app_settings.BACKEND_CORS_ORIGINS:
        logger.info(f"Configuring CORS for origins: {app_settings.BACKEND_CORS_ORIGINS}")
        app_instance.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in app_settings.BACKEND_CORS_ORIGINS],
            allow_credentials=app_settings.CORS_ALLOW_CREDENTIALS,
            allow_methods=app_settings.CORS_ALLOW_METHODS,
            allow_headers=app_settings.CORS_ALLOW_HEADERS,
        )
        logger.info("CORS middleware configured with specific settings from environment.")
    else:
        logger.warning("No CORS origins configured. CORS middleware not added.")

    # --- Routers ---
    logger.info(f"Including API router prefix: {app_settings.API_V1_STR}")
    app_instance.include_router(api_v1_router, prefix=app_settings.API_V1_STR)

    if include_test_routers:
        app_instance.include_router(admin_test_router, prefix=f"{app_settings.API_V1_STR}/admin", tags=["Test Admin"])
        logger.info(f"Including TEST admin router prefix: {app_settings.API_V1_STR}/admin")

    # --- Global Exception Handlers ---
    @app_instance.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        # Log the detailed validation error for internal review
        logger.error(f"Request validation error: {exc.errors()} for request: {request.method} {request.url}")
        # Return a generic Pydantic validation error structure
        return JSONResponse(
            status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": exc.errors()}, # Pydantic's default error structure
        )

    @app_instance.exception_handler(HTTPException)
    async def custom_http_exception_handler(request: Request, exc: HTTPException):
        # Log the HTTP exception details
        logger.error(f"HTTP exception: {exc.detail} (Status: {exc.status_code}) for request: {request.method} {request.url}")
        # Return the standard HTTPException response
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    @app_instance.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        # Log the full, unhandled exception for internal review
        # Be cautious about logging potentially sensitive parts of `exc` or `request`
        # if they could contain PHI in a real scenario.
        logger.critical(
            f"Unhandled exception: {exc.__class__.__name__}: {exc} for request: {request.method} {request.url}",
            exc_info=True # Include traceback
        )
        # Return a generic 500 error to the client, masking internal details.
        return JSONResponse(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"}, # MATCHES TEST EXPECTATION
        )
        
    logger.info("FastAPI application creation complete.")
    return app_instance
