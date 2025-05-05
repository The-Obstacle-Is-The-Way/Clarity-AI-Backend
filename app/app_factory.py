# Standard Library Imports
import logging
import logging.config
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

# Third-Party Imports
import sentry_sdk
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

# Application-Specific Imports
from app.core.config import Settings, settings as global_settings
from app.core.logging_config import LOGGING_CONFIG
from app.core.security.rate_limiting.service import get_rate_limiter_service
from app.infrastructure.database.session import create_db_engine_and_session
import app.infrastructure.persistence.sqlalchemy.models  # noqa: F401 # Ensure models register first
from app.presentation.api.v1.api_router import api_v1_router
from app.presentation.middleware.logging import LoggingMiddleware
from app.presentation.middleware.rate_limiting import RateLimitingMiddleware
from app.presentation.middleware.request_id import RequestIdMiddleware
from app.presentation.middleware.security_headers import SecurityHeadersMiddleware

# Initialize logging early
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

# Initialize Sentry early if DSN is provided.
# Ensure settings are loaded before this point.
if global_settings.SENTRY_DSN:
    logger.info("Sentry DSN found, initializing Sentry.")
    try:
        sentry_sdk.init(
            dsn=str(global_settings.SENTRY_DSN),
            traces_sample_rate=global_settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=global_settings.SENTRY_PROFILES_SAMPLE_RATE,
            environment=global_settings.ENVIRONMENT,
            release=global_settings.VERSION,
            # Consider enabling performance monitoring based on settings
            enable_tracing=True,  # Adjust as needed
        )
    except Exception as e:
        logger.error(f"Failed to initialize Sentry: {e}", exc_info=True)
else:
    logger.info("Sentry DSN not provided, skipping Sentry initialization.")


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
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application lifespan events (startup and shutdown)."""
    logger.info("Application lifespan startup sequence initiated.")

    # Retrieve settings from app state
    current_settings = app.state.settings

    # --- Database Initialization ---
    try:
        logger.info("Initializing database connection...")
        db_engine, db_session_factory = create_db_engine_and_session(
            str(current_settings.ASYNC_DATABASE_URI), echo=current_settings.DB_ECHO_LOG
        )
        app.state.db_engine = db_engine
        app.state.db_session_factory = db_session_factory
        logger.info("Database connection initialized successfully.")
        # Optional: Test connection? (be careful with blocking calls)
        # async with db_engine.connect() as conn:
        #     await conn.run_sync(lambda sync_conn: None) # Simple check
        # logger.info("Database connection tested successfully.")
    except (SQLAlchemyError, ValueError) as e:
        logger.critical(f"Database initialization failed: {e}", exc_info=True)
        # Depending on policy, might want to exit or prevent app startup
        raise RuntimeError(f"Critical database initialization failure: {e}") from e

    # --- Redis Initialization ---
    if current_settings.ENVIRONMENT == "test":
        logger.info("Test environment detected, mocking Redis connection.")
        # Create mock objects with necessary async methods for shutdown
        mock_redis_client = AsyncMock(spec=Redis)
        mock_redis_client.ping = AsyncMock()
        mock_redis_client.close = AsyncMock()
        mock_redis_pool = AsyncMock(spec=ConnectionPool)
        mock_redis_pool.disconnect = AsyncMock()

        app.state.redis = mock_redis_client
        app.state.redis_pool = mock_redis_pool
    else:
        try:
            logger.info("Initializing Redis connection pool...")
            redis_pool = ConnectionPool.from_url(str(current_settings.REDIS_URL), decode_responses=True)
            app.state.redis_pool = redis_pool
            app.state.redis = Redis(connection_pool=redis_pool)
            # Test Redis connection
            await app.state.redis.ping()
            logger.info("Redis connection successful.")
        except RedisError as e:
            logger.error(f"Redis connection failed: {e}", exc_info=True)
            # Decide if this is critical. For now, log and continue, but set state to None.
            app.state.redis_pool = None
            app.state.redis = None
        except Exception as e: # Catch potential parsing errors from from_url etc.
            logger.error(f"An unexpected error occurred during Redis initialization: {e}", exc_info=True)
            app.state.redis_pool = None
            app.state.redis = None

    # --- Sentry Initialization ---
    _initialize_sentry(current_settings)

    logger.info("Application startup complete.")
    yield  # Application runs here

    # --- Shutdown Logic ---
    logger.info("Application lifespan shutdown sequence initiated.")
    # Close Redis pool
    if hasattr(app.state, "redis") and app.state.redis:
        try:
            await app.state.redis.close()
            logger.info("Redis client closed.")
        except Exception as e:
            logger.error(f"Error closing Redis client: {e}", exc_info=True)
    if hasattr(app.state, "redis_pool") and app.state.redis_pool:
        try:
            await app.state.redis_pool.disconnect()
            logger.info("Redis connection pool disconnected.")
        except Exception as e:
            logger.error(f"Error disconnecting Redis pool: {e}", exc_info=True)

    # Dispose SQLAlchemy engine
    if hasattr(app.state, "db_engine") and app.state.db_engine:
        try:
            await app.state.db_engine.dispose()
            logger.info("Database engine disposed successfully.")
        except Exception as e:
            logger.error(f"Error disposing database engine: {e}", exc_info=True)

    logger.info("Application shutdown complete.")


# --- Application Factory ---
def create_application(settings: Settings | None = None) -> FastAPI:
    """Factory function to create and configure the FastAPI application."""
    logger.info("Creating FastAPI application instance...")

    # Resolve settings: Use provided settings or load global ones
    app_settings = settings or global_settings

    # Configure logging early
    logging.config.dictConfig(LOGGING_CONFIG)
    logger.info(
        f"Logging configured with level: {LOGGING_CONFIG.get('loggers', {}).get('app', {}).get('level', 'UNKNOWN')}"
    )

    # Initialize Sentry if DSN is provided
    if app_settings.SENTRY_DSN:
        logger.info(f"Initializing Sentry for environment: {app_settings.ENVIRONMENT}")
        sentry_sdk.init(
            dsn=str(app_settings.SENTRY_DSN),
            traces_sample_rate=app_settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=app_settings.SENTRY_PROFILES_SAMPLE_RATE,
            environment=app_settings.ENVIRONMENT,
            release=app_settings.VERSION,
            # Consider enabling performance monitoring based on settings
            enable_tracing=True,  # Adjust as needed
        )
        logger.info("Sentry initialized.")
    else:
        logger.warning("SENTRY_DSN not found. Sentry integration disabled.")

    # Store settings in app state for access elsewhere (e.g., lifespan)
    app_state = {"settings": app_settings}

    # Explicitly disable docs in production unless overridden
    docs_url = "/docs" if app_settings.ENVIRONMENT != "production" else None
    redoc_url = "/redoc" if app_settings.ENVIRONMENT != "production" else None

    # Initialize FastAPI app with lifespan context manager and state
    app = FastAPI(
        title=app_settings.PROJECT_NAME,
        version=app_settings.API_VERSION,
        description=app_settings.PROJECT_DESCRIPTION,
        openapi_url=f"{app_settings.API_V1_STR}/openapi.json",
        docs_url=docs_url,
        redoc_url=redoc_url,
        lifespan=lifespan,  # Use the lifespan context manager
        state=app_state,  # Pass state containing settings
        # Add other FastAPI parameters as needed
    )

    # --- Middleware Configuration (Order Matters!) ---
    # 1. Security Headers Middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # 2. Request ID Middleware
    app.add_middleware(RequestIdMiddleware)

    # 3. Logging Middleware
    app.add_middleware(LoggingMiddleware, logger=logging.getLogger("app.access")) # Pass specific logger

    # Instantiate RateLimiterService here (could be injected)
    # Temporarily disabled along with middleware
    # rate_limiter_service = get_rate_limiter_service(app_settings) # Uses settings
    # Temporarily disable middleware due to AttributeError: 'InMemoryRateLimiter' object has no attribute 'process_request'
    # app.add_middleware(RateLimitingMiddleware, limiter=rate_limiter_service) # Add middleware here
    # logger.info("Rate limiting middleware added.")
    logger.warning("Rate limiting middleware TEMPORARILY DISABLED due to implementation issue.")

    app.add_middleware(SecurityHeadersMiddleware)
    logger.info("Security headers middleware added.")

    # 4. CORS
    if app_settings.BACKEND_CORS_ORIGINS:
        logger.info(f"Configuring CORS for origins: {app_settings.BACKEND_CORS_ORIGINS}")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in app_settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        logger.warning("No CORS origins configured. CORS middleware not added.")

    # --- Routers ---
    logger.info(f"Including API router prefix: {app_settings.API_V1_STR}")
    app.include_router(api_v1_router, prefix=app_settings.API_V1_STR)

    # --- Custom Exception Handlers ---
    # Example: Add a custom handler for a specific exception type if needed
    # @app.exception_handler(ValueError)
    # async def value_error_exception_handler(request: Request, exc: ValueError):
    #     # Note: If re-enabling this, re-import Request and JSONResponse
    #     from fastapi import Request
    #     from fastapi.responses import JSONResponse
    #     return JSONResponse(
    #         status_code=400,
    #         content={"message": f"Invalid value provided: {exc}"},
    #     )

    logger.info("FastAPI application creation complete.")
    return app
