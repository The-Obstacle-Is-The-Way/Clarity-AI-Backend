# Standard Library Imports
import logging
import logging.config
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any

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
from app.infrastructure.database.session import create_db_engine_and_session
from app.presentation.api.v1.api_router import api_router as api_v1_router
from app.presentation.middleware.logging import LoggingMiddleware
from app.presentation.middleware.rate_limiting import RateLimitingMiddleware
from app.presentation.middleware.request_id import RequestIdMiddleware
from app.presentation.middleware.security_headers import SecurityHeadersMiddleware

# Initialize logging early
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)


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
                release=settings.APP_VERSION,
                # Consider enabling performance monitoring based on settings
                enable_tracing=True, # Adjust as needed
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
            str(current_settings.ASYNC_DATABASE_URI),
            echo=current_settings.DB_ECHO_LOG
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
    try:
        logger.info("Initializing Redis connection pool...")
        redis_pool = ConnectionPool.from_url(
            str(current_settings.REDIS_URL), decode_responses=True
        )
        app.state.redis_pool = redis_pool
        app.state.redis = Redis(connection_pool=redis_pool)
        # Test Redis connection
        await app.state.redis.ping()
        logger.info("Redis connection pool initialized and tested successfully.")
    except RedisError as _e: # Renamed e to _e
        logger.error(
            f"Redis connection failed: {_e}", exc_info=True
        )
        # Decide if Redis failure is critical. Maybe set state to None?
        app.state.redis_pool = None
        app.state.redis = None
        logger.warning("Redis is unavailable.")
    except Exception as _e: # Renamed e to _e
        logger.exception(f"An unexpected error occurred during Redis init: {_e}")
        app.state.redis_pool = None
        app.state.redis = None

    # --- Sentry Initialization ---
    _initialize_sentry(current_settings)

    logger.info("Application startup complete.")
    yield  # Application runs here

    # --- Shutdown Logic ---
    logger.info("Application lifespan shutdown sequence initiated.")
    # Close Redis pool
    if hasattr(app.state, 'redis') and app.state.redis:
        try:
            await app.state.redis.close()
            logger.info("Redis client closed.")
        except Exception as _e:
            logger.error(f"Error closing Redis client: {_e}", exc_info=True)
    if hasattr(app.state, 'redis_pool') and app.state.redis_pool:
        try:
            await app.state.redis_pool.disconnect()
            logger.info("Redis connection pool disconnected.")
        except Exception as _e:
            logger.error(f"Error disconnecting Redis pool: {_e}", exc_info=True)

    # Dispose SQLAlchemy engine
    if hasattr(app.state, 'db_engine') and app.state.db_engine:
        try:
            await app.state.db_engine.dispose()
            logger.info("Database engine disposed successfully.")
        except Exception as _e:
            logger.error(f"Error disposing database engine: {_e}", exc_info=True)

    logger.info("Application shutdown complete.")


# --- Application Factory ---
def create_application(settings: Settings | None = None) -> FastAPI:
    """Factory function to create and configure the FastAPI application."""
    logger.info("Creating FastAPI application instance...")

    # Resolve settings: Use provided settings or load global ones
    app_settings = settings or global_settings

    # Configure logging early
    logging.config.dictConfig(LOGGING_CONFIG)
    logger.info(f"Logging configured with level: {LOGGING_CONFIG.get('loggers', {}).get('app', {}).get('level', 'UNKNOWN')}")

    # Initialize Sentry if DSN is provided
    if app_settings.SENTRY_DSN:
        logger.info(f"Initializing Sentry for environment: {app_settings.ENVIRONMENT}")
        sentry_sdk.init(
            dsn=str(app_settings.SENTRY_DSN),
            traces_sample_rate=app_settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=app_settings.SENTRY_PROFILES_SAMPLE_RATE,
            environment=app_settings.ENVIRONMENT,
            release=app_settings.APP_VERSION,
            # Consider enabling performance monitoring based on settings
            enable_tracing=True, # Adjust as needed
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
        version=app_settings.APP_VERSION,
        description=app_settings.PROJECT_DESCRIPTION,
        openapi_url=f"{app_settings.API_V1_STR}/openapi.json",
        docs_url=docs_url,
        redoc_url=redoc_url,
        lifespan=lifespan,  # Use the lifespan context manager
        state=app_state, # Pass state containing settings
        # Add other FastAPI parameters as needed
    )

    # --- Middleware Configuration (Order Matters!) ---
    # 1. Request ID (early for logging)
    app.add_middleware(RequestIdMiddleware)

    # 2. Logging (after Request ID)
    app.add_middleware(LoggingMiddleware)

    # 3. CORS
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

    # 4. Security Headers
    app.add_middleware(SecurityHeadersMiddleware)

    # 5. Rate Limiting (conditionally, using Redis if available)
    # Check if redis state exists and is not None before adding middleware
    # This check needs to happen *after* the lifespan has potentially run
    # and set app.state.redis. A bit tricky here, maybe defer middleware
    # addition or have middleware handle redis unavailability gracefully.
    # For now, let's assume lifespan runs before requests.
    # if hasattr(app.state, 'redis') and app.state.redis:
    #     logger.info("Redis available, adding Rate Limiting Middleware.")
    #     app.add_middleware(
    #         RateLimitingMiddleware,
    #         redis_client=lambda: app.state.redis,  # Pass redis client factory
    #         limit=app_settings.RATE_LIMIT_REQUESTS,
    #         period=app_settings.RATE_LIMIT_PERIOD_SECONDS,
    #     )
    # else:
    #     logger.warning(
    #         "Redis not available, Rate Limiting Middleware will not be functional."
    #     )
    # Let's add it but have it handle unavailability internally for simplicity now:
    logger.info("Adding Rate Limiting Middleware.")
    app.add_middleware(
        RateLimitingMiddleware,
        # Pass redis client factory - middleware should handle None state
        redis_client_factory=lambda: getattr(app.state, 'redis', None),
        limit=app_settings.RATE_LIMIT_REQUESTS,
        period=app_settings.RATE_LIMIT_PERIOD_SECONDS,
    )

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