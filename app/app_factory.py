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

    # Retrieve settings FROM THE APP STATE
    current_settings = app.state.settings # Use the settings instance already on the app
    logger.info(f"Lifespan using settings from app.state. ENVIRONMENT: {current_settings.ENVIRONMENT}, DB_URL: {current_settings.DATABASE_URL}")

    # Fallback logic if app.state.settings somehow failed (should not happen with proper config)
    if current_settings is None: # Should ideally not be None if get_settings() is robust
        logger.critical(
            "Critical: get_settings() returned None during lifespan startup! Attempting fallback to global_settings."
        )
        current_settings = global_settings 
        if current_settings is None:
            msg = "No settings available for lifespan (get_settings() or global_settings)."
            logger.critical(msg)
            raise RuntimeError(msg)
        logger.info(f"Lifespan fell back to global_settings. ENVIRONMENT: {current_settings.ENVIRONMENT}")


    # --- Database Initialization ---
    try:
        logger.info("Initializing database connection...")
        db_url = str(current_settings.ASYNC_DATABASE_URL or current_settings.DATABASE_URL)
        logger.info(f"Using database URL: {db_url}")
        engine, session_factory = create_db_engine_and_session(db_url)
        
        # Diagnostic log
        if session_factory is None:
            logger.critical("CRITICAL: session_factory is None AFTER create_db_engine_and_session call!")
        else:
            logger.info(f"session_factory obtained: {type(session_factory)}")
            
        app.state.db_engine = engine
        app.state.db_session_factory = session_factory
        logger.info(f"Lifespan: id(app) is {id(app)}, id(app.state) is {id(app.state)}")
        logger.info("Database connection initialized successfully.")

        # In a test environment, ensure tables are created.
        # In production, Alembic migrations would handle this.
        if current_settings.ENVIRONMENT == "test":
            logger.info("Test environment: Ensuring database tables are created.")
            from app.infrastructure.persistence.sqlalchemy.models.base import Base # New correct import
            async with app.state.db_engine.begin() as conn:
                # await conn.run_sync(Base.metadata.drop_all) # Optional: drop if needed for clean slate each app start
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Test environment: Database tables created.")

            # Create test users after tables are created
            logger.info("Test environment: Creating test users...")
            from app.tests.integration.utils.test_db_initializer import create_test_users
            # Create a session to pass to create_test_users
            async with app.state.db_session_factory() as session:
                try:
                    await create_test_users(session)
                    await session.commit() # Ensure users are committed
                    logger.info("Test environment: Test users created successfully.")
                except Exception as e_users:
                    logger.error(f"Test environment: Error creating test users: {e_users}", exc_info=True)
                    await session.rollback()
                    # Optionally re-raise or handle as critical test setup failure
                    raise RuntimeError(f"Failed to create test users: {e_users}") from e_users

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
    # logger.info("Lifespan: Initializing application...") # Removed as part of cleanup
    # # Resolve settings robustly
    # current_settings = getattr(app.state, 'settings', None) # Redundant, current_settings is already defined
    # if not current_settings:
    #     logger.warning("Settings not found in app.state during lifespan startup, using global_settings.")
    #     current_settings = global_settings # Fallback
    # 
    # if not current_settings:
    #     logger.critical("CRITICAL: Settings are None even after fallback in lifespan. Aborting DB init.")
    #     # Potentially raise here or handle as a critical configuration error
    # else:
    #     logger.info(f"Lifespan app.state.settings.DATABASE_URL: {current_settings.DATABASE_URL}") # Debug log, can be removed
    #     logger.info(f"Lifespan id(app): {id(app)}, id(app.state): {id(app.state)}") # DEBUG # Debug log, can be removed
    #     initialize_database(app, current_settings) # THIS IS THE REMOVED CALL
    
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
def create_application(
    settings_override: Settings | None = None,
    # dependency_overrides_param: dict | None = None  # REMOVED PARAMETER
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

    # Create an initial state object to pass to FastAPI constructor
    # initial_state = {"settings": app_settings} # OLD

    # Initialize FastAPI app with lifespan context manager and initial state
    app = FastAPI(
        title=app_settings.PROJECT_NAME,
        version=app_settings.API_VERSION,
        description=app_settings.PROJECT_DESCRIPTION,
        openapi_url=f"{app_settings.API_V1_STR}/openapi.json",
        docs_url="/docs" if app_settings.ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if app_settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,  # Use the lifespan context manager
        # state=initial_state # OLD Pass initial state here
    )
    app.state.settings = app_settings # Set settings directly on app.state

    logger.info(f"Factory: app.state.settings after FastAPI init and direct set: {app.state.settings.ENVIRONMENT if hasattr(app.state, 'settings') and app.state.settings is not None else 'NOT FOUND ON app.state'}") # Diagnostic log
    # REMOVED: Apply overrides if provided
    # if dependency_overrides_param:
    #     app.dependency_overrides = dependency_overrides_param
    #     logger.info(f"Factory: Applied dependency overrides: {list(dependency_overrides_param.keys())}")
    # else:
    #     logger.info("Factory: No dependency overrides provided.")

    # Settings are now in app.state via initial_state, no need to set app.state.settings explicitly here

    # --- Middleware Configuration (Order Matters!) ---
    # 1. Security Headers Middleware
    app.add_middleware(SecurityHeadersMiddleware)
    logger.info("Security headers middleware added.")

    # 2. Request ID Middleware
    app.add_middleware(RequestIdMiddleware)
    logger.info("Request ID middleware added.")

    # 3. Logging Middleware
    # Temporarily commented due to import/implementation issues
    # app.add_middleware(LoggingMiddleware, logger=logging.getLogger("app.access"))
    logger.warning("Logging middleware TEMPORARILY DISABLED due to implementation issue.")

    # 4. Rate Limiting Middleware
    # Temporarily disabled due to implementation issues
    # rate_limiter_service = get_rate_limiter_service(app_settings)
    # app.add_middleware(RateLimitingMiddleware, limiter=rate_limiter_service)
    logger.warning("Rate limiting middleware TEMPORARILY DISABLED due to implementation issue.")

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
