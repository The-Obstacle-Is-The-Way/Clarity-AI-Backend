"""
Application Factory Module.

This module contains the factory function for creating a FastAPI application
with all necessary middleware, routers, and dependencies.
"""

# Standard Library Imports
import logging
import logging.config
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Optional

# Third-Party Imports
import redis.exceptions
import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

# Application-Specific Imports
from app.core.config import Settings, get_settings as global_get_settings
from app.core.interfaces.services.jwt_service_interface import IJWTService
from app.core.interfaces.services.redis_service_interface import IRedisService
from app.core.logging_config import LOGGING_CONFIG_BASE, setup_logging
from app.infrastructure.persistence.sqlalchemy.database import (
    AsyncSession, async_sessionmaker, create_async_engine
)
from app.infrastructure.security.jwt.jwt_service import get_jwt_service
from app.infrastructure.services.redis_service import RedisService
from app.presentation.api.v1.api_router import api_v1_router
from app.presentation.middleware.authentication import AuthenticationMiddleware
from app.presentation.middleware.logging import LoggingMiddleware
from app.presentation.middleware.rate_limiting import RateLimitingMiddleware

# Initialize settings globally once, to be overridden by app-specific if necessary
global_settings = global_get_settings()

# Setup logging early, using global settings initially.
# This ensures that loggers are available from the start.
# It might be reconfigured if app-specific settings override log level.
setup_logging(logging_config=LOGGING_CONFIG_BASE, log_level=global_settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


def _initialize_sentry(current_settings: Settings) -> None:
    """Initializes Sentry if DSN is provided."""
    if current_settings.SENTRY_DSN:
        sentry_sdk.init(
            dsn=str(current_settings.SENTRY_DSN),  # Ensure DSN is a string
            environment=current_settings.ENVIRONMENT,
            traces_sample_rate=current_settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=current_settings.SENTRY_PROFILES_SAMPLE_RATE,
            release=f"{current_settings.PROJECT_NAME}@{current_settings.API_VERSION}",
            attach_stacktrace=True,
        )
        logger.info("Sentry initialized.")
    else:
        logger.info("Sentry DSN not found, Sentry not initialized.")


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Lifespan context manager for FastAPI application.

    Handles application startup and shutdown operations:
    1. Connects to database and initializes session factory
    2. Sets up Redis connection (if configured) using RedisService
    3. Initializes Sentry (if configured)
    4. Adds state-dependent middleware (Authentication, Rate Limiting)
    5. Cleans up resources on shutdown
    """
    logger.info("LIFESPAN_START: Entered lifespan context manager.")
    db_engine = None
    current_settings: Optional[Settings] = None

    try:
        # --- Settings Configuration ---
        if hasattr(fastapi_app.state, 'settings') and fastapi_app.state.settings:
            current_settings = fastapi_app.state.settings
            logger.info(
                "LIFESPAN_SETTINGS_RESOLVED: Using pre-set app settings. Env: %s",
                current_settings.ENVIRONMENT
            )
        else:
            current_settings = global_get_settings()  # Fallback to global
            fastapi_app.state.settings = current_settings  # Store for access elsewhere
            logger.info(
                "LIFESPAN_SETTINGS_RESOLVED: Using global settings. Env: %s",
                current_settings.ENVIRONMENT
            )

        # Re-initialize Sentry here if not already done, or if settings changed
        _initialize_sentry(current_settings)

        # --- Database Configuration ---
        logger.info("LIFESPAN_DB_INIT_START: Connecting to DB: %s", current_settings.ASYNC_DATABASE_URL)
        try:
            db_engine = create_async_engine(
                str(current_settings.ASYNC_DATABASE_URL),
                pool_pre_ping=True,
                pool_recycle=3600,
                # Set echo to True for SQL query logging if needed, controlled by settings
                echo=current_settings.DB_ECHO_LOG,
            )
            fastapi_app.state.db_engine = db_engine

            actual_session_factory = async_sessionmaker(
                bind=db_engine, class_=AsyncSession, expire_on_commit=False
            )
            fastapi_app.state.actual_session_factory = actual_session_factory
            logger.info(
                "LIFESPAN_DB_INIT_SUCCESS: DB session factory created. Type: %s",
                type(fastapi_app.state.actual_session_factory)
            )

        except Exception as e:
            logger.critical("LIFESPAN_DB_CRITICAL_FAILURE: Failed to init DB: %s", e, exc_info=True)
            raise RuntimeError(f"Database initialization failed: {e}") from e

        # --- Redis Configuration ---
        redis_service_instance: Optional[IRedisService] = None
        if current_settings.REDIS_URL:
            logger.info(
                "LIFESPAN_REDIS_INIT_START: Connecting to Redis: %s",
                current_settings.REDIS_URL
            )
            try:
                redis_service_instance = RedisService(redis_url=current_settings.REDIS_URL)
                if await redis_service_instance.ping():
                    fastapi_app.state.redis_service = redis_service_instance
                    logger.info("LIFESPAN_REDIS_INIT_SUCCESS: Connected to Redis and pinged.")
                else:
                    logger.error("LIFESPAN_REDIS_INIT_FAILURE: Connected but PING failed.")
                    if current_settings.ENVIRONMENT == "test":
                        logger.warning(
                            "LIFESPAN_REDIS_INIT_WARN: Test env; proceeding without Redis after ping fail."
                        )
                        fastapi_app.state.redis_service = None
                    else:
                        raise redis.exceptions.ConnectionError(
                            "Redis ping failed after connection."
                        )

            except (redis.exceptions.ConnectionError, OSError) as e:
                logger.error(
                    "LIFESPAN_REDIS_INIT_FAILURE: Failed to connect to Redis: %s. Error: %s",
                    current_settings.REDIS_URL,
                    e,
                    exc_info=True
                )
                if current_settings.ENVIRONMENT != "test":
                    raise RuntimeError(f"Redis connection failed: {e}") from e
                else:
                    logger.warning(
                        "LIFESPAN_REDIS_INIT_WARN: Test env; proceeding without Redis connection."
                    )
                    fastapi_app.state.redis_service = None
        else:
            logger.info("LIFESPAN_REDIS_SKIP: REDIS_URL not set, skipping Redis initialization.")
            fastapi_app.state.redis_service = None

        # --- State-Dependent Middleware Setup (Post-Resource Initialization) ---
        # Authentication Middleware (depends on JWTService which uses settings)
        actual_jwt_service = get_jwt_service(current_settings)
        fastapi_app.add_middleware(
            AuthenticationMiddleware, jwt_service=actual_jwt_service
        )
        logger.info("AuthenticationMiddleware added.")

        # Rate Limiting Middleware (depends on RedisService)
        if fastapi_app.state.redis_service:
            fastapi_app.add_middleware(
                RateLimitingMiddleware, redis_service=fastapi_app.state.redis_service
            )
            logger.info("RateLimitingMiddleware added.")
        else:
            logger.warning("RateLimitingMiddleware NOT added: Redis service not available.")

        yield  # Application runs here

    finally:
        logger.info("LIFESPAN_SHUTDOWN_START: Cleaning up resources...")
        if hasattr(fastapi_app.state, 'redis_service') and fastapi_app.state.redis_service:
            try:
                await fastapi_app.state.redis_service.close()
                logger.info("LIFESPAN_REDIS_SHUTDOWN_SUCCESS: Redis connection closed.")
            except Exception as e:
                logger.error(f"LIFESPAN_REDIS_SHUTDOWN_FAILURE: Error closing Redis: {e}", exc_info=True)

        if db_engine:
            try:
                await db_engine.dispose()
                logger.info("LIFESPAN_DB_SHUTDOWN_SUCCESS: Database engine disposed.")
            except Exception as e:
                logger.error(f"LIFESPAN_DB_SHUTDOWN_FAILURE: Error disposing DB engine: {e}", exc_info=True)
        logger.info("LIFESPAN_SHUTDOWN_COMPLETE: Lifespan cleanup finished.")


def create_application(
    settings_override: Optional[Settings] = None,
    include_test_routers: bool = False,
    jwt_service_override: Optional[IJWTService] = None,
    skip_auth_middleware: bool = False,  # Not directly used here, lifespan handles middleware
    disable_audit_middleware: bool = False  # Not directly used here
) -> FastAPI:
    """
    Application factory function to create and configure a FastAPI application instance.

    Args:
        settings_override: Optional settings object to override global settings.
        include_test_routers: Flag to include test-specific routers.
        jwt_service_override: Optional JWT service for testing or custom implementation.
                         (Note: AuthenticationMiddleware uses its own way to get JWTService)
        skip_auth_middleware: Flag to skip auth middleware (now managed by lifespan logic or env var).
        disable_audit_middleware: Flag to disable audit (now managed by lifespan or env var).

    Returns:
        Configured FastAPI application instance.
    """
    logger.info("CREATE_APPLICATION_START: Starting application factory process...")

    current_settings: Settings = settings_override if settings_override else global_settings
    logger.info(
        "CREATE_APPLICATION_SETTINGS_RESOLVED: Using env: %s",
        current_settings.ENVIRONMENT
    )

    setup_logging(logging_config=LOGGING_CONFIG_BASE, log_level=current_settings.LOG_LEVEL)
    logger.info("Logging configured with level: %s", current_settings.LOG_LEVEL)

    app_instance = FastAPI(
        title=current_settings.PROJECT_NAME,
        description=current_settings.PROJECT_DESCRIPTION,
        version=current_settings.API_VERSION,
        openapi_url=f"{current_settings.API_V1_STR}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    logger.info(f"FastAPI app instance created for '{current_settings.PROJECT_NAME}'.")
    app_instance.state.settings = current_settings  # Ensure settings are on app.state early

    @app_instance.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        # Potentially send to Sentry or other error tracking
        # sentry_sdk.capture_exception(exc)
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal Server Error", "error_id": "ERR_UNHANDLED"}
        )

    # --- Core Middleware Setup (Order Matters) ---
    # CORS Middleware (should be one of the first)
    if current_settings.BACKEND_CORS_ORIGINS:
        app_instance.add_middleware(
            CORSMiddleware,
            allow_origins=[
                str(origin).strip() for origin in current_settings.BACKEND_CORS_ORIGINS
            ],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        logger.info("CORSMiddleware added for origins: %s", current_settings.BACKEND_CORS_ORIGINS)
    else:
        logger.info("CORSMiddleware NOT added: No BACKEND_CORS_ORIGINS configured.")

    # Logging Middleware (logs request/response details)
    app_instance.add_middleware(LoggingMiddleware)
    logger.info("LoggingMiddleware added.")

    # Service Dependencies and other Middleware are now mostly handled in `lifespan`
    # to ensure resources like DB, Redis are available when middleware is initialized.

    # API Routers
    app_instance.include_router(api_v1_router, prefix=current_settings.API_V1_STR)
    logger.info("API v1 router included at prefix: %s", current_settings.API_V1_STR)

    # Example for test-specific routers (if any)
    if include_test_routers:
        logger.info("Test-specific routers included (placeholder).")

    @app_instance.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        """
        Root endpoint for basic health check and application information.
        Provides a simple JSON response indicating the application status and version.
        Useful for load balancers, uptime monitoring, and quick verification of deployment.
        """
        logger.info("Root endpoint / called, performing health check.")
        app_settings = current_settings

        return {
            "status": "healthy",
            "message": f"Welcome to {app_settings.PROJECT_NAME}!",
            "environment": app_settings.ENVIRONMENT,
            "version": app_settings.API_VERSION
        }

    logger.info("CREATE_APPLICATION_COMPLETE: Application factory complete.")
    return app_instance
