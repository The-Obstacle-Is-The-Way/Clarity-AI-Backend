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

import redis
import redis.exceptions
import sentry_sdk

# Third-Party Imports
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.responses import JSONResponse
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

# Application-Specific Imports
from app.core.config import Settings
from app.core.config import get_settings as global_get_settings
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface as IJWTService
from app.core.interfaces.services.redis_service_interface import IRedisService
from app.core.logging_config import LOGGING_CONFIG
from app.core.security.rate_limiting.limiter import RateLimiter
from app.infrastructure.security.jwt.jwt_service import get_jwt_service
from app.infrastructure.services.redis.redis_service import (
    create_redis_service,
)
from app.presentation.api.v1.api_router import api_v1_router
from app.presentation.middleware.authentication import AuthenticationMiddleware
from app.presentation.middleware.logging import LoggingMiddleware

logger = logging.getLogger(__name__)


def _initialize_sentry(current_settings: Settings) -> None:
    """Initializes Sentry if DSN is configured."""
    if current_settings.SENTRY_DSN:
        sentry_sdk.init(
            dsn=str(current_settings.SENTRY_DSN),
            environment=current_settings.ENVIRONMENT,
            traces_sample_rate=current_settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=current_settings.SENTRY_PROFILES_SAMPLE_RATE,
            release=f"{current_settings.PROJECT_NAME}@{current_settings.API_VERSION}",
        )
        logger.info("Sentry initialized.")
    else:
        logger.info("Sentry DSN not found, Sentry not initialized.")


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application startup and shutdown events.
    Initializes and closes resources like database connections and Redis clients.
    Ensures state-dependent middleware is configured after resources are available.
    """
    logger.info("LIFESPAN_START: Entered lifespan context manager.")
    db_engine = None
    current_settings: Settings | None = None

    try:
        # --- Settings Configuration ---
        if hasattr(fastapi_app.state, "settings") and fastapi_app.state.settings:
            current_settings = fastapi_app.state.settings
            logger.info(
                "LIFESPAN_SETTINGS_RESOLVED: Using pre-set app settings. Env: %s",
                current_settings.ENVIRONMENT,
            )
        else:
            current_settings = global_get_settings()
            fastapi_app.state.settings = current_settings
            logger.info(
                "LIFESPAN_SETTINGS_RESOLVED: Using global settings. Env: %s",
                current_settings.ENVIRONMENT,
            )

        _initialize_sentry(current_settings)

        # --- Database Configuration ---
        logger.info(
            "LIFESPAN_DB_INIT_START: Connecting to DB: %s",
            current_settings.ASYNC_DATABASE_URL,
        )
        try:
            db_engine = create_async_engine(
                str(current_settings.ASYNC_DATABASE_URL),
                pool_pre_ping=True,
                pool_recycle=3600,
                echo=current_settings.DB_ECHO_LOG,
            )
            fastapi_app.state.db_engine = db_engine
            actual_session_factory = async_sessionmaker(
                bind=db_engine, expire_on_commit=False, class_=AsyncSession
            )
            fastapi_app.state.actual_session_factory = actual_session_factory
            logger.info(
                "LIFESPAN_DB_INIT_SUCCESS: DB session factory created. Type: %s",
                type(fastapi_app.state.actual_session_factory),
            )

        except Exception as e:
            logger.critical("LIFESPAN_DB_CRITICAL_FAILURE: Failed to init DB: %s", e, exc_info=True)
            raise RuntimeError(f"Database initialization failed: {e}") from e

        # --- Redis Configuration ---
        redis_service_instance: IRedisService | None = None

        # First check if a pre-configured Redis service was provided (useful for testing)
        if (
            hasattr(fastapi_app.state, "redis_service_override")
            and fastapi_app.state.redis_service_override
        ):
            logger.info(
                "LIFESPAN_REDIS_OVERRIDE: Using pre-configured Redis service from app state"
            )
            fastapi_app.state.redis_service = fastapi_app.state.redis_service_override
            redis_service_instance = fastapi_app.state.redis_service_override
        # Otherwise try to create a new Redis service if URL is provided
        elif current_settings.REDIS_URL:
            logger.info(
                "LIFESPAN_REDIS_INIT_START: Connecting to Redis: %s",
                current_settings.REDIS_URL,
            )
            try:
                redis_service_instance = create_redis_service(redis_url=current_settings.REDIS_URL)
                if await redis_service_instance.ping():
                    fastapi_app.state.redis_service = redis_service_instance
                    logger.info(
                        "LIFESPAN_REDIS_INIT_SUCCESS: " "Redis connected and PING successful."
                    )
                else:
                    logger.error("LIFESPAN_REDIS_INIT_FAILURE: Connected but PING failed.")
                    if current_settings.ENVIRONMENT == "test":
                        logger.warning(
                            "LIFESPAN_REDIS_INIT_WARN: Test env; "
                            "proceeding without Redis after ping fail."
                        )
                        # In test environment, create a mock Redis service
                        from unittest.mock import AsyncMock, MagicMock

                        mock_redis = MagicMock()
                        mock_redis.ping = AsyncMock(return_value=True)
                        mock_redis.close = AsyncMock(return_value=None)
                        mock_redis.get = AsyncMock(return_value=None)
                        mock_redis.set = AsyncMock(return_value=True)
                        mock_redis.delete = AsyncMock(return_value=True)
                        mock_redis.exists = AsyncMock(return_value=False)
                        mock_redis.incr = AsyncMock(return_value=1)
                        mock_redis.expire = AsyncMock(return_value=True)
                        fastapi_app.state.redis_service = mock_redis
                    else:
                        raise redis.exceptions.ConnectionError(
                            "Redis ping failed after connection."
                        )

            except (redis.exceptions.ConnectionError, OSError) as e:
                logger.error(
                    "LIFESPAN_REDIS_INIT_FAILURE: Failed to connect to Redis: %s. Error: %s",
                    current_settings.REDIS_URL,
                    e,
                    exc_info=True,
                )
                if current_settings.ENVIRONMENT == "test":
                    logger.warning(
                        "LIFESPAN_REDIS_INIT_WARN: Test env; " "proceeding with mock Redis service."
                    )
                    # Create a mock Redis service for testing
                    from unittest.mock import AsyncMock, MagicMock

                    mock_redis = MagicMock()
                    mock_redis.ping = AsyncMock(return_value=True)
                    mock_redis.close = AsyncMock(return_value=None)
                    mock_redis.get = AsyncMock(return_value=None)
                    mock_redis.set = AsyncMock(return_value=True)
                    mock_redis.delete = AsyncMock(return_value=True)
                    mock_redis.exists = AsyncMock(return_value=False)
                    mock_redis.incr = AsyncMock(return_value=1)
                    mock_redis.expire = AsyncMock(return_value=True)
                    fastapi_app.state.redis_service = mock_redis
                else:
                    raise RuntimeError(f"Redis connection failed: {e}") from e
        else:
            logger.info("LIFESPAN_REDIS_SKIP: REDIS_URL not set, skipping Redis initialization.")
            fastapi_app.state.redis_service = None

        # --- JWT Service Configuration (But NOT adding middleware) ---
        try:
            # Ensure we have a valid JWT service with proper secret key
            jwt_service: IJWTService = get_jwt_service(current_settings)
            fastapi_app.state.jwt_service = jwt_service  # Store the JWT service in app state
            logger.info("JWT service initialized successfully and stored in app state.")
        except Exception as e:
            logger.error(
                "LIFESPAN_JWT_INIT_FAILURE: Failed to initialize JWT service: %s",
                e,
                exc_info=True,
            )
            if current_settings.ENVIRONMENT == "test":
                logger.warning("LIFESPAN_JWT_INIT_WARN: Test env; proceeding without JWT service.")
            else:
                raise RuntimeError(f"JWT service initialization failed: {e}") from e

        yield  # Application runs here

    finally:
        logger.info("LIFESPAN_SHUTDOWN_START: Cleaning up resources...")
        if hasattr(fastapi_app.state, "redis_service") and fastapi_app.state.redis_service:
            try:
                await fastapi_app.state.redis_service.close()
                logger.info("LIFESPAN_REDIS_SHUTDOWN_SUCCESS: Redis connection closed.")
            except Exception as e:
                logger.error(
                    "LIFESPAN_REDIS_SHUTDOWN_FAILURE: Error closing Redis: %s",
                    e,
                    exc_info=True,
                )
        if hasattr(fastapi_app.state, "db_engine") and fastapi_app.state.db_engine:
            try:
                await fastapi_app.state.db_engine.dispose()
                logger.info("LIFESPAN_DB_SHUTDOWN_SUCCESS: DB engine disposed.")
            except Exception as e:
                logger.error(
                    "LIFESPAN_DB_SHUTDOWN_FAILURE: Error disposing DB engine: %s",
                    e,
                    exc_info=True,
                )
        logger.info("LIFESPAN_COMPLETE: Lifespan context manager finished.")


def create_application(
    settings_override: Settings | None = None,
    include_test_routers: bool = False,
    jwt_service_override: IJWTService | None = None,
    skip_auth_middleware: bool = False,
    disable_audit_middleware: bool = False,
    skip_redis_middleware: bool = False,
) -> FastAPI:
    """
    Application factory function to create and configure a FastAPI application instance.

    This function sets up logging, Sentry, database connections, Redis, middleware,
    and API routers based on the provided settings or global defaults.

    Args:
        settings_override: Optional `Settings` object to override global settings.
        include_test_routers: If True, includes test-specific routers (if any).
        jwt_service_override: Optional `JWTServiceInterface` for testing or custom JWT handling.
        skip_auth_middleware: If True, skips adding AuthenticationMiddleware.
        disable_audit_middleware: If True, skips adding AuditLogMiddleware.
        skip_redis_middleware: If True, skips adding RateLimitingMiddleware.

    Returns:
        A configured FastAPI application instance.
    """
    logger.info("CREATE_APPLICATION_START: Starting application factory process...")

    current_settings: Settings = settings_override if settings_override else global_get_settings()
    logger.info(
        "CREATE_APPLICATION_SETTINGS_RESOLVED: Using env: %s",
        current_settings.ENVIRONMENT,
    )

    logging.config.dictConfig(LOGGING_CONFIG)
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
    app_instance.state.settings = current_settings

    # Store authentication middleware flag in app state
    app_instance.state.skip_auth_middleware = skip_auth_middleware

    # Handle JWT service override for testing
    if jwt_service_override:
        app_instance.state.jwt_service = jwt_service_override
        logger.info("Using JWT service override for testing")
    elif not skip_auth_middleware:
        # Add AuthenticationMiddleware during app creation
        # This avoids the middleware timing issue
        try:
            jwt_service = get_jwt_service(current_settings)
            app_instance.add_middleware(
                AuthenticationMiddleware,
                jwt_service=jwt_service,
                settings=current_settings,
            )
            logger.info("AuthenticationMiddleware added during app creation.")
        except Exception as e:
            logger.error("Failed to add auth middleware: %s", e)
            if current_settings.ENVIRONMENT != "test":
                raise RuntimeError(f"Authentication middleware initialization failed: {e}") from e
    else:
        logger.info("Authentication middleware will be skipped (test mode)")

    # Store Redis middleware flag in app state
    app_instance.state.skip_redis_middleware = skip_redis_middleware
    if skip_redis_middleware:
        logger.info("Redis rate limiting middleware will be skipped (test mode)")

    @app_instance.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Global exception handler for unhandled errors."""
        logger.error(
            "Unhandled exception: %s",
            exc,
            exc_info=True,
            extra={
                "url": str(request.url),
                "method": request.method,
            },
        )
        sentry_sdk.capture_exception(exc)
        return JSONResponse(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An unexpected internal server error occurred."},
        )

    # CORS Middleware
    if current_settings.BACKEND_CORS_ORIGINS:
        app_instance.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin).strip() for origin in current_settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        logger.info(
            "CORSMiddleware added for origins: %s",
            [str(origin) for origin in current_settings.BACKEND_CORS_ORIGINS],
        )

    # Add logging middleware (goes near beginning of chain to log everything)
    app_instance.add_middleware(LoggingMiddleware)
    logger.info("LoggingMiddleware added.")

    # Initialize Redis service for rate limiting middleware if Redis URL is configured
    # and skip_redis_middleware is False
    if current_settings.REDIS_URL and not skip_redis_middleware:
        try:
            # Create a minimal Redis service just for middleware initialization
            # The full Redis service will be properly setup in lifespan
            from app.infrastructure.services.redis.redis_service import (
                create_redis_service,
            )

            rate_limit_redis = create_redis_service(redis_url=current_settings.REDIS_URL)

            # Create a rate limiter instance using the Redis service
            rate_limiter = RateLimiter(
                requests_per_minute=getattr(current_settings, "RATE_LIMIT_DEFAULT_RPM", 60)
            )

            # Add rate limiting middleware
            from app.presentation.middleware.rate_limiting import RateLimitingMiddleware

            app_instance.add_middleware(
                RateLimitingMiddleware,
                limiter=rate_limiter,  # Pass limiter as named parameter
                exclude_paths=["/health", "/metrics", "/docs", "/redoc"],
            )
            logger.info("RateLimitingMiddleware added during app initialization.")
        except Exception as e:
            logger.warning("RateLimitingMiddleware NOT added: Redis initialization failed: %s", e)
            if current_settings.ENVIRONMENT != "test":
                logger.error(
                    "Redis service initialization failed in production environment: %s",
                    e,
                    exc_info=True,
                )
    elif skip_redis_middleware:
        logger.info("RateLimitingMiddleware skipped due to skip_redis_middleware flag.")
    else:
        logger.info("RateLimitingMiddleware skipped: No REDIS_URL configured.")

    # API Routers
    app_instance.include_router(api_v1_router, prefix=current_settings.API_V1_STR)
    logger.info("API v1 router included at prefix: %s", current_settings.API_V1_STR)

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
            "version": app_settings.API_VERSION,
        }

    logger.info("CREATE_APPLICATION_COMPLETE: Application factory complete.")
    return app_instance
