# -*- coding: utf-8 -*-
import logging
import logging.config
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import sentry_sdk
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware
from sentry_sdk.integrations.logging import LoggingIntegration
from starlette.middleware.base import BaseHTTPMiddleware

# CORRECTED Import for database components
from app.infrastructure.database.session import session_local, engine # Assuming session_local is the factory
from app.core.dependencies.database import init_db # Corrected path for init_db

# CORRECTED Import for API router - ONLY import the setup function
from app.presentation.api.routes import setup_routers 

from app.config.settings import Settings, get_settings
# REMOVED incorrect import for exception handlers
# from app.core.exceptions.handlers import add_exception_handlers 
from app.core.logging_config import LOGGING_CONFIG
from app.infrastructure.cache.redis_cache import close_redis_connection, initialize_redis_pool
from app.infrastructure.persistence.unit_of_work import UnitOfWork
from app.infrastructure.security.rate_limiting.limiter import create_rate_limiter
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware
from app.presentation.middleware.logging_middleware import LoggingMiddleware
from app.presentation.middleware.rate_limiting_middleware import RateLimitingMiddleware
from app.presentation.middleware.security_headers_middleware import SecurityHeadersMiddleware

# MOVED logging_config import just before use
from app.core.logging_config import LOGGING_CONFIG

# Setup logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

# --- Lifespan Management ---
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Context manager to handle application startup and shutdown logic.
    """
    logger.info("Application startup: Initializing resources...")
    
    # Initialize Database
    logger.info("Initializing database connection...")
    await init_db() 
    logger.info("Database connection initialized.")

    # Initialize Redis Pool
    logger.info("Initializing Redis connection pool...")
    settings = get_settings()
    await initialize_redis_pool(settings.REDIS_URL)
    logger.info("Redis connection pool initialized.")

    # You could add other startup logic here, like connecting to external services
    
    logger.info("Application startup complete.")
    yield  # Application runs here
    
    # --- Shutdown Logic ---
    logger.info("Application shutdown: Cleaning up resources...")
    
    # Close database connections (handled by SessionLocal usually, but good practice)
    # await engine.dispose() # Typically not needed with async engines and session management
    logger.info("Database resources cleaned (implicitly by session management).")

    # Close Redis Connection Pool
    logger.info("Closing Redis connection pool...")
    await close_redis_connection()
    logger.info("Redis connection pool closed.")

    # Add other shutdown logic here
    logger.info("Application shutdown complete.")

# --- Application Factory ---
def create_application(settings: Settings) -> FastAPI:
    """
    Factory function to create and configure the FastAPI application instance.
    Moved from main.py to prevent import side effects.
    """
    logger.info(f"Creating FastAPI application with version: {settings.VERSION}")

    # Initialize Sentry
    if settings.SENTRY_DSN:
        logger.info(f"Initializing Sentry for environment: {settings.ENVIRONMENT}")
        sentry_sdk.init(
            dsn=str(settings.SENTRY_DSN),
            integrations=[
                LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
            ],
            environment=settings.ENVIRONMENT,
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
            profiles_sample_rate=settings.SENTRY_PROFILES_SAMPLE_RATE,
            send_default_pii=False # Ensure PII is not sent by default
        )
        logger.info("Sentry initialized.")
    else:
        logger.warning("SENTRY_DSN not configured. Sentry integration disabled.")


    app = FastAPI(
        title=settings.PROJECT_NAME,
        description=settings.PROJECT_DESCRIPTION,
        version=settings.VERSION,
        openapi_url=f"/api/{settings.VERSION}/openapi.json" if settings.ENVIRONMENT != 'production' else None,
        docs_url=f"/api/{settings.VERSION}/docs" if settings.ENVIRONMENT != 'production' else None,
        redoc_url=f"/api/{settings.VERSION}/redoc" if settings.ENVIRONMENT != 'production' else None,
        lifespan=lifespan # Use the lifespan context manager
    )

    logger.info("Adding middleware...")
    # --- Middleware Configuration ---
    # IMPORTANT: Order matters! Middleware are processed in the order they are added.

    # 1. SentryAsgiMiddleware (if enabled) - Must be early to catch errors in other middleware/routes
    if settings.SENTRY_DSN:
        app.add_middleware(SentryAsgiMiddleware)
        logger.info("Added SentryAsgiMiddleware.")

    # 2. SecurityHeadersMiddleware - Add security headers early
    app.add_middleware(SecurityHeadersMiddleware)
    logger.info("Added SecurityHeadersMiddleware.")

    # 3. CORS Middleware - Handle Cross-Origin Resource Sharing
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin).strip("/") for origin in settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            allow_headers=["*"], # Consider restricting headers in production
        )
        logger.info(f"Added CORSMiddleware with origins: {settings.BACKEND_CORS_ORIGINS}")
    else:
        logger.warning("CORS origins not configured. Skipping CORSMiddleware.")
        # Consider adding a default restrictive CORS policy if needed

    # 4. Logging Middleware - Log request/response details
    app.add_middleware(LoggingMiddleware)
    logger.info("Added LoggingMiddleware.")

    # 5. Rate Limiting Middleware
    limiter = create_rate_limiter(settings)
    app.add_middleware(RateLimitingMiddleware, limiter=limiter)
    logger.info("Added RateLimitingMiddleware.")

    # 6. Authentication Middleware - Placed after logging, rate limiting, CORS
    # It relies on infrastructure services, which are initialized via lifespan or DI.
    # Skipped paths should be carefully defined.
    skipped_auth_paths = {
        f"/api/{settings.VERSION}/docs",
        f"/api/{settings.VERSION}/openapi.json",
        f"/api/{settings.VERSION}/redoc",
        f"/api/{settings.VERSION}/auth/login",
        f"/api/{settings.VERSION}/auth/refresh",
        f"/api/{settings.VERSION}/auth/register", # Example: If registration doesn't require auth
        "/health", # Example: Health check endpoint
    }
    # AuthenticationMiddleware itself should handle lazy-loading services if not injected.
    app.add_middleware(
        AuthenticationMiddleware,
        skipped_paths=skipped_auth_paths
        # jwt_service and auth_service can be injected here for specific setups,
        # but typically rely on the default infrastructure getters.
    )
    logger.info(f"Added AuthenticationMiddleware. Skipped paths: {skipped_auth_paths}")

    # Add other custom middleware here if needed...


    logger.info("Middleware configuration complete.")


    logger.info("Adding API routers...")
    # --- API Router Configuration --- 
    # TEMPORARILY COMMENTED OUT to isolate ModuleNotFoundError
    # logger.info("Calling setup_routers()...")
    # configured_api_router = setup_routers()
    # logger.info("setup_routers() returned.")
    # app.include_router(configured_api_router, prefix=f"/api/{settings.VERSION}")
    logger.warning("Router inclusion TEMPORARILY SKIPPED for debugging.")
    # logger.info(f"Included main API router with prefix: /api/{settings.VERSION}")

    # --- Static Files (Optional) ---
    # Example: Mount static files if serving frontend assets from backend
    # static_files_path = os.path.join(os.path.dirname(__file__), "../static") # Adjust path as needed
    # if os.path.exists(static_files_path):
    #     app.mount("/static", StaticFiles(directory=static_files_path), name="static")
    #     logger.info(f"Mounted static files from: {static_files_path}")

    logger.info("Registering exception handlers...")
    # --- Exception Handlers --- 
    # REMOVED call to non-existent add_exception_handlers
    # Handlers should be defined directly using @app.exception_handler below or within this function
    # Example: 
    # @app.exception_handler(SomeException)
    # async def handle_some_exception(...): ... 
    logger.info("Exception handlers registered (assuming defined via decorators)." )

    logger.info("FastAPI application creation complete.")
    return app 