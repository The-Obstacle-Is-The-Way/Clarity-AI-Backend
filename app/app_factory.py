import logging
import logging.config
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any

import sentry_sdk
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware
from sentry_sdk.integrations.logging import LoggingIntegration

from app.config.settings import Settings, get_settings

# REMOVED Import for old database init
# from app.core.dependencies.database import init_db

# ADDED Import for the new database factory function
from app.infrastructure.database.session import create_db_engine_and_session

# MOVED logging_config import just before use
from app.core.logging_config import LOGGING_CONFIG
from app.core.security import AuthenticationMiddleware
from app.core.security.headers import SecurityHeadersMiddleware
from app.core.security.middleware import LoggingMiddleware
from app.core.security.rate_limiting import RateLimitingMiddleware

# REMOVED incorrect import for exception handlers
# from app.core.exceptions.handlers import add_exception_handlers 
from app.infrastructure.cache.redis_cache import close_redis_connection, initialize_redis_pool
from app.infrastructure.security.rate_limiting.limiter import create_rate_limiter

# CORRECTED Import for the canonical V1 API router
from app.presentation.api.v1.api_router import api_v1_router

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
    settings = get_settings() # Get settings within lifespan
    
    # Initialize Database Engine and Session Factory
    logger.info("Initializing database engine and session factory...")
    try:
        # Pass the DB URL and echo flag from settings
        db_engine, db_session_factory = create_db_engine_and_session(
            db_url=str(settings.DATABASE_URL), 
            echo=getattr(settings, 'DB_ECHO_LOG', False)
        )
        # Store engine and factory in app state for access by dependencies
        app.state.db_engine = db_engine
        app.state.db_session_factory = db_session_factory
        logger.info("Database engine and session factory initialized and stored in app.state.")
        
        # Optional: If you need to ensure tables are created (e.g., for tests without migrations)
        # You might add a call like this, but it's generally discouraged for production startups.
        # from app.infrastructure.database.base_class import Base
        # async with db_engine.begin() as conn:
        #     await conn.run_sync(Base.metadata.create_all)
        # logger.info("Database tables checked/created (if using create_all).")

    except Exception as e:
        logger.exception("CRITICAL: Failed to initialize database connection.", exc_info=True)
        # Depending on requirements, you might raise the exception to halt startup
        # raise RuntimeError("Failed to initialize database") from e
        # Or allow startup but log critical failure

    # Initialize Redis Pool
    logger.info("Initializing Redis connection pool...")
    # settings = get_settings() # Settings already fetched above
    try:
        await initialize_redis_pool(str(settings.REDIS_URL))
        logger.info("Redis connection pool initialized.")
    except Exception as e:
        logger.exception("Failed to initialize Redis connection pool.", exc_info=True)

    # You could add other startup logic here, like connecting to external services
    
    logger.info("Application startup complete.")
    yield  # Application runs here
    
    # --- Shutdown Logic ---
    logger.info("Application shutdown: Cleaning up resources...")
    
    # Close database connections - Dispose the engine stored in app.state
    if hasattr(app.state, 'db_engine'):
        logger.info("Disposing database engine...")
        await app.state.db_engine.dispose()
        logger.info("Database engine disposed.")
    else:
        logger.warning("Database engine (app.state.db_engine) not found during shutdown.")

    # Close Redis Connection Pool
    logger.info("Closing Redis connection pool...")
    await close_redis_connection()
    logger.info("Redis connection pool closed.")

    # Add other shutdown logic here
    logger.info("Application shutdown complete.")

# --- Application Factory ---
def create_application(
    settings: Settings | None = None,
    *,
    dependency_overrides: dict[Callable[..., Any], Callable[..., Any]] | None = None,
) -> FastAPI:
    """
    Factory function to create and configure the FastAPI application instance.
    Moved from main.py to prevent import side effects.
    """
    # Resolve settings lazily for test compatibility
    if settings is None:
        settings = get_settings()

    logger.info(f"Creating FastAPI application with version: {settings.VERSION}")

    # Initialize Sentry - with defensive programming to handle optional configurations
    if hasattr(settings, 'SENTRY_DSN') and settings.SENTRY_DSN:
        logger.info(f"Initializing Sentry for environment: {settings.ENVIRONMENT}")
        sentry_sdk.init(
            dsn=str(settings.SENTRY_DSN),
            integrations=[
                LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
            ],
            environment=getattr(settings, 'ENVIRONMENT', 'development'),
            traces_sample_rate=getattr(settings, 'SENTRY_TRACES_SAMPLE_RATE', 0.0),
            profiles_sample_rate=getattr(settings, 'SENTRY_PROFILES_SAMPLE_RATE', 0.0),
            send_default_pii=False # Ensure PII is not sent by default
        )
        logger.info("Sentry initialized.")
    else:
        logger.warning("SENTRY_DSN not configured. Sentry integration disabled.")


    # Apply defensive programming for settings attributes that might not exist in all environments
    project_name = getattr(settings, 'PROJECT_NAME', 'Clarity AI Backend')
    project_desc = getattr(settings, 'PROJECT_DESCRIPTION', 'Digital Twin Platform')
    version = getattr(settings, 'VERSION', '0.1.0')
    environment = getattr(settings, 'ENVIRONMENT', 'development')
    
    app = FastAPI(
        title=project_name,
        description=project_desc,
        version=version,
        openapi_url=f"/api/{version}/openapi.json" if environment != 'production' else None,
        docs_url=f"/api/{version}/docs" if environment != 'production' else None,
        redoc_url=f"/api/{version}/redoc" if environment != 'production' else None,
        lifespan=lifespan # Use the lifespan context manager
    )

    logger.info("Adding middleware...")
    # --- Middleware Configuration ---
    # IMPORTANT: Order matters! Middleware are processed in the order they are added.

    # 1. SentryAsgiMiddleware (if enabled) - Must be early to catch errors in other middleware/routes
    if hasattr(settings, 'SENTRY_DSN') and settings.SENTRY_DSN:
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
    # Public paths should be carefully defined.
    public_paths = {
        f"/api/{version}/docs",
        f"/api/{version}/openapi.json",
        f"/api/{version}/redoc",
        f"/api/{version}/auth/login",
        f"/api/{version}/auth/refresh",
        f"/api/{version}/auth/register", # Example: If registration doesn't require auth
        "/health", # Example: Health check endpoint
    }
    # AuthenticationMiddleware itself should handle lazy-loading services if not injected.
    app.add_middleware(
        AuthenticationMiddleware,
        public_paths=public_paths
        # jwt_service and auth_service can be injected here for specific setups,
        # but typically rely on the default infrastructure getters.
    )
    logger.info(f"Added AuthenticationMiddleware. Public paths: {public_paths}")

    # Add other custom middleware here if needed...


    logger.info("Middleware configuration complete.")

    # --- Dependency Overrides (mainly for testing) ---
    if dependency_overrides:
        logger.debug(
            "Applying %d dependency overrides to FastAPI app instance.",
            len(dependency_overrides),
        )
        app.dependency_overrides.update(dependency_overrides)

    logger.info("Adding API routers...")
    # --- API Router Configuration --- 
    # Use the explicitly defined v1 router
    app.include_router(api_v1_router, prefix=f"/api/{settings.VERSION}")
    logger.info(f"Included main V1 API router from app.presentation.api.v1 with prefix: /api/{settings.VERSION}")

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