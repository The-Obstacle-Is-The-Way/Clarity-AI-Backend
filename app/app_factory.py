# Standard Library Imports
import logging
import logging.config
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

# Third-Party Imports
import sentry_sdk
from fastapi import FastAPI, Request, HTTPException, status as http_status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Application-Specific Imports
from app.core.config import Settings, settings as global_settings
from app.core.config.settings import get_settings
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
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
from app.infrastructure.security.jwt.jwt_service import get_jwt_service, JWTService
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
from app.presentation.api.v1.endpoints.test_endpoints import router as test_endpoints_router

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
    """
    Lifespan context manager for FastAPI application.
    
    Handles application startup and shutdown operations:
    1. Connects to database and initializes session factory
    2. Sets up Redis connection (if configured)
    3. Initializes Sentry (if configured)
    4. Adds state-dependent middleware (Authentication, Rate Limiting)
    5. Cleans up resources on shutdown
    """
    logger.info("LIFESPAN_START: Entered lifespan context manager.")
    # Local variables to store connections that need clean-up
    redis_client = None
    redis_pool = None
    db_engine = None
    current_settings = None # Initialize current_settings
    
    try:
        # --- Settings Configuration ---
        # Ensure settings are loaded and available first
        logger.info("LIFESPAN_SETTINGS_CONFIG_START: Attempting to access settings from app.state")
        if not hasattr(fastapi_app.state, 'settings') or fastapi_app.state.settings is None:
            logger.warning("LIFESPAN_SETTINGS_CONFIG_WARN: settings not found on fastapi_app.state. Attempting to load globally.")
            # This is a fallback, create_application should have set this.
            # If settings_override was used in create_application, this global_settings might not be the right one.
            # However, create_application explicitly sets app_instance.state.settings.
            current_settings = global_settings 
            fastapi_app.state.settings = current_settings # Ensure it's on state for subsequent steps
        else:
            current_settings = fastapi_app.state.settings
        
        if not current_settings:
            logger.critical("LIFESPAN_SETTINGS_CONFIG_FAILURE: Critical - settings could not be resolved. Aborting lifespan startup.")
            raise RuntimeError("Settings could not be resolved in lifespan context manager.")
        logger.info(f"LIFESPAN_SETTINGS_CONFIG_ACQUIRED: Environment from settings: {current_settings.ENVIRONMENT}")

        # --- Database Configuration ---
        try:
            # Get settings (dependency already configured)
            logger.info("LIFESPAN_DB_CONFIG_START: Attempting to access settings from app.state")
            logger.info(f"LIFESPAN_DB_CONFIG_SETTINGS_ACQUIRED: Environment from settings: {current_settings.ENVIRONMENT}")
            logger.info(f"Lifespan: Creating AsyncEngine with URL: {current_settings.ASYNC_DATABASE_URL}")
            
            # Create engine with SQLite-compatible settings
            is_sqlite = current_settings.ASYNC_DATABASE_URL.startswith('sqlite')
            
            # Base configuration
            engine_args = {
                "echo": current_settings.ENVIRONMENT in ["development", "test"],
            }
            
            # Add connection arguments based on database type
            if is_sqlite:
                # SQLite-specific settings (no pooling)
                engine_args["connect_args"] = {"check_same_thread": False}
            else:
                # PostgreSQL/other database settings
                engine_args.update({
                    "pool_pre_ping": True,
                    "pool_size": 5,
                    "max_overflow": 10,
                    "pool_recycle": 300,  # Recycle connections after 5 minutes
                    "connect_args": {"isolation_level": "SERIALIZABLE"}  # HIPAA requirement
                })
                
            # Create the engine with appropriate args
            db_engine = create_async_engine(
                current_settings.ASYNC_DATABASE_URL,
                **engine_args
            )
            
            # Create session factory - CRITICAL for application to work
            session_factory = async_sessionmaker(
                db_engine, 
                expire_on_commit=False, 
                autoflush=False,
                autocommit=False,
                class_=AsyncSession
            )
            
            # Set factory and engine on application state
            fastapi_app.state.actual_session_factory = session_factory
            fastapi_app.state.db_engine = db_engine
            logger.info(f"LIFESPAN_APP_FACTORY: actual_session_factory ID set on app.state: {id(fastapi_app.state.actual_session_factory)}")
            
            # --- BEGIN CRITICAL: Create database tables ---
            # This must happen after engine creation and before the app serves requests
            # that might access the database.
            if current_settings.ENVIRONMENT == "test" and not getattr(fastapi_app.state, 'db_schema_created', False):
                logger.info(f"LIFESPAN_DB_SCHEMA_CREATION_START (App Lifespan): Attempting to create database tables for {current_settings.ASYNC_DATABASE_URL}...")
                async with db_engine.begin() as conn:
                    # Import Base from where your SQLAlchemy models are defined
                    # This assumes Base is correctly collecting metadata from all your models.
                    from app.infrastructure.persistence.sqlalchemy.models.base import Base # Ensure this is the correct Base
                    await conn.run_sync(Base.metadata.create_all)
                logger.info("LIFESPAN_DB_SCHEMA_CREATION_SUCCESS (App Lifespan): Database tables created (or verified to exist).")
            elif current_settings.ENVIRONMENT == "test" and getattr(fastapi_app.state, 'db_schema_created', False):
                logger.info("LIFESPAN_DB_SCHEMA_CREATION_SKIPPED (App Lifespan): db_schema_created flag is True. Assuming tables created by test fixture.")
            elif current_settings.ENVIRONMENT != "test": # For non-test environments, always try to create/verify
                logger.info(f"LIFESPAN_DB_SCHEMA_CREATION_START (App Lifespan, Non-Test Env): Attempting to create database tables for {current_settings.ASYNC_DATABASE_URL}...")
                async with db_engine.begin() as conn:
                    from app.infrastructure.persistence.sqlalchemy.models.base import Base
                    await conn.run_sync(Base.metadata.create_all)
                logger.info("LIFESPAN_DB_SCHEMA_CREATION_SUCCESS (App Lifespan, Non-Test Env): Database tables created (or verified to exist).")
            # --- END CRITICAL: Create database tables ---
            
            logger.info(f"Database engine and actual_session_factory initialized and set on app.state (id: {id(fastapi_app.state)})")
            logger.info(f"app.state.actual_session_factory type: {type(fastapi_app.state.actual_session_factory)}")
            
        except Exception as e:
            logger.critical(f"LIFESPAN_DB_INIT_FAILURE: Failed to initialize database connection. ErrorType: {type(e).__name__}, Error: {e}", exc_info=True)
            fastapi_app.state.actual_session_factory = None # Ensure it's None on failure
            fastapi_app.state.db_engine = None
            raise # Re-raise the exception to ensure startup fails clearly
            
        # --- Redis Configuration (if enabled) ---
        if current_settings.REDIS_URL:
            try:
                logger.info(f"Connecting to Redis: {current_settings.REDIS_URL}")
                # Create Redis connection pool with appropriate settings for the environment
                connection_kwargs = {
                    "max_connections": 10,
                }
                
                # Only include SSL parameter in production environments
                # Omit during testing to avoid compatibility issues
                if current_settings.ENVIRONMENT != "test" and current_settings.REDIS_SSL:
                    connection_kwargs["ssl"] = current_settings.REDIS_SSL
                
                redis_pool = ConnectionPool.from_url(
                    current_settings.REDIS_URL,
                    **connection_kwargs
                )
                redis_client = Redis(connection_pool=redis_pool)
                
                # Test connection
                await redis_client.ping()
                
                # Assign to app state for use in services
                fastapi_app.state.redis_pool = redis_pool
                fastapi_app.state.redis = redis_client
                logger.info("Redis connection successfully established")
                
            except Exception as e:
                logger.error(f"LIFESPAN_REDIS_INIT_FAILURE: Failed to connect to Redis at {current_settings.REDIS_URL}. Error: {e}", exc_info=True)
                
                # Use different behavior based on environment
                if current_settings.ENVIRONMENT == "test":
                    # In test environment, use a mock Redis client instead of failing
                    logger.warning("Test environment detected. Creating mock Redis client instead of failing critically.")
                    
                    # Create a mock Redis client with the necessary methods
                    mock_redis = MagicMock()
                    # Add async methods that return awaitable objects
                    mock_redis.ping = AsyncMock(return_value=True)
                    mock_redis.get = AsyncMock(return_value=None)
                    mock_redis.set = AsyncMock(return_value=True)
                    mock_redis.delete = AsyncMock(return_value=True)
                    mock_redis.close = AsyncMock(return_value=None)
                    mock_redis.exists = AsyncMock(return_value=0)
                    mock_redis.incr = AsyncMock(return_value=1)
                    mock_redis.expire = AsyncMock(return_value=True)
                    
                    # Set the mock Redis client on app state
                    fastapi_app.state.redis = mock_redis
                    fastapi_app.state.redis_pool = None
                    redis_client = mock_redis
                    redis_pool = None
                    
                    logger.info("Mock Redis client successfully configured for test environment")
                else:
                    # In non-test environments, treat Redis connection failure as critical if URL is provided
                    raise RuntimeError(f"Critical dependency failure: Could not connect to Redis at {current_settings.REDIS_URL}") from e

        # --- Common Setup (Sentry) ---
        _initialize_sentry(current_settings)

        logger.info("Application startup phase in lifespan complete.")
        # logger.info(f"--- LIFESPAN STARTUP (app_factory): Initializing database with session factory: {session_factory}") # Already logged

        # Prepare state to be yielded - include all necessary items
        lifespan_state_to_yield = {
            "settings": current_settings,
            "actual_session_factory": session_factory, # ADDED TO YIELDED STATE
            "db_engine": db_engine,                   # ADDED TO YIELDED STATE
        }
        logger.info(f"--- LIFESPAN STARTUP (app_factory): app instance id: {id(fastapi_app)}")
        logger.info(f"--- LIFESPAN STARTUP (app_factory): app.state id before yield: {id(fastapi_app.state)}")
        # Log current app.state contents more reliably
        current_app_state_dict = {}
        if hasattr(fastapi_app.state, '_state') and isinstance(fastapi_app.state._state, dict): # Starlette State wraps a dict in _state
            current_app_state_dict = {k: type(v) for k, v in fastapi_app.state._state.items()}
        logger.info(f"--- LIFESPAN STARTUP (app_factory): Content of app.state._state before yield: {current_app_state_dict}")
        logger.info(f"--- LIFESPAN STARTUP (app_factory): Yielding state keys: {list(lifespan_state_to_yield.keys())}")

        yield lifespan_state_to_yield  # Explicitly yield the state dictionary

    except Exception as startup_exc:
         logger.critical(f"LIFESPAN_CRITICAL_STARTUP_FAILURE: Application startup failed critically. ErrorType: {type(startup_exc).__name__}, Error: {startup_exc}", exc_info=True)
         # Re-raise to prevent app from starting in a broken state
         raise RuntimeError(f"Application startup failed critically during lifespan: {startup_exc}") from startup_exc
    finally:
        # --- Shutdown Logic ---
        logger.info("Application lifespan shutdown sequence initiated.")
        if redis_client:
            try:
                # Check if it's a mock before calling close to avoid attribute errors
                if not isinstance(redis_client, MagicMock):
                    await redis_client.close()
                    logger.info("Redis client closed.")
                else:
                    logger.info("Mock Redis client - skipping close.")
            except Exception as e:
                logger.error(f"Error closing Redis client: {e}", exc_info=True)
        if redis_pool:
            try:
                await redis_pool.disconnect()
                logger.info("Redis connection pool disconnected.")
            except Exception as e:
                logger.error(f"Error disconnecting Redis pool: {e}", exc_info=True)

        # Safely get db_engine for shutdown from app.state
        # db_engine_for_shutdown = getattr(fastapi_app.state, "db_engine", None) # This was already good
        # The rest of the shutdown logic for db_engine seems okay

        if db_engine: # Use the engine created within the try block if it's still in local scope and valid
            logger.info(f"--- LIFESPAN SHUTDOWN (app_factory): Attempting to dispose of database engine (id: {id(db_engine)} from local lifespan scope)...")
            try:
                await db_engine.dispose()
                logger.info("--- LIFESPAN SHUTDOWN (app_factory): Database engine (from local scope) disposed.")
            except Exception as e:
                logger.error(f"Error disposing database engine (from local scope): {e}", exc_info=True)
        elif hasattr(fastapi_app.state, 'db_engine') and fastapi_app.state.db_engine:
            logger.info(f"--- LIFESPAN SHUTDOWN (app_factory): Attempting to dispose of database engine (id: {id(fastapi_app.state.db_engine)} from app.state)...")
            try:
                await fastapi_app.state.db_engine.dispose()
                logger.info("--- LIFESPAN SHUTDOWN (app_factory): Database engine (from app.state) disposed.")
            except Exception as e:
                logger.error(f"Error disposing database engine (from app.state): {e}", exc_info=True)
        else:
            logger.warning("--- LIFESPAN SHUTDOWN (app_factory): db_engine not found in local scope or on app.state; cannot dispose.")

        logger.info("Application shutdown complete.")


# --- Application Factory ---
def create_application(
    settings_override: Settings | None = None,
    include_test_routers: bool = False,
    jwt_service_override: JWTServiceInterface | None = None,
    skip_auth_middleware: bool = False  # TEMPORARY DEBUG FLAG
) -> FastAPI:
    """Factory function to create and configure the FastAPI application."""
    logger.info("CREATE_APPLICATION_START: Entered create_application factory.")

    # Resolve settings: Use provided settings or load global ones
    app_settings = settings_override if settings_override is not None else global_settings
    logger.info(f"CREATE_APPLICATION_SETTINGS_RESOLVED: Using environment: {app_settings.ENVIRONMENT}")

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
    logger.info(f"CREATE_APPLICATION_SETTINGS_ATTACHED: app.state.settings.ENVIRONMENT is now: {app_instance.state.settings.ENVIRONMENT if hasattr(app_instance.state, 'settings') and app_instance.state.settings is not None else 'NOT FOUND'}")

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

    # 4. Authentication Middleware - MOVED TO LIFESPAN (NOW MOVING BACK)
    # This is where AuthenticationMiddleware should be added.
    # It now depends on jwt_service (from app_settings) and accesses user_repo via request.app.state.
    if not skip_auth_middleware:
        logger.info("Adding AuthenticationMiddleware to the application.")
        try:
            # Get JWT service instance
            if jwt_service_override:
                jwt_service = jwt_service_override
                logger.info("Using provided JWT service override for AuthenticationMiddleware.")
            else:
                jwt_service = get_jwt_service()
                logger.info("JWT service initialized successfully.")
                
            # Determine public paths for authentication bypass
            public_paths = app_settings.PUBLIC_PATHS
            public_path_regexes = app_settings.PUBLIC_PATH_REGEXES
            
            # Create authentication middleware with appropriate settings
            from app.presentation.middleware.authentication import AuthenticationMiddleware
            
            # In test environments, make authentication middleware more permissive
            user_repository = None
            if app_settings.ENVIRONMENT.lower() != "test":
                # Only set up the user repository in non-test environments
                # In test environments, the middleware will use token data directly
                try:
                    from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
                    if hasattr(app_instance, 'state') and hasattr(app_instance.state, 'actual_session_factory'):
                        # Create repository with direct session_factory access
                        user_repository = SQLAlchemyUserRepository(session_factory=app_instance.state.actual_session_factory)
                except Exception as e:
                    logger.warning(f"Could not initialize SQLAlchemyUserRepository: {e}. Authentication may require token data.")
            
            # Register authentication middleware
            app_instance.add_middleware(
                AuthenticationMiddleware,
                jwt_service=jwt_service,
                user_repository=user_repository,
                public_paths=public_paths,
                public_path_regexes=public_path_regexes
            )
            logger.info("APP_FACTORY: AuthenticationMiddleware added successfully.")
            
        except Exception as e:
            logger.error(f"Failed to add AuthenticationMiddleware: {e}", exc_info=True)
            if app_settings.ENVIRONMENT.lower() != "production":
                logger.warning("Continuing without authentication middleware - THIS IS INSECURE")
            else:
                raise RuntimeError(f"Authentication middleware required in production but failed to initialize: {e}")
    else:
        logger.warning("Authentication middleware explicitly skipped! This should only happen in tests.")

    # 5. Rate Limiting Middleware - MOVED TO LIFESPAN (NOW MOVING BACK, still commented)
    # if app_settings.RATE_LIMITING_ENABLED:
    #     logger.info("LIFESPAN: Initializing and registering RateLimitingMiddleware...")
    #     try:
    #         rate_limiter_service = get_rate_limiter_service(app_settings)
    #         fastapi_app.add_middleware(RateLimitingMiddleware, limiter=rate_limiter_service)
    #         logger.info("LIFESPAN: RateLimitingMiddleware registered successfully.")
    #     except Exception as e:
    #         logger.error(f"LIFESPAN: Failed to initialize or register RateLimitingMiddleware: {type(e).__name__} - {e}", exc_info=True)
    #         logger.warning("LIFESPAN: RateLimitingMiddleware FAILED to load.")
    # else:
    #     logger.warning("LIFESPAN: Rate Limiting disabled - skipping RateLimitingMiddleware setup in lifespan.")

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
        app_instance.include_router(test_endpoints_router, prefix=f"{app_settings.API_V1_STR}", tags=["Test"])
        logger.info(f"Including TEST admin router prefix: {app_settings.API_V1_STR}/admin")
        logger.info(f"Including TEST endpoints router prefix: {app_settings.API_V1_STR}/test")

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
        request_id = getattr(request.state, "request_id", "N/A") # Get request_id safely
        logger.critical(
            f"Unhandled exception: {type(exc).__name__}: {exc} for request: {request.method} {request.url} (Request ID: {request_id})",
            exc_info=True, # This will include the stack trace
        )
        
        # HIPAA: Ensure no PHI is returned in error messages to the client.
        # Provide a generic error message.
        error_response_content = {
            "detail": "An unexpected internal server error occurred.",
            "error_id": request_id,
        }
        logger.info(f"Generic exception handler returning JSONResponse with status 500 and content: {error_response_content} (Request ID: {request_id})") # ADDED LOG
        return JSONResponse(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response_content,
        )
        
    logger.info("FastAPI application creation complete.")

    # Dependency overrides (primarily for testing)
    if app_settings.ENVIRONMENT == "test":
        # Example: app_instance.dependency_overrides[some_dependency] = mock_dependency
        logger.info("TEST_ENV_OVERRIDES: Test environment detected, dependency overrides can be applied here if needed globally.")

    # Middleware to copy app_state essentials to request_state
    # THIS IS THE CRUCIAL MIDDLEWARE TO ENSURE DB SESSIONS ARE AVAILABLE TO REQUESTS
    async def set_essential_app_state_on_request_middleware(request: Request, call_next):
        # Directly access and set specific, known attributes from app_instance.state
        # This avoids issues with how Starlette's State object might be structured internally (e.g. via ._state)
        if hasattr(app_instance.state, 'actual_session_factory'):
            request.state.actual_session_factory = app_instance.state.actual_session_factory
            # logger.debug(f"MIDDLEWARE (set_essential): Copied 'actual_session_factory' to request.state for {request.url.path}")
        else:
            logger.error(f"MIDDLEWARE (set_essential): 'actual_session_factory' NOT FOUND on app.state for {request.url.path}. DB sessions will fail.")
           
        if hasattr(app_instance.state, 'db_engine'):
            request.state.db_engine = app_instance.state.db_engine
            # logger.debug(f"MIDDLEWARE (set_essential): Copied 'db_engine' to request.state for {request.url.path}")
        else:
            logger.error(f"MIDDLEWARE (set_essential): 'db_engine' NOT FOUND on app.state for {request.url.path}.")
       
        if hasattr(app_instance.state, 'settings'): # Also copy settings for convenience
            request.state.settings = app_instance.state.settings
        else:
            logger.warning(f"MIDDLEWARE (set_essential): 'settings' NOT FOUND on app.state for {request.url.path}.")

        response = await call_next(request)
        return response
    app_instance.add_middleware(BaseHTTPMiddleware, dispatch=set_essential_app_state_on_request_middleware)
    logger.info("Essential app state to request state middleware added.")

    return app_instance
