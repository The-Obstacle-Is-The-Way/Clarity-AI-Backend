# -*- coding: utf-8 -*-
"""
SQLAlchemy database connection configuration.

This module provides async database session factory and connection pooling
for the SQLAlchemy ORM, configured according to the application settings.
"""

import os
from typing import Optional, Callable, Dict, Any, AsyncGenerator, Annotated
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool, QueuePool, FallbackAsyncAdaptedQueuePool
from fastapi import Depends

# Use canonical config path
from app.config.settings import Settings, get_settings
from app.core.utils.logging import get_logger
from app.infrastructure.persistence.sqlalchemy.config.base import Base

logger = get_logger(__name__)


# ------------------------------------------------------------
# NOTE: This class is also imported directly by several unit/
# integration test modules that expect a *no‑argument* constructor
# exposing a synchronous `get_session()` helper.  To remain
# backward‑compatible with those tests while still supporting the
# main application flow that prefers explicit Settings injection,
# the `settings` parameter has been made optional.
# ------------------------------------------------------------

class Database:
    """
    Database connection manager.
    
    This class manages a SQLAlchemy async engine and session factory,
    providing controlled access to database sessions.
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize the database with main application settings.
        
        Args:
            settings: Application settings object from app.core.config
        """
        # Lazily fetch the settings if none were provided.  This keeps the
        # public constructor signature compatible with legacy tests that call
        # `Database()` without arguments.
        if settings is None:
            settings = get_settings()

        self.settings = settings
        self.engine = self._create_engine()
        self.session_factory = self._create_session_factory()
        
    def _create_engine(self):
        """
        Create the SQLAlchemy async engine using the main settings.
        
        Returns:
            SQLAlchemy async engine
        """
        # DIAGNOSTIC LOGGING
        env_uri_override = os.getenv("SQLALCHEMY_DATABASE_URI")
        logger.info(f"[DB._create_engine] ENTERING. ENVIRONMENT={self.settings.ENVIRONMENT}")
        logger.info(f"[DB._create_engine] Settings URI: {self.settings.DATABASE_URL}")
        logger.info(f"[DB._create_engine] Env Var Override URI: {env_uri_override}")

        # Use the assembled connection string directly from main settings
        connection_url = str(self.settings.DATABASE_URL)
        logger.info(f"[DB._create_engine] Final Connection URL for create_async_engine: {connection_url}")

        # --- Pooling configuration --- 
        # Use NullPool for SQLite in test environment to avoid potential issues
        if connection_url.startswith("sqlite"):
            pooling_args = {"poolclass": NullPool}
            logger.info("[DB._create_engine] Using NullPool for SQLite.")
        else:
            # Default pooling for other DBs (e.g., PostgreSQL)
            pooling_args = {
                "poolclass": FallbackAsyncAdaptedQueuePool,
                "pool_size": 5, 
                "max_overflow": 10,
                "pool_timeout": 30,
                "pool_recycle": 1800,
                "pool_pre_ping": True
            }
            logger.info(f"[DB._create_engine] Using {pooling_args.get('poolclass')} pool.")
            
        # Create engine
        return create_async_engine(
            connection_url,
            # Use ENVIRONMENT from main settings to control echo
            echo=self.settings.ENVIRONMENT == "development", 
            future=True,
            **pooling_args
        )
        
    def _create_session_factory(self):
        """
        Create the session factory for this engine.
        
        Returns:
            Async session factory
        """
        return async_sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
            class_=AsyncSession
        )
        
    @asynccontextmanager
    async def session(self):
        """
        Create a new session as an async context manager.
        
        Yields:
            SQLAlchemy AsyncSession
        """
        session = self.session_factory()
        try:
            yield session
        finally:
            await session.close()
            
    async def create_all(self):
        """Create all tables defined in the models."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            
    async def dispose(self):
        """Dispose the engine and all connections."""
        await self.engine.dispose()

    # ------------------------------------------------------------------
    # Legacy helper methods expected by older parts of the code‑base and
    # several test suites (e.g. tests/security/db and tests/fixtures).
    # ------------------------------------------------------------------

    def get_session(self):  # type: ignore[override]
        """Return a *new* session instance.

        The method intentionally returns the session directly instead of an
        async context manager because a subset of the security/database test
        suite interacts with the session in a synchronous fashion and relies
        on ``MagicMock`` instrumentation.  The consumer is responsible for
        closing/awaiting the session when using the real database engine in
        an asynchronous context.
        """
        try:
            return self.session_factory()
        except Exception as exc:
            # Provide detailed log without leaking credentials.
            logger.error("Failed to create DB session", exc_info=True)
            raise exc
        

# Global database instance
_db_instance = None


def get_db_instance() -> Database:
    """
    Get the database singleton instance.

    This function returns the global database instance, initializing it
    with main application settings if not already initialized.

    For the 'test' environment, it ensures fresh settings are loaded
    by bypassing the global instance and settings cache.

    Returns:
        Database singleton instance
    """
    global _db_instance

    # Check if running in the test environment *first* and handle it separately
    if os.getenv("ENVIRONMENT") == "test":
        # ALWAYS use get_settings() in test env, assuming it's mocked
        test_settings = get_settings()
        logger.info(
            # match our Settings field name; avoid AttributeError on MockSettings
            f"Test Environment: Creating NEW Database instance using settings from get_settings(). URI: {test_settings.DATABASE_URL}"
        )
        # Return a new instance directly, DO NOT assign to _db_instance
        return Database(test_settings)

    # --- Logic for non-test environments --- 
    # Use a lock or thread-safe mechanism if concurrent initialization is possible, 
    # but for typical web app startup, this might be sufficient.
    if _db_instance is None:
        # Get the main application settings instance (potentially cached)
        main_settings = get_settings()
        logger.info(
            f"Non-Test Environment: Initializing global Database instance. URI: {main_settings.DATABASE_URL}"
        )
        # Initialize Database with the main settings object
        _db_instance = Database(main_settings)
        logger.info("Global database instance initialized.")
    else:
        logger.debug("Returning existing global database instance.")

    return _db_instance


# Define a custom type annotation that wraps AsyncSession to prevent FastAPI from
# treating it as a return type in endpoints
DBSessionDep = Annotated[AsyncSession, "DBSession"]

async def get_db_session() -> AsyncGenerator[DBSessionDep, None]:
    """
    Get a database session from the session factory.
    
    This function is used as a FastAPI dependency for database access
    in endpoint handlers. The custom return type annotation prevents
    FastAPI from trying to use AsyncSession in response models.
    
    Yields:
        An async database session (with custom type annotation)
    """
    db = get_db_instance()
    async with db.session() as session:
        yield session


def get_db_dependency() -> Callable:
    """
    Get the database dependency function.
    
    This function is used to provide the database dependency in FastAPI.
    It's also used for dependency overriding in tests.
    
    Returns:
        Database dependency function
    """
    return get_db_session


async def close_db_connections() -> None:
    """
    Close all database connections.
    
    This function should be called during application shutdown.
    """
    if _db_instance is not None:
        await _db_instance.dispose()
        logger.info("Database connections closed")
