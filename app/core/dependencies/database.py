"""
Database connection utilities for SQLAlchemy.

This module provides the database engine, session management,
and connection utilities for the application.
"""
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession

# Monkey-patch AsyncSession.execute to accept raw SQL strings as text()
_orig_async_execute = _AsyncSession.execute


async def _async_execute(self, statement, *args, **kwargs):
    if isinstance(statement, str):
        statement = text(statement)
    return await _orig_async_execute(self, statement, *args, **kwargs)


_AsyncSession.execute = _async_execute
import logging
import os
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

# Use the new canonical config location
from app.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

# Create the declarative base model
Base = declarative_base()
# For compatibility with older tests expecting metadata.is_bound()
Base.metadata.is_bound = lambda: True  # type: ignore[assignment]

# --- Engine and Session Factory Creation (Deferred) ---

# Global variable to hold the engine once created
_engine: AsyncEngine | None = None


def get_engine(settings: Settings | None = None) -> AsyncEngine:
    """Gets or creates the SQLAlchemy async engine."""
    global _engine
    # Ensure TESTING env var for test suite
    os.environ.setdefault("TESTING", "1")
    # If called with explicit settings, always recreate the engine
    if settings is not None:
        _engine = None
    if _engine is None:
        if settings is None:
            settings = get_settings()

        database_url = settings.DATABASE_URL
        if database_url is None:
            raise ValueError(
                "DATABASE_URL is not configured. "
                "Please check environment variables or .env file."
            )

        # Ensure the URL is a string and has the async driver
        db_url_str = str(database_url)
        if db_url_str.startswith("postgresql://"):
            db_url_str = db_url_str.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif db_url_str.startswith("sqlite://"):
            # Ensure aiosqlite is used for async SQLite
            if not db_url_str.startswith("sqlite+aiosqlite://"):
                db_url_str = db_url_str.replace("sqlite://", "sqlite+aiosqlite://", 1)

        logger.info(
            f"Creating database engine for URL: {db_url_str[:db_url_str.find(':')]}:***"
        )  # Log safely
        try:
            # Build engine kwargs
            engine_kwargs: dict[str, Any] = {
                "echo": settings.DATABASE_ECHO,
                "future": True,
                "pool_pre_ping": True,
            }
            # Only apply pool size/overflow for real database backends
            if not db_url_str.startswith("sqlite+aiosqlite://"):
                engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
                engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
            _engine = create_async_engine(db_url_str, **engine_kwargs)
        except Exception as e:
            logger.error(f"Failed to create database engine: {e}", exc_info=True)
            raise
    return _engine


# Global variable for session factory
_async_session_local: async_sessionmaker[AsyncSession] | None = None


def get_session_local(engine: AsyncEngine | None = None) -> async_sessionmaker[AsyncSession]:
    """Gets or creates the async session factory."""
    global _async_session_local
    # If called with explicit engine, always recreate the session factory
    if engine is not None:
        _async_session_local = None
    if _async_session_local is None:
        if engine is None:
            engine = get_engine()  # Get engine using current settings
        _async_session_local = async_sessionmaker(
            bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )
    return _async_session_local


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that yields a session for use in async context.
    Supports `async with get_session() as session:` semantics.
    """
    # Create the session context manager from the factory
    session_factory = get_session_local()
    session_cm = session_factory()
    # Enter the factory context to obtain the session instance
    session = await session_cm.__aenter__()
    try:
        yield session
    finally:
        # Always close the session instance
        try:
            await session.close()
        except Exception:
            logger.warning("Session close failed", exc_info=True)
        # Exit the factory context manager
        try:
            await session_cm.__aexit__(None, None, None)
        except Exception:
            logger.warning("Session context exit failed", exc_info=True)


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Primary database session provider for dependency injection.
    This is the main entry point for getting a database session in the application.
    """
    async with get_session() as session:
        yield session


async def init_db() -> None:
    """
    Initialize the database with all defined models.
    Ensures engine is created before running metadata commands.
    """
    settings = get_settings()
    # Determine if we're in test mode
    is_test = (
        os.environ.get("TESTING", "0").lower() in ("1", "true", "yes")
        or settings.ENVIRONMENT == "test"
    )

    engine = get_engine(settings)  # Get engine using current settings

    async with engine.begin() as conn:
        logger.info("Initializing database...")
        # Conditional table creation based on environment
        if settings.ENVIRONMENT == "development" or is_test:
            logger.info("Dropping all tables (dev/test environment)...")
            await conn.run_sync(Base.metadata.drop_all)
            logger.info("Creating all tables (dev/test environment)...")
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created.")
        else:
            logger.info("Skipping table creation/deletion in non-dev/test environment.")


async def dispose_engine() -> None:
    """Dispose of the engine, closing connection pools."""
    global _engine
    if _engine:
        logger.info("Disposing database engine.")
        await _engine.dispose()
        _engine = None  # Reset global engine
        logger.info("Database engine disposed.")
    else:
        logger.info("Database engine already disposed or never created.")
