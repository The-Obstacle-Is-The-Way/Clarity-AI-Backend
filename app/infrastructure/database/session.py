"""
Database session management for the Novamind Digital Twin Platform.

This module provides functions for creating database connections
and dependency injection for FastAPI endpoints.
"""
import os
from typing import Generator, AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import logging
from sqlalchemy.pool import StaticPool

# Import settings from the canonical location
from app.config.settings import get_settings

# Call the function to get the settings object
settings = get_settings()
# Determine the database URL, fallback to in-memory SQLite if unset
database_url = settings.DATABASE_URL or "sqlite+aiosqlite:///:memory:"

# Create async SQLAlchemy engine, handling SQLite in-memory differently
if database_url.startswith("sqlite+aiosqlite:///:memory:"):
    # Use StaticPool for in-memory SQLite to avoid issues with asyncio
    engine = create_async_engine(
        database_url,
        echo=settings.DATABASE_ECHO,
        future=True,
        connect_args={"check_same_thread": False},  # Specific to SQLite
        poolclass=StaticPool,  # Explicitly set StaticPool
    )
else:
    engine = create_async_engine(
        database_url,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        echo=settings.DATABASE_ECHO,
        future=True,
        poolclass=StaticPool,
        connect_args=(
            {
                "ssl": {
                    "ca_certs": settings.DATABASE_SSL_CA,
                    "ssl_mode": settings.DATABASE_SSL_MODE
                } if settings.DATABASE_SSL_MODE else None
            }
            if database_url.startswith("postgresql")
            else {}
        )
    )

# Create session factory for creating AsyncSession instances
session_local = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

logger = logging.getLogger(__name__)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI endpoints to get a database session.
    
    Yields a new database session for each request, ensuring the session is
    properly closed after the request is completed, even if an exception occurs.
    
    Yields:
        AsyncSession: Database session
    """
    async with session_local() as session:
        try:
            yield session
            # Session will be committed if no exception occurs
            await session.commit()
        except Exception:
            # Roll back session on exception
            await session.rollback()
            raise
        finally:
            # Close session regardless of outcome
            await session.close()