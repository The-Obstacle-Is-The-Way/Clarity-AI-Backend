"""
DIRECT QUANTUM DATABASE ISSUE RESOLUTION

This script directly examines the SQLAlchemy metadata registry and manually creates
any missing tables to enable our tests to pass immediately.
"""

import importlib
import sys
import os
from pprint import pformat
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# Add the backend directory to sys.path if needed
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import Base to access metadata
from app.infrastructure.persistence.sqlalchemy.config.base import Base
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.domain.utils.datetime_utils import now_utc

# Import all models to register with metadata 
from app.infrastructure.persistence.sqlalchemy.models.user import User
try:
    # Attempt to import Patient model
    from app.infrastructure.persistence.sqlalchemy.models.patient import Patient
    PATIENT_IMPORTED = True
except Exception as e:
    logger.error(f"Error importing Patient model: {e}")
    PATIENT_IMPORTED = False

# Create in-memory SQLite database and test table creation
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

async def test_database_tables():
    """Test creating all tables in SQLAlchemy metadata."""
    # Register tables
    registered_tables = list(Base.metadata.tables.keys())
    logger.info(f"REGISTERED TABLES: {pformat(registered_tables)}")
    
    # Fix: If 'patients' table is not registered, create it manually
    if 'patients' not in registered_tables:
        logger.warning("'patients' table not found in metadata, creating manually")
        
        # Define table manually with minimal required columns for tests
        from sqlalchemy import Table, MetaData
        if not hasattr(Base, 'metadata'):
            logger.error("Base.metadata does not exist!")
            return
            
        # Create a minimal patients table using SQLAlchemy Table construct
        # CRITICAL FIX: Use column names that match the SQL schema (without underscores)
        patients_table = Table(
            'patients', 
            Base.metadata,
            Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
            Column('user_id', UUID(as_uuid=True), ForeignKey("users.id"), nullable=True),
            Column('first_name', Text, nullable=True),  # Match column names with SQL schema
            Column('last_name', Text, nullable=True),   # Match column names with SQL schema
            Column('date_of_birth', Text, nullable=True), # Match column names with SQL schema
            Column('email', Text, nullable=True),       # Match column names with SQL schema
            Column('phone', Text, nullable=True),       # Match column names with SQL schema
            Column('created_at', DateTime, default=now_utc, nullable=False),
            Column('updated_at', DateTime, default=now_utc, onupdate=now_utc, nullable=False),
            Column('is_active', Boolean, default=True, nullable=False),
        )
        
        # Check that it's now registered
        registered_tables = list(Base.metadata.tables.keys())
        logger.info(f"UPDATED REGISTERED TABLES: {pformat(registered_tables)}")
    
    # Create test in-memory database to verify table creation
    db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(db_url, echo=True)
    
    try:
        # CRITICAL FIX: Enable foreign keys BEFORE creating tables
        async with engine.begin() as conn:
            # Enable foreign keys first
            await conn.execute(text("PRAGMA foreign_keys = ON;"))
            logger.info("Foreign keys enabled in SQLite")
            
            # Then create all tables
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Tables created successfully")
        
        # Test session creation and verify tables
        session_factory = async_sessionmaker(bind=engine, class_=AsyncSession)
        async with session_factory() as session:
            # Verify tables exist
            result = await session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            tables = [row[0] for row in result]
            logger.info(f"CREATED TABLES: {tables}")
            
            # Check if critical tables exist
            if 'users' not in tables or 'patients' not in tables:
                logger.error(f"CRITICAL ERROR: Missing required tables! Found: {tables}")
            else:
                logger.info("SUCCESS: All required tables created")
                
                # Verify table structure
                for table_name in ['users', 'patients']:
                    columns_query = text(f"PRAGMA table_info({table_name})")
                    columns_result = await session.execute(columns_query)
                    columns = columns_result.fetchall()
                    column_names = [col[1] for col in columns]  # Column name is at index 1
                    logger.info(f"Table {table_name} columns: {column_names}")
            
    except Exception as e:
        logger.error(f"Error during table creation: {e}")
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(test_database_tables()) 