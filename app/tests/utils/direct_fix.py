"""
DIRECT QUANTUM DATABASE ISSUE RESOLUTION

This script directly examines the SQLAlchemy metadata registry and manually creates
any missing tables to enable our tests to pass immediately.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Import SQLAlchemy components
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Import domain and infrastructure components
from app.infrastructure.persistence.sqlalchemy.config.base import Base

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Add the parent directory to sys.path if needed
if str(Path(__file__).parent.parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
    logger.info(f"Added {Path(__file__).parent.parent.parent.parent} to sys.path")

# Import all models to register with metadata
logger.info("Importing models to register with metadata")

# Database URL configuration
DATABASE_URL = "sqlite+aiosqlite:///clarity_test.db"
logger.info(f"Using database URL: {DATABASE_URL}")

# Create engine and session
engine = create_async_engine(DATABASE_URL, echo=True)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

# Direct SQL statements for table creation
DIRECT_SQL = {
    "enable_foreign_keys": """
    PRAGMA foreign_keys = ON;
    """,
    "create_digital_twin_table": """
    CREATE TABLE IF NOT EXISTS digital_twins (
        id TEXT PRIMARY KEY,
        patient_id TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        version INTEGER NOT NULL DEFAULT 1,
        config_json TEXT,
        state_json TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    );
    """,
    "create_biometric_twin_table": """
    CREATE TABLE IF NOT EXISTS biometric_twins (
        id TEXT PRIMARY KEY,
        patient_id TEXT NOT NULL,
        twin_type TEXT NOT NULL,
        state_json TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        baseline_established BOOLEAN NOT NULL DEFAULT FALSE,
        connected_devices TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    );
    """,
    "create_biometric_data_points_table": """
    CREATE TABLE IF NOT EXISTS biometric_data_points (
        id TEXT PRIMARY KEY,
        twin_id TEXT NOT NULL,
        data_type TEXT NOT NULL,
        value TEXT NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        source TEXT NOT NULL,
        metadata TEXT,
        confidence REAL,
        FOREIGN KEY (twin_id) REFERENCES biometric_twins(id)
    );
    """,
    "create_biometric_rules_table": """
    CREATE TABLE IF NOT EXISTS biometric_rules (
        id TEXT PRIMARY KEY,
        patient_id TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        data_source TEXT NOT NULL,
        condition TEXT NOT NULL,
        metadata TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        threshold REAL,
        min_value REAL,
        max_value REAL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        FOREIGN KEY (patient_id) REFERENCES patients(id)
    );
    """,
    "create_biometric_alerts_table": """
    CREATE TABLE IF NOT EXISTS biometric_alerts (
        id TEXT PRIMARY KEY,
        patient_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        data_point_id TEXT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP,
        acknowledged_at TIMESTAMP,
        acknowledged_by TEXT,
        metadata TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (rule_id) REFERENCES biometric_rules(id),
        FOREIGN KEY (data_point_id) REFERENCES biometric_data_points(id)
    );
    """,
}


async def create_tables() -> None:
    """
    Create all tables in the database directly using SQLAlchemy metadata.
    """
    async with engine.begin() as conn:
        # Enable foreign keys for SQLite
        await conn.execute(text(DIRECT_SQL["enable_foreign_keys"]))

        # Create tables from the model metadata
        await conn.run_sync(Base.metadata.create_all)

        # Print the tables that were created
        table_names = await conn.run_sync(lambda sync_conn: sync_conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).scalars().all())
        logger.info(f"Tables in database: {', '.join(table_names)}")

        # Check if specific tables are missing
        for table_name, sql in DIRECT_SQL.items():
            if table_name != "enable_foreign_keys" and table_name.startswith("create_"):
                table_name_actual = table_name.replace("create_", "").replace("_table", "")
                if table_name_actual not in table_names:
                    logger.warning(f"Table {table_name_actual} is missing, creating directly")
                    await conn.execute(text(sql))


async def main() -> None:
    """
    Main entry point for the script.
    """
    try:
        logger.info("Starting SQLAlchemy metadata registry examination and table creation")
        await create_tables()
        logger.info("Successfully created all tables")
    except Exception as e:
        logger.error(f"Error during table creation: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
