# -*- coding: utf-8 -*-
"""
Alembic environment configuration for NOVAMIND database migrations.

This module configures the alembic environment for database migrations,
ensuring proper integration with SQLAlchemy models and environment variables.
"""
import os
import sys
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool, create_engine

# Add the project root directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables from .env file
load_dotenv()

# Import SQLAlchemy models to ensure they're registered with the metadata
from app.infrastructure.persistence.sqlalchemy.config.database import Base
from app.infrastructure.persistence.sqlalchemy.models import (
    patient,
    user,
    digital_twin,
    appointment,
    medication,
    clinical_note,
    provider
)

# This is the Alembic Config object, which provides access to the values within the .ini file
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import SQLAlchemy models to ensure they're registered with the metadata
from app.infrastructure.database.base import Base  
target_metadata = Base.metadata

# Get database URL from environment variable or fallback to config
# Ensure you set DATABASE_URL environment variable
# Format: postgresql://user:password@host/database
db_user = os.environ.get("DB_USER", "postgres")
db_password = os.environ.get("DB_PASSWORD", "")  # Read password from environment
db_host = os.environ.get("DB_HOST", "localhost")
db_name = os.environ.get("DB_NAME", "novamind")
    
if not db_password:
    print("WARNING: DB_PASSWORD environment variable not set. Alembic might fail.")
    # Optionally, raise an error or use a default unsafe password for local dev ONLY
    # raise ValueError("DB_PASSWORD environment variable must be set")
    # db_password = "unsafe_default_dev_password" # Use with extreme caution

sqlalchemy_url = f"postgresql://{db_user}:{db_password}@{db_host}/{db_name}"
    
# Override URL from config if environment variable is not set (less secure)
# sqlalchemy_url = os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url"))

config.set_main_option("sqlalchemy.url", sqlalchemy_url)


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.
    
    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine creation
    we don't even need a DBAPI to be available.
    
    Calls to context.execute() here emit the given string to the script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.
    
    In this scenario we need to create an Engine and associate a connection with the context.
    """
    # Connectable = engine_from_config(
    #     config.get_section(config.config_ini_section, {}),
    #     prefix="sqlalchemy.",
    #     poolclass=pool.NullPool,
    # )
        
    # Use the URL set in run_migrations_offline
    connectable = create_engine(config.get_main_option("sqlalchemy.url"))

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            render_as_batch=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()