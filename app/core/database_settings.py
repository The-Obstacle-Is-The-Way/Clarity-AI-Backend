"""
Database Settings Configuration.

This module provides configuration settings specific to database connections,
including connection pooling, credentials, and other database-specific options.
"""

from urllib.parse import quote_plus

from pydantic import ConfigDict, field_validator
from pydantic_settings import BaseSettings


class DatabaseSettings(BaseSettings):
    """
    Database connection settings.

    This class defines configuration settings for database connections,
    with validation and default values.
    """

    # Connection settings
    HOST: str = "localhost"
    PORT: int = 5432
    USERNAME: str = "postgres"
    PASSWORD: str = "postgres"
    DATABASE: str = "novamind"

    # Connection pool settings
    POOL_SIZE: int = 5
    POOL_MAX_OVERFLOW: int = 10
    POOL_TIMEOUT: int = 30
    POOL_RECYCLE: int = 1800
    DISABLE_POOLING: bool = False

    # SQLAlchemy settings
    ECHO_SQL: bool = False
    SSL_MODE: str | None = None
    SSL_CA_CERT: str | None = None

    # Default schema
    DEFAULT_SCHEMA: str = "public"

    # Migration settings
    AUTO_MIGRATE: bool = True

    # Pydantic v2 configuration
    model_config = ConfigDict(
        env_file=".env",
        env_prefix="DB_",
        case_sensitive=True,
    )

    @field_validator("PORT")
    def validate_port(cls, v: int) -> int:
        """
        Validate that port is within allowed range.

        Args:
            v: Port number to validate

        Returns:
            Validated port number

        Raises:
            ValueError: If port is outside allowed range
        """
        if not 1 <= v <= 65535:
            raise ValueError(f"Port must be between 1 and 65535: {v}")
        return v

    @field_validator("POOL_SIZE", "POOL_MAX_OVERFLOW", "POOL_TIMEOUT", "POOL_RECYCLE")
    def validate_positive_int(cls, v: int) -> int:
        """
        Validate that a value is a positive integer.

        Args:
            v: Value to validate

        Returns:
            Validated value

        Raises:
            ValueError: If value is not positive
        """
        if v <= 0:
            raise ValueError(f"Value must be a positive integer: {v}")
        return v

    def get_connection_string(self) -> str:
        """
        Get database connection string from settings.

        Returns:
            Connection string for SQLAlchemy
        """
        # Escape special characters in username and password
        username = quote_plus(self.USERNAME)
        password = quote_plus(self.PASSWORD)

        # Build SSL parameters if needed
        ssl_params = ""
        if self.SSL_MODE:
            ssl_params = f"?sslmode={self.SSL_MODE}"
            if self.SSL_CA_CERT:
                ssl_params += f"&sslrootcert={self.SSL_CA_CERT}"

        # Build basic connection string
        conn_str = (
            f"postgresql+asyncpg://{username}:{password}@"
            f"{self.HOST}:{self.PORT}/{self.DATABASE}{ssl_params}"
        )

        return conn_str
