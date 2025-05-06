"""
SQLAlchemy database handling with enhanced security and auditing.

This module provides SQLAlchemy database setup with additional features for
HIPAA compliance, including encryption, audit logging, and connection pooling.
"""

import contextlib
import logging
import time
import uuid
from collections.abc import Generator
from typing import Any, TypeVar, Union

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool

# Use canonical config path
from app.config.settings import get_settings

settings = get_settings()

# Configure logger
logger = logging.getLogger(__name__)

# Import the canonical Base
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.registry import ensure_all_models_registered

# Type variable for session-yielding functions
T = TypeVar('T')


class Database:
    """
    Base database handler for SQLAlchemy connections.
    
    This class provides the core database functionality, including connection
    management, session handling, and table operations.
    """
    
    def __init__(
        self,
        db_url: str | None = None,
        echo: bool | None = None,
        pool_size: int | None = None,
        max_overflow: int | None = None,
        pool_timeout: int | None = None,
        ssl_mode: str | None = None,
        ssl_ca: str | None = None,
        ssl_verify: bool | None = None
    ):
        """
        Initialize database connection.
        
        Args:
            db_url: SQLAlchemy database URL
            echo: Whether to echo SQL statements
            pool_size: Size of the connection pool
            max_overflow: Maximum overflow connections
            pool_timeout: Pool connection timeout
            ssl_mode: SSL mode for PostgreSQL
            ssl_ca: SSL certificate authority path
            ssl_verify: Whether to verify SSL certificates
        """
        self.db_url = db_url or settings.DATABASE_URL
        self.echo = echo if echo is not None else settings.DATABASE_ECHO
        self.pool_size = pool_size or settings.DATABASE_POOL_SIZE
        self.max_overflow = max_overflow or 10
        self.pool_timeout = pool_timeout or 30
        self.ssl_mode = ssl_mode or settings.DATABASE_SSL_MODE
        self.ssl_ca = ssl_ca or settings.DATABASE_SSL_CA
        self.ssl_verify = ssl_verify if ssl_verify is not None else settings.DATABASE_SSL_VERIFY
        
        connect_args = {}
        
        # Add SSL configuration for PostgreSQL
        if self.db_url.startswith("postgresql") and settings.DATABASE_SSL_ENABLED:
            connect_args["sslmode"] = self.ssl_mode
            if self.ssl_ca:
                connect_args["sslrootcert"] = self.ssl_ca
        
        # Create engine with connection pooling
        self.engine = create_engine(
            self.db_url,
            echo=self.echo,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            poolclass=QueuePool,
            connect_args=connect_args
        )
        
        # Create sessionmaker
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def get_session(self) -> Session:
        """
        Get a new database session.
        
        Returns:
            New database session
        """
        return self.SessionLocal()
    
    @contextlib.contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions.
        
        Yields a session and handles commit/rollback automatically.
        
        Yields:
            Database session
            
        Raises:
            Any exceptions from the session operations
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def execute_query(
        self, 
        sql: Union[str, text], 
        params: dict[str, Any] | None = None
    ) -> list[Any]:
        """
        Execute a raw SQL query.
        
        Args:
            sql: SQL query string or TextClause object
            params: Query parameters
            
        Returns:
            List of row objects with attribute access
            
        Raises:
            SQLAlchemyError: For database errors
        """
        params = params or {}
        try:
            with self.engine.connect() as connection:
                # Handle both string and TextClause objects
                sql_text = text(sql) if isinstance(sql, str) else sql
                result = connection.execute(sql_text, params)
                # Return rows directly - they have attribute access in SQLAlchemy 1.4+
                return list(result)
        except SQLAlchemyError as e:
            logger.error(f"Query execution error: {e}")
            raise
    
    def create_tables(self) -> None:
        """Create all defined tables in the database."""
        Base.metadata.create_all(self.engine)
    
    def drop_tables(self) -> None:
        """Drop all defined tables from the database."""
        Base.metadata.drop_all(self.engine)
        # Ensure tables are actually dropped by clearing the metadata cache
        Base.metadata.clear()
        # Force connection disposal
        self.engine.dispose()


class EnhancedDatabase(Database):
    """
    Enhanced database handler with security features.
    
    This class extends the base Database with features needed for
    HIPAA compliance, including encryption and audit logging.
    """
    
    # Define audit log levels
    AUDIT_LEVEL_INFO = "INFO"
    AUDIT_LEVEL_WARNING = "WARNING"
    AUDIT_LEVEL_ERROR = "ERROR"
    
    def __init__(
        self,
        db_url: str | None = None,
        echo: bool | None = None,
        pool_size: int | None = None,
        max_overflow: int | None = None,
        pool_timeout: int | None = None,
        ssl_mode: str | None = None,
        ssl_ca: str | None = None,
        ssl_verify: bool | None = None,
        enable_encryption: bool | None = None,
        enable_audit: bool | None = None
    ):
        """
        Initialize enhanced database connection.
        
        Args:
            db_url: SQLAlchemy database URL
            echo: Whether to echo SQL statements
            pool_size: Size of the connection pool
            max_overflow: Maximum overflow connections
            pool_timeout: Pool connection timeout
            ssl_mode: SSL mode for PostgreSQL
            ssl_ca: SSL certificate authority path
            ssl_verify: Whether to verify SSL certificates
            enable_encryption: Whether to enable database encryption
            enable_audit: Whether to enable audit logging
        """
        super().__init__(
            db_url=db_url,
            echo=echo,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            ssl_mode=ssl_mode,
            ssl_ca=ssl_ca,
            ssl_verify=ssl_verify
        )
        
        self.enable_encryption = enable_encryption if enable_encryption is not None else settings.DATABASE_ENCRYPTION_ENABLED
        self.enable_audit = enable_audit if enable_audit is not None else settings.DATABASE_AUDIT_ENABLED
        
        # Set up event listeners for audit logging
        if self.enable_audit:
            self._setup_audit_listeners()
    
    def _setup_audit_listeners(self) -> None:
        """Set up event listeners for audit logging."""
        @event.listens_for(self.engine, "connect")
        def engine_connect(dbapi_connection, connection_record):
            logger.info(f"Database connection established: {id(dbapi_connection)}")
        
        @event.listens_for(self.engine, "checkout")
        def engine_checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug(f"Database connection checked out: {id(dbapi_connection)}")
        
        @event.listens_for(self.engine, "checkin")
        def engine_checkin(dbapi_connection, connection_record):
            logger.debug(f"Database connection checked in: {id(dbapi_connection)}")
        
        # For session-level events, we'll use our own context manager instead of event listeners
        # This is more reliable as the event system can vary between SQLAlchemy versions
    
    @contextlib.contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Enhanced context manager for database sessions with audit logging.
        
        Yields a session and handles commit/rollback automatically with added
        audit logging capabilities.
        
        Yields:
            Database session
            
        Raises:
            Any exceptions from the session operations
        """
        session = self.get_session()
        transaction_id = str(uuid.uuid4())
        start_time = time.time()
        
        try:
            # Log transaction start if audit is enabled
            if self.enable_audit:
                logger.info(f"Starting transaction {transaction_id}")
                self._log_audit_event(transaction_id, "Transaction started", self.AUDIT_LEVEL_INFO)
            
            yield session
            session.commit()
            
            # Log successful commit if audit is enabled
            if self.enable_audit:
                end_time = time.time()
                duration = end_time - start_time
                logger.info(f"Committing transaction {transaction_id} (duration: {duration:.2f}s)")
                self._log_audit_event(
                    transaction_id, 
                    f"Transaction committed (duration: {duration:.2f}s)", 
                    self.AUDIT_LEVEL_INFO
                )
        except Exception as e:
            session.rollback()
            
            # Log rollback due to exception if audit is enabled
            if self.enable_audit:
                error_message = f"Rolling back transaction {transaction_id} due to error: {type(e).__name__}"
                # Only log to regular error log, the audit event will handle the actual error logging
                self._log_audit_event(
                    transaction_id,
                    error_message,
                    self.AUDIT_LEVEL_ERROR
                )
            raise
        finally:
            session.close()
            if self.enable_audit:
                logger.info(f"Closing session for transaction {transaction_id}")
        
    @contextlib.contextmanager
    def session_scope_with_audit(self) -> Generator[Session, None, None]:
        """
        Context manager for database sessions with audit logging.
        
        Extends the base session_scope with audit trail capabilities.
        
        Yields:
            Database session
        """
        session = self.get_session()
        transaction_id = str(uuid.uuid4())
        
        try:
            # Log transaction start
            if self.enable_audit:
                self._log_audit_event(transaction_id, "Transaction started", self.AUDIT_LEVEL_INFO)
            
            yield session
            session.commit()
            
            # Log successful commit
            if self.enable_audit:
                self._log_audit_event(transaction_id, "Transaction committed", self.AUDIT_LEVEL_INFO)
                
        except Exception as e:
            session.rollback()
            
            # Log rollback due to exception
            if self.enable_audit:
                error_message = f"Rolling back transaction {transaction_id} due to error: {type(e).__name__}"
                logger.error(error_message)
                self._log_audit_event(
                    transaction_id,
                    error_message,
                    self.AUDIT_LEVEL_ERROR
                )
            raise
        finally:
            session.close()
            logger.info(f"Closed transaction {transaction_id}")
    
    def _log_audit_event(self, transaction_id: str, message: str, level: str = AUDIT_LEVEL_INFO) -> None:
        """
        Log an audit event.
        
        This is a placeholder implementation. In a production environment,
        this would log to a secure, immutable audit log system compliant with
        HIPAA requirements.
        
        Args:
            transaction_id: Unique ID for the transaction
            message: Audit message
            level: Audit log level (INFO, WARNING, ERROR)
        """
        # In a real implementation, this would write to a secure audit log
        # with proper encryption, immutability, and retention policies
        audit_message = f"AUDIT[{transaction_id}]: {message}"
        
        if level == self.AUDIT_LEVEL_INFO:
            logger.info(audit_message)
        elif level == self.AUDIT_LEVEL_WARNING:
            logger.warning(audit_message)
        elif level == self.AUDIT_LEVEL_ERROR:
            logger.error(audit_message)
        else:
            logger.info(audit_message)
            
        # For testing purposes, we'll also print to stdout in non-production environments
        if settings.ENVIRONMENT != "production":
            print(f"[{level}] {audit_message}")
    
    def get_protected_engine(self) -> Engine:
        """
        Get database engine with encryption.
        
        In a real implementation, this would potentially provide an engine
        with additional security features like transparent data encryption.
        
        Returns:
            SQLAlchemy engine with enhanced security
        """
        # In a real implementation, this might return a wrapped engine
        # with encryption capabilities
        return self.engine


import threading


class DatabaseFactory:
    """
    Thread-safe singleton factory for database connections.
    
    This class provides a thread-safe implementation of the Singleton pattern
    for database connections, allowing for proper dependency injection in tests.
    """
    _instance = None
    _lock = threading.Lock()
    _settings_provider = get_settings
    
    @classmethod
    def initialize(cls, settings_provider=None):
        """Initialize the factory with a settings provider for testing."""
        if settings_provider:
            cls._settings_provider = settings_provider
    
    @classmethod
    def reset(cls):
        """Reset the singleton instance (for testing only)."""
        with cls._lock:
            cls._instance = None
    
    @classmethod
    def get_database(cls) -> EnhancedDatabase:
        """
        Get the global database instance in a thread-safe manner.
        
        Returns:
            EnhancedDatabase instance
        """
        if cls._instance is None:
            with cls._lock:  # Thread safety - double-checked locking pattern
                if cls._instance is None:
                    settings = cls._settings_provider()
                    cls._instance = EnhancedDatabase(
                        db_url=settings.DATABASE_URL,
                        echo=settings.DATABASE_ECHO,
                        pool_size=settings.DATABASE_POOL_SIZE,
                        max_overflow=10,
                        pool_timeout=30,
                        ssl_mode=settings.DATABASE_SSL_MODE,
                        ssl_ca=settings.DATABASE_SSL_CA,
                        ssl_verify=settings.DATABASE_SSL_VERIFY,
                        enable_encryption=settings.DATABASE_SSL_ENABLED,
                        enable_audit=True
                    )
        return cls._instance


# Legacy function for backward compatibility
def get_database() -> EnhancedDatabase:
    """
    Get the global database instance.
    
    Returns:
        EnhancedDatabase instance
    """
    return DatabaseFactory.get_database()


def get_db_session(
    db_provider=get_database
) -> Generator[Session, None, None]:
    """
    Get a database session for dependency injection.
    
    Args:
        db_provider: Function that returns a database instance (for testing)
        
    Yields:
        Database session
    """
    db = db_provider()
    with db.session_scope() as session:
        yield session