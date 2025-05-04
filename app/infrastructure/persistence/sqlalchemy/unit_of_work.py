"""
HIPAA-compliant SQLAlchemy Unit of Work implementation.

This module provides a robust implementation of the Unit of Work pattern using SQLAlchemy,
ensuring transactional integrity for PHI data operations according to HIPAA requirements.
"""

import abc
import contextlib
import logging
from typing import Any, ContextManager, TypeVar

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.domain.exceptions import RepositoryError
from app.domain.interfaces.unit_of_work import UnitOfWork

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

Repo = TypeVar('Repo', bound=abc.ABC)

class SQLAlchemyUnitOfWork(UnitOfWork):
    """
    SQLAlchemy Unit of Work implementation.
    Manages session lifecycle and transaction boundaries for HIPAA-compliant data access.
    """
    # Use sessionmaker type hint for clarity
    session_factory: sessionmaker

    def __init__(self, session_factory: sessionmaker):
        """
        Initialize the Unit of Work.

        Args:
            session_factory: A SQLAlchemy sessionmaker instance.
        """
        # Enforce passing a sessionmaker
        if not isinstance(session_factory, sessionmaker):
             # Check if callable as a fallback, but sessionmaker is preferred
             if not callable(session_factory):
                  raise TypeError("session_factory must be a SQLAlchemy sessionmaker instance or a callable factory.")
        self.session_factory = session_factory
        self._session: Session | None = None
        self._transaction_level = 0 # Track nesting
        # Track read-only status per level. Using a list as a stack.
        self._is_read_only_stack: list[bool] = [] 
        self._committed = False # Track if commit was called in the current context
        self._repositories: dict[str, abc.ABC] = {}
        self._metadata: dict[str, Any] = {}

    @property
    def session(self) -> Session:
        """
        Get the current session.

        Returns:
            The current SQLAlchemy session

        Raises:
            RepositoryError: If no session is active (i.e., outside UoW context)
        """
        # Session is created on __enter__ for the top-level context
        if self._session is None:
            raise RepositoryError("Session is not active. Use 'with unit_of_work:' context.")
        return self._session

    def __enter__(self) -> "SQLAlchemyUnitOfWork":
        """Enter the unit of work context, managing transactions and savepoints."""
        self._committed = False # Reset committed flag for this context level
        if self._transaction_level == 0:
            # Top-level context: create session and begin transaction
            self._session = self.session_factory()
            self._session.begin()
            self._is_read_only_stack.append(False) # Default non-read-only for top level
            logger.debug("Started UoW context: Session created, transaction begun.")
        else:
            # Nested context: begin nested transaction (savepoint)
            if self._session is None: # Safety check
                 raise RepositoryError("Cannot start nested transaction without active session.")
            self._session.begin_nested() # Creates a savepoint
            # Inherit read-only status from the current top of the stack
            current_read_only = self._is_read_only_stack[-1] if self._is_read_only_stack else False
            self._is_read_only_stack.append(current_read_only)
            logger.debug("Started nested transaction (savepoint).")

        self._transaction_level += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any | None,
    ) -> None:
        """Exit the unit of work context, handling commit/rollback and session closing."""
        if self._session is None: # Should not happen if __enter__ succeeded
             logger.warning("Exiting UoW context, but no active session found.")
             # Decrement level anyway to prevent lock-up if __enter__ partially failed
             if self._transaction_level > 0:
                 self._transaction_level -= 1
             if self._is_read_only_stack:
                 self._is_read_only_stack.pop()
             return

        # Get read-only status for the current level *before* popping
        is_read_only = self._is_read_only_stack[-1]
        is_top_level = self._transaction_level == 1

        try:
            if exc_type:
                # --- Exception Occurred --- 
                log_level = "main" if is_top_level else "nested"
                logger.warning(f"Rolling back {log_level} transaction due to exception: {exc_val}")
                self._session.rollback() # Rolls back to savepoint or start
            else:
                # --- No Exception --- 
                if is_read_only:
                    log_level = "read-only main" if is_top_level else "read-only nested"
                    logger.debug(f"Rolling back {log_level} transaction.")
                    self._session.rollback() # Always rollback read-only
                elif self._committed:
                    log_level = "main" if is_top_level else "nested (releasing savepoint)"
                    logger.debug(f"Committing {log_level} transaction.")
                    # Add audit logic here if needed
                    if is_top_level and self._metadata:
                        # Log audit trail for HIPAA compliance
                        logger.info(f"AUDIT: Transaction committed with metadata: {self._metadata}")
                    self._session.commit() # Commits main transaction or releases savepoint
                else:
                    # --- No exception, not read-only, but no explicit commit --- 
                    log_level = "main" if is_top_level else "nested"
                    # Only warn/rollback if top-level requires explicit commit
                    # Nested transactions without commit implicitly rollback savepoint changes
                    if is_top_level:
                         logger.warning(f"Rolling back {log_level} transaction: No explicit commit was called.")
                         self._session.rollback()
                    else:
                         logger.debug(f"Rolling back {log_level} transaction (savepoint): No explicit commit.")
                         self._session.rollback() # Rolls back savepoint changes

        except SQLAlchemyError as e:
            logger.error(f"SQLAlchemyError during transaction cleanup: {e}. Force rolling back.")
            # Attempt to rollback the entire transaction if possible
            if is_top_level and self._session:
                try:
                    self._session.rollback()
                except Exception as final_rb_err:
                    logger.error(f"Error during final rollback attempt: {final_rb_err}")
            raise RepositoryError(f"Error during transaction cleanup: {e!s}") from e
        except Exception as e:
            logger.error(f"Unexpected error during transaction cleanup: {e}. Force rolling back.")
            if is_top_level and self._session:
                 try:
                     self._session.rollback()
                 except Exception as final_rb_err:
                     logger.error(f"Error during final rollback attempt: {final_rb_err}")
            raise # Re-raise unexpected errors
        finally:
            # Cleanup stack and level regardless of errors during commit/rollback
            if self._is_read_only_stack:
                self._is_read_only_stack.pop()
            if self._transaction_level > 0:
                self._transaction_level -= 1
            
            # Close session *only* when exiting the top-level context
            if self._transaction_level == 0:
                if self._session:
                    self._session.close()
                    self._session = None
                    logger.debug("Exited UoW context: Session closed.")
            elif self._transaction_level > 0:
                logger.debug(f"Exited nested context. Level now: {self._transaction_level}")
            else: # Should not happen
                 logger.warning("Transaction level became negative during cleanup.")


    def commit(self) -> None:
        """
        Mark the current transaction level for commit upon exiting its context.
        
        Raises:
            RepositoryError: If the transaction is read-only or no session is active
        """
        if self._transaction_level == 0:
            raise RepositoryError("No active transaction to commit.")
        if not self._session: # Should be redundant if level > 0
            raise RepositoryError("No active session for commit.")
        if self._is_read_only_stack[-1]:
            raise RepositoryError("Cannot commit changes in a read-only transaction.")

        self._committed = True # Mark for commit on __exit__
        logger.debug(f"Marked transaction level {self._transaction_level} for commit.")
        # Actual commit/savepoint release happens in __exit__

    def rollback(self) -> None:
        """
        Explicitly roll back the current transaction level (main or savepoint).
        The context manager (`__exit__`) will still run for cleanup.
        
        Raises:
            RepositoryError: If no session is active
        """
        if self._transaction_level == 0:
            raise RepositoryError("No active transaction to roll back.")
        if not self._session:
            raise RepositoryError("No active session to roll back.")
            
        logger.debug(f"Explicit rollback called for transaction level {self._transaction_level}.")
        self._session.rollback() # Rollback immediately
        self._committed = False # Ensure commit doesn't happen in __exit__ for this level
        # If nested, this rolls back the savepoint. If top-level, rolls back the entire transaction.
    
    @contextlib.contextmanager
    def nested(self) -> ContextManager["SQLAlchemyUnitOfWork"]:
        """Enter a nested transaction context (uses savepoints)."""
        # The main __enter__ and __exit__ now handle nesting via _transaction_level
        with self as uow:
             yield uow
    
    @contextlib.contextmanager
    def read_only(self) -> ContextManager["SQLAlchemyUnitOfWork"]:
        """Enter a read-only transaction context."""
        # Check if already in read-only context
        if self._transaction_level > 0 and self._is_read_only_stack and self._is_read_only_stack[-1]:
             logger.debug("Already in read-only mode, entering nested context.")
             # Already read-only, just enter nested context normally
             with self as uow:
                 yield uow
             return

        # --- Entering a new read-only context --- 
        # We need to manage the read-only flag *before* calling __enter__ 
        # for the *next* level, but associate it with the current operation.
        
        # Enter normally, then modify state.
        with self as uow: # Calls __enter__, increments level, pushes False (or inherited) to stack
            # Now, overwrite the pushed status for the *current* level to True
            if uow._is_read_only_stack: # Should exist after __enter__
                uow._is_read_only_stack[-1] = True
                logger.debug(f"Entered read-only transaction context (level {uow._transaction_level}).")
                try:
                    yield uow
                finally:
                    # __exit__ will handle the rollback based on the flag we set
                    # No need to manually pop here, __exit__ does that.
                    pass 
            else: # Should not happen
                 logger.error("Read-only stack empty after entering context.")
                 raise RepositoryError("Failed to enter read-only context properly.")

    def set_metadata(self, metadata: dict[str, Any]) -> None:
        """Sets metadata for the current transaction for audit logging."""
        # Store metadata for audit logging 
        self._metadata.update(metadata)
        logger.debug(f"UoW Metadata set: {metadata}")

    def _get_repository(self, repo_type: type[Repo]) -> Repo:
        """Retrieves or creates a repository instance of the given type."""
        repo_name = repo_type.__name__ # Get the class name (e.g., 'PatientRepository')
        
        # Check cache first
        if repo_name not in self._repositories: 
            # Instantiate the repository
            try:
                logger.debug(f"Creating repository instance for {repo_name}")
                # Pass the *current* session from the UoW
                instance = repo_type(self.session) 
                self._repositories[repo_name] = instance
            except Exception as e:
                logger.error(f"Failed to instantiate repository {repo_name}: {e}")
                # Propagate error to signal failure in UoW setup/usage
                raise RepositoryError(f"Could not instantiate repository {repo_name}.") from e
        
        # Return the cached or newly created instance
        return self._repositories[repo_name] # type: ignore[return-value]

    # Allow accessing repositories using dictionary-like syntax (uow[PatientRepository])
    def __getitem__(self, repo_type: type[Repo]) -> Repo:
        """Allows accessing repositories using dictionary-like syntax."""
        return self._get_repository(repo_type)