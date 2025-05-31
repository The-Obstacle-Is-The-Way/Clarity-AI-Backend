"""User repository interface re-export for compatibility.

This module bridges legacy imports expecting
``app.domain.interfaces.user_repository.UserRepositoryInterface``
by re-exporting the abstract ``UserRepository`` defined in
``app.domain.repositories.user_repository`` under the alias
``UserRepositoryInterface``.

Keeping a single source of truth for the repository interface avoids
code duplication while satisfying import paths required by the public
API and test-suite.
"""

from app.domain.repositories.user_repository import UserRepository as UserRepositoryInterface

__all__: list[str] = ["UserRepositoryInterface"]
