from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.entities.user import User
from app.core.interfaces.repositories.user_repository_interface import IUserRepository


class SQLAlchemyUserRepository(IUserRepository):
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session

    async def get_user_by_id(self, user_id: UUID) -> User | None:  # Matching middleware usage
        """Retrieve a user by their unique ID."""
        # Placeholder implementation - replace with actual SQLAlchemy query
        # For example:
        # result = await self.db_session.execute(
        #     select(UserModel).where(UserModel.id == user_id)
        # )
        # model_instance = result.scalar_one_or_none()
        # if model_instance:
        #     return User(
        #         id=model_instance.id,
        #         username=model_instance.username,
        #         email=model_instance.email,
        #         hashed_password=model_instance.hashed_password, # Ensure User entity has these
        #         status=model_instance.status,
        #         # ... other fields ...
        #     )
        # return None
        print(
            f"SQLAlchemyUserRepository.get_user_by_id called with {user_id}. "
            f"Placeholder implementation."
        )
        return None  # Placeholder

    async def get_by_id(self, user_id: str | UUID) -> User | None:
        """Retrieve a user by their unique ID (Interface compliant)."""
        if isinstance(user_id, str):
            try:
                user_id = UUID(user_id)
            except ValueError:
                # Handle invalid UUID string format if necessary, e.g., log and return None
                return None
        return await self.get_user_by_id(user_id)  # Delegate for now

    async def get_by_email(self, email: str) -> User | None:
        raise NotImplementedError

    async def get_by_username(self, username: str) -> User | None:
        raise NotImplementedError

    async def create(self, user: User) -> User:
        raise NotImplementedError

    async def update(self, user: User) -> User:
        raise NotImplementedError

    async def delete(self, user_id: str | UUID) -> bool:
        raise NotImplementedError

    async def list_all(self, skip: int = 0, limit: int = 100) -> list[User]:
        raise NotImplementedError

    async def count(self) -> int:
        raise NotImplementedError
