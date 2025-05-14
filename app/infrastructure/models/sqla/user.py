import uuid
from sqlalchemy import Column, String, Enum as SQLAlchemyEnum, DateTime
from sqlalchemy.dialects.postgresql import UUID as PG_UUID # For PostgreSQL
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import func

from app.core.domain.entities.user import UserStatus # For the status Enum

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    status = Column(SQLAlchemyEnum(UserStatus), nullable=False, default=UserStatus.PENDING)
    
    # Optional: Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}', status='{self.status.value}')>"
