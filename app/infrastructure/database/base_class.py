"""
SQLAlchemy Base class definition for the Novamind Digital Twin Platform.

This module defines the declarative base class used for all ORM models.
"""
from typing import Any

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import registry

# Create SQLAlchemy models declarative base
Base = declarative_base()

# Initialize the mapper registry
mapper_registry = registry()

# Create a type alias for SQLAlchemy models
SQLAlchemyModel = mapper_registry.generate_base()


class BaseModel(SQLAlchemyModel):
    """
    Base model class for all SQLAlchemy models.
    
    This class provides common functionality for all models,
    such as to_dict() and from_dict() methods.
    
    All model classes should inherit from this class.
    """
    __abstract__ = True
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert model to dictionary.
        
        Returns:
            Dictionary representation of the model
        """
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaseModel":
        """
        Create model instance from dictionary data.
        
        Args:
            data: Dictionary containing model data
            
        Returns:
            Instance of the model class
        """
        return cls(**{
            k: v for k, v in data.items() 
            if k in [c.name for c in cls.__table__.columns]
        })