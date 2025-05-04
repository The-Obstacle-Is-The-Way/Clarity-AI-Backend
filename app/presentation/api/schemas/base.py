"""
Base Pydantic model configuration for API schemas.
"""

from pydantic import BaseModel


class BaseModelConfig(BaseModel):
    """Base Pydantic model configuration."""

    class Config:
        populate_by_name = True
        from_attributes = True
        arbitrary_types_allowed = True
