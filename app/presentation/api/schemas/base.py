"""
Base Pydantic model configuration for API schemas.
"""

from pydantic import BaseModel, ConfigDict


class BaseModelConfig(BaseModel):
    """Base Pydantic model configuration."""

    model_config = ConfigDict(
        populate_by_name=True,
        from_attributes=True,
        arbitrary_types_allowed=True,
        protected_namespaces=()
    )
