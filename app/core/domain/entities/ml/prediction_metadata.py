"""
Domain entity representing metadata associated with a machine learning prediction.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, Field


class PredictionMetadata(BaseModel):
    """Metadata about a specific prediction result."""

    prediction_id: UUID = Field(..., description="Unique identifier for the prediction event.")
    model_id: str = Field(..., description="Identifier of the model used for the prediction.")
    model_version: str = Field(..., description="Version of the model used.")
    timestamp: datetime = Field(..., description="Timestamp when the prediction was generated.")
    input_features_summary: Optional[Dict[str, Any]] = Field(
        None, description="Summary or hash of the input features used."
    )
    # Add other relevant metadata fields as needed

    class Config:
        orm_mode = True  # Allow compatibility with ORM models if needed later
