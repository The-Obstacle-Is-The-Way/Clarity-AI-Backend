"""
Common API schemas used across different endpoints.
"""

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

# Define a generic type variable
T = TypeVar("T")


class PaginationInfo(BaseModel):
    """Schema for pagination metadata."""

    total_items: int = Field(..., description="Total number of items available.")
    total_pages: int = Field(..., description="Total number of pages.")
    current_page: int = Field(..., description="The current page number (1-based).")
    page_size: int = Field(..., description="Number of items per page.")
    next_page: int | None = Field(None, description="Number of the next page, if available.")
    prev_page: int | None = Field(None, description="Number of the previous page, if available.")


class PaginatedResponseSchema(BaseModel, Generic[T]):
    """Generic schema for paginated API responses."""

    items: list[T] = Field(..., description="List of items for the current page.")
    pagination: PaginationInfo = Field(..., description="Pagination metadata.")


class MessageResponseSchema(BaseModel):
    """Simple schema for returning messages."""

    message: str


class DetailResponseSchema(BaseModel):
    """Schema for returning detailed error messages."""

    detail: str
