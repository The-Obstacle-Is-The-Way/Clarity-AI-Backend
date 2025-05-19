"""
Actigraphy request validation dependencies.

Provides reusable dependencies to validate and parse actigraphy API payloads
using Pydantic models, decoupling schema validation from endpoint logic.
"""
from fastapi import HTTPException, Request, status
from pydantic import ValidationError as PydanticValidationError

from app.presentation.api.schemas.actigraphy import (
    AnalyzeActigraphyRequest,
    GetActigraphyEmbeddingsRequest,
)


async def validate_analyze_actigraphy_request(
    request: Request,
) -> AnalyzeActigraphyRequest:
    """
    Dependency to parse and validate analyze actigraphy request payload.
    Raises HTTPException 422 if validation fails.
    """
    try:
        payload = await request.json()
        return AnalyzeActigraphyRequest.model_validate(payload)
    except PydanticValidationError as exc:
        # Return validation errors in HTTPException detail
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors())


async def validate_get_actigraphy_embeddings_request(
    request: Request,
) -> GetActigraphyEmbeddingsRequest:
    """
    Dependency to parse and validate get actigraphy embeddings request payload.
    Raises HTTPException 422 if validation fails.
    """
    try:
        payload = await request.json()
        return GetActigraphyEmbeddingsRequest.model_validate(payload)
    except PydanticValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors())
