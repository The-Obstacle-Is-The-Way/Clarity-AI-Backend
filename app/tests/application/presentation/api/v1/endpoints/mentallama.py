"""MentaLLaMA API Endpoints."""

import json
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from app.api.routes.ml import verify_api_key
from app.core.services.ml.interface import MentaLLaMAInterface
from app.presentation.api.v1.dependencies.ml import get_mentallama_service

router = APIRouter()

def _check_health(svc: MentaLLaMAInterface):
    if (hasattr(svc, "initialized") and not svc.initialized) or \
       (hasattr(svc, "is_healthy") and not svc.is_healthy()):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MentaLLaMA service unavailable")

async def _parse_payload(request: Request) -> dict:
    try:
        body = await request.body()
        return json.loads(body or b"{}")
    except Exception:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid JSON payload")

@router.post(
    "/process",
    dependencies=[Depends(verify_api_key)],
    status_code=status.HTTP_200_OK
)
async def process_endpoint(
    prompt: str = Body(..., description="The prompt to process"),
    model: str | None = Body(None, description="Optional model name"),
    max_tokens: int | None = Body(None, description="Maximum number of tokens"),
    temperature: float | None = Body(None, description="Sampling temperature"),
    service: MentaLLaMAInterface = Depends(get_mentallama_service)
) -> dict[str, Any]:
    """Process text using MentaLLaMA (stub)."""
    svc = service() if callable(service) else service
    _check_health(svc)
    # Simulate service unavailability when model not specified
    if model is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MentaLLaMA service unavailable"
        )
    # Validate prompt
    if not isinstance(prompt, str) or not prompt:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Prompt cannot be empty"
        )
    # Validate model if provided
    valid_models = ["mentallama-7b", "mentallama-33b", "mentallama-33b-lora"]
    if model and model not in valid_models:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model {model} not found"
        )
    # Return mock response (ignoring max_tokens and temperature)
    return {
        "model": model or "mentallama-33b",
        "text": "This is a mock response from MentaLLaMA.",
        "provider": "aws-bedrock"
    }

@router.post(
    "/analyze",
    dependencies=[Depends(verify_api_key)],
    status_code=status.HTTP_200_OK
)
async def analyze_endpoint(
    request: Request,
    service: MentaLLaMAInterface = Depends(get_mentallama_service)
) -> dict[str, Any]:
    """General text analysis endpoint (stub)."""
    svc = service() if callable(service) else service
    _check_health(svc)
    payload = await _parse_payload(request)
    text = payload.get("text")
    analysis_type = payload.get("analysis_type")
    if not isinstance(text, str) or not text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Text cannot be empty")
    if not isinstance(analysis_type, str) or not analysis_type:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Analysis type cannot be empty")
    structured_data: dict[str, Any] = {
        "sentiment": {},
        "entities": [],
        "conditions": [],
        "therapeutic_approach": None,
        "techniques": [],
        "risk_level": None,
        "risk_factors": [],
        "protective_factors": [],
        "recommendations": [],
        "immediate_action_required": False,
        "dimensions": {}
    }
    return {"structured_data": structured_data}

@router.post(
    "/detect_conditions",
    dependencies=[Depends(verify_api_key)],
    status_code=status.HTTP_200_OK
)
async def detect_conditions_endpoint(
    request: Request,
    service: MentaLLaMAInterface = Depends(get_mentallama_service)
) -> dict[str, Any]:
    """Detect mental health conditions (stub)."""
    svc = service() if callable(service) else service
    _check_health(svc)
    payload = await _parse_payload(request)
    text = payload.get("text")
    if not isinstance(text, str) or not text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Text cannot be empty")
    conditions: list[dict[str, Any]] = [{"condition": "", "confidence": 0.0}]
    return {"structured_data": {"conditions": conditions}}

@router.post(
    "/therapeutic_response",
    dependencies=[Depends(verify_api_key)],
    status_code=status.HTTP_200_OK
)
async def therapeutic_response_endpoint(
    request: Request,
    service: MentaLLaMAInterface = Depends(get_mentallama_service)
) -> dict[str, Any]:
    """Generate therapeutic response (stub)."""
    svc = service() if callable(service) else service
    _check_health(svc)
    payload = await _parse_payload(request)
    text = payload.get("text")
    if not isinstance(text, str) or not text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Text cannot be empty")
    structured_data: dict[str, Any] = {"therapeutic_approach": "", "techniques": []}
    return {"text": "", "structured_data": structured_data}

@router.post(
    "/assess_suicide_risk",
    dependencies=[Depends(verify_api_key)],
    status_code=status.HTTP_200_OK
)
async def assess_suicide_risk_endpoint(
    request: Request,
    service: MentaLLaMAInterface = Depends(get_mentallama_service)
) -> dict[str, Any]:
    """Assess suicide risk (stub)."""
    svc = service() if callable(service) else service
    _check_health(svc)
    payload = await _parse_payload(request)
    text = payload.get("text")
    if not isinstance(text, str) or not text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Text cannot be empty")
    structured: dict[str, Any] = {
        "risk_level": None,
        "risk_factors": [],
        "protective_factors": [],
        "recommendations": [],
        "immediate_action_required": False
    }
    return {"structured_data": structured}

@router.post(
    "/analyze_wellness_dimensions",
    dependencies=[Depends(verify_api_key)],
    status_code=status.HTTP_200_OK
)
async def analyze_wellness_dimensions_endpoint(
    request: Request,
    service: MentaLLaMAInterface = Depends(get_mentallama_service)
) -> dict[str, Any]:
    """Analyze wellness dimensions (stub)."""
    svc = service() if callable(service) else service
    _check_health(svc)
    payload = await _parse_payload(request)
    text = payload.get("text")
    dimensions = payload.get("dimensions")
    include_recommendations = payload.get("include_recommendations", False)
    if not isinstance(text, str) or not text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Text cannot be empty")
    if not isinstance(dimensions, list) or not dimensions:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="At least one dimension must be specified")
    dims: dict[str, Any] = {dim: {"score": 0.0, "recommendations": []} for dim in dimensions}
    return {"structured_data": {"dimensions": dims}}

@router.get(
    "/health",
    status_code=status.HTTP_200_OK
)
async def health_endpoint() -> dict[str, Any]:
    """Health check for MentaLLaMA service (stub)."""
    return {"status": "healthy", "version": "mock-0.1"}
