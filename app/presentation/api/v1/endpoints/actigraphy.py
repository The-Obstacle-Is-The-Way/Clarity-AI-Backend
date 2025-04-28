"""
FastAPI routes for actigraphy data analysis.

This module defines the API endpoints for actigraphy data analysis, embedding
generation, and integration with digital twins.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime

# Adjust imports based on new location under presentation/
from app.presentation.api.schemas.actigraphy import (
    AnalysesList,
    AnalysisResult,
    AnalyzeActigraphyRequest,
    EmbeddingResult,
    GetActigraphyEmbeddingsRequest,
    IntegrateWithDigitalTwinRequest,
    IntegrationResult,
    AnalysisType,
)
# Assuming standard dependency injection setup within presentation layer
from app.presentation.api.dependencies.auth import get_current_user  # Corrected import
from app.presentation.api.v1.dependencies.actigraphy import (
    validate_analyze_actigraphy_request,
    validate_get_actigraphy_embeddings_request,
)
from typing import Dict, Any # Import Dict and Any for type hinting

# Assuming core/services paths remain stable or adjust if moved
from app.core.services.ml.pat import (
    AnalysisError,
    AuthorizationError,
    EmbeddingError,
    InitializationError,
    IntegrationError,
    PATInterface,
    PATServiceFactory,
    ResourceNotFoundError,
    ValidationError,
)

# Set up logging with no PHI
logger = logging.getLogger(__name__)

# Set up router
router = APIRouter() # Prefix is usually added when including the router

# ---------------------------------------------------------------------------
# Helper – convert AnalysisType enums or raw strings to plain string values
# ---------------------------------------------------------------------------


def _normalize_analysis_type(value: Any) -> str:  # noqa: ANN401
    """Return the *string* representation for an ``AnalysisType`` value.

    The PAT service (or tests) might return a mixture of raw strings and
    ``AnalysisType`` enumeration members.  This helper normalises the output
    so the API response is always a list of *plain* strings.
    """

    if hasattr(value, "value"):
        return str(value.value)
    return str(value)

# Security might be handled by middleware or dependencies now, review if needed
# security = HTTPBearer()


async def get_pat_service() -> PATInterface:
    """Get an initialized PAT service instance.
    
    This dependency provides a configured PAT service using the service factory.
    The service type is determined by configuration.
    
    Returns:
        An initialized PAT service
        
    Raises:
        HTTPException: If service initialization fails
    """
    try:
        # Create a PAT service using the factory
        # In production, the service type would be determined by configuration
        factory = PATServiceFactory()
        # Configuration for service type should come from settings
        # settings = get_settings() # Inject settings if needed
        # service_type = settings.PAT_SERVICE_TYPE
        service_type = "mock" # Keep mock for now, make configurable later
        service = factory.create_service(service_type)
        
        # Initialize the service
        # In production, configuration would be loaded from env vars or settings
        # config = settings.PAT_SERVICE_CONFIG if hasattr(settings, 'PAT_SERVICE_CONFIG') else {}
        config = {"mock_delay_ms": 100} # Keep mock config for now
        service.initialize(config)
        
        return service
    
    except InitializationError as e:
        logger.error(f"Failed to initialize PAT service: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PAT service is currently unavailable"
        )


@router.post(
    "/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyze actigraphy data",
    description="Analyze raw actigraphy data to derive physical activity insights."
)
async def analyze_actigraphy(
    request: Request,
    payload: AnalyzeActigraphyRequest = Depends(validate_analyze_actigraphy_request),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pat_service: PATInterface = Depends(get_pat_service)
    ) -> AnalysisResult:
    """Analyze actigraphy data endpoint.
    
    This endpoint processes raw accelerometer data to extract physical activity
    patterns and insights, such as activity levels, sleep patterns, gait
    characteristics, and tremor analysis.
    
    Args:
        request: The analysis request containing the data to analyze
        current_user: The authenticated user dictionary/object.
        pat_service: PAT service for analysis
    
    Returns:
        Analysis results
    
    Raises:
        HTTPException: If analysis fails or validation errors occur
    """
    # Require Authorization header even if get_current_user is overridden
    if not request.headers.get("authorization"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    try:
        # Log analysis request (without PHI)
        logger.info(
            f"Analyzing actigraphy data: readings_count={len(payload.readings)}, "
            f"analysis_types={[t.value for t in payload.analysis_types]}"
        )
        # Prepare inputs for service
        readings_list = [r.model_dump() for r in payload.readings]
        types_list = [t.value for t in payload.analysis_types]
        # Perform analysis via PAT service
        result = pat_service.analyze_actigraphy(
            patient_id=payload.patient_id,
            readings=readings_list,
            start_time=payload.start_time,
            end_time=payload.end_time,
            sampling_rate_hz=payload.sampling_rate_hz,
            device_info=payload.device_info.model_dump(),
            analysis_types=types_list
        )
        # Log success (without PHI)
        logger.info(
            f"Successfully analyzed actigraphy data: analysis_id={result['analysis_id']}"
        )
        # Build data summary
        # Parse ISO timestamps, normalizing Zulu indicator
        start_str = payload.start_time
        if start_str.endswith("Z"):
            start_str = start_str[:-1]
        start_dt = datetime.fromisoformat(start_str)  # type: ignore
        end_str = payload.end_time
        if end_str.endswith("Z"):
            end_str = end_str[:-1]
        end_dt = datetime.fromisoformat(end_str)      # type: ignore
        duration_seconds = (end_dt - start_dt).total_seconds()
        data_summary = {
            "start_time": payload.start_time,
            "end_time": payload.end_time,
            "duration_seconds": duration_seconds,
            "readings_count": len(payload.readings),
            "sampling_rate_hz": payload.sampling_rate_hz
        }
        # Build and return response payload
        payload_dict: Dict[str, Any] = {
            "analysis_id": result.get("analysis_id"),
            "patient_id": result.get("patient_id"),
            "timestamp": result.get("timestamp") or result.get("created_at"),
            "analysis_types": types_list,
            "device_info": payload.device_info.model_dump(),
            "data_summary": data_summary,
            "results": result.get("results", {})
        }
        # Include individual metrics at top-level for convenience
        if "sleep_metrics" in result:
            payload_dict["sleep_metrics"] = result["sleep_metrics"]
        elif AnalysisType.SLEEP_QUALITY.value in payload_dict["results"]:
            payload_dict["sleep_metrics"] = payload_dict["results"][AnalysisType.SLEEP_QUALITY.value]
        if "activity_levels" in result:
            payload_dict["activity_levels"] = result["activity_levels"]
        elif AnalysisType.ACTIVITY_LEVELS.value in payload_dict["results"]:
            payload_dict["activity_levels"] = payload_dict["results"][AnalysisType.ACTIVITY_LEVELS.value]
        return payload_dict
        # Include individual metrics at top-level for convenience
        if "sleep_metrics" in result:
            payload["sleep_metrics"] = result["sleep_metrics"]
        elif AnalysisType.SLEEP_QUALITY.value in payload["results"]:
            payload["sleep_metrics"] = payload["results"][AnalysisType.SLEEP_QUALITY.value]
        if "activity_levels" in result:
            payload["activity_levels"] = result["activity_levels"]
        elif AnalysisType.ACTIVITY_LEVELS.value in payload["results"]:
            payload["activity_levels"] = payload["results"][AnalysisType.ACTIVITY_LEVELS.value]
        return payload
    except ValidationError as e:
        logger.warning(f"Validation error in analyze_actigraphy: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except AnalysisError as e:
        logger.error(f"Analysis error in analyze_actigraphy: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error in analyze_actigraphy: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during analysis"
        )


@router.post(
    "/embeddings",
    response_model=EmbeddingResult,
    status_code=status.HTTP_201_CREATED,
    summary="Generate embeddings from actigraphy data",
    description="Generate embeddings from actigraphy data for machine learning models."
)
async def get_actigraphy_embeddings(
    payload: GetActigraphyEmbeddingsRequest = Depends(validate_get_actigraphy_embeddings_request),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pat_service: PATInterface = Depends(get_pat_service)
    ) -> EmbeddingResult:
    """Generate embeddings from actigraphy data endpoint.
    
    This endpoint processes raw accelerometer data to generate vector embeddings
    that can be used for similarity search, clustering, or as input to other
    machine learning models.
    
    Args:
        request: The embedding request containing the data
        current_user: The authenticated user dictionary/object.
        pat_service: PAT service for embedding generation
        
    Returns:
        Embedding results
        
    Raises:
        HTTPException: If embedding generation fails or validation errors occur
    """
    try:
        # Log embedding request (without PHI)
        logger.info(
            f"Generating actigraphy embeddings: readings_count={len(payload.readings)}"
        )
        # Prepare inputs for service
        readings_list = [r.model_dump() for r in payload.readings]
        # Generate embeddings via PAT service
        result = pat_service.get_actigraphy_embeddings(
            patient_id=payload.patient_id,
            readings=readings_list,
            start_time=payload.start_time,
            end_time=payload.end_time,
            sampling_rate_hz=payload.sampling_rate_hz
        )
        # Log success (without PHI)
        logger.info(
            f"Successfully generated actigraphy embeddings: embedding_id={result['embedding_id']}"
        )
        # Build data summary
        # Parse ISO timestamps, normalizing Zulu indicator
        start_str = payload.start_time
        if start_str.endswith("Z"):
            start_str = start_str[:-1]
        start_dt = datetime.fromisoformat(start_str)  # type: ignore
        end_str = payload.end_time
        if end_str.endswith("Z"):
            end_str = end_str[:-1]
        end_dt = datetime.fromisoformat(end_str)      # type: ignore
        duration_seconds = (end_dt - start_dt).total_seconds()
        data_summary = {
            "start_time": payload.start_time,
            "end_time": payload.end_time,
            "duration_seconds": duration_seconds,
            "readings_count": len(payload.readings),
            "sampling_rate_hz": payload.sampling_rate_hz
        }
        # Build embedding dict, supporting legacy list or nested dict
        embedding_data = result.get("embedding")
        if isinstance(embedding_data, list):
            # Legacy format: list of vector values
            vector = embedding_data
            dimension = result.get("embedding_dim", result.get("dimension", len(vector)))
            model_version = result.get("model_version", "")
            embedding_payload = {
                "vector": vector,
                "dimension": dimension,
                "model_version": model_version
            }
        else:
            # Nested dict format
            ed = embedding_data or {}
            embedding_payload = {
                "vector": ed.get("vector", []),
                "dimension": ed.get("dimension", 0),
                "model_version": ed.get("model_version", "")
            }
        # Build and return response payload
        payload = {
            "embedding_id": result.get("embedding_id"),
            "patient_id": result.get("patient_id"),
            "timestamp": result.get("timestamp") or result.get("created_at"),
            "data_summary": data_summary,
            "embedding": embedding_payload
        }
        # Alias for embedding (plural) to satisfy legacy tests: vector list
        payload["embeddings"] = embedding_payload.get("vector", [])
        # Alias for embedding size
        payload["embedding_size"] = embedding_payload.get("dimension", 0)
        return payload
    
    except ValidationError as e:
        logger.warning(f"Validation error in get_actigraphy_embeddings: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    except EmbeddingError as e:
        logger.error(f"Embedding error in get_actigraphy_embeddings: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Embedding generation failed: {str(e)}"
        )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error in get_actigraphy_embeddings: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during embedding generation"
        )


@router.get(
    "/analyses/{analysis_id}",
    status_code=status.HTTP_200_OK,
    summary="Get an analysis by ID",
    description="Retrieve a specific actigraphy analysis by its ID."
)
async def get_analysis_by_id(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pat_service: PATInterface = Depends(get_pat_service)
) -> Dict[str, Any]:
    """Get an analysis by ID endpoint.
    
    This endpoint retrieves a specific analysis by its unique identifier,
    including all analysis results and metadata.
    
    Args:
        analysis_id: The unique identifier of the analysis
        current_user: The authenticated user dictionary/object.
        pat_service: PAT service
        
    Returns:
        The requested analysis
        
    Raises:
        HTTPException: If the analysis is not found or access is denied
    """
    try:
        logger.info(f"Retrieving analysis: analysis_id={analysis_id}")
        
        # Get the analysis
        result = pat_service.get_analysis_by_id(analysis_id)
        
        user_id = current_user.get("id")
        user_roles = current_user.get("roles", [])
        
        # Authorization Check (allow clinicians)
        if not (
            user_id == result.get("patient_id")
            or "admin" in user_roles
            or "doctor" in user_roles
            or "clinician" in user_roles
        ):
            logger.warning(
                f"Unauthorized attempt to access analysis: "
                f"user_id={user_id}, patient_id={result.get('patient_id')}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this analysis"
            )
        
        logger.info(f"Successfully retrieved analysis: analysis_id={analysis_id}")
        # Shape payload to match analyze endpoint output
        payload: Dict[str, Any] = {
            "analysis_id": result.get("analysis_id"),
            "patient_id": result.get("patient_id"),
            # use provided timestamp or fallback
            "timestamp": result.get("timestamp") or result.get("created_at"),
        }
        # Top-level sleep metrics
        if "sleep_metrics" in result:
            payload["sleep_metrics"] = result["sleep_metrics"]
        elif result.get("results") and AnalysisType.SLEEP_QUALITY.value in result["results"]:
            payload["sleep_metrics"] = result["results"][AnalysisType.SLEEP_QUALITY.value]
        # Top-level activity levels
        if "activity_levels" in result:
            payload["activity_levels"] = result["activity_levels"]
        elif result.get("results") and AnalysisType.ACTIVITY_LEVELS.value in result["results"]:
            payload["activity_levels"] = result["results"][AnalysisType.ACTIVITY_LEVELS.value]
        return payload
    
    except ResourceNotFoundError as e:
        logger.warning(f"Analysis not found: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis not found: {analysis_id}"
        )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error in get_analysis_by_id: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving the analysis"
        )


@router.get(
    "/patient/{patient_id}/analyses",
    status_code=status.HTTP_200_OK,
    summary="Get analyses for a patient",
    description="Retrieve a list of actigraphy analyses for a specific patient."
)
async def get_patient_analyses(
    patient_id: str,
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pat_service: PATInterface = Depends(get_pat_service)
) -> Dict[str, Any]:
    """Get analyses for a patient endpoint.
    
    This endpoint retrieves a paginated list of analyses for a specific patient,
    including summary information for each analysis.
    
    Args:
        patient_id: The patient's unique identifier
        limit: Maximum number of analyses to return
        offset: Offset for pagination
        current_user: The authenticated user dictionary/object.
        pat_service: PAT service
        
    Returns:
        Paginated list of analyses
        
    Raises:
        HTTPException: If access is denied or an error occurs
    """
    try:
        user_id = current_user.get("id")
        user_roles = current_user.get("roles", [])
        
        # Authorization Check (allow clinicians)
        if not (
            user_id == patient_id
            or "admin" in user_roles
            or "doctor" in user_roles
            or "clinician" in user_roles
        ):
            logger.warning(
                f"Unauthorized attempt to access patient analyses: "
                f"user_id={user_id}, patient_id={patient_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this patient's analyses"
            )
        
        logger.info(
            f"Retrieving patient analyses: "
            f"patient_id={patient_id}, limit={limit}, offset={offset}"
        )
        
        # Get the analyses from service
        result = pat_service.get_patient_analyses(
            patient_id=patient_id,
            limit=limit,
            offset=offset
        )
        
        logger.info(
            f"Successfully retrieved patient analyses: "
            f"count={len(result.get('analyses', []))}"
        )
        # Shape payload for response
        analyses_payload: List[Dict[str, Any]] = []
        for a in result.get("analyses", []):
            entry: Dict[str, Any] = {
                "analysis_id": a.get("analysis_id"),
                "patient_id": a.get("patient_id"),
                "timestamp": a.get("timestamp") or a.get("created_at"),
            }
            # Include metrics if available
            if "sleep_metrics" in a:
                entry["sleep_metrics"] = a["sleep_metrics"]
            elif a.get("results") and AnalysisType.SLEEP_QUALITY.value in a["results"]:
                entry["sleep_metrics"] = a["results"][AnalysisType.SLEEP_QUALITY.value]
            if "activity_levels" in a:
                entry["activity_levels"] = a["activity_levels"]
            elif a.get("results") and AnalysisType.ACTIVITY_LEVELS.value in a["results"]:
                entry["activity_levels"] = a["results"][AnalysisType.ACTIVITY_LEVELS.value]
            analyses_payload.append(entry)
        # Return structured response for patient analyses
        return {
            "patient_id": patient_id,
            "analyses": analyses_payload,
            "total": len(analyses_payload),
        }
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error in get_patient_analyses: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving analyses"
        )


@router.get(
    "/model-info",
    status_code=status.HTTP_200_OK,
    summary="Get PAT model information",
    description="Retrieve information about the PAT model being used."
)
async def get_model_info(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pat_service: PATInterface = Depends(get_pat_service)
) -> Dict[str, Any]:
    """Get PAT model information endpoint.

    Retrieves information about the PAT model, including capabilities,
    version, and metadata. Authentication enforced by dependency.
    """
    try:
        logger.info("Retrieving PAT model information")
        result = pat_service.get_model_info()
        logger.info("Successfully retrieved PAT model information")
        # Shape response to expected API fields for client expectations
        return {
            "name": result.get("name"),
            "version": result.get("version"),
            "capabilities": result.get("capabilities"),
            "developer": result.get("developer"),
        }
    except Exception as e:
        logger.error(f"Unexpected error in get_model_info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving model information"
        )


# ---------------------------------------------------------------------------
# New: GET /analysis_types
# ---------------------------------------------------------------------------


@router.get(
    "/analysis_types",
    response_model=List[str],
    status_code=status.HTTP_200_OK,
    summary="List available actigraphy analysis types",
    description="Return the list of analysis types supported by the PAT service."
)
async def get_analysis_types(
    pat_service: PATInterface = Depends(get_pat_service),
) -> List[str]:
    """Return the list of supported analysis types.

    The values ultimately originate from the PAT service so that advanced
    (e.g. model‑specific) capabilities can be surfaced without redeploying
    the API layer.  A fallback to the canonical list defined in the
    ``AnalysisType`` enumeration is provided to guarantee availability even
    when the underlying service does not implement the new method.
    """

    try:
        types_raw = pat_service.get_analysis_types()  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover – defensive
        logger.warning("PAT service did not expose get_analysis_types: %s", exc)
        types_raw = [t.value for t in AnalysisType]

    # Normalise to *plain* strings for the public API.
    normalized = [_normalize_analysis_type(t) for t in types_raw]
    return normalized


@router.post(
    "/integrate-with-digital-twin",
    status_code=status.HTTP_200_OK,
    summary="Integrate with Digital Twin",
    description="Integrate actigraphy analysis with a digital twin profile."
)
async def integrate_with_digital_twin(
    request_data: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
    pat_service: PATInterface = Depends(get_pat_service)
) -> Dict[str, Any]:
    """Integrate with digital twin endpoint.
    
    This endpoint integrates actigraphy analysis results with a digital twin
    profile, providing insights and updating the digital twin model based on
    physical activity data.
    
    Args:
        request: The integration request
        current_user: The authenticated user dictionary/object.
        pat_service: PAT service
        
    Returns:
        Integration results
        
    Raises:
        HTTPException: If integration fails or validation errors occur
    """
    # Authorization Check (allow clinicians)
    user_id = current_user.get("id")
    user_roles = current_user.get("roles", [])
    if not (
        user_id == request_data.get("patient_id")
        or "admin" in user_roles
        or "doctor" in user_roles
        or "clinician" in user_roles
    ):
        logger.warning(
            f"Unauthorized attempt to integrate with digital twin: "
            f"user_id={user_id}, patient_id={request_data.get('patient_id')}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to integrate with this patient's digital twin"
        )
    # Perform integration
    try:
        logger.info(
            f"Integrating with Digital Twin: "
            f"patient_id={request_data.get('patient_id')}, "
            f"profile_id={request_data.get('profile_id')}"
        )
        # Call service with analysis_id or full analysis data, pass integration options
        result = pat_service.integrate_with_digital_twin(
            patient_id=request_data.get("patient_id"),
            profile_id=request_data.get("profile_id"),
            analysis_id=request_data.get("analysis_id"),
            actigraphy_analysis=request_data.get("actigraphy_analysis"),
            **request_data.get("integration_options", {})
        )
        logger.info(
            f"Successfully integrated with Digital Twin: "
            f"integration_id={result.get('integration_id')}"
        )
        # Shape response to expected API fields for integration
        return {
            "patient_id": result.get("patient_id"),
            "profile_id": result.get("profile_id"),
            "timestamp": result.get("timestamp"),
            "integrated_profile": result.get("updated_profile"),
        }
    
    except ValidationError as e:
        logger.warning(f"Validation error in integrate_with_digital_twin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    except ResourceNotFoundError as e:
        logger.warning(f"Resource not found in integrate_with_digital_twin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    
    except AuthorizationError as e:
        logger.warning(f"Authorization error in integrate_with_digital_twin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    
    except IntegrationError as e:
        logger.error(f"Integration error in integrate_with_digital_twin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Integration failed: {str(e)}"
        )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error in integrate_with_digital_twin: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during integration"
        )
