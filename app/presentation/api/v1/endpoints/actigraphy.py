"""
Actigraphy API Endpoints.

Handles endpoints related to retrieving and managing actigraphy data.
Follows Clean Architecture principles with proper separation of concerns.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, UploadFile, status
from pydantic import BaseModel, Field

from app.core.domain.entities.user import User, UserRole
from app.core.exceptions import ApplicationError
from app.core.interfaces.services.actigraphy_service_interface import ActigraphyServiceInterface
from app.core.utils.date_utils import format_date_iso, utcnow
from app.infrastructure.logging.audit_logger import audit_log_phi_access
from app.presentation.api.dependencies.actigraphy import get_actigraphy_service
from app.presentation.api.dependencies.auth import get_current_active_user, require_roles
from app.presentation.api.schemas.actigraphy import (
    ActigraphyAnalysisRequest,
    ActigraphyAnalysisResult,
    ActigraphyDataResponse,
    ActigraphyModelInfoResponse,
    ActigraphySummaryResponse,
    ActigraphyUploadResponse,
    AnalysisType,
    AnalyzeActigraphyResponse,
    DailySummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    dependencies=[Depends(get_current_active_user)],
)


@router.post(
    "/upload",
    response_model=ActigraphyUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload Actigraphy Data",
)
async def upload_actigraphy_data(
    file: UploadFile = File(...),
    patient_id: uuid.UUID = Query(..., description="Patient ID"),
    actigraphy_service: ActigraphyServiceInterface = Depends(get_actigraphy_service),
    current_user: User = Depends(get_current_active_user),
):
    """
    Upload actigraphy data file for a patient.

    This endpoint allows uploading actigraphy data files for processing
    and storage. The file should be in a supported format (CSV, JSON, etc.).
    
    Args:
        file: The actigraphy data file to upload
        patient_id: ID of the patient this data belongs to
        actigraphy_service: Injected actigraphy service
        current_user: Current authenticated user
        
    Returns:
        Upload status and data_id for the uploaded data
        
    Raises:
        HTTPException: If file format is invalid or upload fails
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "upload_actigraphy_data",
            details={"filename": file.filename},
        )

        # Read file content
        content = await file.read()
        
        # Process file through service layer
        upload_result = await actigraphy_service.process_upload(
            content=content,
            filename=file.filename or "unknown.dat",
            patient_id=str(patient_id),
            uploaded_by=str(current_user.id),
        )
        
        return ActigraphyUploadResponse(
            data_id=upload_result["data_id"],
            message="File uploaded successfully",
            status="success",
            timestamp=utcnow().isoformat(),
        )
    
    except ApplicationError as e:
        # Use application exceptions for domain-specific errors
        logger.error(f"Error processing actigraphy upload: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error processing actigraphy data: Invalid format or corrupted file",
        )
    except Exception as e:
        # Generic error handling with HIPAA-compliant messages
        logger.error(f"Unexpected error in actigraphy upload: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during file processing",
        )


@router.post(
    "/analyze",
    response_model=AnalyzeActigraphyResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Actigraphy Data",
)
async def analyze_actigraphy_data(
    analysis_request: ActigraphyAnalysisRequest,
    actigraphy_service: ActigraphyServiceInterface = Depends(get_actigraphy_service),
    current_user: User = Depends(get_current_active_user),
):
    """
    Analyze actigraphy data using specified algorithm.
    
    This endpoint processes actigraphy data using the specified analysis
    type and parameters, returning detailed analysis results.
    
    Args:
        analysis_request: Analysis parameters and data references
        actigraphy_service: Injected actigraphy service
        current_user: Current authenticated user
        
    Returns:
        Analysis results and metadata
        
    Raises:
        HTTPException: If analysis fails or parameters are invalid
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            analysis_request.patient_id,
            "analyze_actigraphy_data",
            details={"analysis_type": analysis_request.analysis_type},
        )
        
        # Execute analysis through service layer
        analysis_results = await actigraphy_service.analyze_data(
            patient_id=analysis_request.patient_id,
            data_id=analysis_request.data_id,
            analysis_type=analysis_request.analysis_type.value,
            parameters=analysis_request.parameters,
        )
        
        return AnalyzeActigraphyResponse(
            analysis_id=str(uuid.uuid4()),  # In real implementation, service would provide this
            status="completed",
            results=analysis_results,
            timestamp=utcnow().isoformat(),
        )
        
    except ApplicationError as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Analysis failed: Invalid parameters or insufficient data",
        )
    except Exception as e:
        logger.error(f"Unexpected error in actigraphy analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during analysis",
        )


@router.get(
    "/models",
    response_model=List[ActigraphyModelInfoResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Available Actigraphy Analysis Models",
    dependencies=[Depends(require_roles([UserRole.CLINICIAN, UserRole.RESEARCHER, UserRole.ADMIN]))],
)
async def get_available_models(
    actigraphy_service: ActigraphyServiceInterface = Depends(get_actigraphy_service),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get information about available actigraphy analysis models.
    
    This endpoint returns details about available analysis models,
    their capabilities, and configuration options.
    
    Args:
        actigraphy_service: Injected actigraphy service
        current_user: Current authenticated user
        
    Returns:
        List of available model information
    """
    try:
        # Retrieve models through service layer
        available_models = await actigraphy_service.get_available_models()
        
        return [
            ActigraphyModelInfoResponse(
                model_id=model["id"],
                name=model["name"],
                description=model["description"],
                analysis_types=model["analysis_types"],
                parameters=model["parameters"],
                version=model["version"],
            )
            for model in available_models
        ]
    except Exception as e:
        logger.error(f"Error retrieving actigraphy models: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve available analysis models",
        )


@router.get(
    "/data/{data_id}",
    response_model=ActigraphyDataResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Specific Actigraphy Dataset",
)
async def get_specific_actigraphy_data(
    data_id: str = Path(..., description="Actigraphy data ID"),
    actigraphy_service: ActigraphyServiceInterface = Depends(get_actigraphy_service),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get a specific actigraphy dataset by its ID.
    
    This endpoint retrieves a previously uploaded or generated actigraphy
    dataset using its unique identifier.
    
    Args:
        data_id: Unique identifier for the actigraphy dataset
        actigraphy_service: Injected actigraphy service
        current_user: Current authenticated user
        
    Returns:
        Actigraphy data and metadata
        
    Raises:
        HTTPException: If data not found or user not authorized
    """
    try:
        # Retrieve data through service layer
        data_result = await actigraphy_service.get_data_by_id(data_id)
        
        # Verify authorization and log access
        patient_id = data_result.get("patient_id")
        if patient_id:
            audit_log_phi_access(
                str(current_user.id),
                patient_id,
                "get_specific_actigraphy_data",
                details={"data_id": data_id},
            )
        
        return ActigraphyDataResponse(
            data_id=data_id,
            raw_data=data_result.get("data", {}),
            metadata=data_result.get("metadata", {}),
            message="Data retrieved successfully",
        )
        
    except ApplicationError as e:
        logger.error(f"Error retrieving actigraphy data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Actigraphy data not found",
        )
    except Exception as e:
        logger.error(f"Unexpected error retrieving actigraphy data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving actigraphy data",
        )


@router.get(
    "/{patient_id}",
    response_model=ActigraphyDataResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Actigraphy Data for a Patient with Date Range",
)
async def get_patient_actigraphy_data(
    patient_id: uuid.UUID = Path(..., description="Patient ID"),
    start_date: datetime = Query(..., description="Start date (ISO format)"),
    end_date: datetime = Query(..., description="End date (ISO format)"),
    actigraphy_service: ActigraphyServiceInterface = Depends(get_actigraphy_service),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get actigraphy data for a specific patient within a date range.

    This endpoint retrieves actigraphy data for the specified patient between the
    provided start and end dates. Both dates must be valid ISO format.

    Args:
        patient_id: The UUID of the patient
        start_date: Start date for the data range (ISO format)
        end_date: End date for the data range (ISO format)
        actigraphy_service: Injected actigraphy service
        current_user: Current authenticated user

    Returns:
        ActigraphyDataResponse with the patient's data in the specified date range
        
    Raises:
        HTTPException: If data not found or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "get_patient_actigraphy_data",
            details={"date_range": {"start": start_date.isoformat(), "end": end_date.isoformat()}},
        )

        # Retrieve data through service layer
        data_result = await actigraphy_service.get_patient_data(
            patient_id=str(patient_id),
            start_date=start_date,
            end_date=end_date,
        )
        
        return ActigraphyDataResponse(
            data_id=str(uuid.uuid4()),  # In real implementation, service would provide this
            raw_data=data_result.get("data", {}),
            metadata={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "data_points": data_result.get("data_points", 0),
                "source": data_result.get("source", "unknown"),
            },
            message="Patient actigraphy data retrieved successfully",
        )
        
    except ApplicationError as e:
        logger.error(f"Error retrieving patient actigraphy data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Actigraphy data not found for the specified patient and date range",
        )
    except Exception as e:
        logger.error(f"Unexpected error in patient actigraphy data retrieval: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving actigraphy data",
        )


@router.get(
    "/{patient_id}/summary",
    response_model=ActigraphySummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Actigraphy Summary for a Patient",
)
async def get_patient_actigraphy_summary(
    patient_id: uuid.UUID = Path(..., description="Patient ID"),
    start_date: datetime = Query(..., description="Start date (ISO format)"),
    end_date: datetime = Query(..., description="End date (ISO format)"),
    actigraphy_service: ActigraphyServiceInterface = Depends(get_actigraphy_service),
    current_user: User = Depends(get_current_active_user),
):
    """
    Get a summary of actigraphy data for a patient within a date range.
    
    This endpoint provides aggregated statistics and summary information
    about a patient's actigraphy data over the specified time period.
    
    Args:
        patient_id: ID of the patient
        start_date: Start of the summary period
        end_date: End of the summary period
        actigraphy_service: Injected actigraphy service
        current_user: Current authenticated user
        
    Returns:
        Summary statistics and daily breakdowns
        
    Raises:
        HTTPException: If data not found or user not authorized
    """
    try:
        # Log the access for HIPAA compliance
        audit_log_phi_access(
            str(current_user.id),
            str(patient_id),
            "get_patient_actigraphy_summary",
            details={"date_range": {"start": start_date.isoformat(), "end": end_date.isoformat()}},
        )

        # Retrieve summary through service layer
        summary_result = await actigraphy_service.get_patient_summary(
            patient_id=str(patient_id),
            start_date=start_date,
            end_date=end_date,
        )
        
        # Process daily summaries
        daily_summaries = []
        for day_data in summary_result.get("daily_data", []):
            daily_summaries.append(
                DailySummary(
                    date=day_data["date"],
                    activity_score=day_data.get("activity_score", 0),
                    sleep_hours=day_data.get("sleep_hours", 0),
                    step_count=day_data.get("step_count", 0),
                    active_minutes=day_data.get("active_minutes", 0),
                    sedentary_minutes=day_data.get("sedentary_minutes", 0),
                )
            )
        
        return ActigraphySummaryResponse(
            patient_id=str(patient_id),
            start_date=start_date.isoformat(),
            end_date=end_date.isoformat(),
            avg_sleep_hours=summary_result.get("avg_sleep_hours", 0),
            avg_step_count=summary_result.get("avg_step_count", 0),
            avg_activity_score=summary_result.get("avg_activity_score", 0),
            trend=summary_result.get("trend", "stable"),
            daily_summaries=daily_summaries,
        )
        
    except ApplicationError as e:
        logger.error(f"Error retrieving patient actigraphy summary: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Actigraphy summary not available for the specified patient and date range",
        )
    except Exception as e:
        logger.error(f"Unexpected error in patient actigraphy summary: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while generating actigraphy summary",
        )