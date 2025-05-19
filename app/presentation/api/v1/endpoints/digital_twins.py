from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.exceptions.base_exceptions import (
    ModelExecutionError,
    ResourceNotFoundError,
)
from app.core.interfaces.services.digital_twin_service import (
    IDigitalTwinIntegrationService,
)
from app.domain.entities.user import User
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.api.dependencies.services import get_digital_twin_service
from app.presentation.api.schemas.digital_twin_schemas import (
    ClinicalTextAnalysisRequest,
    ClinicalTextAnalysisResponse,
    DigitalTwinStatusResponse,
    PersonalizedInsightResponse,  # Assuming single insight for now based on test fixture
)

router = APIRouter(
    prefix="/digital-twins",
    tags=["Digital Twins"],
)


@router.get(
    "/{patient_id}/status",
    response_model=DigitalTwinStatusResponse,
    summary="Get Digital Twin Status",
    description="Retrieves the current status and completeness of a patient's digital twin.",
)
async def get_twin_status(
    patient_id: UUID,
    current_user: User = Depends(get_current_user),  # Add auth dependency
    digital_twin_service: IDigitalTwinIntegrationService = Depends(get_digital_twin_service),
) -> DigitalTwinStatusResponse:
    # TODO: Implement authorization logic (e.g., check if user can access patient_id)
    try:
        twin_status = await digital_twin_service.get_digital_twin_status(patient_id)
        if twin_status is None:  # Or however the service indicates not found
            raise ResourceNotFoundError(f"Digital twin status not found for patient {patient_id}")
        # Assuming service returns an object compatible with DigitalTwinStatusResponse
        return twin_status
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except Exception as e:
        # Log the unexpected error
        # logger.error(f"Unexpected error fetching twin status for {patient_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while fetching digital twin status.",
        ) from e


@router.get(
    "/{patient_id}/insights",
    response_model=PersonalizedInsightResponse,  # Or List[PersonalizedInsightResponse]?
    summary="Get Comprehensive Patient Insights",
    description="Retrieves comprehensive insights generated from the patient's digital twin.",
)
async def get_comprehensive_insights(
    patient_id: UUID,
    current_user: User = Depends(get_current_user),
    digital_twin_service: IDigitalTwinIntegrationService = Depends(get_digital_twin_service),
) -> PersonalizedInsightResponse:
    # TODO: Implement authorization logic
    try:
        # The test uses a single PersonalizedInsightResponse fixture, so let's assume the service returns one for now.
        # This might need adjustment based on actual service design (e.g., return List, handle filters).
        insights = await digital_twin_service.generate_comprehensive_patient_insights(patient_id)
        if insights is None:
            raise ResourceNotFoundError(f"Insights not found for patient {patient_id}")
        return insights
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except ModelExecutionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating insights: {e}",
        ) from e
    except Exception as e:
        # Log the unexpected error
        # logger.error(f"Unexpected error fetching insights for {patient_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while fetching insights.",
        ) from e


@router.post(
    "/{patient_id}/analyze-text",
    response_model=ClinicalTextAnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,  # Analysis might be async
    summary="Analyze Clinical Text with MentaLLaMA",
    description="Submits clinical text for analysis using the MentaLLaMA model integrated with the digital twin.",
)
async def analyze_clinical_text(
    patient_id: UUID,
    request: ClinicalTextAnalysisRequest,
    current_user: User = Depends(get_current_user),
    digital_twin_service: IDigitalTwinIntegrationService = Depends(get_digital_twin_service),
) -> ClinicalTextAnalysisResponse:
    # TODO: Implement authorization logic
    try:
        # Assuming the service method handles the async nature and returns an initial response
        analysis_response = await digital_twin_service.analyze_clinical_text_mentallama(
            patient_id=patient_id,
            text_data=request.clinical_text,  # Pass the text from the request
            # focus=request.analysis_focus # Pass focus if service uses it
        )
        if analysis_response is None:
            # This might indicate an issue submitting the job rather than not found
            raise ModelExecutionError(
                f"Failed to initiate clinical text analysis for patient {patient_id}"
            )
        return analysis_response
    except ModelExecutionError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during text analysis: {e}",
        ) from e
    except Exception as e:
        # Log the unexpected error
        # logger.error(f"Unexpected error analyzing text for {patient_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during clinical text analysis.",
        ) from e
