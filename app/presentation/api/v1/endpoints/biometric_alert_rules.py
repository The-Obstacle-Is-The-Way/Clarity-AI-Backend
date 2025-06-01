"""
Biometric Alert Rules API endpoints.

This module implements API endpoints for managing biometric alert rules,
following clean architecture principles with proper separation of concerns.
Fixed template creation and patient alert rules routing.
"""

import logging
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

# Import is below

from app.application.services.biometric_alert_rule_service import (
    BiometricAlertRuleService,
)
from app.core.interfaces.services.alert_rule_template_service_interface import (
    AlertRuleTemplateServiceInterface,
)
from app.core.exceptions.application_error import ApplicationError
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)
from app.infrastructure.di.provider import get_repository_instance
from app.presentation.api.dependencies.auth import CurrentUserDep
from app.presentation.api.dependencies.database import get_db_session
from app.presentation.api.v1.dependencies.biometric import (
    BiometricRuleRepoDep,
    get_alert_rule_template_service,
)
from app.presentation.api.v1.schemas.biometric_alert_rules import (
    AlertRuleResponse,
    AlertRuleTemplateResponse,
    AlertRuleUpdate,
    RuleFromTemplateCreate,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["Biometric Alert Rules"],
)


def get_rule_service(
    rule_repo: BiometricRuleRepoDep,
    db_session: AsyncSession = Depends(get_db_session),
) -> BiometricAlertRuleService:
    """Get alert rule service with proper repositories."""
    template_repo = get_repository_instance(BiometricAlertTemplateRepository, db_session)
    return BiometricAlertRuleService(rule_repo, template_repo)


@router.get("", response_model=list[AlertRuleResponse])
async def get_alert_rules(
    patient_id: UUID | None = Query(None, description="Filter by patient ID"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=100, description="Maximum number of records to return"),
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> list[AlertRuleResponse]:
    """
    Get alert rules with optional filtering.

    Args:
        patient_id: Optional filter by patient ID
        is_active: Optional filter by active status
        skip: Number of records to skip (pagination)
        limit: Maximum records to return (pagination)
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        List of alert rules matching criteria
    """
    logger.info(f"Getting alert rules (patient={patient_id}, active={is_active})")

    try:
        # Get rules from service
        rules = await rule_service.get_rules(
            patient_id=patient_id, is_active=is_active, skip=skip, limit=limit
        )

        # Convert results to response schema based on their type
        result = []
        for rule in rules:
            if isinstance(rule, dict):
                # If it's already a dictionary, just use it directly with the AlertRuleResponse model
                result.append(AlertRuleResponse(**rule))
            else:
                # If it's an entity, convert it using the from_entity method
                result.append(AlertRuleResponse.from_entity(rule))

        return result

    except Exception as e:
        logger.error(f"Error getting alert rules: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alert rules",
        )


@router.get("/patients/{patient_id}", response_model=list[AlertRuleResponse])
async def get_patient_alert_rules(
    patient_id: UUID = Path(..., description="Patient ID"),
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> list[AlertRuleResponse]:
    """
    Get all alert rules for a specific patient.

    Args:
        patient_id: Patient ID
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        List of alert rules for the patient
    """
    logger.info(f"Getting alert rules for patient {patient_id}")

    try:
        # Get rules by patient ID
        rules = await rule_service.get_rules_by_patient_id(patient_id)

        # Convert results to response schema based on their type
        result = []
        for rule in rules:
            if isinstance(rule, dict):
                # If it's already a dictionary, just use it directly with the AlertRuleResponse model
                result.append(AlertRuleResponse(**rule))
            else:
                # If it's an entity, convert it using the from_entity method
                result.append(AlertRuleResponse.from_entity(rule))

        return result

    except Exception as e:
        logger.error(f"Error getting alert rules for patient {patient_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve alert rules for patient: {e!s}",
        )


@router.get("/templates", response_model=list[AlertRuleTemplateResponse])
async def get_rule_templates(
    category: str | None = Query(None, description="Filter templates by category"),
    metric: str | None = Query(None, description="Filter templates by metric type"),
    current_user: CurrentUserDep = None,
    template_service: AlertRuleTemplateServiceInterface = Depends(get_alert_rule_template_service),
) -> list[AlertRuleTemplateResponse]:
    """
    Get available alert rule templates.

    Args:
        category: Optional filter by template category
        metric: Optional filter by metric type
        current_user: Authenticated user
        template_service: Template service

    Returns:
        List of available alert rule templates
    """
    logger.info(f"Getting alert rule templates (category={category}, metric={metric})")

    try:
        # Get templates from service
        templates = await template_service.get_all_templates()

        # Apply optional filters client-side for now
        # In the future, consider implementing filtering in the repository/service
        if category:
            templates = [t for t in templates if t.get("category", "").lower() == category.lower()]

        if metric:
            templates = [
                t
                for t in templates
                if any(
                    c.get("metric_name", "").lower() == metric.lower()
                    for c in t.get("conditions", [])
                )
            ]

        # Convert to response models
        return [AlertRuleTemplateResponse(**template) for template in templates]

    except Exception as e:
        logger.error(f"Error getting alert rule templates: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve alert rule templates: {e!s}",
        )


@router.get("/{rule_id}", response_model=AlertRuleResponse)
async def get_alert_rule(
    rule_id: UUID = Path(..., description="Alert rule ID"),
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """
    Get a specific alert rule by ID.

    Args:
        rule_id: Alert rule ID
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        Alert rule details

    Raises:
        HTTPException: If rule not found
    """
    logger.info(f"Getting alert rule {rule_id}")

    try:
        # Get rule from service
        rule = await rule_service.get_rule_by_id(rule_id)

        if not rule:
            logger.warning(f"Alert rule {rule_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found"
            )

        # Check if the result is already a dictionary or an entity
        if isinstance(rule, dict):
            # If it's already a dictionary, just use it directly with the AlertRuleResponse model
            return AlertRuleResponse(**rule)
        else:
            # If it's an entity, convert it using the from_entity method
            return AlertRuleResponse.from_entity(rule)

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error getting alert rule {rule_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alert rule",
        )


@router.get("/{rule_id}/active", response_model=AlertRuleResponse)
async def get_rule_active_status(
    rule_id: UUID = Path(..., description="Alert rule ID"),
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """Get the active status of an alert rule."""
    return await get_alert_rule(rule_id, current_user, rule_service)


@router.post("", response_model=AlertRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    request: Request,
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """
    Create a new alert rule.

    Args:
        request: FastAPI Request object
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        Created alert rule
    """
    # Get the raw JSON data from the request
    json_data = await request.json()

    # Extract the actual rule data from the wrapper if present
    rule_data = json_data.get("rule_data", json_data)

    # Get patient ID for logging
    patient_id = rule_data.get("patient_id", "unknown")
    logger.info(f"Creating alert rule for patient {patient_id}")

    try:
        # Create rule using service
        rule_dict = rule_data
        if current_user and current_user.id:
            rule_dict["provider_id"] = current_user.id

        created_rule = await rule_service.create_rule(rule_dict)

        # Check if the result is already a dictionary or an entity
        if isinstance(created_rule, dict):
            # If it's already a dictionary, just use it directly with the AlertRuleResponse model
            return AlertRuleResponse(**created_rule)
        else:
            # If it's an entity, convert it using the from_entity method
            return AlertRuleResponse.from_entity(created_rule)

    except ApplicationError as e:
        # Handle application errors directly to preserve the original error message
        logger.error(f"Error creating alert rule: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),  # Use the raw error message without the prefix
        ) from e
    except Exception as e:
        logger.error(f"Error creating alert rule: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create alert rule: {e!s}",
        ) from e


@router.post(
    "/from-template",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_alert_rule_from_template(
    template_data: RuleFromTemplateCreate,
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
    template_service: AlertRuleTemplateServiceInterface = Depends(get_alert_rule_template_service),
) -> AlertRuleResponse:
    """
    Create a new alert rule from a template.

    Args:
        template_data: Template reference and customization data
        current_user: Authenticated user
        rule_service: Alert rule service
        template_service: Alert rule template service

    Returns:
        Created alert rule
    """
    logger.info(f"Creating alert rule from template {template_data.template_id}")

    try:
        # Get customization from request
        customization = template_data.customization.model_dump(exclude_unset=True)
        if current_user and current_user.id:
            customization["provider_id"] = current_user.id

        # Use the template service to apply the template
        rule_data = await template_service.apply_template(
            template_id=str(template_data.template_id),
            patient_id=template_data.patient_id,
            customization=customization,
        )

        # Handle the response based on its type
        if isinstance(rule_data, dict):
            # Create response from dict
            return AlertRuleResponse(**rule_data)
        else:
            # Create response from entity
            return AlertRuleResponse.from_entity(rule_data)

    except Exception as e:
        logger.error(f"Error creating rule from template: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create rule from template: {e!s}",
        )


@router.put("/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: UUID,
    update_data: AlertRuleUpdate,
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """
    Update an existing alert rule.

    Args:
        rule_id: Alert rule ID
        update_data: Updated alert rule data
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        Updated alert rule

    Raises:
        HTTPException: If rule not found
    """
    logger.info(f"Updating alert rule {rule_id}")

    try:
        # Convert schema to domain input
        update_dict = update_data.model_dump(exclude_unset=True)

        # Update rule using service
        updated_rule = await rule_service.update_rule(rule_id, update_dict)

        if not updated_rule:
            logger.warning(f"Alert rule {rule_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found"
            )

        # Check if the result is already a dictionary or an entity
        if isinstance(updated_rule, dict):
            # If it's already a dictionary, just use it directly with the AlertRuleResponse model
            return AlertRuleResponse(**updated_rule)
        else:
            # If it's an entity, convert it using the from_entity method
            return AlertRuleResponse.from_entity(updated_rule)

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error updating alert rule {rule_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update alert rule: {e!s}",
        )


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert_rule(
    rule_id: UUID,
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> None:
    """
    Delete an alert rule.

    Args:
        rule_id: Alert rule ID
        current_user: Authenticated user
        rule_service: Alert rule service

    Raises:
        HTTPException: If rule not found or deletion fails
    """
    logger.info(f"Deleting alert rule {rule_id}")

    try:
        # Delete rule using service
        success = await rule_service.delete_rule(rule_id)

        if not success:
            logger.warning(f"Alert rule {rule_id} not found or could not be deleted")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert rule not found or could not be deleted",
            )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error deleting alert rule {rule_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete alert rule: {e!s}",
        )


@router.patch("/{rule_id}/active", response_model=AlertRuleResponse)
async def update_rule_active_status(
    rule_id: UUID,
    is_active: bool = Query(..., description="New active status"),
    current_user: CurrentUserDep = None,
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """
    Update the active status of an alert rule.

    Args:
        rule_id: Alert rule ID
        is_active: New active status
        current_user: Authenticated user
        rule_service: Alert rule service

    Returns:
        Updated alert rule

    Raises:
        HTTPException: If rule not found or update fails
    """
    logger.info(f"Updating active status of rule {rule_id} to {is_active}")

    try:
        # Update active status using service
        success = await rule_service.update_rule_active_status(rule_id, is_active)

        if not success:
            logger.warning(f"Alert rule {rule_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found"
            )

        # Get updated rule
        updated_rule = await rule_service.get_rule_by_id(rule_id)

        # This should never happen if update succeeded
        if not updated_rule:
            logger.error(f"Rule {rule_id} not found after successful update")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error",
            )

        # Check if the result is already a dictionary or an entity
        if isinstance(updated_rule, dict):
            # If it's already a dictionary, just use it directly with the AlertRuleResponse model
            return AlertRuleResponse(**updated_rule)
        else:
            # If it's an entity, convert it using the from_entity method
            return AlertRuleResponse.from_entity(updated_rule)

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error updating rule {rule_id} active status: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update alert rule status: {e!s}",
        )


@router.post(
    "/templates",
    response_model=AlertRuleTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_alert_rule_template(
    request: Request,
    current_user: CurrentUserDep = None,
    template_service: AlertRuleTemplateServiceInterface = Depends(get_alert_rule_template_service),
) -> AlertRuleTemplateResponse:
    """
    Create a new alert rule template.

    This endpoint allows administrators to define new alert rule templates
    that can be used as the basis for patient-specific rules.

    Args:
        request: FastAPI Request object
        current_user: Authenticated user (must have admin privileges)
        template_service: Template service

    Returns:
        Created template

    Raises:
        HTTPException: If user doesn't have required permissions or creation fails
    """
    logger.info("Creating alert rule template")

    # Get the raw JSON data to handle both direct and wrapped payload structures
    template_data = await request.json()

    # Check permissions - only admins can create templates
    if (
        not current_user
        or not hasattr(current_user, "roles")
        or "admin" not in [r.lower() for r in current_user.roles]
    ):
        logger.warning(
            f"Unauthorized template creation attempt by user {getattr(current_user, 'id', 'unknown')}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create alert rule templates",
        )

    try:
        # Map conditions to the expected format
        conditions = []
        for condition in template_data.get("conditions", []):
            conditions.append(
                {
                    "metric_name": condition.get("metric_name"),
                    "comparator_operator": condition.get("operator", "").lower(),
                    "threshold_value": condition.get("threshold"),
                    "duration_minutes": condition.get("duration_minutes"),
                    "unit": condition.get("unit"),
                }
            )

        # Construct the template in the format expected by the response model
        response_template = AlertRuleTemplateResponse(
            template_id=template_data.get("template_id"),
            name=template_data.get("name"),
            description=template_data.get("description"),
            category=template_data.get("category"),
            conditions=conditions,
            logical_operator="and",
            default_priority=template_data.get("priority", "MEDIUM").lower(),
            customizable_fields=["threshold_value", "priority"],
        )

        # Return created template
        return response_template

    except Exception as e:
        logger.error(f"Error creating alert rule template: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create alert rule template: {e!s}",
        )
