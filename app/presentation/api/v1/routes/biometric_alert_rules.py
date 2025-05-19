"""
Biometric Alert Rules Endpoints Module.

Provides API endpoints for managing biometric alert rules.
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import UUID4
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.biometric_alert_rule_service import (
    BiometricAlertRuleService,
)
from app.core.domain.entities.user import User
from app.presentation.api.dependencies.auth import (
    get_current_active_user_wrapper,
)
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.schemas.alert import (
    AlertRuleCreateFromTemplateRequest,
    AlertRuleCreateRequest,
    AlertRuleResponse,
    AlertRuleUpdateRequest,
)
from app.presentation.api.v1.dependencies.biometric_alert import (
    get_biometric_alert_rule_service,
)

logger = logging.getLogger(__name__)

# Router without global dependencies that might interfere with static analysis
router = APIRouter(
    tags=["biometric-alert-rules"],
)


@router.post(
    "",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new biometric alert rule",
    description="Adds a new biometric alert rule to the system.",
)
async def create_alert_rule(
    rule_data: AlertRuleCreateRequest,
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
    db: AsyncSession = Depends(get_db),
) -> AlertRuleResponse:
    """Endpoint to create a new biometric alert rule."""
    logger.info(f"User {current_user.id} creating alert rule: {rule_data.name}")

    try:
        # Convert request data to service format
        rule_dict = {
            "name": rule_data.name,
            "description": rule_data.description,
            "patient_id": UUID(rule_data.patient_id) if rule_data.patient_id else None,
            "provider_id": UUID(current_user.id) if current_user.id else None,
            "conditions": [
                {
                    "metric_name": rule_data.biometric_type,
                    "comparator_operator": rule_data.comparison_operator,
                    "threshold_value": rule_data.threshold_level,
                    "description": rule_data.description,
                }
            ],
            "logical_operator": "and",  # Default for simple rule
            "priority": rule_data.priority,
            "is_active": rule_data.is_active,
        }

        # Create rule using service
        rule = await alert_rule_service.create_rule(rule_dict)

        # Convert to response model
        return AlertRuleResponse(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            biometric_type=rule.conditions[0].metric_type.value if rule.conditions else None,
            threshold_level=rule.conditions[0].threshold_value if rule.conditions else None,
            comparison_operator=rule.conditions[0].operator.value if rule.conditions else None,
            is_active=rule.is_active,
            created_by=str(rule.provider_id) if rule.provider_id else str(current_user.id),
            updated_by=str(current_user.id),
            created_at=rule.created_at,
            last_updated=rule.updated_at or rule.created_at,
        )
    except Exception as e:
        logger.error(f"Error creating alert rule: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create alert rule: {e!s}",
        )


@router.post(
    "/from-template",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new alert rule from a template",
    description="Creates a new alert rule based on a predefined template with custom overrides.",
)
async def create_alert_rule_from_template(
    template_request: AlertRuleCreateFromTemplateRequest,
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
) -> AlertRuleResponse:
    """Endpoint to create a new alert rule from a template."""
    logger.info(
        f"User {current_user.id} creating alert rule from template: {template_request.template_id}"
    )

    try:
        # Parse IDs
        try:
            template_id = UUID(template_request.template_id)
            patient_id = UUID(template_request.patient_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid UUID format in request",
            )

        # Prepare overrides
        custom_overrides = (
            template_request.customization.model_dump() if template_request.customization else {}
        )
        custom_overrides["provider_id"] = UUID(current_user.id) if current_user.id else None

        # Create rule from template
        rule = await alert_rule_service.create_rule_from_template(
            template_id=template_id,
            patient_id=patient_id,
            custom_overrides=custom_overrides,
        )

        # Convert to response model
        return AlertRuleResponse(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            biometric_type=rule.conditions[0].metric_type.value if rule.conditions else None,
            threshold_level=rule.conditions[0].threshold_value if rule.conditions else None,
            comparison_operator=rule.conditions[0].operator.value if rule.conditions else None,
            is_active=rule.is_active,
            created_by=str(rule.provider_id) if rule.provider_id else str(current_user.id),
            updated_by=str(current_user.id),
            created_at=rule.created_at,
            last_updated=rule.updated_at or rule.created_at,
        )
    except Exception as e:
        logger.error(f"Error creating alert rule from template: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create alert rule from template: {e!s}",
        )


@router.get(
    "",
    response_model=list[AlertRuleResponse],
    summary="Get biometric alert rules",
    description=("Retrieves a list of biometric alert rules with optional filtering."),
)
async def get_alert_rules(
    patient_id: UUID | None = Query(None, description="Filter by patient ID"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[AlertRuleResponse]:
    """Get a list of alert rules with optional filtering."""
    logger.info(
        f"User {current_user.id} fetching alert rules with filters: patient_id={patient_id}, is_active={is_active}"
    )

    try:
        # Fetch rules using service
        rules = await alert_rule_service.get_rules(
            patient_id=patient_id, is_active=is_active, skip=offset, limit=limit
        )

        # Convert to response models
        return [
            AlertRuleResponse(
                id=rule.id,
                name=rule.name,
                description=rule.description,
                biometric_type=rule.conditions[0].metric_type.value if rule.conditions else None,
                threshold_level=rule.conditions[0].threshold_value if rule.conditions else None,
                comparison_operator=rule.conditions[0].operator.value if rule.conditions else None,
                is_active=rule.is_active,
                created_by=str(rule.provider_id) if rule.provider_id else "unknown",
                updated_by=str(rule.provider_id) if rule.provider_id else "unknown",
                created_at=rule.created_at,
                last_updated=rule.updated_at or rule.created_at,
            )
            for rule in rules
        ]
    except Exception as e:
        logger.error(f"Error fetching alert rules: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving alert rules",
        )


@router.get(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a specific biometric alert rule by ID",
)
async def get_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to retrieve"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
) -> AlertRuleResponse:
    """
    Get details for a specific biometric alert rule.
    """
    logger.info(f"User {current_user.id} fetching alert rule {rule_id}")

    try:
        # Fetch rule using service
        rule = await alert_rule_service.get_rule_by_id(rule_id)

        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found"
            )

        # Convert to response model
        return AlertRuleResponse(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            biometric_type=rule.conditions[0].metric_type.value if rule.conditions else None,
            threshold_level=rule.conditions[0].threshold_value if rule.conditions else None,
            comparison_operator=rule.conditions[0].operator.value if rule.conditions else None,
            is_active=rule.is_active,
            created_by=str(rule.provider_id) if rule.provider_id else "unknown",
            updated_by=str(rule.provider_id) if rule.provider_id else "unknown",
            created_at=rule.created_at,
            last_updated=rule.updated_at or rule.created_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching alert rule {rule_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving the alert rule",
        )


@router.put(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a biometric alert rule",
)
async def update_alert_rule(
    rule_data: AlertRuleUpdateRequest,
    rule_id: UUID4 = Path(..., description="ID of the alert rule to update"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
) -> AlertRuleResponse:
    """
    Update an existing biometric alert rule.
    """
    logger.info(f"User {current_user.id} updating alert rule {rule_id}")

    try:
        # Convert request data to service format
        update_dict = rule_data.model_dump(exclude_unset=True)

        # If there are biometric-related updates, format them as conditions
        if any(
            key in update_dict
            for key in ["biometric_type", "comparison_operator", "threshold_level"]
        ):
            # Get the current rule to maintain consistency for fields not being updated
            current_rule = await alert_rule_service.get_rule_by_id(rule_id)
            if not current_rule:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found"
                )

            # Extract current values to use as defaults
            current_metric = (
                current_rule.conditions[0].metric_type.value if current_rule.conditions else None
            )
            current_operator = (
                current_rule.conditions[0].operator.value if current_rule.conditions else None
            )
            current_threshold = (
                current_rule.conditions[0].threshold_value if current_rule.conditions else None
            )
            current_description = (
                current_rule.conditions[0].description if current_rule.conditions else None
            )

            # Create conditions with updated values
            update_dict["conditions"] = [
                {
                    "metric_name": update_dict.pop("biometric_type", current_metric),
                    "comparator_operator": update_dict.pop("comparison_operator", current_operator),
                    "threshold_value": update_dict.pop("threshold_level", current_threshold),
                    "description": current_description,
                }
            ]

        # Add updated_by
        update_dict["provider_id"] = UUID(current_user.id) if current_user.id else None

        # Update rule using service
        updated_rule = await alert_rule_service.update_rule(rule_id, update_dict)

        if not updated_rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert rule not found or update failed",
            )

        # Convert to response model
        return AlertRuleResponse(
            id=updated_rule.id,
            name=updated_rule.name,
            description=updated_rule.description,
            biometric_type=updated_rule.conditions[0].metric_type.value
            if updated_rule.conditions
            else None,
            threshold_level=updated_rule.conditions[0].threshold_value
            if updated_rule.conditions
            else None,
            comparison_operator=updated_rule.conditions[0].operator.value
            if updated_rule.conditions
            else None,
            is_active=updated_rule.is_active,
            created_by=str(updated_rule.provider_id) if updated_rule.provider_id else "unknown",
            updated_by=str(current_user.id),
            created_at=updated_rule.created_at,
            last_updated=updated_rule.updated_at or datetime.now(timezone.utc),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert rule {rule_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update alert rule: {e!s}",
        )


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a biometric alert rule",
)
async def delete_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to delete"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
) -> None:
    """
    Delete a specific biometric alert rule.
    """
    logger.info(f"User {current_user.id} deleting alert rule {rule_id}")

    try:
        # Delete rule using service
        success = await alert_rule_service.delete_rule(rule_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found"
            )

        # No return body for 204
        return None
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting alert rule {rule_id}: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while deleting the alert rule",
        )
