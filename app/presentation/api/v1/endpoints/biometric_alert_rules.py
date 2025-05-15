"""
Biometric Alert Rules API endpoints.

This module implements API endpoints for managing biometric alert rules,
following clean architecture principles with proper separation of concerns.
"""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field, validator

from app.application.services.biometric_alert_rule_service import BiometricAlertRuleService
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.domain.entities.biometric_alert_rule import (
    AlertPriority,
    BiometricAlertRule,
    ComparatorOperator,
    RuleCondition,
    RuleLogicalOperator,
)
from app.domain.models.user import User
from app.presentation.api.dependencies.auth import CurrentUserDep
from app.presentation.api.v1.dependencies.biometric import (
    BiometricRuleRepoDep,
)
from app.domain.repositories.biometric_alert_template_repository import BiometricAlertTemplateRepository
from app.infrastructure.di.provider import get_repository_instance
from app.presentation.api.v1.schemas.biometric_alert_rules import (
    AlertRuleCreate,
    AlertRuleResponse,
    AlertRuleUpdate,
    RuleFromTemplateCreate,
    AlertRuleList,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/biometric-alert-rules",
    tags=["Biometric Alert Rules"],
)


def get_rule_service(
    rule_repo: BiometricRuleRepoDep,
    db_session = Depends(app.core.dependencies.database.get_db_session),
) -> BiometricAlertRuleService:
    """Get alert rule service with proper repositories."""
    template_repo = get_repository_instance(BiometricAlertTemplateRepository, db_session)
    return BiometricAlertRuleService(rule_repo, template_repo)


@router.get("", response_model=List[AlertRuleResponse])
async def get_alert_rules(
    patient_id: Optional[UUID] = Query(None, description="Filter by patient ID"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=100, description="Maximum number of records to return"),
    current_user: CurrentUserDep = Depends(),
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> List[AlertRuleResponse]:
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
            patient_id=patient_id,
            is_active=is_active,
            skip=skip,
            limit=limit
        )
        
        # Convert domain entities to response schema
        return [AlertRuleResponse.from_entity(rule) for rule in rules]
        
    except Exception as e:
        logger.error(f"Error getting alert rules: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alert rules"
        )


@router.get("/{rule_id}", response_model=AlertRuleResponse)
async def get_alert_rule(
    rule_id: UUID = Path(..., description="Alert rule ID"),
    current_user: CurrentUserDep = Depends(),
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
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert rule not found"
            )
            
        # Convert domain entity to response schema
        return AlertRuleResponse.from_entity(rule)
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error getting alert rule {rule_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alert rule"
        )


@router.post("", response_model=AlertRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    rule_data: AlertRuleCreate,
    current_user: CurrentUserDep = Depends(),
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """
    Create a new alert rule.
    
    Args:
        rule_data: Alert rule data
        current_user: Authenticated user
        rule_service: Alert rule service
        
    Returns:
        Created alert rule
    """
    logger.info(f"Creating alert rule for patient {rule_data.patient_id}")
    
    try:
        # Convert schema to domain input
        rule_dict = rule_data.dict(exclude_unset=True)
        rule_dict["provider_id"] = current_user.id
        
        # Create rule using service
        rule = await rule_service.create_rule(rule_dict)
        
        # Convert domain entity to response schema
        return AlertRuleResponse.from_entity(rule)
        
    except Exception as e:
        logger.error(f"Error creating alert rule: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create alert rule: {str(e)}"
        )


@router.post("/from-template", response_model=AlertRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_alert_rule_from_template(
    template_data: RuleFromTemplateCreate,
    current_user: CurrentUserDep = Depends(),
    rule_service: BiometricAlertRuleService = Depends(get_rule_service),
) -> AlertRuleResponse:
    """
    Create a new alert rule from a template.
    
    Args:
        template_data: Template reference and customization data
        current_user: Authenticated user
        rule_service: Alert rule service
        
    Returns:
        Created alert rule
    """
    logger.info(f"Creating alert rule from template {template_data.template_id}")
    
    try:
        # Add current user as provider
        custom_overrides = template_data.customization.dict(exclude_unset=True)
        custom_overrides["provider_id"] = current_user.id
        
        # Create rule from template using service
        rule = await rule_service.create_rule_from_template(
            template_id=template_data.template_id,
            patient_id=template_data.patient_id,
            custom_overrides=custom_overrides
        )
        
        # Convert domain entity to response schema
        return AlertRuleResponse.from_entity(rule)
        
    except Exception as e:
        logger.error(f"Error creating rule from template: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create rule from template: {str(e)}"
        )


@router.put("/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: UUID,
    update_data: AlertRuleUpdate,
    current_user: CurrentUserDep = Depends(),
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
        update_dict = update_data.dict(exclude_unset=True)
        
        # Update rule using service
        updated_rule = await rule_service.update_rule(rule_id, update_dict)
        
        if not updated_rule:
            logger.warning(f"Alert rule {rule_id} not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert rule not found"
            )
            
        # Convert domain entity to response schema
        return AlertRuleResponse.from_entity(updated_rule)
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error updating alert rule {rule_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update alert rule: {str(e)}"
        )


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert_rule(
    rule_id: UUID,
    current_user: CurrentUserDep = Depends(),
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
                detail="Alert rule not found or could not be deleted"
            )
            
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error deleting alert rule {rule_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete alert rule: {str(e)}"
        )


@router.patch("/{rule_id}/active", response_model=AlertRuleResponse)
async def update_rule_active_status(
    rule_id: UUID,
    is_active: bool = Query(..., description="New active status"),
    current_user: CurrentUserDep = Depends(),
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
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert rule not found"
            )
            
        # Get updated rule
        updated_rule = await rule_service.get_rule_by_id(rule_id)
        
        # This should never happen if update succeeded
        if not updated_rule:
            logger.error(f"Rule {rule_id} not found after successful update")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
            
        # Convert domain entity to response schema
        return AlertRuleResponse.from_entity(updated_rule)
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error updating rule {rule_id} active status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update alert rule status: {str(e)}"
        )
