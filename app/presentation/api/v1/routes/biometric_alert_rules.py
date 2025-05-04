"""
Biometric Alert Rules Endpoints Module.

Provides API endpoints for managing biometric alert rules.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import UUID4

from app.core.domain.entities.user import User

# Domain / Repository imports
from app.domain.repositories.biometric_rule_repository import (
    BiometricRuleRepository,
)
from app.presentation.api.dependencies.auth import get_current_active_user

# Presentation layer imports
from app.presentation.api.schemas.alert import (
    AlertRuleCreateRequest,
    AlertRuleResponse,
    AlertRuleUpdateRequest,
)
from app.presentation.api.v1.dependencies.biometric import (
    get_biometric_rule_repository,
)

logger = logging.getLogger(__name__)

# Router without global dependencies that might interfere with static analysis
router = APIRouter(
    prefix="/alert-rules",
    tags=["biometric-alert-rules"],
)


# =============================================================================
# Temporarily comment out the entire POST endpoint to isolate the FastAPIError
# =============================================================================
# @router.post(
#     "",
#     # response_model=AlertRuleResponse, # Temporarily set to None
#     response_model=None,
#     status_code=status.HTTP_201_CREATED,
#     summary="Create a new biometric alert rule",
#     description="Adds a new biometric alert rule to the system.",
# )
# async def create_alert_rule(
#     rule_data: AlertRuleCreateRequest,
#     # rule_repo: BiometricRuleRepository = Depends(get_biometric_rule_repository),
#     current_user: User = Depends(get_current_active_user),
# ) -> AlertRuleResponse:
#     """Endpoint to create a new biometric alert rule."""
#     # Placeholder implementation
#     # In a real implementation, you would use rule_repo to save the rule
#     # logger.info(f"User {current_user.id} creating alert rule: {rule_data.name}") # Needs uncommenting later
#     logger.info(f"User creating alert rule: {rule_data.name}") # Temp log
#     # TODO: Implement actual repository call
#     # rule = await rule_repo.create_rule(user_id=current_user.id, rule_data=rule_data)
#     # Placeholder response - replace with actual created object
#     # return AlertRuleResponse.model_validate(rule)
#     return AlertRuleResponse(
#         id=UUID("11111111-1111-1111-1111-111111111111"),  # Dummy ID
#         name=rule_data.name,
#         description=rule_data.description,
#         biometric_type=rule_data.biometric_type,
#         threshold_level=rule_data.threshold_level,
#         comparison_operator=rule_data.comparison_operator,
#         is_active=rule_data.is_active,
#         created_by=str(current_user.id),  # RESTORED (assuming string UUID)
#         updated_by=str(current_user.id),  # RESTORED
#     )
# =============================================================================


@router.get(
    "",
    response_model=list[AlertRuleResponse],
    summary="Get biometric alert rules for the current user",
)
async def get_alert_rules(
    current_user: User = Depends(get_current_active_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[AlertRuleResponse]:
    """
    Get a list of biometric alert rules for the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} fetching alert rules.")
    # TODO: Implement actual repository call
    # rules = await rule_repo.get_rules_by_user(user_id=current_user.id, limit=limit, offset=offset)
    # Placeholder response:
    return []


@router.get(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a specific biometric alert rule by ID",
)
async def get_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to retrieve"),
    current_user: User = Depends(get_current_active_user),
) -> AlertRuleResponse:
    """
    Get details for a specific biometric alert rule owned by the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} fetching alert rule {rule_id}")
    # TODO: Implement actual repository call
    # rule = await rule_repo.get_rule_by_id(rule_id=rule_id, user_id=current_user.id)
    # if not rule:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not authorized")
    # Placeholder response:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not implemented yet"
    )
    # return rule


@router.put(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    summary="Update a biometric alert rule",
)
async def update_alert_rule(
    rule_data: AlertRuleUpdateRequest,
    rule_id: UUID4 = Path(..., description="ID of the alert rule to update"),
    current_user: User = Depends(get_current_active_user),
) -> AlertRuleResponse:
    """
    Update an existing biometric alert rule owned by the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} updating alert rule {rule_id}")
    # TODO: Implement actual repository call
    # updated_rule = await rule_repo.update_rule(rule_id=rule_id, user_id=current_user.id, rule_data=rule_data)
    # if not updated_rule:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not authorized")
    # Placeholder response:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not implemented yet"
    )
    # return updated_rule


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a specific biometric alert rule",
)
async def delete_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to delete"),
    current_user: User = Depends(get_current_active_user),
) -> None:
    """
    Delete a specific biometric alert rule owned by the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} deleting alert rule {rule_id}")
    # TODO: Implement actual repository call
    # success = await rule_repo.delete_rule(rule_id=rule_id, user_id=current_user.id)
    # if not success:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not authorized")
    # Placeholder response (no return on success):
    # return None
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not implemented yet"
    )
