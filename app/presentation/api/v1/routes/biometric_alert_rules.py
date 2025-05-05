"""
Biometric Alert Rules Endpoints Module.

Provides API endpoints for managing biometric alert rules.
"""

import logging
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import UUID4
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.entities.user import User
from app.infrastructure.database.session import get_async_session
from app.infrastructure.security.rate_limiting.limiter import RateLimiter
from app.presentation.api.dependencies.auth import get_current_active_user
from app.presentation.api.schemas.alert import (
    AlertRuleResponse,
    AlertRuleUpdateRequest,
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
    description=(
        "Retrieves a list of biometric alert rules configured for the currently "
        "authenticated user."
    ),
    tags=["Biometric Alert Rules"],
    dependencies=[Depends(RateLimiter(times=20, seconds=60))],
)
async def get_alert_rules(
    db: Annotated[AsyncSession, Depends(get_async_session)],
    current_user: User = Depends(get_current_active_user),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[AlertRuleResponse]:
    """
    Get a list of biometric alert rules for the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} fetching alert rules with limit {limit}, offset {offset}.")
    # TODO: Implement actual repository call using the 'db' session
    # rules = await rule_repo.get_rules_by_user(db=db, user_id=current_user.id, limit=limit, offset=offset)
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
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_active_user),
) -> AlertRuleResponse:
    """
    Get details for a specific biometric alert rule owned by the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} fetching alert rule {rule_id}")
    # TODO: Implement actual repository call using the 'db' session
    # rule = await rule_repo.get_rule_by_id(db=db, rule_id=rule_id, user_id=current_user.id)
    # if not rule:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not authorized")
    # Placeholder response:
    # This placeholder needs access to AlertRuleResponse fields to be valid
    # For now, let's assume we'd fetch and return based on the ID
    if str(rule_id) == "11111111-1111-1111-1111-111111111111": # Dummy check
        return AlertRuleResponse(
            id=UUID("11111111-1111-1111-1111-111111111111"),
            name="Placeholder Rule",
            description="This is a placeholder",
            biometric_type="HEART_RATE", # Assuming biometric type
            threshold_level=100, # Assuming threshold level
            comparison_operator="GREATER_THAN", # Assuming comparison operator
            is_active=True,
            created_by=str(current_user.id),  # RESTORED (assuming string UUID)
            updated_by=str(current_user.id),  # RESTORED
            created_at=datetime.now(),
            last_updated=datetime.now(),
        )
    else:
        raise HTTPException(status_code=404, detail="Rule not found")


@router.put(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_200_OK,
    summary="Update a biometric alert rule",
)
async def update_alert_rule(
    rule_data: AlertRuleUpdateRequest,
    rule_id: UUID4 = Path(..., description="ID of the alert rule to update"),
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_active_user),
) -> AlertRuleResponse:
    """
    Update an existing biometric alert rule owned by the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} updating alert rule {rule_id}")
    # TODO: Implement actual repository call using the 'db' session
    # updated_rule = await rule_repo.update_rule(db=db, rule_id=rule_id, user_id=current_user.id, update_data=rule_data)
    # if not updated_rule:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not authorized")
    # Placeholder response:
    return AlertRuleResponse(
        id=rule_id,
        name=rule_data.name or "Updated Rule Name",
        description=rule_data.description or "Updated description",
        biometric_type=rule_data.biometric_type or "HEART_RATE", # Assuming biometric type
        threshold_level=rule_data.threshold_level or 100, # Assuming threshold level
        comparison_operator=rule_data.comparison_operator or "GREATER_THAN", # Assuming comparison operator
        is_active=rule_data.is_active if rule_data.is_active is not None else True,
        created_by=str(current_user.id),
        updated_by=str(current_user.id),
        created_at=datetime.now(), # Placeholder - should be original
        last_updated=datetime.now(),
    )


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a biometric alert rule",
)
async def delete_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to delete"),
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_active_user),
) -> None:
    """
    Delete a specific biometric alert rule owned by the current user.

    (Placeholder Implementation)
    """
    logger.info(f"User {current_user.id} deleting alert rule {rule_id}")
    # TODO: Implement actual repository call using the 'db' session
    # success = await rule_repo.delete_rule(db=db, rule_id=rule_id, user_id=current_user.id)
    # if not success:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found or not authorized")
    # No return body for 204
    return None
