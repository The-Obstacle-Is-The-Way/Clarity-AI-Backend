from fastapi import APIRouter, Depends, HTTPException, status
from app.core.domain.entities.user import UserRole, User as DomainUser
from app.presentation.api.dependencies.auth import require_roles

router = APIRouter()

@router.get("/test-auth", summary="Test endpoint for admin role")
async def test_admin_auth(
    current_user: DomainUser = Depends(require_roles([UserRole.ADMIN]))
):
    """
    A test endpoint that requires admin privileges.
    """
    return {"message": "Admin access granted", "user_id": str(current_user.id), "user_roles": [role.value for role in current_user.roles]} 