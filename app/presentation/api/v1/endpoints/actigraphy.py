from fastapi import APIRouter

router = APIRouter(
    prefix="/actigraphy",
    tags=["Actigraphy"],
)

# TODO: Implement actigraphy endpoints
# Placeholder for dependency needed by integration tests
# from app.presentation.api.dependencies.services import get_pat_service
