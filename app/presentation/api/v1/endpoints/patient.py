from fastapi import APIRouter

router = APIRouter(
    prefix="/patients",
    tags=["Patients"],
)

# TODO: Implement patient endpoints
# Placeholder for dependencies potentially needed by tests
# from app.presentation.api.dependencies.services import get_patient_service
