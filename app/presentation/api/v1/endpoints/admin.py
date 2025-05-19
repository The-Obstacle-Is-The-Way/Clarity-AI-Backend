from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings  # Corrected import
from app.core.domain.dto.admin_dto import AdminDashboardResponse, HealthCheckResponse
from app.core.domain.entities.user import User
