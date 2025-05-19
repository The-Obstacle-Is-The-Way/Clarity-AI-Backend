from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings  # Corrected import
from app.core.domain.dto.user_dto import (
    UserCreateRequest,
    UserResponse,
    UserCreateResponse,
)

# ... existing code ...
