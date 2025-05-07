from fastapi.security import HTTPBearer
from pydantic import BaseModel

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import
from app.core.domain.dto.actigraphy_analysis_dto import ActigraphyAnalysisRequest, ActigraphySummaryResponse
from app.core.domain.entities.actigraphy_analysis import ActigraphyAnalysis 