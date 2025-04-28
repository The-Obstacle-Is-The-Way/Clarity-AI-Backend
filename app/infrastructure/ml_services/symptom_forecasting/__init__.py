"""
/mnt/c/Users/JJ/Desktop/NOVAMIND-WEB/Novamind-Backend/app/infrastructure/ml_services/symptom_forecasting/__init__.py

Initialization file for the Symptom Forecasting Service module.
"""

from app.infrastructure.ml_services.symptom_forecasting.service import (
    SymptomForecastingServiceImpl,
)

__all__ = ["SymptomForecastingServiceImpl"]
