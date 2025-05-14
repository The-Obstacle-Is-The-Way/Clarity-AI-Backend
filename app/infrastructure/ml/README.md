# Clarity AI ML Microservices Architecture

This directory contains the implementation of the Clarity AI ML Microservices architecture, which powers the Digital Twin functionality of the platform. The architecture follows Clean Architecture principles, ensuring a clear separation of concerns between the domain and infrastructure layers while maintaining HIPAA compliance.

## Architecture Overview

The ML Microservices architecture consists of four main components:

1. **Symptom Forecasting Microservice**
2. **Biometric-Mental Health Correlation Microservice**
3. **Pharmacogenomics Microservice**
4. **Digital Twin Integration Service**

Each microservice is designed to be independently deployable, scalable, and maintainable, while the integration service provides a unified interface for the domain layer.

## Directory Structure

```
ml/
├── base/                           # Base classes for ML models
│   ├── __init__.py
│   ├── base_model.py               # Abstract base class for all ML models
│   └── model_metrics.py            # Utilities for calculating model metrics
├── utils/                          # Shared utilities
│   ├── __init__.py
│   ├── preprocessing.py            # Data preprocessing utilities
│   └── serialization.py            # Model serialization utilities
├── symptom_forecasting/            # Symptom Forecasting Microservice
│   ├── __init__.py
│   ├── model_service.py            # Service layer for symptom forecasting
│   ├── transformer_model.py        # Transformer-based model implementation
│   ├── xgboost_model.py            # XGBoost model implementation
│   └── ensemble_model.py           # Ensemble model combining transformer and XGBoost
├── biometric_correlation/          # Biometric Correlation Microservice
│   ├── __init__.py
│   ├── model_service.py            # Service layer for biometric correlation
│   └── lstm_model.py               # LSTM model for biometric-mental health correlation
├── pharmacogenomics/               # Pharmacogenomics Microservice
│   ├── __init__.py
│   ├── model_service.py            # Service layer for pharmacogenomics
│   └── gene_medication_model.py    # Model for gene-medication interaction analysis
└── digital_twin_integration_service.py  # Integration service for all microservices
```

## Microservices Details

### 1. Symptom Forecasting Microservice

This microservice predicts the future trajectory of psychiatric symptoms based on historical data. It uses an ensemble approach combining:

- **Transformer-based Model**: A deep learning model with attention mechanisms for capturing complex temporal patterns
- **XGBoost Model**: A gradient boosting model with Bayesian hyperparameter optimization for interpretable predictions
- **Ensemble Approach**: Combines predictions from both models for improved accuracy

Key features:
- Multi-horizon forecasting with uncertainty quantification
- Identification of symptom trends and potential risk periods
- Feature importance analysis for clinical insights

### 2. Biometric-Mental Health Correlation Microservice

This microservice analyzes correlations between biometric data (heart rate, sleep patterns, activity levels) and mental health indicators. It uses:

- **LSTM-based Model**: A deep learning model for time series analysis with attention mechanisms
- **Anomaly Detection**: Identifies unusual patterns in biometric data that may indicate mental health changes
- **Lag Correlation Analysis**: Determines how biometric changes precede mental health changes

Key features:
- Identification of key biometric indicators for each patient
- Personalized monitoring plan recommendations
- Early warning system for mental health deterioration

### 3. Pharmacogenomics Microservice

This microservice predicts medication responses based on genetic markers and provides personalized treatment recommendations. It includes:

- **Medication Response Prediction**: Predicts efficacy of psychiatric medications based on genetic profile
- **Gene-Medication Interaction Analysis**: Identifies potential interactions between genetic variants and medications
- **Side Effect Prediction**: Estimates risk of side effects based on genetic markers

Key features:
- Personalized medication recommendations
- Risk stratification for medication side effects
- Evidence-based rationale for treatment decisions

### 4. Digital Twin Integration Service

This service coordinates all three microservices and provides a unified interface for the domain layer. It:

- Orchestrates parallel execution of microservices
- Combines insights from all analyses into comprehensive patient insights
- Generates integrated recommendations based on all available data

Key features:
- Comprehensive patient insights dashboard
- Prioritized clinical recommendations
- Longitudinal tracking of patient progress

## HIPAA Compliance

All microservices implement strict HIPAA compliance measures:

- PHI is encrypted at rest and in transit
- Field-level encryption for sensitive data
- Patient data is sanitized before processing
- No PHI is included in logs or external calls
- All PHI access is comprehensively logged 
- Access is restricted based on role-based permissions
- Error responses are sanitized to prevent PHI leakage

## Clean Architecture Integration

The ML services follow clean architecture principles:

- **Domain Interfaces**: Core interfaces defined in the domain layer
- **Application Services**: Orchestration at the application layer
- **Infrastructure Implementation**: Concrete implementations in this directory
- **Dependency Inversion**: High-level modules don't depend on low-level modules

## Error Handling

The architecture implements robust error handling:

- Domain-specific exceptions for clear error communication
- Graceful degradation when individual microservices fail
- Comprehensive logging for troubleshooting
- PHI-safe error messages that never expose protected information

## Usage Examples

### Generating Comprehensive Patient Insights

```python
from app.infrastructure.ml.digital_twin_integration_service import DigitalTwinIntegrationService

# Initialize the integration service
integration_service = DigitalTwinIntegrationService(model_base_dir="/path/to/models")

# Generate comprehensive insights
patient_id = "550e8400-e29b-41d4-a716-446655440000"
patient_data = {
    "symptom_history": [...],
    "biometric_data": [...],
    "mental_health_indicators": [...],
    "genetic_markers": {...}
}

insights = await integration_service.generate_comprehensive_patient_insights(
    patient_id=patient_id,
    patient_data=patient_data
)
```

### Using Individual Microservices

Each microservice can also be used independently:

```python
from app.infrastructure.ml.symptom_forecasting.model_service import SymptomForecastingService

# Initialize the service
forecasting_service = SymptomForecastingService(model_dir="/path/to/models")

# Generate symptom forecast
forecast = await forecasting_service.forecast_symptoms(
    patient_id=patient_id,
    data={"symptom_history": [...]},
    horizon=30
)
```

## Development Guidelines

When extending or modifying the ML Microservices architecture:

1. Maintain the separation of concerns between domain and infrastructure layers
2. Follow the BaseModel interface for all new model implementations
3. Ensure all patient data is properly sanitized for HIPAA compliance
4. Add comprehensive unit tests for all new functionality
5. Document all changes in the appropriate README files

## Dependencies

- numpy
- pandas
- scikit-learn
- torch
- xgboost
- joblib

## License

Proprietary - Clarity AI, Inc. All rights reserved.
