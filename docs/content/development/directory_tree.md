# Directory Tree Structure

This document provides a visual tree representation of the Clarity-AI Backend codebase structure. This complements the detailed [Project Structure](./project_structure.md) documentation.

## Root Directory Structure

```
Clarity-AI-Backend/
├── app/                    # Main application code
├── alembic/                # Database migrations
├── docs/                   # Documentation
│   ├── content/            # Structured documentation content
│   ├── templates/          # Documentation templates
│   └── audit/              # Documentation audit results
├── deployment/             # Deployment configurations
├── logs/                   # Application logs
├── scripts/                # Utility scripts
├── tasks/                  # Task management
├── tools/                  # Development tools
│   ├── hipaa/              # HIPAA compliance tools
│   ├── refactor/           # Code refactoring tools
│   └── test/               # Testing tools
├── .vale/                  # Documentation linting rules
├── main.py                 # Application entry point
└── requirements.txt        # Dependencies
```

## Core Application Structure

The following tree shows the key directories in the application structure, focusing on the primary architecture components:

```
app/
├── core/
│   ├── config/
│   ├── domain/
│   │   ├── entities/
│   │   ├── enums/
│   │   └── exceptions/
│   ├── interfaces/
│   │   ├── repositories/
│   │   ├── security/
│   │   └── services/
│   └── services/
│       ├── encryption/
│       └── ml/
│
├── domain/
│   ├── entities/
│   │   ├── digital_twin/
│   │   └── ml/
│   ├── value_objects/
│   ├── services/
│   └── repositories/
│
├── application/
│   ├── use_cases/
│   │   ├── analytics/
│   │   ├── appointment/
│   │   ├── digital_twin/
│   │   └── patient/
│   ├── services/
│   └── dtos/
│
├── infrastructure/
│   ├── persistence/
│   │   ├── repositories/
│   │   └── sqlalchemy/
│   ├── security/
│   │   ├── audit/
│   │   └── jwt/
│   ├── ml_services/
│   │   ├── biometric_correlation/
│   │   ├── digital_twin_integration/
│   │   └── pharmacogenomics/
│   └── external/
│       ├── aws/
│       └── openai/
│
├── presentation/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── endpoints/
│   │   │   ├── dependencies/
│   │   │   ├── routes/
│   │   │   └── schemas/
│   │   └── adapters/
│   └── middleware/
│
└── tests/
    ├── unit/
    │   ├── domain/
    │   ├── application/
    │   ├── infrastructure/
    │   └── presentation/
    └── integration/
        ├── api/
        └── infrastructure/
```

## Key Components by Layer

### Domain Layer

```
domain/
├── entities/                # Business entities
│   ├── digital_twin.py      # Digital twin entity
│   ├── patient.py           # Patient entity
│   ├── alert.py             # Alert entity
│   └── ml/
│       ├── model.py         # ML model entity
│       └── prediction.py    # Prediction entity
├── value_objects/           # Immutable value objects
│   ├── patient_id.py        # Patient identifier
│   ├── biometric_reading.py # Biometric reading value
│   └── medication.py        # Medication value object
└── services/                # Domain services
    ├── digital_twin_service.py  # Digital twin service
    └── alert_service.py     # Alert service
```

### Application Layer

```
application/
├── use_cases/               # Business use cases
│   ├── digital_twin/
│   │   ├── create_digital_twin.py
│   │   ├── update_digital_twin.py
│   │   └── analyze_digital_twin.py
│   └── patient/
│       ├── register_patient.py
│       ├── update_patient.py
│       └── get_patient_history.py
└── dtos/                    # Data transfer objects
    ├── patient_dto.py
    ├── digital_twin_dto.py
    └── alert_dto.py
```

### Infrastructure Layer

```
infrastructure/
├── persistence/             # Data persistence
│   ├── repositories/
│   │   ├── patient_repository.py
│   │   └── digital_twin_repository.py
│   └── sqlalchemy/
│       ├── models/
│       │   ├── patient_model.py
│       │   └── digital_twin_model.py
│       └── repositories/
│           ├── sqlalchemy_patient_repository.py
│           └── sqlalchemy_digital_twin_repository.py
└── ml_services/
    ├── mentallama/
    │   ├── client.py
    │   └── models.py
    └── xgboost/
        ├── predictor.py
        └── trainer.py
```

### Presentation Layer

```
presentation/
├── api/
│   └── v1/
│       ├── endpoints/
│       │   ├── patients.py
│       │   ├── digital_twins.py
│       │   ├── alerts.py
│       │   └── auth.py
│       └── schemas/
│           ├── patient.py
│           ├── digital_twin.py
│           └── alert.py
└── middleware/
    ├── auth_middleware.py
    ├── error_handler.py
    └── rate_limiter.py
```

## Documentation Structure

```
docs/
├── content/
│   ├── api/                 # API documentation
│   │   ├── README.md
│   │   └── endpoints/
│   │       ├── patients.md
│   │       ├── digital_twins.md
│   │       └── auth.md
│   ├── architecture/        # Architecture documentation
│   │   ├── overview.md
│   │   ├── clean_architecture_diagram.md
│   │   └── domain_model.md
│   ├── development/         # Development guides
│   │   ├── project_structure.md
│   │   ├── directory_tree.md
│   │   ├── getting_started.md
│   │   └── test_strategy.md
│   └── compliance/          # Compliance documentation
│       └── HIPAA_Compliance.md
├── templates/               # Documentation templates
│   ├── API_ENDPOINT_TEMPLATE.md
│   ├── ARCHITECTURE_COMPONENT_TEMPLATE.md
│   └── README_TEMPLATE.md
└── STYLE_GUIDE.md           # Documentation style guide
```

This directory tree provides a visual representation of the key components of the Clarity-AI Backend codebase. For more detailed information about each component, refer to the [Project Structure](./project_structure.md) documentation.