# Clarity-AI Digital Twin Backend

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourorganization/Clarity-AI-Backend/) [![Coverage](https://img.shields.io/badge/coverage-87%25-green)](https://github.com/yourorganization/Clarity-AI-Backend/) [![HIPAA Compliant](https://img.shields.io/badge/HIPAA-compliant-blue)](./docs/HIPAA_Compliance.md) [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE) [![Dependencies](https://img.shields.io/badge/deps-UV%20managed-blueviolet)](uv.lock)

> A HIPAA‑compliant platform designed to create computational representations of psychiatric patients—integrating clinical data, biometrics, and other inputs to provide clinicians with additional insights. Clarity AI aims to augment psychiatric care by offering objective analytics, clinical alerts, and documentation assistance.

## What is a Digital Twin for Mental Health?

A digital twin is a computational representation of a patient's mental health state that evolves over time as new data is incorporated. In psychiatry, digital twins integrate diverse data streams (biometric, clinical, genetic, behavioral) to create personalized models that could potentially:

- **Provide Continuous Monitoring**: Track quantitative metrics between appointments
- **Identify Patterns**: Surface correlations between various data points
- **Assist Clinical Decision-Making**: Provide additional data for clinicians to consider
- **Enable Personalization**: Help tailor interventions based on individual characteristics

This approach aims to complement traditional psychiatric assessment methods, which often rely on self-reporting and periodic clinical observations, with additional quantitative measurements.

![Conceptual diagram of a Digital Twin for Health (DT4H), showing the connection between physical entity data and digital twin applications.](./images/digital_twin_concept.png)

## Core Features

- **HIPAA-Compliant Architecture**: End-to-end security with PHI protection
- **Clean Architecture Implementation**: Domain-driven design with separation of concerns
- **Biometric Alert System**: Rule-based monitoring of biometric data
- **Multi-Modal Data Integration**: Combining diverse data sources
- **RESTful API**: Comprehensive endpoints for client applications
- **ML Service Integration**: Infrastructure for deploying ML models

## Quick Start

### Modern Installation (with UV)

```bash
# Clone repository
git clone <repository-url>
cd Clarity-AI-Backend

# Install UV (if needed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create and activate virtual environment
uv venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies (blazing fast!)
uv sync
```

### Start Services

```bash
# Using Docker (Recommended)
docker compose -f docker-compose.test.yml up -d

# Run database migrations
alembic upgrade head

# Start the FastAPI server
uvicorn app.main:app --reload
```

Visit [http://localhost:8000/docs](http://localhost:8000/docs) for API documentation.

## Documentation

- [Architecture Overview](./docs/Architecture_Overview.md): Clean architecture implementation
- [API Reference](./docs/API_Reference.md): Comprehensive API documentation
- [HIPAA Compliance](./docs/HIPAA_Compliance.md): Security and compliance measures
- [Project Structure](./docs/Project_Structure.md): Codebase organization
- [Installation Guide](./docs/INSTALLATION_GUIDE.md): Detailed setup instructions
- [Development Guide](./docs/Development_Guide.md): Development workflow
- [ML Integration](./docs/ML_Integration.md): Machine learning services
- [Domain Model](./docs/Domain_Model.md): Core domain entities and models

## Digital Twin Concept

### Multi-Modal Data Integration

The system integrates data from multiple sources:

- **Biometric Data**: Heart rate, sleep patterns, activity levels
- **Clinical Assessments**: Standardized evaluations, therapy notes
- **Behavioral Data**: Digital biomarkers, activity patterns
- **Environmental Data**: Contextual information
- **Self-Reported Data**: Patient-provided information

### Biometric Alert System

The platform includes a rule-based alerting system for biometric data:

- **Customizable Alert Rules**: Configurable thresholds and conditions
- **Severity Classification**: Multi-level alert categorization
- **Clinical Workflow Integration**: Designed to fit into clinical processes
- **Audit Trail**: Comprehensive logging of alerts and responses

### Machine Learning Services

The backend provides infrastructure for multiple ML services:

- **MentaLLaMA**: A HIPAA-compliant psychiatric analysis service
- **XGBoost Models**: For predictive analytics
- **Psychiatric Analysis Tool (PAT)**: Specialized analysis toolkit

## Technology Stack

- **Backend**: FastAPI, Python 3.11+, SQLAlchemy ORM
- **Database**: PostgreSQL (production), SQLite (development)
- **Caching**: Redis
- **Authentication**: JWT with role-based access control
- **Testing**: Pytest, coverage.py
- **Documentation**: OpenAPI/Swagger
- **Containerization**: Docker, Docker Compose
- **Dependency Management**: UV (modern Python package manager)

## Research Context

The digital twin approach to psychiatric care represents an emerging field of research. This platform provides the technical infrastructure to explore the potential of computational models in mental health, with the understanding that:

- The efficacy of these approaches requires rigorous clinical validation
- Integration of technology into psychiatric care must be done thoughtfully and ethically
- Computational models should complement, not replace, clinical judgment
- Data privacy and security are paramount concerns

## Contributing

We welcome contributions to the Clarity-AI Backend project. See [CONTRIBUTING.md](./CONTRIBUTING.md) for comprehensive guidelines on how to contribute.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for the full terms.

## Enterprise Readiness

The Clarity-AI Backend demonstrates professional engineering practices:

- **Performance-Focused**: UV dependency management for faster development
- **Security-Aware**: Comprehensive vulnerability and license auditing
- **Enterprise Documentation**: Professional documentation and compliance reports
- **Modern Tooling**: Industry-leading Python ecosystem adoption
- **HIPAA Compliance**: Designed with privacy and security at its core