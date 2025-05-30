# Clarity-AI Digital Twin Backend

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/The-Obstacle-Is-The-Way/Clarity-AI-Backend/actions) [![Coverage](https://img.shields.io/badge/coverage-85%25-green)](https://github.com/The-Obstacle-Is-The-Way/Clarity-AI-Backend/coverage) [![HIPAA Compliant](https://img.shields.io/badge/HIPAA-compliant-blue)](./docs/content/compliance/HIPAA_Compliance.md) [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE) [![Dependencies](https://img.shields.io/badge/deps-UV%20managed-blueviolet)](uv.lock)

> A HIPAA‑compliant platform designed to create computational representations of psychiatric patients—integrating 
> clinical data, biometrics, and other inputs to provide clinicians with additional insights. Clarity AI aims to 
> augment psychiatric care by offering objective analytics, clinical alerts, and documentation assistance.

## What is a Digital Twin for Mental Health?

A digital twin is a computational representation of a patient's mental health state that evolves over time 
as new data is incorporated. In psychiatry, digital twins integrate diverse data streams (biometric, clinical, 
genetic, behavioral) to create personalized models that aim to:

- **Provide Continuous Monitoring**: Track quantitative metrics between appointments
- **Identify Patterns**: Surface correlations between various data points
- **Assist Clinical Decision-Making**: Provide additional data for clinicians to consider
- **Enable Personalization**: Help tailor interventions based on individual characteristics

This approach is designed to complement traditional psychiatric assessment methods, which often rely on 
self-reporting and periodic clinical observations, with additional quantitative measurements.

![Conceptual diagram of a Digital Twin for Health (DT4H), showing the connection between physical entity data and digital twin applications.](./docs/images/digital_twin_concept.png)

## Core Features

- **HIPAA-Compliant Architecture**: End-to-end security with PHI protection
- **Clean Architecture Implementation**: Domain-driven design with clear separation of concerns
- **RESTful API**: Well-documented endpoints with OpenAPI/Swagger
- **Advanced Authentication**: JWT-based authentication with role-based access control
- **Extensible Machine Learning Framework**: Integration of multiple analysis models
- **Digital Twin Management**: Creation and updates of patient digital representations
- **Real-time Processing**: Stream processing capabilities for sensor and clinical data
- **Secure PHI Storage**: Encrypted data storage and transmission

### Clinical Monitoring

The platform includes tools designed to assist clinicians in their existing workflows:

- **Objective Measurement**: Collection of quantitative metrics to supplement clinical assessments
- **Alert System**: Configurable notifications based on predefined clinical thresholds
- **Documentation Assistant**: Tools aimed at streamlining documentation of clinical processes
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
- **Documentation**: OpenAPI/Swagger, MkDocs with Material theme
- **Containerization**: Docker, Docker Compose
- **Dependency Management**: UV (modern Python package manager)

## Research Context

The digital twin approach to psychiatric care represents an emerging field of research. This platform 
provides the technical infrastructure to explore the potential of computational models in mental health, 
with the understanding that:

- The efficacy of these approaches requires rigorous clinical validation
- Integration of technology into psychiatric care must be done thoughtfully and ethically
- Computational models should complement, not replace, clinical judgment
- Data privacy and security are paramount concerns

## Getting Started

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for containerized deployment)
- PostgreSQL (for production deployment)

### Installation

1. Clone the repository

   ```bash
   git clone https://github.com/The-Obstacle-Is-The-Way/Clarity-AI-Backend.git
   cd Clarity-AI-Backend
   ```

2. Install dependencies using UV

   ```bash
   pip install uv
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -r requirements.txt
   ```

3. Set up environment variables

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Initialize the database

   ```bash
   python -m scripts.initialize_db
   ```

5. Run the application

   ```bash
   uvicorn app.main:app --reload
   ```

6. Access the API documentation at http://localhost:8000/docs

### Docker Deployment

```bash
docker-compose up -d
```

## Documentation

Comprehensive documentation is available in the [docs](./docs) directory:

- [API Documentation](./docs/content/api/README.md)
- [Architecture Overview](./docs/content/architecture/README.md)
- [Development Guide](./docs/content/development/README.md)
- [HIPAA Compliance](./docs/content/compliance/HIPAA_Compliance.md)

## Contributing

We welcome contributions to the Clarity-AI Backend project. See [CONTRIBUTING.md](./CONTRIBUTING.md) for 
comprehensive guidelines on how to contribute.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) for the full terms.

## Enterprise Readiness

The Clarity-AI Backend demonstrates professional engineering practices:

- **Performance-Focused**: UV dependency management for faster development
- **Security-Aware**: Comprehensive vulnerability and license auditing
- **Enterprise Documentation**: Professional documentation and compliance reports
- **Modern Tooling**: Industry-leading Python ecosystem adoption
- **HIPAA Compliance**: Designed with privacy and security at its core