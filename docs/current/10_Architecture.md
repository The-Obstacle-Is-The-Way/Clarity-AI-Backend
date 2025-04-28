# Novamind Backend Architecture

**Version:** 2.0
**Date:** Current *(Updated [Current Date] to reflect codebase analysis)*

## 1. Introduction

### 1.1. Purpose

This document outlines the *intended* architecture for the Novamind Digital Twin Platform's backend system. It serves as a guide for architectural decisions, aiming to ensure consistency, maintainability, and scalability. *While the codebase contains elements aligned with this vision, significant refactoring is required to fully realize this architecture.*

The architecture *aims to adhere* to Clean Architecture principles, emphasizing separation of concerns, testability, and independence from specific frameworks or databases.

### 1.2. Dependency Rule

The fundamental rule *should be* that dependencies can only point inward:

1.  **Domain layer** has no dependencies on any other layer.
2.  **Application layer** depends only on the domain layer.
3.  **Infrastructure layer** depends on domain and application layers.
4.  **API/Presentation layer** depends on application and sometimes infrastructure layers. *(Note: The code currently has both `api/` and `presentation/` directories within `app/`. Their distinct roles and interaction with this rule need refinement.)*
5.  **Core layer** is used by all other layers but depends on none.

This rule *is intended to be* enforced through:

-   **Interfaces**: Inner layers define interfaces that outer layers implement.
-   **Dependency Injection**: Dependencies are injected rather than directly imported. *(Note: DI is used, but the codebase contains extensive test-specific monkey-patching, indicating potential issues with dependency management or test strategy.)*
-   **DTOs**: Data Transfer Objects for crossing layer boundaries.
-   **Mappers**: Convert between domain entities and infrastructure/API models.

*Current Status: Analysis indicates potential violations of the dependency rule, particularly due to extensive mocking and patching in API endpoint implementations (`patients.py`, `digital_twins.py`) that bypass standard repository patterns for test purposes.*

## 2. Architectural Layers (Clean Architecture)

The platform *adopts* Clean Architecture principles with the following *target* layers. *The actual directory structure shows some deviation.*

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  ┌───────────────────────────────────────────────────────┐   │
│  │                                                       │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │                                                │   │   │
│  │  │  ┌─────────────────────────────────────────┐   │   │   │
│  │  │  │                                         │   │   │   │
│  │  │  │  ┌─────────────────────────────────┐    │   │   │   │
│  │  │  │  │                                 │    │   │   │   │
│  │  │  │  │          Domain Layer           │    │   │   │   │
│  │  │  │  │    (Entities, Value Objects,    │    │   │   │   │
│  │  │  │  │     Repository Interfaces)      │    │   │   │   │
│  │  │  │  └─────────────────────────────────┘    │   │   │   │
│  │  │  │           Application Layer             │   │   │   │
│  │  │  │      (Use Cases, Services, DTOs)        │   │   │   │
│  │  │  └─────────────────────────────────────────┘   │   │   │
│  │  │              Infrastructure Layer              │   │   │
│  │  │     (Repositories, External Services)          │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  │            API / Presentation Layer(s)                │   │
│  │             (FastAPI, Controllers, UI)                │   │
│  └───────────────────────────────────────────────────────┘   │
│                       Core Layer (Shared Utilities)          │
│                      (Config, Logging, Errors)               │
└──────────────────────────────────────────────────────────────┘
```
*Actual Directory Structure (`backend/app/`): `domain/`, `application/`, `infrastructure/`, `api/`, `presentation/`, `core/`, `config/`, `tests/`, `demo/`. The presence of both `api/` and `presentation/` needs clarification. `config/` likely belongs in or serves `core/`. `demo/` purpose is unclear.*

### 2.1. Domain Layer

*Intended to represent* the heart of the system and contain the core business logic and entities.

**Key Components (Target)**:

-   **Entities**: Business objects (Patient, Clinician, Treatment, DigitalTwin). *(Note: `DigitalTwin` entity exists but is simpler than the full vision. A more complex, potentially disconnected version also exists.)*
-   **Value Objects**: Immutable descriptive objects. *(Implementation status TBD)*
-   **Aggregates**: Clusters treated as single units. *(Implementation status TBD)*
-   **Domain Services**: Stateless operations. *(Note: `DigitalTwinService` exists, but some logic is placeholder/aspirational.)*
-   **Domain Events**: Representations of activities. *(Implementation status TBD)*
-   **Repository Interfaces**: Abstractions for data access. *(Interfaces exist, but implementations are often mocked or in-memory stores in API layers.)*

**Implementation Principles (Target)**:
-   Entities use primitives, other entities, or value objects.
-   No dependencies on frameworks, databases, or external services.
-   Rich domain model with behavior.

*Current Status: Core entities like `Patient` and `DigitalTwin` exist, along with repository interfaces. However, the richness of the domain model and adherence to principles require further validation and refactoring. Multiple conflicting `DigitalTwin` entity definitions exist.*

### 2.2. Application Layer

*Intended to orchestrate* the flow of data to and from domain entities.

**Key Components (Target/Partial)**:

-   **Use Cases/Services**: Application-specific business rules (e.g., `CreatePatientUseCase`). *(Structure exists in `application/use_cases/`. Application services like `DigitalTwinApplicationService` exist in `application/services/` and correctly orchestrate repository interactions for some features.)*
-   **DTOs**: Simple objects for data passing. *(Used in API layer, TBD in Application)*
-   **Command/Query Handlers**: CQRS pattern implementation. *(Aspirational)*
-   **Application Interfaces**: Abstractions of infrastructure services. *(Used, e.g., ML service interfaces defined in `domain/interfaces`, likely implemented in `infrastructure` and used by Application services)*

**Implementation Principles (Target)**:
-   Thin layer coordinating domain objects.
-   Does not contain business rules itself.
-   Mediates between the API/UI and the Domain.

*Current Status: The application layer structure (`use_cases/`, `services/`, `interfaces/`) exists and contains services (e.g., `DigitalTwinApplicationService`) that demonstrate the intended orchestration role. However, the API layer (`patients.py`, `digital_twins.py`) currently bypasses this layer for many operations, directly using mocks/in-memory stores, indicating incomplete integration.*

### 2.3. Infrastructure Layer

*Intended to provide implementations* for interfaces defined in inner layers.

**Key Components (Target/Partial)**:

-   **Repository Implementations**: Data access (e.g., `PostgreSQLPatientRepository`). *(Largely missing or replaced by mocks/in-memory stores (`mock_patient_repository.py`, `mock_digital_twin_repository.py`) in current API implementations. Other repositories like `user_repository.py` may have partial/alternative implementations.)*
-   **External Service Integrations / Adapters**: Adapters for third-party services. *(Structure exists in `infrastructure/external/`, specific implementations TBD. Adapters for ML services exist in `infrastructure/ml/adapters.py`.)*
-   **ML Service Implementations**: Concrete implementations of ML models/pipelines. *(Implementations for PAT, MentalLLaMA, PHI Detection, etc., exist in `infrastructure/ml/`.)*
-   **ORM Models**: Database-specific models. *(Basic SQLAlchemy models like `PatientModel` exist in `infrastructure/database/models.py`, but appear disconnected from current API/repository mock implementations.)*
-   **Security Implementations**: Auth mechanisms. *(Largely missing, `infrastructure/security/` directory exists but content TBD)*
-   **Data Storage**: Database access. *(SQLAlchemy session setup exists (`infrastructure/database/session.py`), but functionally replaced by mocks/in-memory stores in key areas.)*
-   **Messaging**: Message queue implementations. *(Directory `infrastructure/messaging/` exists, content TBD)*
-   **Caching**: Cache implementations. *(Directory `infrastructure/cache/` exists, content TBD)*
-   **Logging**: Logging setup/handlers. *(Directory `infrastructure/logging/` exists, content TBD)*

**Implementation Principles (Target)**:
-   Adapts external libraries.
-   Implements interfaces from inner layers.
-   Isolates framework-specific code.

*Current Status: The infrastructure layer is underdeveloped. Key repository implementations are missing, hindering proper adherence to Clean Architecture.*

### 2.4. API / Presentation Layer

*Serves* as the primary external interface. *(Note: Code has both `api/` and `presentation/` dirs. `presentation/` seems to contain the FastAPI implementation as per `11_API_Architecture.md`.)*

**Key Components (Implemented/Partial)**:

-   **Controllers/Endpoints**: Handle HTTP requests (FastAPI Routers in `presentation/api/v1/endpoints/`). *(Implemented, but many documented endpoints are missing, and many implemented endpoints are undocumented. Heavy test-specific patching exists.)*
-   **Request/Response Models**: Pydantic DTOs/Schemas (`presentation/api/v1/schemas/`). *(Implemented)*
-   **Middleware**: Cross-cutting concerns (`presentation/middleware/`). *(Directory exists, specific implementations like Auth, PHI Scrubbing, Rate Limiting TBD/missing)*
-   **API Documentation**: OpenAPI/Swagger. *(Intended, but docs are inconsistent with code.)*
-   **Validation**: Request validation using Pydantic. *(Implemented)*

**Implementation Principles (Target)**:
-   Uses FastAPI framework. *(Confirmed)*
-   Performs input validation. *(Confirmed)*
-   Handles authentication and authorization. *(Largely missing)*
-   Maps requests to application use cases. *(Needs verification, current endpoints often contain significant logic)*
-   Formats responses according to API standards. *(Partially implemented, error formatting needs improvement)*

*Current Status: FastAPI is used, and Pydantic validation is present. However, crucial aspects like authentication, authorization, comprehensive error handling, and alignment with documented endpoints are missing or incomplete. Significant reliance on mocks and test-specific patches compromises architectural integrity.*

### 2.5. Core Layer

*Contains* cross-cutting concerns and shared utilities.

**Key Components (Target/Partial)**:

-   **Error Handling**: Global error types (`core/exceptions/`). *(Base exceptions defined)*
-   **Logging**: Centralized logging setup. *(TBD - infrastructure/logging exists)*
-   **Configuration**: Application configuration. *(Implemented via `config/settings.py`, likely Pydantic BaseSettings)*
-   **Common Utilities**: Shared helpers (`core/utils/`). *(Directory exists, content TBD)*
-   **Security Utilities**: Shared security functions (`core/security/`). *(Directory exists, content TBD)*
-   **Base Types**: Common enums/types (`core/constants.py`). *(File exists)*

*Current Status: The `core/` directory exists with exceptions, constants, and utils. Configuration is handled in `app/config/settings.py`. The purpose/placement of subdirectories like `core/models/`, `core/services/`, `core/ml/` needs clarification as they might better belong in other layers.*

## 3. AI/ML Stack

The backend *is intended to integrate* multiple advanced AI/ML components:

-   **Digital Twin Core:** Domain-driven patient modeling. *(Basic entity/service exists, complex vision largely aspirational)*
-   **Pretrained Actigraphy Transformer (PAT):** Multimodal behavioral analysis. *(Implementation logic exists in `infrastructure/ml/pat/`, API endpoint exists, integration depth TBD)*
-   **XGBoost:** Clinical prediction. *(Implementation logic likely within `infrastructure/ml/symptom_forecasting` or `biometric_correlation`, API endpoint exists, integration depth TBD)*
-   **MentalLLaMA33b:** Foundation model for mental health NLP. *(Implementation logic exists in `infrastructure/ml/mentallama/`, API endpoint exists, integration depth TBD)*
-   **LSTM:** Temporal modeling. *(Mentioned in docs, specific implementation TBD)*
-   **PHI Detection:** Service for identifying PHI in text. *(Implementation logic exists in `infrastructure/ml/phi_detection/`)*

*Current Status: Implementation code for PAT, MentalLLaMA, PHI Detection, and likely XGBoost exists within `infrastructure/ml/`. API endpoints also exist. However, their effective integration into the application services and core Digital Twin state management requires further validation and potential refactoring.*

## 4. Technology Stack

### 4.1. Backend Technologies (Target/Partial)

-   **Primary Language:** Python 3.10+ *(Confirmed)*
-   **Framework:** FastAPI *(Confirmed)*
-   **Databases:** PostgreSQL (Relational), MongoDB (Document) *(Aspirational; current implementation uses mocks/in-memory)*
-   **Cache:** Redis *(Aspirational)*
-   **Message Queue:** RabbitMQ / Kafka / AWS SNS/SQS *(Aspirational)*
-   **Search:** Elasticsearch *(Aspirational)*

### 4.2. AI/ML Technologies (Target/Partial)

-   **Machine Learning:** PyTorch, scikit-learn, XGBoost *(XGBoost endpoint exists)*
-   **Deep Learning:** PyTorch, Hugging Face Transformers *(MentalLLaMA likely uses Transformers; PAT potentially PyTorch)*
-   **Natural Language Processing:** spaCy, NLTK, Hugging Face *(MentalLLaMA likely uses Transformers)*
-   **Scientific Computing:** NumPy, SciPy, Pandas *(Likely used, TBD)*
-   **Visualization:** Matplotlib, Plotly, Bokeh *(Visualization endpoint exists, library used TBD)*

### 4.3. Infrastructure (Target)

-   **Containerization:** Docker *(Dockerfile likely exists, TBD)*
-   **Orchestration:** Kubernetes *(Aspirational)*
-   **CI/CD:** GitHub Actions *(Workflow files likely exist, TBD)*
-   **Monitoring:** Prometheus, Grafana *(Aspirational)*
-   **Logging:** ELK Stack / CloudWatch *(Aspirational)*

### 4.4. Security Technologies (Target/Aspirational)

-   **Authentication:** OAuth 2.0 / OpenID Connect *(Aspirational; implementation missing)*
-   **Encryption:** AES-256 (at rest), TLS 1.3 (in transit) *(Aspirational; implementation TBD)*
-   **Secrets Management:** HashiCorp Vault / AWS Secrets Manager *(Aspirational)*
-   **Vulnerability Scanning:** OWASP ZAP, Snyk / equivalent tools *(Aspirational)*

*Current Status: The core language and framework (Python/FastAPI) are confirmed. Most other technologies, especially databases, caching, messaging, monitoring, and specific security tools, appear to be aspirational or not yet implemented/verified in the codebase.*

## 5. Key Design Patterns (Target/Aspirational)

The platform *aims to utilize* several design patterns:

### 5.1. Structural Patterns

-   **Repository Pattern**: Abstracts data access. *(Interfaces exist, but implementations are missing/mocked in key areas)*
-   **Adapter Pattern**: Wraps external services. *(TBD)*
-   **Dependency Injection**: Services receive dependencies. *(Used by FastAPI, but potentially undermined by test patching)*
-   **Facade Pattern**: Simplifies subsystems. *(TBD)*

### 5.2. Behavioral Patterns

-   **Command Pattern**: Encapsulates actions (CQRS). *(Aspirational)*
-   **Observer Pattern**: Event-driven interactions. *(Aspirational)*
-   **Strategy Pattern**: Selectable algorithms. *(TBD)*
-   **Chain of Responsibility**: Processing pipelines. *(TBD)*

### 5.3. Creational Patterns

-   **Factory Pattern**: Creates objects. *(TBD)*
-   **Builder Pattern**: Constructs complex objects. *(TBD)*
-   **Singleton Pattern**: Shared resources. *(TBD)*

*Current Status: Repository and Dependency Injection patterns are present architecturally, but their implementation is currently flawed or incomplete. Other patterns are largely aspirational.*

## 6. System Interactions (Target/Aspirational)

### 6.1. Event-Driven Architecture

The system *is intended to use* events for loose coupling:

-   **Domain Events**, **Integration Events**, **Event Bus**, **Event Sourcing**. *(Aspirational)*

### 6.2. External Integrations

The platform *is planned to integrate* with:

-   **EHR Systems** (HL7 FHIR), **Patient Portals**, **Wearable Devices**, **Analytics Dashboards**. *(Aspirational)*

*Current Status: Event-driven architecture and major external integrations appear aspirational.*

## 7. Security Architecture

*Refer to `12_Security_Architecture.md` for the detailed security vision. Key aspects include HIPAA compliance, PHI protection, robust AuthN/AuthZ, encryption, and audit logging.*

*Current Status: Security implementation is currently minimal. Core components like authentication, authorization, and audit logging are largely missing in the reviewed API code. See `12_Security_Architecture.md` (pending updates) for a detailed gap analysis.*

## 8. Deployment Architecture (Target/Aspirational)

The platform is *designed for* cloud-native deployment:

-   **Containerization** (Docker), **Orchestration** (Kubernetes), **IaC** (Terraform), **CI/CD Pipeline**, **Blue/Green Deployments**, **Auto-scaling**. *(Largely aspirational, requires infrastructure setup)*

## 9. Current Capabilities and Roadmap

### 9.1. Current Capabilities *(Revised)*
-   Basic project structure partially aligned with Clean Architecture layers (`domain`, `application`, `infrastructure`, `api`, `presentation`, `core`).
-   Use of Python/FastAPI.
-   Pydantic for basic request validation in API endpoints.
-   Existence of core domain entities (`Patient`, `DigitalTwin`) and repository interfaces.
-   Presence of API endpoints for Patients, Digital Twins, and specific ML models (Actigraphy, XGBoost, MentalLLaMA), though many are undocumented or have placeholder logic.
-   Extensive (but potentially problematic) unit/integration test suite.

### 9.2. Known Limitations *(Revised)*
-   **Significant deviation from Clean Architecture:** API endpoints contain excessive logic, use mocks/in-memory stores instead of proper repository implementations, and rely heavily on test-specific patching.
-   **Incomplete Features:** Many documented API endpoints and Digital Twin capabilities are missing or have placeholder implementations. Numerous implemented API endpoints are undocumented.
-   **Missing Core Security:** Authentication, authorization, audit logging, secure error handling, and other critical security features are largely unimplemented.
-   **Database/Infrastructure:** Lack of actual database integration, caching, messaging queues.
-   **Inconsistent Documentation:** Significant discrepancies exist between different documentation files and between documentation and the actual codebase.
-   **Test Suite Issues:** Tests rely on extensive mocking and patching, potentially hiding architectural problems and hindering refactoring towards a production-ready state. Many tests might be failing (requires execution).

### 9.3. Roadmap *(Remains largely valid, but needs reprioritization)*
-   **Refactor API/Presentation Layer:** Implement proper dependency injection, remove mocks/patches, connect to Application/Infrastructure layers.
-   **Implement Infrastructure Layer:** Build production-ready repository implementations (e.g., using SQLAlchemy with PostgreSQL) and other infrastructure components (caching, messaging if needed).
-   **Implement Application Layer:** Develop use cases/services to orchestrate domain logic.
-   **Implement Security:** Add robust Authentication, Authorization (RBAC), Audit Logging, Secure Error Handling, PHI Scrubbing, etc.
-   **Refine Domain Layer:** Consolidate `DigitalTwin` definitions, enrich domain models.
-   **Align API Endpoints:** Implement missing documented endpoints, document existing ones, resolve path inconsistencies.
-   **Fix/Refactor Tests:** Update tests to work with real dependencies (or controlled fakes) instead of excessive mocking/patching. Ensure all tests pass.
-   **Update Documentation:** Keep documentation in sync with codebase reality *and* the evolving target architecture.
-   Complete implementation of planned microservices and data pipelines (if applicable).
-   Expand test coverage.
-   Enhance documentation for contributors.

## 10. For Contributors

-   Always reference the codebase and test suite as the ultimate source of truth, *but be aware of current limitations and inconsistencies.*
-   Follow Clean Architecture, SOLID, and HIPAA compliance rules strictly *as the target state during refactoring*.
-   Document all architectural changes.
-   Ensure backward compatibility or provide migration paths *where feasible during refactoring*.

---

This architecture document is maintained and updated with each significant architectural change. The codebase remains the ultimate source of truth for implementation details, *and this document now attempts to reflect its current state while preserving the target vision.*

Last Updated: 2025-04-20
