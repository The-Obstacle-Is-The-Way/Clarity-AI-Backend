# 65. Machine Learning (ML) Integration Guide

This document explains how Machine Learning (ML) models are integrated and utilized within the Novamind backend application architecture.

---

## 1. Overview

ML models provide core functionality for analysis, prediction, and data processing (like PHI detection) within the platform. Integration follows standard software engineering principles, aiming for decoupling and testability. ML functionalities are typically exposed via dedicated services or adapters residing within the `infrastructure` layer, which are then consumed by the `application` or `domain` layers.

## 2. Configuration

- **Centralized Settings**: Configuration for all integrated ML models (e.g., model paths, API endpoints, API keys, provider details) is managed centrally in `backend/app/config/settings.py` under the `MLSettings` object and its nested models (`MentalLlamaSettings`, `PATSettings`, `XGBoostSettings`, `LSTMSettings`, `PHIDetectionSettings`, etc.).
- **Environment Specificity**: These settings are loaded from environment variables, allowing different configurations for development, testing, and production (e.g., using mock model servers in testing, production model endpoints in production).
- **Reference**: See `30_Configuration_Management.md` for details on the configuration loading mechanism.

## 3. Integration Pattern

- **ML Service Abstraction**: Interactions with ML models are typically abstracted behind service interfaces (defined in the `application` or `domain` layer using `Protocol` or abstract base classes) or adapter classes (in the `infrastructure` layer).
- **Infrastructure Implementation**: Concrete implementations of these interfaces/adapters reside in the `infrastructure` layer (e.g., `backend/app/infrastructure/ml/` or `backend/app/infrastructure/services/`). These implementations handle:
    - Loading models (from paths specified in settings).
    - Connecting to external ML API endpoints (using URLs and keys from settings).
    - Data marshalling/unmarshalling (transforming application data into the format required by the model/API and vice-versa).
    - Error handling specific to the ML model/API interaction.
- **Dependency Injection**: Application services (in `backend/app/application/services/`) or domain services (in `backend/app/domain/services/`) receive instances of these ML service interfaces/adapters via FastAPI's dependency injection mechanism. This decouples the core application logic from the specifics of *how* an ML prediction is obtained.

## 4. Example Workflow (Conceptual)

Consider generating insights using the MentalLlama model for a Digital Twin:

1.  **API Request**: An API endpoint (e.g., `/twins/{twin_id}/insights`) receives a request.
2.  **Application Service**: The API endpoint calls an application service (e.g., `DigitalTwinInsightService`).
3.  **Dependency**: The `DigitalTwinInsightService` has an `IMentalLlamaService` (interface) injected into its constructor.
4.  **ML Service Call**: The application service prepares the necessary data (e.g., recent patient notes, biometric data) and calls a method on the `IMentalLlamaService` instance (e.g., `await mental_llama_service.generate_clinical_summary(data)`).
5.  **Infrastructure Implementation**: The concrete `MentalLlamaService` (in infrastructure) receives the call.
    - It retrieves necessary configuration (API key, endpoint/model mapping) from the injected `Settings` object.
    - It formats the data according to the MentalLlama API requirements.
    - It makes the API call to the configured OpenAI/Azure/Local endpoint.
    - It parses the response.
    - It handles potential API errors (e.g., rate limits, connection issues) and may raise specific exceptions.
6.  **Return Value**: The result (e.g., generated summary) is returned to the application service.
7.  **Response**: The application service processes the result and returns it via the API endpoint.

*Note: Specific implementations for PHI detection (e.g., using Presidio based on `PHIDetectionSettings`) might be integrated as middleware or called explicitly within services before logging or returning potentially sensitive data.* 

## 5. Key ML Components & Services (Actual & Illustrative)

Based on the settings structure (`config/settings.py`) and analysis of the `backend/app/infrastructure/ml/` directory ([[Current Date]]), the following ML-related components exist or are anticipated:

**Existing Components in `backend/app/infrastructure/ml/`:**

*   **`digital_twin_integration_service.py`:** Likely orchestrates interactions between various ML models/services related to the Digital Twin.
*   **`pharmacogenomics/`:** Suggests components related to pharmacogenomic analysis. (Details TBD)
*   **`biometric_correlation/`:** Suggests components for correlating biometric data streams. (Details TBD)
*   **`symptom_forecasting/`:** Contains logic related to symptom forecasting models. (Details TBD)
*   **`phi/`, `phi_detection/`, `phi_detection_service.py`, `phi_detection.py`:** Implements PHI detection and potentially redaction logic, likely using tools like Presidio or custom models based on `PHIDetectionSettings`.
*   **`mentallama/`, `mentallama.py`:** Contains integration logic for interacting with Large Language Models (LLMs) like GPT variants (OpenAI, Azure) or local models, configured via `MentalLlamaSettings`.
*   **`pat/`:** Holds components related to the Patient Acuity Tracker (PAT) model/analysis, configured via `PATSettings`.
*   **`adapters.py`:** Likely contains adapter classes to standardize interactions with different ML models or APIs.
*   **`base/`, `utils/`:** Contain base classes and utility functions supporting the ML components.

**Illustrative Services (Based on Settings - Existence as specific services TBD):**

*   `XGBoostPredictionService`: Would load and use XGBoost models based on `XGBoostSettings`.
*   `LSTMAnalysisService`: Would utilize LSTM models based on `LSTMSettings`.

*Note: The exact implementation details and responsibilities of components within the directories require further code review. This list reflects the structure found during analysis.*

## 6. Error Handling

- Implementations within the infrastructure layer should catch errors specific to the ML model or API (e.g., connection errors, API-specific exceptions, model loading failures).
- These specific errors should ideally be translated into more generic application-level or domain-level exceptions (e.g., `MLExecutionError`, `ExternalServiceError`) before being raised to the calling service.
- Application services should handle these exceptions appropriately (e.g., logging the error securely, returning a specific error response via the API).

## 7. Testing ML Integrations

Testing ML integrations requires careful consideration:

- **Unit Testing (Application/Domain)**:
    - **Mocking**: When unit testing application/domain services, the injected ML service interface/adapter should be mocked (e.g., using `unittest.mock` or pytest fixtures).
    - **Focus**: Verify that the application logic correctly prepares data for the ML service, calls the appropriate methods, and handles the expected responses or exceptions from the *mocked* service.
- **Integration Testing (Infrastructure)**:
    - **Mock External APIs**: For models relying on external APIs (like OpenAI/Azure), integration tests might use mock servers (e.g., using `aiohttp` test utilities, `requests-mock`, or specialized libraries) to simulate API responses and failures without making actual external calls.
    - **Test Local Models**: For locally hosted models or libraries, integration tests could potentially load a small test version of the model or use pre-defined inputs/outputs if feasible.
    - **Focus**: Verify that the infrastructure service/adapter correctly interacts with the (mocked) external endpoint or local model library, handles configuration loading, and performs data marshalling/unmarshalling correctly.
- **End-to-End Testing**: E2E tests might cover workflows involving ML predictions, likely relying on mocked ML responses configured at the boundary to ensure predictable behavior and avoid flakiness/cost associated with real ML calls.

Refer to `80_Testing_Guide.md` for general testing tools and practices.

---

This guide provides the strategy for integrating ML models. Consistency in abstraction and testing is key to maintaining a robust and scalable system.

Last Updated: 2025-04-20
