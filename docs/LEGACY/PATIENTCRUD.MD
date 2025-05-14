# Product Requirements Document (PRD): Patient CRUD Functionality

**Version:** 1.0
**Date:** 2025-05-05

**1. Introduction**

This document outlines the requirements for implementing comprehensive CRUD (Create, Read, Update, Delete) functionality for Patient entities within the Clarity Digital Twin platform. The implementation must adhere to clean architecture principles (SOLID, DRY), ensure HIPAA compliance, and be fully tested.

**2. Goals**

*   Provide robust and secure API endpoints for managing patient records.
*   Ensure data integrity and validation for all patient information.
*   Establish a clear separation of concerns between API, Application, Domain, and Infrastructure layers.
*   Achieve high test coverage (unit, integration) for all CRUD operations.
*   Maintain compliance with HIPAA regulations regarding Protected Health Information (PHI).

**3. Functional Requirements**

**3.1 Patient Data Model (Domain Layer)**

*   Define a `Patient` domain entity (`app/domain/entities/patient.py`).
*   Core Attributes:
    *   `id`: Unique identifier (e.g., UUID). Must be generated, not supplied by the client on create.
    *   `created_at`: Timestamp of creation.
    *   `updated_at`: Timestamp of last update.
    *   `name`: Patient's full name (string, required).
    *   `date_of_birth`: Patient's date of birth (date, required).
    *   `contact_info`: Contact details (e.g., phone, email - consider structure, potentially a separate value object or entity).
    *   `medical_record_number`: MRN (string, unique, required).
    *   *(Add other relevant non-PHI attributes as needed)*
*   PHI considerations: Attributes containing PHI must be handled securely (encryption at rest, access controls).

**3.2 API Endpoints (Presentation Layer - `app/presentation/api/v1/routes/patient.py`)**

*   **`POST /api/v1/patients/` (Create)**
    *   Input: `PatientCreateRequest` schema (excluding `id`, `created_at`, `updated_at`).
    *   Action: Creates a new patient record.
    *   Response: `PatientRead` schema (or dedicated `PatientCreateResponse`), status code `201 Created`.
    *   Validation: Use Pydantic for input validation. Handle validation errors with `422 Unprocessable Entity`.
    *   Error Handling: Handle potential service/repository errors (e.g., duplicate MRN) with appropriate status codes (e.g., `409 Conflict`).
*   **`GET /api/v1/patients/{patient_id}` (Read One)**
    *   Input: `patient_id` (path parameter, UUID).
    *   Action: Retrieves a specific patient record by ID.
    *   Response: `PatientRead` schema, status code `200 OK`.
    *   Error Handling: Return `404 Not Found` if the patient ID does not exist.
*   **`GET /api/v1/patients/` (Read Many/List)**
    *   Input: Optional query parameters for filtering, sorting, pagination (e.g., `limit`, `offset`, `sort_by`, `name_filter`). Define these clearly.
    *   Action: Retrieves a list of patient records based on query parameters.
    *   Response: List of `PatientRead` schemas (or a paginated response object), status code `200 OK`.
*   **`PUT /api/v1/patients/{patient_id}` (Update)**
    *   Input: `patient_id` (path parameter, UUID), `PatientUpdateRequest` schema (containing fields allowed for update).
    *   Action: Updates an existing patient record.
    *   Response: `PatientRead` schema (updated record), status code `200 OK`.
    *   Validation: Use Pydantic for input validation (`422`).
    *   Error Handling: Return `404 Not Found` if the patient ID does not exist. Handle potential conflicts (e.g., trying to update MRN to an existing one) with `409 Conflict`.
*   **`DELETE /api/v1/patients/{patient_id}` (Delete)**
    *   Input: `patient_id` (path parameter, UUID).
    *   Action: Deletes a specific patient record (consider soft vs. hard delete - soft delete preferred for audit/recovery).
    *   Response: Status code `204 No Content`.
    *   Error Handling: Return `404 Not Found` if the patient ID does not exist.

**3.3 Application Service (Application Layer - `app/application/services/patient_service.py`)**

*   Define `PatientService` responsible for business logic.
*   Methods:
    *   `create_patient(data: PatientCreateRequest) -> Patient`
    *   `get_patient_by_id(patient_id: UUID) -> Patient | None`
    *   `get_patients(filters: dict, pagination: dict, sorting: dict) -> list[Patient]`
    *   `update_patient(patient_id: UUID, data: PatientUpdateRequest) -> Patient | None`
    *   `delete_patient(patient_id: UUID) -> bool` (returns True if deleted, False if not found)
*   Inject `IPatientRepository` interface.
*   Handles business rules (e.g., checking for duplicate MRN before creating/updating).

**3.4 Repository Interface (Domain Layer - `app/domain/interfaces/repositories/patient_repository_interface.py`)**

*   Define `IPatientRepository` abstract interface.
*   Methods:
    *   `add(patient: Patient) -> Patient`
    *   `get_by_id(patient_id: UUID) -> Patient | None`
    *   `get_by_mrn(mrn: str) -> Patient | None`
    *   `list(filters: dict, pagination: dict, sorting: dict) -> list[Patient]`
    *   `update(patient: Patient) -> Patient`
    *   `delete(patient_id: UUID) -> bool`

**3.5 Repository Implementation (Infrastructure Layer - `app/infrastructure/persistence/sqlalchemy/repositories/patient_repository.py`)**

*   Implement `SQLAlchemyPatientRepository` conforming to `IPatientRepository`.
*   Use SQLAlchemy ORM for database interactions.
*   Inject `AsyncSession`.
*   Handle database-specific exceptions and potentially map them to domain/application exceptions.

**4. Non-Functional Requirements**

*   **Security:**
    *   Authentication/Authorization: Secure endpoints appropriately (e.g., using JWT, role-based access).
    *   Input Validation: Prevent injection attacks via strict Pydantic validation.
    *   PHI Handling: Encrypt sensitive data at rest and in transit. Avoid PHI in logs and error messages.
    *   Output Sanitization: Ensure API responses do not leak sensitive internal details.
*   **Performance:** Endpoints should respond within acceptable time limits (define targets if necessary).
*   **Testability:** Code must be highly testable with clear dependencies.
*   **Logging:** Implement structured logging for key events (creation, update, deletion, errors) including request IDs but excluding PHI.
*   **Auditing:** Implement audit trails for all CRUD operations (who did what, when).
*   **Error Handling:** Consistent and informative error responses without revealing sensitive information.
*   **Documentation:** Generate OpenAPI documentation automatically via FastAPI.

**5. Implementation Checklist**

**Phase 1: Setup & Read**

*   [ ] Define `Patient` domain entity (`app/domain/entities/patient.py`).
*   [ ] Define `IPatientRepository` interface (`app/domain/interfaces/repositories/patient_repository_interface.py`).
*   [ ] Implement basic `SQLAlchemyPatientRepository` (`app/infrastructure/persistence/.../patient_repository.py`) with `get_by_id` and `list` methods.
*   [ ] Define `PatientRead` Pydantic schema (`app/presentation/api/schemas/patient.py`).
*   [ ] Implement `get_patient_by_id` and `get_patients` methods in `PatientService` (`app/application/services/patient_service.py`).
*   [ ] Implement `GET /api/v1/patients/{patient_id}` endpoint (`app/presentation/api/v1/routes/patient.py`).
*   [ ] Implement `GET /api/v1/patients/` endpoint (basic list, no filters yet).
*   [ ] Add Unit Tests for `PatientService.get_patient_by_id`.
*   [ ] Add Unit Tests for `GET /api/v1/patients/{patient_id}` endpoint (success, not found).
*   [ ] Add Unit Tests for `GET /api/v1/patients/` endpoint (basic success).
*   [ ] Add Integration Tests for `SQLAlchemyPatientRepository.get_by_id`.
*   [ ] Add Integration Tests for `GET /api/v1/patients/{patient_id}` and `GET /api/v1/patients/`.

**Phase 2: Create**

*   [x] Define `PatientCreateRequest` Pydantic schema.
*   [x] Define `PatientCreateResponse` Pydantic schema (or alias `PatientRead`).
*   [ ] Implement `add` and `get_by_mrn` methods in `IPatientRepository` and `SQLAlchemyPatientRepository`.
*   [x] Implement `create_patient` method in `PatientService` (handling potential duplicate MRN).
*   [x] Implement `POST /api/v1/patients/` endpoint.
*   [x] Add Unit Tests for `PatientService.create_patient` (success, duplicate MRN).
*   [x] Add Unit Tests for `POST /api/v1/patients/` endpoint (success - `201`, validation error - `422`, conflict - `409`).
*   [ ] Add Integration Tests for `SQLAlchemyPatientRepository.add`.
*   [ ] Add Integration Tests for `POST /api/v1/patients/`.

**Phase 3: Update**

*   [ ] Define `PatientUpdateRequest` Pydantic schema.
*   [ ] Implement `update` method in `IPatientRepository` and `SQLAlchemyPatientRepository`.
*   [ ] Implement `update_patient` method in `PatientService` (handle not found, potential conflicts).
*   [ ] Implement `PUT /api/v1/patients/{patient_id}` endpoint.
*   [ ] Add Unit Tests for `PatientService.update_patient` (success, not found, conflict).
*   [ ] Add Unit Tests for `PUT /api/v1/patients/{patient_id}` endpoint (success, not found, validation error, conflict).
*   [ ] Add Integration Tests for `SQLAlchemyPatientRepository.update`.
*   [ ] Add Integration Tests for `PUT /api/v1/patients/{patient_id}`.

**Phase 4: Delete**

*   [ ] Decide on soft vs. hard delete strategy (document decision).
*   [ ] Add `is_deleted` flag or similar to `Patient` entity/model if using soft delete.
*   [ ] Implement `delete` method in `IPatientRepository` and `SQLAlchemyPatientRepository`.
*   [ ] Implement `delete_patient` method in `PatientService`.
*   [ ] Implement `DELETE /api/v1/patients/{patient_id}` endpoint.
*   [ ] Add Unit Tests for `PatientService.delete_patient` (success, not found).
*   [ ] Add Unit Tests for `DELETE /api/v1/patients/{patient_id}` endpoint (success - `204`, not found).
*   [ ] Add Integration Tests for `SQLAlchemyPatientRepository.delete`.
*   [ ] Add Integration Tests for `DELETE /api/v1/patients/{patient_id}`.

**Phase 5: Refinements & Non-Functional**

*   [ ] Implement advanced filtering/sorting/pagination for `GET /api/v1/patients/`.
*   [ ] Add corresponding tests for filtering/sorting/pagination.
*   [ ] Implement Authentication/Authorization checks on all endpoints.
*   [ ] Add tests for authorization failures (`401`/`403`).
*   [ ] Implement structured logging with request IDs (excluding PHI).
*   [ ] Implement audit logging.
*   [ ] Review and ensure HIPAA compliance (encryption, PHI handling in errors/logs).
*   [ ] Generate/update OpenAPI documentation.
*   [ ] Conduct final code review for adherence to SOLID/DRY principles.

**6. Open Questions/Future Considerations**

*   Detailed structure for `contact_info`.
*   Specific list of filterable/sortable fields for the list endpoint.
*   Exact requirements for audit logging (what fields, storage).
*   Soft vs. Hard delete final decision and implementation details.
*   Specific performance targets.

**Implementation Checklist (Updated)**

*   **Goals:**
     *   [x] Define basic `Patient` SQLAlchemy model (`app/domain/models/patient.py`).
     *   [x] Define basic Pydantic schemas (`PatientCreateRequest`, `PatientRead`) (`app/presentation/schemas/patient.py`).
     *   [x] Implement `PatientRepository` interface and concrete class (`app/domain/repositories/patient_repository.py`, `app/infrastructure/repositories/sqlalchemy_patient_repository.py`).
     *   [x] Implement `PatientService` (`app/application/services/patient_service.py`) with basic CRUD methods (`create`, `get_by_id`).
     *   [x] Create FastAPI router (`app/presentation/api/v1/routes/patient.py`) with `POST /patients/` and `GET /patients/{patient_id}` endpoints.
     *   [x] Write unit/integration tests (`app/tests/`) for service and repository.
     *   [x] Write endpoint tests (`app/tests/`) covering success, not found (404), and validation errors (422).
         *   [x] `test_read_patient_success` (Passed)
         *   [x] `test_read_patient_not_found` (Passed)
         *   [x] `test_create_patient_success` (Passed)
         *   [ ] Fix `TypeError: get_async_session() missing 1 required positional argument: 'request'` in `test_create_patient_validation_error`.
             *   **Issue:** FastAPI 422 error handling seems to bypass/ignore `get_async_session` override from `conftest.py::initialized_app`.
             *   **Attempts:**
                 *   Refactored `override_get_async_session` signature (with/without `request`).
                 *   Simplified `mock_session` fixture.
                 *   Applied override inside the test function (caused fixture conflict).
                 *   Corrected test to use client from `initialized_app` fixture (Pending test run).
     *   [ ] Implement `UPDATE` endpoint and tests.
     *   [ ] Implement `DELETE` endpoint and tests.
     *   [ ] Ensure proper dependency injection throughout.