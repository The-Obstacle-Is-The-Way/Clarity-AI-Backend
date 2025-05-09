# Technical Requirements Document & Implementation Plan: Patient Data Encryption

## 1. Overview and Goals

*   **Primary Goal:** Implement robust, field-level encryption for all Personally Identifiable Information (PII) and Protected Health Information (PHI) within the `Patient` SQLAlchemy model to ensure data confidentiality at rest.
*   **Compliance Objective:** Align with HIPAA security rule requirements for protecting sensitive patient data.
*   **Technical Approach:** Leverage SQLAlchemy's `TypeDecorator` pattern in conjunction with the existing `EncryptionService` to achieve transparent encryption and decryption of specified model fields.

## 2. Core Components & Technologies

*   **`EncryptionService`**:
    *   Located at `app/infrastructure/security/encryption/encryption_service.py` (implementing `IEncryptionService`).
    *   Relies on `BaseEncryptionService` (`app/infrastructure/security/encryption/base_encryption_service.py`).
    *   Uses Fernet symmetric encryption.
    *   Requires `ENCRYPTION_KEY` environment variable.
*   **SQLAlchemy Custom Encrypted Types**:
    *   Defined in `app/infrastructure/persistence/sqlalchemy/types/encrypted_types.py`.
    *   Classes: `EncryptedString`, `EncryptedText`, `EncryptedJSON`.
    *   These `TypeDecorator` subclasses will wrap standard SQLAlchemy types (`String`, `Text`) and use the `EncryptionService` for data transformation.
*   **`Patient` SQLAlchemy Model**:
    *   Located at `app/infrastructure/persistence/sqlalchemy/models/patient.py`.
    *   This model will be modified to use the custom encrypted types for PII/PHI fields.

## 3. Detailed Implementation Plan & Checklist

### Phase 1: Preparation and Verification

*   [X] **P1.1: Verify `EncryptionService` Functionality** (Covered in prior session analysis)
    *   [X] Ensure `ENCRYPTION_KEY` is correctly configured in the development environment (e.g., `.env` file).
    *   [X] Manually test (or confirm via existing unit tests for `EncryptionService`) that `encrypt()` and `decrypt()` methods work as expected with strings and JSON-serializable data.
    *   *Note: `BaseEncryptionService` methods `encrypt_string` and `decrypt_string` are the ones used by the `EncryptionService` wrapper. The `EncryptedTypeBase` calls `self.encryption_service.encrypt()` and `self.encryption_service.decrypt()` which should map to these.*
*   [X] **P1.2: Review `EncryptedType` Implementations** (Covered in prior session analysis)
    *   [X] Confirm `EncryptedString`, `EncryptedText`, and `EncryptedJSON` in `encrypted_types.py` correctly initialize with an `EncryptionService` instance.
    *   [X] Verify `process_bind_param` in these types correctly calls the `EncryptionService`'s encryption method.
    *   [X] Verify `process_result_value` in these types correctly calls the `EncryptionService`'s decryption method and handles potential deserialization.
    *   [X] Ensure appropriate underlying SQLAlchemy types are specified in `impl`.

### Phase 2: Refactoring `Patient` SQLAlchemy Model (`app/infrastructure/persistence/sqlalchemy/models/patient.py`)

*   [ ] **P2.1: Import Necessary Modules**
    *   [ ] Add import for `EncryptionService` from `app.infrastructure.security.encryption.encryption_service`.
    *   [ ] Add import for `settings` from `app.core.config`.
    *   [ ] Add imports for `EncryptedString`, `EncryptedText`, `EncryptedJSON` from `app.infrastructure.persistence.sqlalchemy.types.encrypted_types`.
*   [ ] **P2.2: Prepare `EncryptionService` Instance for TypeDecorators**
    *   [ ] In `patient.py`, ensure an `EncryptionService` instance, properly initialized with `settings.ENCRYPTION_KEY`, is available to be passed to the `EncryptedType` constructors when defining columns. This will likely involve creating it at the module level after importing settings.
      ```python
      # Example conceptual placement in patient.py
      # from app.core.config import settings
      # from app.infrastructure.security.encryption.encryption_service import EncryptionService
      # encryption_service_instance = EncryptionService(secret_key=settings.ENCRYPTION_KEY)
      ```
*   [ ] **P2.3: Update PII/PHI Column Definitions**
    *   Identify all fields in the `Patient` model that store PII/PHI.
    *   For each identified PII/PHI field:
        *   Change the SQLAlchemy `Column` type to the corresponding custom encrypted type (`EncryptedString`, `EncryptedText`, `EncryptedJSON`).
        *   Pass the module-level `encryption_service_instance` to the constructor of the custom type.
        *   **Example:**
            ```python
            # Before:
            # _first_name: Mapped[str | None] = mapped_column(String, nullable=True)
            # After:
            # _first_name: Mapped[str | None] = mapped_column(EncryptedString(encryption_service=encryption_service_instance), nullable=True)
            ```
        *   **List of Fields to Update (verify against actual `patient.py` content):**
            *   [ ] `_first_name` (String -> EncryptedString)
            *   [ ] `_middle_name` (String -> EncryptedString)
            *   [ ] `_last_name` (String -> EncryptedString)
            *   [ ] `_date_of_birth` (String -> EncryptedString)
            *   [ ] `_gender` (String -> EncryptedString)
            *   [ ] `_sex_at_birth` (String -> EncryptedString)
            *   [ ] `_email` (String -> EncryptedString)
            *   [ ] `_phone_number` (String -> EncryptedString)
            *   [ ] `_address_line1` (String -> EncryptedString)
            *   [ ] `_address_line2` (String -> EncryptedString)
            *   [ ] `_city` (String -> EncryptedString)
            *   [ ] `_state_province_region` (String -> EncryptedString)
            *   [ ] `_zip_postal_code` (String -> EncryptedString)
            *   [ ] `_country` (String -> EncryptedString)
            *   [ ] `_pronouns` (String -> EncryptedString)
            *   [ ] `_ethnicity` (String -> EncryptedString)
            *   [ ] `_race` (String -> EncryptedString)
            *   [ ] `_preferred_language` (String -> EncryptedString)
            *   [ ] `_religion_spirituality` (String -> EncryptedString)
            *   [ ] `_occupation` (String -> EncryptedString)
            *   [ ] `_education_level` (String -> EncryptedString)
            *   [ ] `_marital_status` (String -> EncryptedString)
            *   [ ] `_medical_record_number_lve` (Text -> EncryptedText)
            *   [ ] `_social_security_number_lve` (Text -> EncryptedText)
            *   [ ] `_drivers_license_number_lve` (Text -> EncryptedText)
            *   [ ] `_insurance_policy_number_lve` (Text -> EncryptedText)
            *   [ ] `_insurance_group_number_lve` (Text -> EncryptedText)
            *   [ ] `_living_arrangement` (Text -> EncryptedText)
            *   [ ] `_allergies_sensitivities` (Text -> EncryptedText)
            *   [ ] `_problem_list` (Text -> EncryptedText)
            *   [ ] `_primary_care_physician` (Text -> EncryptedText)
            *   [ ] `_pharmacy_information` (Text -> EncryptedText)
            *   [ ] `_care_team_contact_info` (Text -> EncryptedText)
            *   [ ] `_treatment_history_notes` (Text -> EncryptedText)
            *   [ ] `_current_medications_lve` (Text -> EncryptedText)
            *   [ ] `_confidential_information_lve` (Text -> EncryptedText)
            *   [ ] `_additional_notes_lve` (Text -> EncryptedText)
            *   [ ] `_contact_details` (postgresql.JSONB or Text -> EncryptedJSON)
            *   [ ] `_emergency_contact` (postgresql.JSONB or Text -> EncryptedJSON)
            *   [ ] `_preferences` (postgresql.JSONB or Text -> EncryptedJSON)
*   [ ] **P2.4: Remove Manual Encryption/Decryption Logic in `from_domain`**
    *   [ ] Delete helper functions `_encrypt` and `_encrypt_serializable`.
    *   [ ] Change PII/PHI field assignments to direct assignment from the domain model.
*   [ ] **P2.5: Remove Manual Encryption/Decryption Logic in `to_domain`**
    *   [ ] Delete helper functions `_decrypt` and `_decrypt_serializable`.
    *   [ ] Change PII/PHI field retrievals to directly access ORM field values.

### Phase 3: Testing and Verification

*   [ ] **P3.1: Update/Create Unit Tests for `Patient` Model**
    *   [ ] Ensure tests cover `from_domain` and `to_domain` methods with PII data, verifying round-trip integrity.
*   [ ] **P3.2: Integration Testing**
    *   [ ] Test create, retrieve, update operations involving `Patient` records.
    *   [ ] **Database Check:** Manually inspect the test database to confirm PII fields are stored encrypted.
    *   [ ] **Application Check:** Verify retrieved `Patient` domain objects have decrypted PII.
    *   [ ] Test null values and empty strings for encrypted fields.
*   [ ] **P3.3: Alembic Migration Considerations**
    *   [ ] Determine if an Alembic schema migration is needed (unlikely if underlying DB types like `TEXT` don't change).
    *   [ ] **Data Migration Strategy (For future production):** Note the requirement for a data migration script to encrypt existing plaintext PII if deploying to a database with live, unencrypted data. This is not part of the immediate refactoring task for a dev environment.

### Phase 4: Code Review and Finalization

*   [ ] **P4.1: Code Review**
    *   [ ] Review changes for correctness, clarity, and security.
    *   [ ] Confirm all identified PII fields are using encrypted types.
*   [ ] **P4.2: Run Full Test Suite**
    *   [ ] Address any new failures.
*   [ ] **P4.3: Documentation Update (If Necessary)**
    *   [ ] Update internal documentation regarding encryption.

## 4. Security Considerations & Best Practices

*   **Key Management:** `ENCRYPTION_KEY` must be secure (environment variables, secrets manager). Not hardcoded.
*   **No Plaintext Logging:** Avoid logging decrypted PII/PHI outside of secured audit logs.
*   **Searchability:** Encrypted fields are not directly searchable in SQL on plaintext values.
*   **Key Rotation:** Plan for future key rotation.
*   **Performance:** Monitor encryption/decryption overhead.

## 5. Assumptions

*   `EncryptionService` and `ENCRYPTION_KEY` are correctly set up.
*   `EncryptedType`s are correctly implemented.
*   Focus is on code refactoring; migration of existing live plaintext data is a separate future task.

This document will guide the refactoring of `patient.py`.
