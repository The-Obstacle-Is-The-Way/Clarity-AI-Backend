# Technical Requirements Document & Implementation Plan: Patient Data Encryption

## 1. Overview and Goals

*   **Primary Goal:** Implement robust, field-level encryption for all Personally Identifiable Information (PII) and Protected Health Information (PHI) within the `Patient` SQLAlchemy model to ensure data confidentiality at rests.
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
    *   [X] Ensure `ENCRYPTION_KEY` is correctly configured in the development environment (e.g., `.env` file). (Now `PHI_ENCRYPTION_KEY`)
    *   [X] Manually test (or confirm via existing unit tests for `EncryptionService`) that `encrypt()` and `decrypt()` methods work as expected with strings and JSON-serializable data.
    *   [X] *Note: `BaseEncryptionService` methods `encrypt_string` and `decrypt_string` are the ones used by the `EncryptionService` wrapper. The `EncryptedTypeBase` calls `self.encryption_service.encrypt()` and `self.encryption_service.decrypt()` which should map to these.*
*   [X] **P1.2: Review `EncryptedType` Implementations** (Covered in prior session analysis)
    *   [X] Confirm `EncryptedString`, `EncryptedText`, and `EncryptedJSON` in `encrypted_types.py` correctly initialize and access an `EncryptionService` instance (now imported from `patient.py` within methods).
    *   [X] Verify `process_bind_param` in these types correctly calls the `EncryptionService`'s encryption method.
    *   [X] Verify `process_result_value` in these types correctly calls the `EncryptionService`'s decryption method and handles potential deserialization.
    *   [X] Ensure appropriate underlying SQLAlchemy types are specified in `impl`.

### Phase 2: Refactoring `Patient` SQLAlchemy Model (`app/infrastructure/persistence/sqlalchemy/models/patient.py`)

*   [X] **P2.1: Import Necessary Modules**
    *   [X] Add import for `EncryptionService` from `app.infrastructure.security.encryption.encryption_service`.
    *   [X] Add import for `settings` from `app.core.config`.
    *   [X] Add imports for `EncryptedString`, `EncryptedText`, `EncryptedJSON` from `app.infrastructure.persistence.sqlalchemy.types.encrypted_types`.
*   [X] **P2.2: Prepare `EncryptionService` Instance for TypeDecorators**
    *   [X] In `patient.py`, ensure an `EncryptionService` instance, properly initialized (now using its internal key loading from `BaseEncryptionService`), is available at the module level (`encryption_service_instance`).
      ```python
      # Example conceptual placement in patient.py
      # from app.core.config import settings # Settings object used by EncryptionService internally
      # from app.infrastructure.security.encryption.encryption_service import EncryptionService
      # encryption_service_instance = EncryptionService() # Key loaded internally
      ```
*   [X] **P2.3: Update PII/PHI Column Definitions**
    *   Identify all fields in the `Patient` model that store PII/PHI.
    *   For each identified PII/PHI field:
        *   [X] Change the SQLAlchemy `Column` type to the corresponding custom encrypted type (`EncryptedString`, `EncryptedText`, `EncryptedJSON`).
        *   [X] Ensure custom types *do not* take `encryption_service_instance` in constructor (they import it).
        *   **Example:**
            ```python
            # Before:
            # _first_name: Mapped[str | None] = mapped_column(String, nullable=True)
            # After:
            # _first_name: Mapped[str | None] = mapped_column(EncryptedString, nullable=True) # TypeDecorator gets service from patient.py
            ```
        *   **List of Fields to Update (verify against actual `patient.py` content):** (Assumed all DONE as per prior edits)
            *   [X] `_first_name` (String -> EncryptedString)
            *   [X] `_middle_name` (String -> EncryptedString)
            *   [X] `_last_name` (String -> EncryptedString)
            *   [X] `_date_of_birth` (String -> EncryptedString)
            *   [X] `_gender` (String -> EncryptedString)
            *   [X] `_sex_at_birth` (String -> EncryptedString)
            *   [X] `_email` (String -> EncryptedString)
            *   [X] `_phone_number` (String -> EncryptedString)
            *   [X] `_address_line1` (String -> EncryptedString)
            *   [X] `_address_line2` (String -> EncryptedString)
            *   [X] `_city` (String -> EncryptedString)
            *   [X] `_state_province_region` (String -> EncryptedString)
            *   [X] `_zip_postal_code` (String -> EncryptedString)
            *   [X] `_country` (String -> EncryptedString)
                *   [X] `_pronouns` (String -> EncryptedString)
            *   [X] `_ethnicity` (String -> EncryptedString)
            *   [X] `_race` (String -> EncryptedString)
            *   [X] `_preferred_language` (String -> EncryptedString)
            *   [X] `_religion_spirituality` (String -> EncryptedString)
            *   [X] `_occupation` (String -> EncryptedString)
            *   [X] `_education_level` (String -> EncryptedString)
            *   [X] `_marital_status` (String -> EncryptedString)
            *   [X] `_medical_record_number_lve` (Text -> EncryptedText)
            *   [X] `_social_security_number_lve` (Text -> EncryptedText)
            *   [X] `_drivers_license_number_lve` (Text -> EncryptedText)
            *   [X] `_insurance_policy_number_lve` (Text -> EncryptedText)
            *   [X] `_insurance_group_number_lve` (Text -> EncryptedText)
            *   [X] `_living_arrangement` (Text -> EncryptedText)
            *   [X] `_allergies_sensitivities` (Text -> EncryptedText)
            *   [X] `_problem_list` (Text -> EncryptedText)
            *   [X] `_primary_care_physician` (Text -> EncryptedText)
            *   [X] `_pharmacy_information` (Text -> EncryptedText)
            *   [X] `_care_team_contact_info` (Text -> EncryptedText)
            *   [X] `_treatment_history_notes` (Text -> EncryptedText)
            *   [X] `_current_medications_lve` (Text -> EncryptedText)
            *   [X] `_confidential_information_lve` (Text -> EncryptedText)
            *   [X] `_additional_notes_lve` (Text -> EncryptedText)
            *   [X] `_contact_details` (postgresql.JSONB or Text -> EncryptedJSON)
            *   [X] `_emergency_contact` (postgresql.JSONB or Text -> EncryptedJSON)
            *   [X] `_preferences` (postgresql.JSONB or Text -> EncryptedJSON)
*   [X] **P2.4: Remove Manual Encryption/Decryption Logic in `from_domain`**
    *   [X] Delete helper functions `_encrypt` and `_encrypt_serializable`.
    *   [X] Change PII/PHI field assignments to direct assignment from the domain model (or `str()` for complex Pydantic objects mapped to `EncryptedText`).
*   [X] **P2.5: Remove Manual Encryption/Decryption Logic in `to_domain`**
    *   [X] Delete helper functions `_decrypt` and `_decrypt_serializable`.
    *   [X] Change PII/PHI field retrievals to directly access ORM field values.

### Phase 3: Testing and Verification

*   [/] **P3.1: Update/Create Unit Tests for `Patient` Model** (Integration tests PASSING for `test_patient_encryption_integration.py` covering `from_domain`, `to_domain`, and round-trip integrity. Unit tests for `models/test_patient_encryption.py` and `repositories/test_patient_repository.py` are IN PROGRESS.)
    *   [X] Ensure tests cover `from_domain` and `to_domain` methods with PII data, verifying round-trip integrity.
        *   `test_patient_encryption_integration.py` (`TestPatientEncryptionIntegration`):
            *   `test_phi_decrypted_in_repository`: **PASSING**
            *   `test_encryption_error_handling`: **PASSING**
            *   `test_phi_encrypted_in_database`: **PASSING**
*   [/] **P3.2: Integration Testing** (Database and Application checks via `test_patient_encryption_integration.py` are PASSING. Unit test verification for repository and model methods is IN PROGRESS.)
    *   [X] **Database Check:** Programmatic checks in `test_phi_encrypted_in_database` confirm raw DB values are encrypted and differ from plaintext.
    *   [X] **Application Check:** Verified by `test_phi_decrypted_in_repository` that retrieved `Patient` domain objects have decrypted PII.
    *   [X] Test null values and empty strings for encrypted fields (Covered by `test_encryption_error_handling` and behavior of `BaseEncryptionService`).
*   [ ] **P3.3: Alembic Migration Considerations** (Status unchanged - for future production)
    *   [ ] Determine if an Alembic schema migration is needed (unlikely if underlying DB types like `TEXT` don't change).
    *   [ ] **Data Migration Strategy (For future production):** Note the requirement for a data migration script to encrypt existing plaintext PII if deploying to a database with live, unencrypted data. This is not part of the immediate refactoring task for a dev environment.

### Phase 4: Code Review and Finalization

*   [/] **P4.1: Code Review** (Significantly progressed during iterative debugging of Phase 3)
    *   [/] Review changes for correctness, clarity, and security.
    *   [/] Confirm all identified PII fields are using encrypted types.
*   [ ] **P4.2: Run Full Test Suite** (PENDING - Next immediate step after this update)
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
