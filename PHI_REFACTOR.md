# Product Requirements Document: PHI Handling Refactor

## 1. Introduction

This document outlines the requirements for refactoring the Protected Health Information (PHI) detection, redaction, and auditing mechanisms within the Clarity AI backend codebase. The goal is to establish a robust, centralized, and secure system for handling PHI, adhering to Clean Architecture principles and HIPAA best practices, while resolving existing test failures.

## 2. Goals

* Consolidate all PHI detection logic into a single, well-defined service.
* Implement comprehensive PHI auditing for code, data, and logs.
* Ensure no PHI leaks into error messages or logs.
* Refactor related components (middleware, analyzers) for clarity and maintainability.
* Achieve 100% passing tests for the `app/tests/security/phi/` suite.
* Align PHI handling with Clean Architecture and SOLID principles.

## 3. Scope

This refactor encompasses:

* `PHIDetectionService` implementation and configuration.
* `PHIAuditor` implementation and integration.
* `PHICodeAnalyzer` implementation and integration.
* API Middleware related to PHI handling.
* Error handling mechanisms concerning PHI.
* Test fixtures, mocks, and test cases related to PHI.
* Configuration management for PHI patterns and settings.

## 4. Requirements

### 4.1. Consolidated PHI Detection Service (`app.infrastructure.ml.phi_detection.service`)

* **SRV-PHI-001:** The `PHIDetectionService` shall be the single source of truth for core PHI pattern matching and detection logic.
* **SRV-PHI-002:** The service must correctly load patterns from the configured YAML file (`app/infrastructure/security/phi/phi_patterns.yaml`). *Fix the current `FileNotFoundError` caused by incorrect path calculation.*
* **SRV-PHI-003:** Provide clear, well-documented methods for:
  * `scan_text(text: str) -> Generator[PHIMatch, None, None]`: Yields all PHI matches.
  * `detect_phi(text: str) -> list[PHIMatch]`: Returns a list of all PHI matches.
  * `redact_phi(text: str, replacement: str = "[REDACTED]") -> str`: Replaces detected PHI.
  * `anonymize_phi(text: str) -> str`: Replaces PHI with category placeholders (e.g., `[NAME]`)
  * `contains_phi(text: str) -> bool`: Checks for the presence of any PHI.
* **SRV-PHI-004:** The service must be easily injectable using FastAPI's dependency injection system where needed.
* **SRV-PHI-005:** Default patterns should be robust and cover common PHI types (SSN, Name, Address, Date, Contact Info, etc.).

### 4.2. PHI Auditor Implementation (`PHIAuditor`)

* **AUD-PHI-001:** Define/locate the canonical `PHIAuditor` class (suggested: `app/infrastructure/security/phi/auditor.py`).
* **AUD-PHI-002:** Implement methods for auditing various targets:
  * `audit_file(file_path: Path, strict_mode: bool = False)`
  * `audit_directory(dir_path: Path, strict_mode: bool = False)`
  * `audit_log_entry(log_entry: str)`
  * *(Add other methods as required by tests)*
* **AUD-PHI-003:** Integrate with `PHIDetectionService` to identify PHI within targets.
* **AUD-PHI-004:** **N/A for infra `PHIAuditor`; logic belongs in runner/caller.**
* **AUD-PHI-005:** Ensure `test_phi_audit_logic.py` tests pass after implementation.

### 4.3. PHI Code Analyzer Implementation (`PHICodeAnalyzer`)

* **CZA-PHI-001:** Define/locate the canonical `PHICodeAnalyzer` class (suggested: `app/infrastructure/security/phi/code_analyzer.py`).
* **CZA-PHI-002:** Implement methods required by `test_phi_code_patterns.py`:
  * `scan_file(file_path: Path)`
  * `scan_directory(dir_path: Path, exclude_patterns: list[str] | None = None)`
  * `analyze_code_string(code_snippet: str)`
  * `audit_api_endpoints()` *(Requires integration with FastAPI routing)*
  * `audit_configuration()` *(Requires integration with config loading)*
* **CZA-PHI-003:** Integrate with `PHIDetectionService` to find PHI literals/patterns in code and config files.
* **CZA-PHI-004:** Handle different file types (Python, JavaScript, YAML, JSON, etc.) appropriately.
* **CZA-PHI-005:** Implement file/directory exclusion logic.
* **CZA-PHI-006:** Ensure `test_phi_code_patterns.py` tests pass after implementation.

### 4.4. PHI Middleware

* **MID-PHI-001:** Review/implement API middleware (suggested: `app/presentation/api/middleware/phi_middleware.py`) for optional, configurable PHI redaction of request/response bodies.
* **MID-PHI-002:** Ensure middleware correctly handles whitelisting patterns/fields as required by `test_phi_middleware.py`.
* **MID-PHI-003:** Ensure `test_whitelist_patterns` in `test_phi_middleware.py` passes.

### 4.5. Secure Error Handling

* **ERR-PHI-001:** Implement global error handlers or logging filters to ensure *no PHI* is ever included in logged stack traces or error responses returned to clients.
* **ERR-PHI-002:** Ensure `test_secure_error_handling` in `test_patient_phi_security.py` passes.

### 4.6. Test Suite (`app/tests/security/phi/`)

* **TST-PHI-001:** Fix all `ERROR` states (starting with `FileNotFoundError`).
* **TST-PHI-002:** Fix all `FAILED` states by implementing the required logic in `PHIAuditor`, `PHICodeAnalyzer`, middleware, and error handling.
* **TST-PHI-003:** Review and address all `SKIPPED` tests.
* **TST-PHI-004:** Update mocks for `PHIAuditor`, `PHICodeAnalyzer` in test files to accurately reflect the implemented interfaces if necessary.
* **TST-PHI-005:** Add new tests to ensure coverage for all requirements outlined in this PRD.

### 4.7. Configuration

* **CFG-PHI-001:** Centralize configuration related to PHI handling (e.g., pattern file path, default redaction text, middleware enablement) potentially in `app/core/config.py` or a dedicated section.
* **CFG-PHI-002:** Ensure configuration files themselves are audited and do not contain hardcoded PHI.

## 5. Non-Goals

* Implementing real-time PHI detection in user input fields (this might be a future feature).
* Advanced de-identification techniques beyond simple redaction/placeholder replacement.

## 6. Open Questions

* Where should the canonical `PHIAuditor` and `PHICodeAnalyzer` classes reside? (`app/infrastructure/security/phi/` seems appropriate).
* What is the exact expected behavior for `audit_api_endpoints` and `audit_configuration`? Requires deeper analysis of their intent.

## 7. Success Metrics

* 100% pass rate for tests in `app/tests/security/phi/`.
* Manual code review confirms adherence to Clean Architecture and removal of redundant PHI logic.
* No PHI detected in logs or error responses during testing.

## 8. Refactoring Checklist & Resumption Guide

### Instructions for Resuming Work

1. Run Tests: Execute `pytest app/tests/security/phi/` in the terminal from the project root (`/Users/ray/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Backend`) within the activated virtual environment (`.venv/bin/python -m pytest app/tests/security/phi/`).
2. Analyze Failures: Compare the test output (errors and failures) against this checklist.
3. Work Incrementally: Address one checklist item (or a small group of related items) at a time.
4. Verify: Rerun the tests after each change to confirm the fix and ensure no regressions.
5. Update Checklist: Mark completed items `[x]`.

### Checklist

#### Phase 1: Core Service & Basic Auditing

* [x] Fix `FileNotFoundError` (SRV-PHI-002): Correct the path calculation for `phi_patterns.yaml` within `PHIDetectionService.__init__` or `_load_patterns` in `app/infrastructure/ml/phi_detection/service.py`.
* [x] Define `PHIAuditor` (AUD-PHI-001): Create the class structure in `app/infrastructure/security/phi/auditor.py` (or confirm location).
* [x] Implement `PHIAuditor.audit_file` (AUD-PHI-002): Add basic implementation logic.
* [x] Implement `PHIAuditor.audit_directory` (AUD-PHI-002): Add basic implementation logic.
* [ ] Implement `PHIAuditor` Strict Mode/Path Logic (AUD-PHI-004): **N/A for infra `PHIAuditor`; logic belongs in runner/caller.**
* [ ] Fix `test_audit_file_detection` (TST-PHI-002): Ensure this test passes after `PHIAuditor` implementation.
* [ ] Fix `test_strict_mode_disables_special_handling` (TST-PHI-002): **Test relates to runner logic, not infra `PHIAuditor`.**

#### Phase 2: Code Analysis

* [x] Define `PHICodeAnalyzer` (CZA-PHI-001): Create the class structure in `app/infrastructure/security/phi/code_analyzer.py` (or confirm location).
* [x] Implement `PHICodeAnalyzer.analyze_file` (CZA-PHI-002): Add implementation.
* [x] Implement `PHICodeAnalyzer.analyze_directory` (CZA-PHI-002, CZA-PHI-005): Add implementation including exclusion logic.
* [x] Implement `PHICodeAnalyzer.analyze_code_string` (CZA-PHI-002): Add implementation.
* [x] Implement `PHICodeAnalyzer.audit_api_endpoints` (CZA-PHI-002): Added stub; **actual logic requires API layer access and belongs elsewhere.**
* [x] Implement `PHICodeAnalyzer.analyze_ast` (CZA-PHI-003): Basic implementation.
* [ ] Fix `AttributeError`s in `test_phi_code_patterns.py` (TST-PHI-002): Ensure all tests pass after `PHICodeAnalyzer` implementation.

#### Phase 3: Middleware & Error Handling

* [ ] Implement/Review PHI Middleware (MID-PHI-001, MID-PHI-002): Ensure middleware exists (e.g., `app/presentation/api/middleware/phi_middleware.py`) and handles whitelisting correctly.
* [ ] Fix `test_whitelist_patterns` (MID-PHI-003, TST-PHI-002): Ensure this middleware test passes.
* [ ] Implement Secure Error Handling (ERR-PHI-001): Add logging filters or adapt error handlers to prevent PHI leakage.
* [ ] Fix `test_secure_error_handling` (ERR-PHI-002, TST-PHI-002): Ensure this security test passes.

#### Phase 4: Cleanup & Finalization

* [ ] Address Skipped Tests (TST-PHI-003): Investigate why `test_patient_phi_security.py:147` (and potentially others) are skipped and resolve the underlying issues (e.g., missing Patient model fields).
* [ ] Review Test Mocks (TST-PHI-004): Ensure mocks for `PHIAuditor`, `PHICodeAnalyzer` are accurate.
* [ ] Add New Tests (TST-PHI-005): Enhance test coverage if gaps are identified.
* [ ] Centralize Configuration (CFG-PHI-001, CFG-PHI-002): Move PHI-related settings to a central config and ensure it's audited.
* [ ] Final Test Run: Confirm 100% pass rate for `app/tests/security/phi/`.
* [ ] Code Review: Perform manual review for Clean Architecture adherence and overall quality.
