# Project Architecture Overview

This document outlines the intended architecture for the Clarity-AI-Backend project, following Clean Architecture principles.

## Layers

The application is structured into the following distinct layers:

1.  **Domain Layer (`app/core/domain`)**:
    *   Contains core business logic, entities (e.g., Patient, DigitalTwin), and value objects.
    *   Has no dependencies on other layers.
    *   Defines interfaces for repositories and services required by use cases.

2.  **Application Layer (`app/core/services`, `app/core/use_cases`)**:
    *   Orchestrates use cases by coordinating domain entities and interfaces.
    *   Implements the interfaces defined in the Domain layer (e.g., service implementations).
    *   Depends only on the Domain layer.

3.  **Infrastructure Layer (`app/infrastructure`)**:
    *   Provides concrete implementations for external concerns like databases, external APIs, and frameworks.
    *   Implements repository interfaces defined in the Domain layer (e.g., using SQLAlchemy for persistence).
    *   Handles integrations with third-party services (AWS, Temporal, etc.).
    *   Depends on Domain and Application layers (interfaces).

4.  **Presentation Layer (`app/presentation`)**:
    *   Handles interaction with the outside world (e.g., web APIs, CLI).
    *   Adapts data between the Application layer and the external interface format.
    *   **API Sub-layer (`app/presentation/api`)**: Contains API-specific components:
        *   `schemas/`: Pydantic models for request/response validation and serialization.
        *   `dependencies/`: FastAPI dependencies (e.g., for authentication, service injection).
        *   `v1/endpoints/`: FastAPI routers and endpoint definitions, organized by version and resource.

## Current Architectural Inconsistencies (`app/api` vs `app/presentation/api`)

There is currently a significant inconsistency regarding the location of the API layer components:

*   **Intended Structure:** Based on Clean Architecture principles and the organization within `app/presentation/api` (containing `schemas`, `dependencies`, `v1/endpoints`), this (`app/presentation/api`) is the **correct and intended location** for the API presentation layer.
*   **Conflicting Code/Comments:**
    *   An older(?) `app/api` directory exists.
    *   Files within `app/presentation/api` (specifically `__init__.py` and `rule_templates.py`) contain comments and compatibility imports suggesting that `app/api` is the *new* location and `app/presentation/api` is for backward compatibility. **This is considered incorrect/outdated documentation.**
    *   Current `pytest` errors and tracebacks consistently indicate that modules are expected under `app/presentation/api`.

## Resolution Path

1.  **Source of Truth:** This document establishes `app/presentation/api` as the definitive API layer.
2.  **Immediate Focus:** Fix current `pytest` errors by creating/modifying files within `app/presentation/api` as dictated by the tracebacks. This is necessary to unblock testing.
3.  **Future Refactoring Goal:**
    *   **Consolidate** all API-related code (endpoints, schemas, dependencies, routing) **exclusively** within `app/presentation/api`.
    *   **Remove** the compatibility shims in `app/presentation/api/__init__.py` and `app/presentation/api/rule_templates.py`.
    *   **Refactor or Remove** the `app/api` directory entirely, migrating any essential setup logic (like main router configuration) into the `app/presentation/api` structure or the main application factory (`app/main.py`).
    *   Ensure all code consistently uses imports from `app/presentation/api`.

This documentation serves as the **source of truth** for the intended architecture. We will work towards resolving the inconsistencies and fully aligning the codebase with this structure.

## Directory Analysis (`app/presentation/api`) - As of 2025-05-03

*   **`app/presentation/api/__init__.py`**: *Problematic.* Contains outdated compatibility shim importing from `app.api`. **Should be empty or contain minimal presentation-level initialization.** (Refactoring target)
*   **`app/presentation/api/dependencies/`**: Correctly structured. Contains API dependencies:
    *   `auth.py`: Authentication dependencies.
    *   `rate_limiter_deps.py`: Rate limiting dependencies.
    *   `services.py`: Service injection dependencies.
*   **`app/presentation/api/schemas/`**: Correctly structured. Contains Pydantic API schemas:
    *   `xgboost.py`: Schemas for XGBoost endpoints (created during error fixing).
*   **`app/presentation/api/v1/`**: Correctly structured. Contains version 1 endpoints:
    *   `endpoints/`: Directory holding specific endpoint routers.
*   **`app/presentation/api/rule_templates.py`**: *Problematic.* Contains outdated compatibility shim importing from `app.api.rules`. **Should likely be removed or its contents moved to `app/presentation/api/schemas` if they represent API data structures.** (Refactoring target)
