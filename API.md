# PRD: API Structure Refactoring & Consolidation (Version 2.0 - Explicit)

## 1. Document Purpose & Target Audience

**Purpose:** This document provides extremely detailed, step-by-step instructions to refactor the FastAPI API structure. The goal is to establish a single, canonical location for all V1 API endpoint routers within the presentation layer, adhering to Clean Architecture principles, and eliminating all legacy/conflicting structures.

**Target Audience:** Any developer or AI agent tasked with executing this refactoring. Assumes basic familiarity with Python, FastAPI, and the project's file system. **No prior context regarding previous refactoring attempts should be necessary if these steps are followed precisely.**

## 2. Problem Statement & Root Cause

The current codebase suffers from a fractured and inconsistent API structure:

* **Multiple Conflicting Locations:** API endpoint router (`.py` files containing `APIRouter` instances) logic exists scattershot across:
  * `app/api/routes/` (Incorrect top-level)
  * `app/api/routes/v1/endpoints/` (Incorrect nested structure)
  * `app/presentation/api/v1/endpoints/` (Legacy presentation structure)
* **Architectural Violation:** Routers, being part of the user interface/HTTP layer, belong strictly within the **Presentation Layer**, not mixed within a generic `app/api/` directory.
* **Import Errors:** The main API router (`app/presentation/api/v1/api_router.py`) contains imports pointing to these inconsistent and sometimes non-existent locations, causing `ModuleNotFoundError` during startup and testing.
* **Developer Confusion:** It's unclear where new or existing API endpoints should reside.
* **Missing Endpoints:** Placeholders/commented imports exist for `biometric_alert_rules` and `digital_twin` routers, which are currently missing from *any* location.

## 3. Goal: Achieve Architectural Purity & Consistency

1. **Establish Single Source of Truth:** Define **`app/presentation/api/v1/routes/`** as the **sole, canonical, and architecturally correct** directory for *all* Version 1 API endpoint router definition files (`.py` files).
2. **Flat Structure:** This target directory (`app/presentation/api/v1/routes/`) **MUST** contain router files directly within it (e.g., `app/presentation/api/v1/routes/auth.py`). **NO subdirectories** are allowed within this `routes` folder for organizing V1 routers.
3. **Migrate ALL Logic:** Relocate *all* existing, active router logic from the incorrect/legacy locations into the single target directory.
4. **Update Main Router:** Modify `app/presentation/api/v1/api_router.py` to import V1 routers *exclusively* from `app.presentation.api.v1.routes.<router_name>`.
5. **Fix Internal Imports:** Ensure all relative imports within the moved router files are updated to use correct absolute paths based on their new location.
6. **Eliminate Obsolete Structures:** Completely remove the legacy `app/presentation/api/v1/endpoints/` directory and the *entire* incorrect `app/api/` directory structure.
7. **Handle Missing Endpoints:** Keep imports for `biometric_alert_rules` and `digital_twin` commented out in `api_router.py` until these endpoints are implemented *in the correct target location* (`app/presentation/api/v1/routes/`).

## 4. Prerequisites

* Access to the project filesystem.
* Ability to execute file system commands (move, delete) and edit files.
* Python environment with `pytest` installed to run verification checks.
* **CRITICAL:** Any previous, partially executed refactoring steps related to moving these files must be reverted or accounted for. The following steps assume the state described in the "Problem Statement".

---
