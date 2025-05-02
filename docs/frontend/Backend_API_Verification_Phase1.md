# Backend API Verification Summary (Phase 1)

This document summarizes the verified backend API endpoints and schemas identified in the `Clarity-AI-Backend` codebase (`/Users/ray/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Backend`) relevant to Phase 1 frontend integration.

**Base Path:** `/api/v1/`

---

## 1. Authentication

**Source File:** `app/presentation/api/v1/endpoints/auth.py`

*   **Login:**
    *   **Method:** `POST`
    *   **Path:** `/api/v1/auth/login`
    *   **Request Body (`LoginRequest`):** `{ username: str, password: str, remember_me: bool }`
    *   **Response Body (`TokenResponse`):** `{ access_token: str, refresh_token: str, token_type: "bearer", expires_in: int }`
    *   **Notes:** Sets `access_token` and `refresh_token` as HttpOnly cookies. Frontend should primarily rely on cookies for session management after login.
*   **Refresh Token:**
    *   **Method:** `POST`
    *   **Path:** `/api/v1/auth/refresh`
    *   **Request Body (`RefreshRequest` - Optional):** `{ refresh_token: str }` (Also reads `refresh_token` from cookie)
    *   **Response Body (`TokenResponse`):** Same as Login.
    *   **Notes:** Used to obtain a new access token using the refresh token. Frontend might need logic to handle token expiration and refresh.
*   **Logout:**
    *   **Method:** `POST`
    *   **Path:** `/api/v1/auth/logout`
    *   **Request Body:** None (Uses tokens from cookies/headers)
    *   **Response:** `204 No Content`
    *   **Notes:** Clears auth cookies. Frontend should call this endpoint upon user logout action.
*   **Get Current User:**
    *   **Method:** `GET`
    *   **Path:** `/api/v1/auth/me`
    *   **Request:** Requires valid access token (via cookie or Authorization header, handled by backend dependency `get_current_user`).
    *   **Response Body (`UserResponse`):** `{ id: str, email: EmailStr, first_name: Optional[str], last_name: Optional[str], roles: list[str], is_active: bool }`
    *   **Notes:** Essential for initializing `AuthContext` on application load or after login/refresh.

---

## 2. Patients

**Source File:** `app/presentation/api/v1/endpoints/patients.py`
**Schema File:** `app/presentation/api/v1/schemas/patient.py` (Currently a placeholder)

*   **Notes:**
    *   The backend implementation currently uses a **simple in-memory store** for testing purposes, not a persistent database.
    *   Endpoints accept and return plain `Dict[str, Any]` rather than strictly typed Pydantic models defined in the placeholder schema file. Frontend needs to handle this.
    *   Includes specific hardcoded logic for a test patient ID "P12345".
*   **Create Patient:**
    *   **Method:** `POST`
    *   **Path:** `/api/v1/patients/`
    *   **Request Body (`Dict[str, Any]`):** Requires `id`, `medical_record_number`, `name`. Optional: `date_of_birth` (str YYYY-MM-DD), `gender` (str), `email` (str).
    *   **Response Body (`Dict[str, Any]`):** Echoes back the created patient data dictionary.
*   **Get Patient by ID:**
    *   **Method:** `GET`
    *   **Path:** `/api/v1/patients/{patient_id}`
    *   **Request:** Path parameter `patient_id: str`
    *   **Response Body (`Dict[str, Any]`):** Patient data dictionary.
*   **Update Patient:**
    *   **Method:** `PATCH`
    *   **Path:** `/api/v1/patients/{patient_id}`
    *   **Request Body (`Dict[str, Any]`):** Dictionary of fields to update.
    *   **Response Body (`Dict[str, Any]`):** Updated patient data dictionary.
*   **Delete Patient:**
    *   **Method:** `DELETE`
    *   **Path:** `/api/v1/patients/{patient_id}`
    *   **Request:** Path parameter `patient_id: str`
    *   **Response:** `204 No Content`
*   **(Get List - Implied):** No explicit `/api/v1/patients/` GET endpoint was found in `patients.py` for listing all patients. This might be missing or located elsewhere. **Action:** Needs confirmation or implementation on the backend if required by the frontend.

---

## 3. Brain Models (via Digital Twins)

**Source File:** `app/presentation/api/v1/endpoints/digital_twins.py`
**Schema File:** `app/presentation/api/v1/schemas/digital_twin_schemas.py`

*   **Notes:**
    *   Brain model data is retrieved via the Digital Twin visualization endpoint.
    *   The specific response schema for the visualization data is not defined in `digital_twin_schemas.py` but returned as `Dict[str, Any]` from the service layer. Frontend needs to adapt to the actual structure returned.
*   **Get Brain Model Visualization:**
    *   **Method:** `GET`
    *   **Path:** `/api/v1/digital-twins/{patient_id}/visualization`
    *   **Request:** Path parameter `patient_id: UUID`. Optional query parameter `visualization_type: str` (defaults to `brain_model_3d`). Requires authentication.
    *   **Response Body (`Dict[str, Any]`):** Expected to contain data suitable for rendering the 3D brain model (e.g., geometry, regions, activity levels). Actual structure needs confirmation during integration.

---

## Discrepancies & Frontend Impact Summary

1.  **Patients API:** Backend uses `Dict[str, Any]` due to in-memory store, frontend uses typed `Patient`. Frontend services need to correctly format requests and parse dictionary responses, potentially mapping them to the `Patient` type. Lack of a "Get List" endpoint needs clarification.
2.  **Brain Model API:**
    *   **Endpoint Mismatch:** Frontend mock/service uses `/brain-models/{model_id}`; Backend uses `/digital-twins/{patient_id}/visualization`. Frontend `brain-model.service.ts` needs significant updates to use the correct path and parameter (`patient_id`).
    *   **Schema Mismatch:** Backend returns `Dict[str, Any]`; Frontend expects typed `BrainModel`. Frontend needs to adapt to the actual structure returned by the visualization endpoint. 