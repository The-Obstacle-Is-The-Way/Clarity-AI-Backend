# Frontend Integration Checklist (Phase 1)

This checklist outlines the frontend tasks required to integrate with the verified backend API for Phase 1 features, based on the findings in `docs/Backend_API_Verification_Phase1.md`.

**Reference:** `docs/E2E/README.md` (Phase 1)
**DIRECTORIES**: 
        "/Users/ray/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Backend",
        "/Users/ray/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Frontend"
            - Both are available via MCP Tool
---

## Prerequisites

- [x] Verify backend API endpoints and schemas (See `docs/Backend_API_Verification_Phase1.md`)
- [x] Modify `ApiGateway.ts` to default to the *real* `ApiClient` in development mode.

---

## Tasks

### 1. Configuration

-   [ ] **Vite Proxy:**
    -   [ ] Examine `config/vite.config.ts` (or `vite.config.ts` at root).
    -   [ ] Ensure `server.proxy` correctly forwards `/api` requests to the running backend address and port (e.g., `target: 'http://localhost:8000'`).
    -   [ ] Add `changeOrigin: true` to the proxy options if necessary.
    -   [ ] Configure `secure: false` if the backend uses self-signed SSL certificates in development.
-   [ ] **Environment Variables:**
    -   [ ] Confirm `VITE_API_BASE_URL` in `.env` files points to the correct base path (e.g., `/api/v1` or the full backend URL if not using proxy effectively).

### 2. Authentication Integration (Phase 1, Item 2)

-   [ ] **`authService.ts` (`src/application/services/authService.ts`):
    -   [ ] Verify `login` method:
        -   [ ] Calls `POST /api/v1/auth/login` via `apiClient` (from `ApiGateway`).
        -   [ ] Sends correct request body: `{ username: string, password: string, remember_me: boolean }`.
        -   [ ] Handles successful response (Tokens are primarily handled via cookies by the backend, but the response body `{ access_token, refresh_token, ... }` might be used for initial state).
        -   [ ] Handles error responses (e.g., 401 Unauthorized).
    -   [ ] Implement `logout` method:
        -   [ ] Calls `POST /api/v1/auth/logout` via `apiClient`.
        -   [ ] Handles success/error.
    -   [ ] Implement `getCurrentUser` (or similar for fetching user profile):
        -   [ ] Calls `GET /api/v1/auth/me` via `apiClient`.
        -   [ ] Parses the `UserResponse` (`{ id, email, ... }`).
        -   [ ] Handles success/error (e.g., 401 if no valid session).
    -   [ ] (Optional) Implement `refreshToken` method if frontend needs to manage refresh logic.
-   [ ] **`AuthContext.tsx` (`src/application/context/AuthContext.tsx`):
    -   [ ] Modify `login` function to call `authService.login`.
    -   [ ] On successful login, call `authService.getCurrentUser` to fetch user profile and update context state (user, isAuthenticated).
    -   [ ] Modify `logout` function to call `authService.logout` and clear context state.
    -   [ ] Implement logic on application load to call `authService.getCurrentUser` to check for existing session cookies and initialize context state.
-   [ ] **`LoginForm.tsx` (`src/presentation/organisms/LoginForm.tsx`):
    -   [ ] Ensure it uses React Hook Form (`useForm`) + Zod (`zodResolver`) for input validation (`username`, `password`).
    -   [ ] On submit, call the `login` function from `AuthContext` with form data.
    -   [ ] Display success/error messages (e.g., using `react-hot-toast`).
-   [ ] **`ProtectedRoute.tsx` (`src/presentation/routes/ProtectedRoute.tsx`):
    -   [ ] Verify it correctly checks `isAuthenticated` status from `AuthContext` to control route access.
-   [ ] **Verification:**
    -   [ ] Restart dev server (`npm run dev`).
    -   [ ] Use browser DevTools (Network, Console) to confirm successful login API calls (`POST /api/v1/auth/login`, `GET /api/v1/auth/me`).
    -   [ ] Check for HttpOnly cookies (`access_token`, `refresh_token`) being set in the browser.
    -   [ ] Confirm failed login attempts result in appropriate errors.
    -   [ ] Verify protected routes are inaccessible when logged out and accessible when logged in.
    -   [ ] Verify logout clears session/cookies and redirects appropriately.

### 3. Patient Service Integration (Phase 1, Item 3 - Partial)

-   [ ] **`patientService.ts` (`src/application/services/patientService.ts`):
    -   [ ] **Path Alignment:** Update all API call paths to match the backend:
        -   Create: `POST /api/v1/patients/`
        -   Get by ID: `GET /api/v1/patients/{patient_id}`
        -   Update: `PATCH /api/v1/patients/{patient_id}`
        -   Delete: `DELETE /api/v1/patients/{patient_id}`
    -   [ ] **Schema Handling:**
        -   Modify methods to send required fields as a plain JavaScript object (`Dict[str, Any]`) in request bodies (e.g., `createPatient`, `updatePatient`).
        -   Modify methods to handle plain JavaScript object responses (`Dict[str, Any]`) and potentially map them back to the frontend `Patient` type if needed by TanStack Query or UI components.
    -   [ ] **Get List:** Clarify backend requirements/implementation for a `GET /api/v1/patients/` endpoint to fetch all patients. Implement frontend call if/when backend endpoint exists.
-   [ ] **TanStack Query Hooks (`src/application/hooks/usePatients.ts`?):
    -   [ ] Update query keys and query functions to use the corrected `patientService` methods.
    -   [ ] Ensure data transformation/mapping (from `Dict` to `Patient` type) happens correctly if needed.
-   [ ] **UI Components (`src/presentation/pages/PatientListPage.tsx`, `PatientDetailPage.tsx`, etc.):**
    -   [ ] Verify components correctly use the TanStack Query hooks and handle the potentially mapped `Patient` data or the raw dictionary structure.

### 4. Brain Model Service Integration (Phase 1, Item 4)

-   [ ] **`brain-model.service.ts` (`src/application/services/brain-model.service.ts`):
    -   [ ] **Endpoint Update:** Change the method for fetching brain model data (e.g., `getBrainModel`) to target the correct backend endpoint:
        -   **Method:** `GET`
        -   **Path:** `/api/v1/digital-twins/{patient_id}/visualization`
        -   **Parameters:** Use `patient_id` (likely UUID/string) instead of `model_id`. Pass `visualization_type=brain_model_3d` if needed (or rely on default).
    -   [ ] **Schema Handling:**
        -   Modify the method to expect a `Dict[str, Any]` response.
        -   Adapt the response handling to parse the actual structure returned by the backend and map it to the frontend `BrainModel` type (`src/domain/types/brain/models.ts`). This requires inspecting the actual API response during integration.
-   [ ] **TanStack Query Hooks (`src/application/hooks/useBrainModel.ts`?):
    -   [ ] Update query keys and query functions to use the corrected `brain-model.service` method.
    -   [ ] Ensure data transformation/mapping (from `Dict` to `BrainModel` type) is robust.
-   [ ] **UI Components (`src/presentation/organisms/BrainVisualizationContainer.tsx`, `BrainModelViewer.tsx`):
    -   [ ] Verify components receive the correctly typed `BrainModel` data from the hook.
    -   [ ] Ensure the structure passed to R3F components matches the expected props based on the fetched and mapped data.

---

## Post-Integration

- [ ] Update `docs/E2E/README.md` checklist items for Phase 1 upon completion of relevant tasks.
- [ ] Address any CORS issues encountered during integration.
- [ ] Perform thorough testing of integrated features. 