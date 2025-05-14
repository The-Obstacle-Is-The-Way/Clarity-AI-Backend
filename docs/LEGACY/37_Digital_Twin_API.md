# Digital Twin API

**Status:** This document is **outdated** and requires significant revision. It describes a **target API** that differs substantially from the **current implementation** found in `backend/app/presentation/api/v1/endpoints/digital_twins.py`. Many endpoints listed here are **not implemented**, while many implemented endpoints are **not documented** here. The path structures also differ.

This document *aims* to describe the API endpoints for interacting with the Novamind Digital Twin system. It *needs updates* to provide accurate information about available endpoints, request/response formats, and usage examples based on the actual code.

---

## 1. Overview

The Digital Twin API *is intended to provide* programmatic access to create, update, query, and analyze Digital Twins. The API *should follow* RESTful principles and use JSON.

### 1.1. Base URL (Target)

*Target* Base URL:
```
https://api.novamind.io/api/v1
```
*Actual code uses routers mounted under `/api/v1`, e.g., `/api/v1/digital-twins/...`*

### 1.2. Authentication (Aspirational)

All API requests *should require* authentication using JWT.
```
Authorization: Bearer {token}
```
*Current Status: Authentication is not implemented. Auth endpoints and token validation logic are missing.*

### 1.3. Response Format (Target/Inconsistent)

*Target* response format:
```json
{
  "data": { ... },
  "meta": { ... } // timestamp, request_id, pagination
}
// Errors handled separately (see 1.4)
```
*Note: This differs slightly from the format in `11_API_Architecture.md` which included an `errors` array. The code's actual response format needs verification. Metadata like `request_id`, `pagination` is likely aspirational.*

### 1.4. Error Handling (Target/Inconsistent)

*Target* error response format:
```json
{
  "error": { // Note: singular 'error' object here vs 'errors' array in 11_...
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": { ... }
  },
  "meta": { ... }
}
```
Common error codes *should include*:
| Code | Description |
|------|-------------|
| `AUTHENTICATION_ERROR` | Invalid/missing authentication |
| `AUTHORIZATION_ERROR` | Insufficient permissions |
| `VALIDATION_ERROR` | Invalid request parameters |
| `RESOURCE_NOT_FOUND` | Resource does not exist |
| `TWIN_STATE_ERROR` | Invalid state transition |
| `INTERNAL_ERROR` | Server-side error |

*Current Status: Partially implemented. Actual code raises basic `HTTPException`. Standardized, structured error responses with codes and details are mostly unimplemented.*

## 2. Documented Digital Twin Endpoints (Largely Unimplemented)

*The following endpoints were documented but are **mostly NOT IMPLEMENTED** in the current codebase (`backend/app/presentation/api/v1/endpoints/digital_twins.py`). The path structure (`/digital-twins/{twin_id}`) also differs from the code's actual usage (`/digital-twins/{patient_id}`).*

### 2.1. Create Digital Twin
**Endpoint:** `POST /digital-twins`
*Status: **MISSING**.*

### 2.2. Get Digital Twin
**Endpoint:** `GET /digital-twins/{twin_id}`
*Status: **MISSING**. Code implements `GET /digital-twins/{patient_id}` which seems to initialize or get latest state.*

### 2.3. Get Digital Twin by Subject
**Endpoint:** `GET /subjects/{subject_id}/digital-twin`
*Status: **MISSING**.*

### 2.4. Update Digital Twin Data
**Endpoint:** `POST /digital-twins/{twin_id}/data`
*Status: **MISSING**. Code implements `POST /digital-twins/{patient_id}/events` which might serve a similar purpose but is undocumented here.*

### 2.5. Get Digital Twin State
**Endpoint:** `GET /digital-twins/{twin_id}/state`
*Status: **MISSING**. Code implements `GET /digital-twins/{patient_id}` which returns some state.*

### 2.6. Get Digital Twin History
**Endpoint:** `GET /digital-twins/{twin_id}/history`
*Status: **MISSING**.*

### 2.7. Generate Insights
**Endpoint:** `POST /digital-twins/{twin_id}/insights/generate`
*Status: **MISSING**. Code implements `GET /digital-twins/{patient_id}/insights` which generates and returns insights directly.*

### 2.8. Get Insights
**Endpoint:** `GET /digital-twins/{twin_id}/insights`
*Status: **MISSING**. Code implements `GET /digital-twins/{patient_id}/insights` which generates and returns insights directly.*

### 2.9. Simulate Intervention
**Endpoint:** `POST /digital-twins/{twin_id}/simulate`
*Status: **MISSING**.*

### 2.10. Archive Digital Twin
**Endpoint:** `POST /digital-twins/{twin_id}/archive`
*Status: **MISSING**.*

## 3. Documented Data Points Endpoints (Unimplemented)

*Endpoints for granular data point management (`POST` and `GET /digital-twins/{twin_id}/data-points`) are documented below but **MISSING** from the code.*

### 3.1. Add Data Points
**Endpoint:** `POST /digital-twins/{twin_id}/data-points`
*Status: **MISSING**.*

### 3.2. Get Data Points
**Endpoint:** `GET /digital-twins/{twin_id}/data-points`
*Status: **MISSING**.*

## 4. Documented Features Endpoints (Unimplemented)

*Endpoint for retrieving features (`GET /digital-twins/{twin_id}/features`) is documented below but **MISSING** from the code.*

### 4.1. Get Features
**Endpoint:** `GET /digital-twins/{twin_id}/features`
*Status: **MISSING**.*

## 5. Documented Models Endpoints (Unimplemented)

*Endpoints for retrieving and training models (`GET /digital-twins/{twin_id}/models`, `POST /digital-twins/{twin_id}/models/train`) are documented below but **MISSING** from the code.*

### 5.1. Get Models
**Endpoint:** `GET /digital-twins/{twin_id}/models`
*Status: **MISSING**.*

### 5.2. Train Model
**Endpoint:** `POST /digital-twins/{twin_id}/models/train`
*Status: **MISSING**.*

## 6. Documented Export Endpoints (Unimplemented)

*Endpoints for data export (`POST /digital-twins/{twin_id}/export`, `GET /exports/{export_id}`) are documented below but **MISSING** from the code.*

### 6.1. Export Digital Twin Data
**Endpoint:** `POST /digital-twins/{twin_id}/export`
*Status: **MISSING**.*

### 6.2. Get Export Status
**Endpoint:** `GET /exports/{export_id}`
*Status: **MISSING**.*

## 7. Documented Job Status Endpoints (Unimplemented)

*Endpoint for checking job status (`GET /jobs/{job_id}`) is documented below but **MISSING** from the code.*

### 7.1. Get Job Status
**Endpoint:** `GET /jobs/{job_id}`
*Status: **MISSING**.*

## 8. Documented Webhooks (Unimplemented)

*Endpoints and functionality for webhooks (`POST /webhooks`, payload format) are documented below but **MISSING** from the code.*

### 8.1. Configure Webhooks
**Endpoint:** `POST /webhooks`
*Status: **MISSING**.*

### 8.2. Webhook Payload Format (Aspirational)
*Status: **MISSING**.*

## 9. Rate Limits (Aspirational)

*Specific rate limits described below are aspirational. Implementation is missing.*

## 10. Client Libraries (Aspirational)

*Client libraries mentioned are aspirational and depend on a stable, implemented API.*

---

## Appendix: Implemented (but Undocumented Here) Endpoints

*The following endpoints **exist** in `backend/app/presentation/api/v1/endpoints/digital_twins.py` but are **not documented** above. They generally use the path prefix `/api/v1/digital-twins/{patient_id}`.*

-   `GET /{patient_id}/status`: Get Digital Twin build status.
-   `GET /{patient_id}/insights`: Generate comprehensive patient insights.
-   `POST /{patient_id}/analyze-text`: Analyze clinical text (MentalLLaMA).
-   `GET /{patient_id}/forecast`: Generate symptom forecast.
-   `GET /{patient_id}/correlations`: Correlate biometrics.
-   `GET /{patient_id}/medication-response`: Predict medication response.
-   `GET /{patient_id}/treatment-plan`: Generate personalized treatment plan.
-   `GET /{patient_id}`: Get latest state (potentially initialize).
-   `POST /{patient_id}/events`: Process a treatment event.
-   `GET /{patient_id}/recommendations`: Generate treatment recommendations.
-   `GET /{patient_id}/visualization`: Get visualization data.
-   `POST /{patient_id}/compare`: Compare two digital twin states.
-   `GET /{patient_id}/summary`: Generate clinical summary.

*Note: The exact request/response formats and behavior of these implemented endpoints need to be documented properly.* 

Last Updated: 2025-04-20
