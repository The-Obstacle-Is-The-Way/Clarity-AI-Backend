# 30. Configuration Management

This document describes how application settings are managed across different environments (development, testing, production) for the Novamind backend.

---

## 1. Overview

The application utilizes the `pydantic-settings` library to manage configuration. Settings are defined in Python classes inheriting from `BaseSettings` and are primarily loaded from environment variables, providing a flexible and secure way to configure the application for different deployment scenarios.

## 2. Configuration Structure

- **Primary File**: The main configuration definitions reside in `backend/app/config/settings.py`.
- **Main Class**: A central `Settings` class aggregates all configuration options.
- **Nested Models**: To improve organization, related settings are grouped into nested `BaseSettings` models (e.g., `MLSettings`, `MentalLlamaSettings`, `DatabaseSettings` [if refactored]).
- **Type Safety**: Pydantic ensures that loaded settings conform to their defined types (e.g., `str`, `int`, `bool`, `SecretStr`, `PostgresDsn`).

## 3. Loading Mechanism

- **Environment Variables**: The primary source for configuration values. `pydantic-settings` automatically reads values from environment variables corresponding to the field names (or specified `env` names in `json_schema_extra`).
    - **Prefixes**: Nested settings models can define an `env_prefix` (e.g., `MENTALLAMA_`) so their corresponding environment variables are structured (e.g., `MENTALLAMA_PROVIDER`, `MENTALLAMA_OPENAI_API_KEY`).
    - **Case Insensitivity**: Environment variable names are typically case-insensitive during loading.
- **`.env` Files**: `pydantic-settings` supports loading variables from `.env` files automatically during development, though this should be verified if actively used. Production environments should rely solely on explicitly set environment variables.
- **Defaults**: Default values are defined directly in the `Settings` classes, used when corresponding environment variables are not set.
- **Validation**: Pydantic validators (`@field_validator`, `@model_validator`) are used to:
    - Parse complex environment variable values (e.g., JSON strings for lists/dicts like `BACKEND_CORS_ORIGINS`).
    - Implement conditional logic (e.g., constructing `DATABASE_URL` from individual components like `POSTGRES_USER`, `POSTGRES_PASSWORD`, etc., if `DATABASE_URL` itself isn't provided).

## 4. Key Configuration Areas

The `settings.py` file manages critical settings, including but not limited to:

- **API Configuration**: Base paths (`API_V1_STR`), project name, description.
- **Environment**: `ENVIRONMENT` (e.g., "development", "testing", "production"), `DEBUG`, `TESTING` flags.
- **Security**: `SECRET_KEY`, `ALGORITHM`, token expiry times (`ACCESS_TOKEN_EXPIRE_MINUTES`), MFA secrets.
- **Database**: Connection details (`DATABASE_URL` or individual components like `POSTGRES_SERVER`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_PORT`), pool settings (`DB_POOL_SIZE`), SSL options.
- **CORS**: Allowed origins (`BACKEND_CORS_ORIGINS`).
- **ML Models**: Paths, API keys, provider details for various ML components (MentalLlama, PAT, XGBoost, etc.), often nested under an `MLSettings` object.
- **PHI Handling**: Paths to exclude from certain middleware (`PHI_EXCLUDE_PATHS`), audit modes.
- **Audit Logging**: Log level, file output options.
- **Encryption**: Keys (`ENCRYPTION_KEY`) and salts.

Refer directly to `backend/app/config/settings.py` for the complete list of settings and their corresponding environment variable names (often specified via `json_schema_extra={'env': '...'}`).

## 5. Secrets Management

- **`SecretStr`**: Sensitive values like API keys, passwords, and secret keys are typed as `pydantic.SecretStr`. This prevents their actual values from being inadvertently exposed in logs, tracebacks, or standard string representations (`repr`). Access the actual value using `.get_secret_value()` only when strictly necessary.
- **Environment Variables**: In production, sensitive values must **only** be supplied via secure environment variable injection mechanisms (e.g., Kubernetes Secrets, cloud provider secret managers), never hardcoded or stored in version control.

## 6. Environment-Specific Configuration

- **Loading**: The same `Settings` class is used for all environments. The behavior changes based on the values loaded from the environment variables specific to that environment.
- **`ENVIRONMENT` Variable**: The `ENVIRONMENT` setting variable (e.g., set to `production` or `staging`) can be used within the application code (sparingly) to enable/disable features or modify behavior if absolutely necessary, though feature flags are often preferred.
- **Defaults**: Default values in `settings.py` are typically suitable for local development.

## 7. Accessing Settings in Application

- **Dependency Injection**: The recommended way to access settings within FastAPI is via dependency injection.
- **`get_settings()` Function**: A cached function `get_settings()` (likely located in `settings.py` or a dependencies module) provides a singleton instance of the loaded `Settings` object.

  ```python
  from fastapi import Depends, FastAPI
  from ..config.settings import Settings, get_settings # Adjust import path

  app = FastAPI()

  @app.get("/info")
  async def info(settings: Settings = Depends(get_settings)):
      return {
          "project_name": settings.PROJECT_NAME,
          "environment": settings.ENVIRONMENT,
          # Avoid exposing sensitive settings here!
      }
  ```

---

Proper configuration management is crucial for security and operational stability. Ensure all environment-specific settings, especially secrets, are managed securely.

Last Updated: 2025-04-20
