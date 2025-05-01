# Clarity-AI Digital Twin Backend

> A HIPAA‑compliant, ML‑driven backend for creating and managing "digital twins" of patients—aggregating wearable data, surfacing analytics, automating alerts, and drafting clinical documentation to augment psychiatric care.

## What is a Digital Twin for Mental Health?

A digital twin is a computational representation of a patient's mental health state that evolves over time as new data is incorporated. In psychiatry, digital twins integrate diverse data streams (biometric, clinical, genetic, behavioral) to create personalized models that enable:

- **Continuous Monitoring**: Track mental health state changes between appointments
- **Pattern Recognition**: Identify correlations between biometrics and symptoms
- **Predictive Insights**: Forecast symptom trajectories and treatment responses
- **Personalized Treatment**: Tailor interventions to individual patient characteristics

This system aims to bridge the critical gap in psychiatric care by providing objective, quantitative measurements and predictions where traditional assessments rely heavily on subjective self-reporting and infrequent clinical observations.

![Conceptual diagram of a Digital Twin for Health (DT4H), showing the connection between physical entity data and digital twin applications.](./images/digital-twin-for-health.png)
*Fig. 1: Digital twin for health (DT4H) envisioned. From: [Katsoulakis, E., Wang, Q., Wu, H. et al. Digital twins for health: a scoping review. npj Digit. Med. 7, 77 (2024).](https://www.nature.com/articles/s41746-024-01073-0)*

## Technical Architecture

The Clarity-AI backend employs a clean architecture approach with four distinct layers:

```ascii
┌───────────────────┐      ┌───────────────────┐
│  Presentation     │─▶───▶│  Application      │
│ (FastAPI + Schemas│      │ (Use‑Cases)       │
│  + Middleware)    │      └───────────────────┘
└───────────────────┘              │
        ▲                          ▼
        │                  ┌───────────────────┐
┌───────────────────┐      │  Domain           │
│ Infrastructure    │◀────▶│ (Pydantic Models) │
│ (DB, ML, Cache,   │      └───────────────────┘
│  Messaging, Auth) │
└───────────────────┘
```

- **Domain Layer**: Core entities, value objects, and domain services that encapsulate psychiatric digital twin models
- **Application Layer**: Orchestrates use cases and workflows across multiple domain entities
- **Infrastructure Layer**: Implements external service integrations, persistence, and ML model execution
- **Presentation Layer**: HIPAA-compliant API with versioning, schema validation, and PHI protections

## AI/ML Components

Clarity-AI leverages multiple ML technologies to derive insights from patient data:

- **MentalLLaMA33B**: Large language model specially fine-tuned for mental health to analyze clinical notes, extract insights, and draft documentation
- **XGBoost**: Gradient-boosted decision trees for treatment response prediction, medication efficacy analysis, and risk assessment
- **Pretrained Actigraphy Transformer (PAT)**: Foundation model for analyzing wearable movement data to identify behavioral patterns
- **LSTM Networks**: Recurrent neural networks for time-series analysis of symptom trajectories and biometric data

## Key Features

- **Patient Management**: CRUD APIs for encrypted, PHI‑safe patient records  
- **Biometric Ingestion**: High‑frequency wearable/event streams (actigraphy, HR, sleep)  
- **Digital Twin Generation**: Aggregate time‑series into unified patient profiles  
- **Predictive Analytics**: XGBoost, LSTM, and LLM‑driven risk insights  
- **Rule‑Based Alerts**: Dynamic clinical rule engine for threshold/anomaly notifications  
- **Clinical Documentation**: Auto‑draft encounter notes via OpenAI LLM  
- **Secure Messaging**: SMS/email reminders & alerts (Twilio/SES)  
- **PHI Sanitization & Audit**: Middleware that strips/logs PHI access events  
- **Auth & RBAC**: JWT authentication, role‑based access control, rate limiting

## Clinical Significance

The Clarity-AI Digital Twin platform addresses critical gaps in traditional psychiatric care:

1. **Objective Measurement**: Replaces subjective self-reporting with continuous quantitative data
2. **Longitudinal Insights**: Extends visibility beyond sparse clinical appointments
3. **Early Intervention**: Enables detection of subtle state changes before acute episodes
4. **Treatment Optimization**: Uses predictive models to identify optimal medication and therapy approaches
5. **Reduced Clinician Burden**: Automates documentation and routine monitoring tasks

Research in digital twins for mental health indicates potential for revolutionizing psychiatric practice through:
- Enhanced precision in diagnosis and treatment planning
- Reduced time to treatment optimization
- Improved patient engagement and outcomes
- More efficient resource allocation

## Getting Started

### Prerequisites

- **Python 3.10+**  
- **PostgreSQL 13+**  
- **Redis**  
- **Docker & Docker Compose** (optional)  
- **AWS Credentials** (S3)  
- **OpenAI API Key**  

### Installation

```bash
git clone https://github.com/your-org/Clarity-AI-Backend.git
cd Clarity-AI-Backend
```

### Configuration

This project uses Pydantic V2's BaseSettings. You must set the following environment variables (or load them via your own .env):

1. **Core**
   - `ENVIRONMENT`: development/test/staging/production
   - `DATABASE_URL`: Postgres DSN (postgres://user:pass@host:5432/db)
   - `REDIS_URL`: Redis URI (redis://host:6379/0)
   - `JWT_SECRET_KEY`: Secret for signing JWTs

2. **AWS & Storage**
   - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
   - `S3_BUCKET`: for any attachments

3. **OpenAI**
   - `OPENAI_API_KEY`
   - `MENTALLAMA_MODEL_MAPPINGS`: JSON string mapping LLM model names

4. **XGBoost Models**
   - `XGBOOST_TREATMENT_RESPONSE_MODEL_PATH`
   - `XGBOOST_OUTCOME_PREDICTION_MODEL_PATH`
   - `XGBOOST_RISK_PREDICTION_MODEL_PATH`

5. **Feature Flags**
   - `RATE_LIMITING_ENABLED`: true/false
   - `PHI_SANITIZATION_ENABLED`: true/false

### Database Migrations

```bash
cd backend
pip install -r requirements.txt
alembic upgrade head
```

### Run Locally

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Visit [http://localhost:8000/docs](http://localhost:8000/docs) for Swagger UI.

## Usage Examples

Replace `<TOKEN>` with a valid JWT from `/api/v1/auth/login`.

```bash
# Create Patient
curl -X POST http://localhost:8000/api/v1/patients \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "first_name": "Alice", "last_name": "Smith", "date_of_birth":"1985-07-20" }'

# Ingest Biometric Event
curl -X POST http://localhost:8000/api/v1/biometric-events \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "patient_id":"<UUID>", "data_type":"heart_rate", "timestamp":"2025-04-17T14:23:00Z", "data":{"bpm":72} }'

# Generate Digital Twin
curl -X POST http://localhost:8000/api/v1/digital-twins/generate \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{ "patient_id":"<UUID>" }'

# Retrieve Aggregated Analytics
curl -G http://localhost:8000/api/v1/analytics/aggregated \
  -H "Authorization: Bearer <TOKEN>" \
  --data-urlencode "patient_id=<UUID>"
```

## Testing & Quality

### Unit Tests

```bash
cd backend
pytest app/tests/unit
```

### Integration Tests

```bash
docker-compose -f deployment/docker-compose.test.yml up -d
pytest app/tests/integration
```

### Lint & Type

```bash
flake8 app
black --check app
isort --check-only --profile black app
mypy app
```

### Coverage

```bash
pytest --cov=app
```

## Security & Audits

- PHI Audits: see `reports/` & `security-reports/`

### Run PHI Audit

```bash
python tools/security/run_phi_audit_only.py
```

### Dependency Scans

```bash
python tools/security/bandit-runner.py
```

## Tools & Scripts

- **Maintenance**: `tools/maintenance/` (refactor, migration helpers)
- **Prompt Templates**: `prompt-templates/`
- **Demo Scripts**: `demo/`
- **Architecture Docs**: `docs/`

## Docker & Deployment

```bash
docker-compose -f deployment/docker-compose.yml up --build
```

Services: FastAPI API, Postgres, Redis, (optional) Traefik ingress.

For production CI/CD:

- One pipeline for lint/tests/security
- One pipeline for build/push Docker & helm/k8s deploy
- Health checks & auto‑migrations on startup

## Configuration Reference

| Env Var | Description | Example |
|---------|-------------|---------|
| `ENVIRONMENT` | development/test/staging/production | `production` |
| `DATABASE_URL` | Postgres DSN | `postgres://user:pass@host:5432/db` |
| `REDIS_URL` | Redis URI | `redis://localhost:6379/0` |
| `JWT_SECRET_KEY` | JWT signing secret | `supersecretjwtkey` |
| `AWS_ACCESS_KEY_ID` | AWS IAM key | `AKIA…` |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM secret | `wJalrXUtnFEMI/K7…` |
| `S3_BUCKET` | S3 bucket name for attachments | `clarity-ai-backend-prod` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-…` |
| `MENTALLAMA_MODEL_MAPPINGS` | JSON mapping of LLM model identifiers | `{"clinical":"gpt-4","psychiatry":"gpt-4"}` |
| `XGBOOST_TREATMENT_RESPONSE_MODEL_PATH` | Path to XGBoost treatment response model | `/models/treatment_response.xgb` |
| `XGBOOST_OUTCOME_PREDICTION_MODEL_PATH` | Path to outcome prediction model | `/models/outcome_prediction.xgb` |
| `XGBOOST_RISK_PREDICTION_MODEL_PATH` | Path to risk prediction model | `/models/risk_prediction.xgb` |
| `RATE_LIMITING_ENABLED` | Enable in‑memory rate limiting (true/false) | `true` |
| `PHI_SANITIZATION_ENABLED` | Enable PHI detection & sanitization (true/false) | `true` |

## Contributing

We love contributions! Please:

1. Fork & create a feature branch.
2. Install hooks: `pre-commit install`.
3. Adhere to linters (black, isort, flake8) and add tests.
4. Open a clear PR referencing an issue.

See `CONTRIBUTING.md` for details.

## License

This project is licensed under the Apache License 2.0.
See `LICENSE` for the full terms.
