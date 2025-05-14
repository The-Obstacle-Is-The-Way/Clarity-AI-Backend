# Novamind Digital Twin Platform — Overview

This document is the single source of truth for the Novamind Digital Twin psychiatry
platform. It synthesizes and supersedes all legacy overviews, providing a maximally
concise, code-aligned, and compliance-focused summary for all stakeholders.

---

## 1. Purpose and Vision

Novamind is a next-generation AI/ML analytics system for psychiatry and mental health,
architected from first principles for clinical rigor, extensibility, and HIPAA
compliance. The platform unifies multimodal data, domain services, and advanced AI
models into a secure, production-grade digital twin of each patient's mental health
state.

The platform aims to:

- Provide clinically-validated mental health state modeling
- Enable personalized treatment planning through predictive analytics
- Support research and understanding of psychiatric conditions
- Maintain the highest standards for data security and patient privacy

## 2. AI/ML Stack

Novamind is powered by a modular, extensible AI/ML stack designed for psychiatric and
mental health analytics. The core components are:

- **Digital Twin Core:** Domain-driven patient modeling and state tracking
- **Pretrained Actigraphy Transformer:** Multimodal behavioral signal analysis
- **XGBoost:** Used for clinical prediction and pharmacogenomics modeling
- **MentalLLaMA33b:** Foundation model for mental health NLP and reasoning
- **LSTM:** Temporal modeling of patient trajectories and event sequences

All components are orchestrated via Clean Architecture, with event-driven communication
and robust compliance controls.

## 3. Architecture Overview

The platform implements Clean Architecture with strict separation of concerns:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ Presentation Layer (API endpoints, UI, client)                             │
└───────────────────────────────┬────────────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Application Layer (Use cases, orchestrators, services)                     │
└───────────────────────────────┬────────────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Domain Layer (Core logic, entities, AI models, business rules)             │
└───────────────────────────────┬────────────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Infrastructure Layer (Persistence, AWS, external APIs, security, logging)  │
└────────────────────────────────────────────────────────────────────────────┘
```

**Key Principles:**

- **Clean Architecture:** Strict layering, dependency inversion, explicit boundaries
- **SOLID & GOF Patterns:** Maintainable, extensible, testable code
- **HIPAA Compliance:** Encryption at rest/in transit, audit logging, zero PHI in
  URLs/errors, pseudonymization, entity versioning
- **Observability:** Metrics, logging, and tracing at each layer
- **Event-Driven:** Major components communicate via events for coupling and auditability

## 4. Core Modules

| Area                          | Description                                      |
|-------------------------------|--------------------------------------------------|
| Authentication & Authorization| OAuth2, JWT, session management, role-based access|
| Data Layer                    | SQLAlchemy models, migrations, data pipelines     |
| AI/ML Services                | Digital Twin, PAT, Prediction Engine, explainable|
| Infrastructure                | AWS ECS, Terraform, CI/CD pipelines, observability|
| Testing                       | Unit, integration, security, performance testing  |

## 5. Documentation Organization

All up-to-date documentation lives in `/backend/docs/current/`. See
`00_Documentation_Structure.md` for a complete map of the documentation and recommended
reading paths for different stakeholders.

## 6. Current Capabilities and Known Issues

### Strengths

- Clean, modular architecture (Clean Architecture, SOLID, GOF)
- HIPAA compliance focus (encryption, audit logging, no PHI in URLs/errors)
- Extensible AI/ML stack for clinical and temporal modeling
- Modern CI/CD and test automation pipeline

### Known Issues & Gaps

- Some tests are currently failing (see Testing Guide and CI output)
- Certain architectural components are incomplete or missing (see TODOs in codebase)
- Not all security/compliance features are fully implemented (e.g., session timeouts,
  output sanitization)
- Documentation may lag behind code changes; always check codebase for source of truth

### Opportunities for Improvement

- Increase test coverage and fix failing tests
- Complete implementation of all planned microservices and data pipelines
- Harden security and compliance controls (especially output sanitization and sessions)
- Improve documentation for agentic/AI contributors

## 7. For Agentic/AI Contributors

- Always reference the codebase and test suite as the ultimate source of truth
- Review the AI/ML stack and ensure new models are integrated via the Application layer
- Follow Clean Architecture, SOLID, and HIPAA compliance rules strictly
- Document all changes and update this documentation as needed
- Report all test failures and architectural holes in the documentation and codebase

---

Novamind sets a new standard for clinical AI systems: secure, modular, and future-proof.
This documentation is your entry point to understanding, building, and extending the
platform.

Last Updated: 2025-04-20
