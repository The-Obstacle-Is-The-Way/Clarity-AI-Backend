# Data Pipeline

This document outlines the **intended future state** for Novamind's data pipeline architecture, harmonized with Clean Architecture. It serves as a roadmap rather than a description of the currently implemented system.

> **CRITICAL NOTE (Analysis Date: [[Current Date]]):** Analysis of the `/backend/app/` codebase indicates that **significant portions of this described pipeline are NOT YET IMPLEMENTED**. References to specific services (like time series processing), feature registries, and advanced storage solutions (S3, Feature Store) **do not currently exist** in the codebase. Assume descriptions of specific processing steps, feature engineering techniques, storage layers, and access APIs are **ASPIRATIONAL** unless explicitly verified against existing code in the `infrastructure` layer. Consult `65_ML_Integration.md` for details on *existing* ML components. The "Known Issues & Gaps" section reflects the state as of April 20, 2025, and further gaps exist.

---

## 1. Data Collection Layer (Aspirational / Partially Implemented)

- **EHR:** Secure API integration with FHIR or proprietary EHR systems. *(Status: Implementation details TBD/Unverified)*
- **Wearables:** Actigraphy streams processed by the PAT microservice. *(Status: `infrastructure/ml/pat/` exists, integration TBD)*
- **Patient-Reported Outcomes:** Portal uploads via web client. *(Status: Implementation details TBD/Unverified)*
- **Clinical Assessments:** Structured clinician input forms. *(Status: Implementation details TBD/Unverified)*
- **Digital Phenotyping:** Browser and smartphone sensor data. *(Status: Implementation details TBD/Unverified)*

---

## 2. Data Processing Layer (Aspirational)

> **Note:** The services and specific logic described below are currently aspirational and not found in the codebase.

- **Validation:** Pydantic schemas and quality checks. *(Implementation TBD)*
- **Missing Values:** Imputation strategies. *(Implementation TBD - No `time_series_service.py` found)*
- **Outliers:** Z‑score thresholding and anomaly detection. *(Implementation TBD)*
- **Temporal Alignment:** Sliding windows and hop-length configurations. *(Implementation TBD)*

---

## 3. Feature Engineering (Aspirational / Partially Implemented)

> **Note:** While a `symptom_forecasting` directory exists, the broader feature engineering capabilities, registry, and lineage tracking described are aspirational.

- **Extraction:** Domain-specific feature pipelines (e.g., `app/infrastructure/ml/symptom_forecasting/` exists, content/integration TBD).
- **Transformation:** Scaling, normalization, encoding. *(Implementation TBD)*
- **Selection:** L1 regularization, tree-based importance, recursive feature elimination. *(Implementation TBD)*
- **Versioning:** Feature registry and lineage tracking. *(Implementation TBD - No `feature_registry.yaml` found)*

---

## 4. Data Storage (Aspirational)

> **Note:** The storage solutions described below are aspirational. Current verified storage is handled via SQLAlchemy as per `40_Database_Management.md`.

- **Raw Data:** Encrypted S3 buckets and versioned backups. *(Implementation TBD)*
- **Feature Store:** Centralized repository (e.g., DynamoDB or FSx) with on-demand computation and caching. *(Implementation TBD)*

---

## 5. Access & APIs (Aspirational)

> **Note:** Specific APIs for batch/stream access to pipeline data are aspirational. Current API details are in `50_API_Guidelines.md` and related documents.

- **Retrieval:** Secure API endpoints for batch and real-time feature access. *(Implementation TBD)*
- **Batch Exports:** Data dumps for offline model training. *(Implementation TBD)*
- **Stream Access:** WebSocket or gRPC interfaces for live inference. *(Implementation TBD)*

---

## 6. Monitoring & Auditing (Aspirational / Partially Implemented)

> **Note:** While basic logging exists, comprehensive pipeline-specific monitoring and auditing are aspirational.

- Audit logs for ingestion, processing, and feature computation. *(Implementation TBD)*
- Metrics (throughput, latency) via OpenTelemetry and Prometheus. *(Implementation TBD / Depends on core logging/metrics infrastructure)*

---

## 7. Known Issues & Gaps (as of April 20, 2025 - Additional Gaps Identified [[Current Date]])

> **Note:** The primary gap is that the majority of the pipeline described above is not yet implemented.

- Not all new data sources are integrated (see TODOs in codebase)
- Some transformations are not fully audited
- Validation logic is duplicated in some places
- Data lineage tracking is incomplete / Non-existent
- Documentation may lag behind code changes **(This document was significantly aspirational)**
- Microservice boundaries for data ingestion and transformation are not always explicit—review architecture docs for current boundaries
- **Missing Components:** No evidence of `time_series_service.py`, `feature_registry.yaml`, S3/Feature Store integration, dedicated processing/access APIs.

---

## 8. Living Documentation & Changelog

This reference is updated with every major architectural, compliance, or implementation change. For any ambiguity, the codebase is the final source of truth.

**Last major update:** [[Current Date]] — **Significant revision to mark document as primarily ASPIRATIONAL based on codebase analysis.** Removed incorrect file references. Clarified that most described components do not currently exist.

---

*End of Data Pipeline Reference.*

Last Updated: [[Current Date]]
