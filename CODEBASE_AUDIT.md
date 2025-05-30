# Clarity-AI Backend — Deep-Dive Codebase Audit

_Aim: catalogue **non-breaking** discrepancies, tech-debt pockets, and cleanliness issues discovered across the repository.  Use this as a punch-list for incremental, low-risk hardening while keeping velocity._

> Legend · 🔧 quick fix · 🧩 design refactor (post-demo) · 🚨 security/comp · 💤 legacy/unused

---

## 1. Architectural Layering

| Area | Finding | Impact | Action |
|------|---------|--------|--------|
| Core⇄Infra imports | `JWTService` imports concrete `AuditLogger` (infra). | Violates Clean Arch; tighter coupling. | 🔧 Introduce `IAuditLogger` port in `core.interfaces`, inject impl via provider. |
| Interface placement | `ITokenRepository` resides in `domain/interfaces`. | Layer leakage. | 🔧 Move to `core/interfaces/repositories/token_repository_interface.py`; update imports. |
| Redundant files | Duplicate `IUserRepository` interface (`*_interface.py` vs plain). | Confusion, IDE collisions. | 🔧 Delete redundant file; fix imports (memory 63f6bf19). |
| Middlewares missing | `RequestIdMiddleware`, `RateLimitingMiddleware` refs exist but code missing. | App fails if enabled. | 🔧 Re-implement or remove registrations until stable. |
| Redis in `app.state` | Direct global usage inside `lifespan`. | Hard to test & swap. | 🧩 Introduce `IRedisService` (+ provider) as per memory d6c8556f. |

## 2. Missing Interfaces / Stubs

| Interface | Used By | Status | Fix |
|-----------|---------|--------|-----|
| `IPasswordHandler` | Dependency provider | Missing | 🔧 Add stub in `core.interfaces.security`; ensure infra impl inherits. |
| `ITokenBlacklistRepository` | `JWTService` (commented) | Missing | 🔧 Define interface; stub Redis impl. |
| `IAuditLogger` | Needed by security | Missing | 🔧 (see above). |
| `AlertRuleService / TemplateService` | Tests skipped | Unimplemented | 🧩 Add skeletons returning dummy values. |

## 3. Orphaned TODOs / Partial Implementations

- 60+ `# TODO` comments flagged (grep).  Concentrated in:
  - `digital_twin_service.py` (entity mapping)
  - `rate_limiting/service.py` (in-memory vs Redis)
  - Test stubs under `app/tests/application/...`
- **Plan**: tag items ➜ open GitHub issues or Task-Master tasks; triage high-risk vs nice-to-have.

## 4. Dependency Hygiene

- Mixed pinning: `requirements.lock` exists but `.in`/`*.txt` divergence. 🚨
- Dev deps scattered; unify into `requirements-dev.txt`.
- Use `pip-compile --generate-hashes` for deterministic builds. 🔧

## 5. Repository Bloat

- Large artefacts committed: `pytest_output.log` (~0.8 MB), `bandit-report.json` (5 MB), type/lint reports. 💤  
  _Action_: Move to CI artefacts / `.gitignore`.
- `.venv` checked-in locally (excluded by `.gitignore` but ensure). 🔧

## 6. CI / Quality Gates

- Only `Dockerfile.test` and Compose for tests; no GitHub Actions pipeline.  
  _Action_: add `ci.yml` → lint + test + smoke boot. 🔧
- Ruff import order lint failing in `app_factory.py` (memory a711df13).  Fix or configure isort profile.

## 7. Tests

- 23 biometric alerts + 5 patient tests pass after temp fixes (memory f283f318). ✅
- Numerous skipped tests due to missing services or fixtures (digital twin, alert rules, PAT). 💤  
  - Provide dummy implementations returning 501 or raising `NotImplementedError` to un-skip while signalling unfinished work.
- `pytest.ini` marks slow ML tests; ensure they’re behind env flag.

## 8. Security & Compliance

- PHI redaction utilities exist; verify they’re wired into exception handlers.
- JWT blacklisting disabled (missing repo) ➜ risk of stolen refresh token reuse. 🚨  _Quick stub_: in-memory set with TTL.
- Rate-limiting middleware disabled ➜ denial-of-service risk.  Provide simple leaky-bucket using Redis later.

## 9. Documentation Gaps

- `/docs/` holds architecture diagrams but no high-level overview; create `ARCHITECTURE.md`.
- Swagger tags uneven; some routers missing `tags=[...]`, causing clutter.
- Update README quick-start (see ONBOARDING_CHECKLIST).

## 10. Misc Clean-ups

- Consistent UUID vs int IDs: some entities use `id: int`, others `uuid.UUID`.  Align via ValueObject later.
- Alembic heads diverge? run `alembic heads`. If multiple, merge.
- Remove unused legacy scripts under `scripts/test/report/` unless needed.

---

### Prioritised Sequence (Non-breaking)

1. **Repo hygiene** (remove logs, ignore artefacts).
2. **Interfaces & stubs** (missing but referenced).
3. **Dependency pinning + Makefile bootstrap** (DX).
4. **CI pipeline** (lint, test, boot).
5. **Re-enable middlewares** once classes exist.
6. **Gradual TODO burns** (track via Task-Master).

This audit pairs with `ONBOARDING_CHECKLIST.md`; tackle checklist items as mini-PRs referencing audit sections (e.g., `refs #audit-4-dep-pinning`).
