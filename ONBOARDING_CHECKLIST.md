# Clarity-AI Backend — On-Boarding DX Checklist

> Non-breaking, high-impact housekeeping you can tackle **before tomorrow’s pairing session**.  Everything here is additive (✅ safe on `experimental`), improves first-run experience, and avoids deep refactors.

---

## 0. Fast Bootstrap

- [ ] **Makefile shortcuts**  
  - `make setup` → create/activate `.venv`, `pip install -r requirements-dev.txt`, install pre-commit hooks.  
  - `make start` → `docker compose up -d redis db`, run Alembic migrations, `uvicorn app.app_factory:create_app --reload`.
- [ ] `README.md` → add *Quick Start* (≤ 10 lines) that mirrors the Make targets.

## 1. Dependencies

- [ ] Pin & hash prod deps with `pip-compile` → `requirements.txt` & `requirements.lock`.  
- [ ] Merge dev tooling into `requirements-dev.txt` (pytest, ruff, black, mypy, pre-commit).
- [ ] CI: `pip install --require-hashes -r requirements.txt` to fail on drift.

## 2. Environment Config

- [ ] Ship `.env.example` (already exists – verify values) and document `cp .env.example .env`.
- [ ] Ensure `settings.py` gracefully falls back to defaults so clone→run works w/out a `.env` file.

## 3. Developer Experience

- [ ] Pre-commit: ruff → black → isort → mypy (fail early, auto-fix style).
- [ ] VS Code & PyCharm launch configs checked-in (`.vscode/launch.json`, `.idea/runConfigurations`).
- [ ] `scripts/seed_demo.py` – populate one user/patient/alert-rule for Swagger demos.
- [ ] `docs/ARCHITECTURE.md` – 1-pager of Clean Architecture layers + key modules.

## 4. Test & Lint Automation

- [ ] GitHub Action `ci.yml` → matrix: 3.11 / 3.12 → install, lint, pytest, run `uvicorn --factory --port 80 --host 0.0.0.0 --lifespan=off` smoke-boot.
- [ ] Badge in `README.md` for CI status.

## 5. Low-Hanging Codebase Clean-ups (no logic changes)

- [ ] Delete redundant interface file `app/core/interfaces/repositories/user_repository.py` (keep `_interface.py`) and update imports.  
- [ ] Add missing empty interface stubs to unblock IDE autocomplete:  
  - `app/core/interfaces/repositories/token_blacklist_repository_interface.py`  
  - `app/core/interfaces/security/password_handler_interface.py`  
  - `app/core/interfaces/services/audit_logger_interface.py`
- [ ] Re-enable commented-out fixtures & routes once stubs compile (tests will stay skipped, nothing breaks).
- [ ] Re-register middlewares (`RequestIdMiddleware`, `RateLimitingMiddleware`) *after* confirming their classes exist.

## 6. Repo hygiene

- [ ] `.gitattributes` → `* text=auto eol=lf` for consistent line endings.  
- [ ] Remove committed artefacts (`pytest_output.log`, large JSON reports) or move to `logs/` and add to `.gitignore`.
- [ ] Ensure `infrastructure/persistence/data/` path exists with `.gitkeep`; DB files ignored.

## 7. Optional (Post-Demo)

- [ ] `Dockerfile.dev` + `docker-compose.yml` (app, postgres, redis) – enables `docker compose up` dev env.  
- [ ] `mkdocs` or Docusaurus site from `/docs` folder for richer documentation.  
- [ ] Dependabot & Renovate configs for automatic PRs on dependency updates.

---

### How to use this list

1. Work top-to-bottom; each item is independent.  
2. Granular commits, e.g. `chore(makefile): add setup & start targets`.  
3. Push, confirm CI green; squash merge into `experimental`.  
4. Celebrate when your co-founder clones, runs **two commands**, and is greeted by Swagger UI. 🎉
