# Clarity-AI Backend - Installation Guide

> **🎯 Quick Start Goal**: Get the backend running in under 5 minutes with minimal friction.

## Prerequisites

- **Python 3.10+** (Currently tested with Python 3.12)
- **Git**
- **Docker & Docker Compose** (for Redis/PostgreSQL)
- **Make** (optional, for convenience commands)

## Fast Track Installation (Recommended)

### 1. Clone & Setup
```bash
git clone <repository-url>
cd Clarity-AI-Backend

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .[dev,test]
```

### 2. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings (optional - defaults work for development)
# The app will run with sensible defaults if you skip this step
```

### 3. Start Services
```bash
# Option A: Using Docker (Recommended)
docker compose -f docker-compose.test.yml up -d

# Option B: Local services (if you have Redis/PostgreSQL installed)
# Just ensure Redis is running on localhost:6379
```

### 4. Run the Application
```bash
# Run database migrations (if using PostgreSQL)
alembic upgrade head

# Start the FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Verify Installation
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/api/v1/health
- **Alternative Docs**: http://localhost:8000/redoc

## What Works Out of the Box

✅ **Core API Endpoints**: Authentication, user management, basic ML endpoints  
✅ **FastAPI with Auto-docs**: Full OpenAPI specification available  
✅ **Authentication System**: JWT-based auth with HIPAA compliance features  
✅ **Database Integration**: SQLAlchemy with Alembic migrations  
✅ **Redis Caching**: For session management and rate limiting  
✅ **Clean Architecture**: Proper layer separation and dependency injection  
✅ **Test Suite**: Comprehensive test coverage with pytest  

## Known Development Status

🔧 **In Progress**: Some ML model endpoints may return 501 (Not Implemented)  
🔧 **Testing**: Some tests may be skipped for incomplete features  
🔧 **MyPy**: Type checking has some warnings (non-blocking)  
🔧 **Middleware**: Some advanced middleware is stubbed for development  

## Development Workflow

```bash
# Run tests
pytest app/tests

# Type checking
mypy app

# Linting and formatting
ruff check app
ruff format app

# Security scanning
bandit -r app
```

## Common Issues & Solutions

### Issue: ModuleNotFoundError
**Solution**: Ensure you're in the virtual environment and installed with `pip install -e .[dev,test]`

### Issue: Database connection errors
**Solution**: 
- For development: App defaults to SQLite in-memory (no setup needed)
- For full testing: Start PostgreSQL with `docker compose -f docker-compose.test.yml up -d`

### Issue: Redis connection errors
**Solution**: 
- App gracefully degrades without Redis in development mode
- For full functionality: Start Redis with Docker Compose

### Issue: Large files in repo
**Note**: Report files (pytest_output.log, bandit-report.json, etc.) are artifacts and safe to ignore

## Docker Development Environment

```bash
# Full development stack
docker compose -f docker-compose.test.yml up -d

# This starts:
# - PostgreSQL database
# - Redis cache
# - (Application runs locally for faster development)
```

## Production Considerations

- Environment variables should be properly configured
- Use PostgreSQL instead of SQLite
- Configure proper Redis instance
- Set up proper logging and monitoring
- Review HIPAA compliance settings in production

## Getting Help

1. **Check the logs**: The application has comprehensive logging
2. **Review tests**: `pytest -v` shows what's working
3. **API Documentation**: http://localhost:8000/docs shows all available endpoints
4. **Architecture docs**: See `/docs` folder for detailed architecture information

---

**🚀 TL;DR**: `pip install -e .[dev,test]`, start Docker services, run `uvicorn app.main:app --reload`, visit http://localhost:8000/docs