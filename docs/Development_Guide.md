# Development Guide

## Environment Setup

### Prerequisites

- Python 3.9+
- PostgreSQL 13+ (for production) or SQLite (for development)
- Redis (for caching and rate limiting)

### Installation

```bash
# Clone the repository
git clone https://github.com/Clarity-AI-Backend/clarity-ai.git
cd clarity-ai

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies
```

### Environment Configuration

Create a `.env` file in the project root:

```
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/clarity_ai
TEST_DATABASE_URL=sqlite+aiosqlite:///./test.db

# Security
SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Redis
REDIS_URL=redis://localhost:6379/0

# Logging
LOG_LEVEL=INFO

# Feature flags
ENABLE_RATE_LIMITING=true
```

## Development Workflow

### Code Quality Tools

The project uses Ruff for linting and formatting:

```bash
# Run linter
ruff check .

# Run formatter
ruff format .
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test category
pytest tests/unit/
pytest tests/integration/

# Run tests with persistent database (for debugging)
TEST_PERSISTENT_DB=1 pytest tests/integration/
```

### Local Development Server

```bash
# Run the development server
uvicorn app.main:app --reload

# API documentation available at:
# http://localhost:8000/docs
```

## Contribution Guidelines

### Branching Strategy

- `main`: Production-ready code
- `develop`: Integration branch for feature development
- `feature/*`: Feature branches
- `fix/*`: Bug fixes
- `refactor/*`: Code refactoring

### Pull Request Process

1. Create a feature/fix branch from `develop`
2. Implement changes with appropriate tests
3. Run linting and tests locally
4. Submit a pull request to `develop`
5. Ensure CI pipeline passes
6. Request code review

### Commit Message Format

```
<type>(<scope>): <subject>

<body>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `docs`: Documentation only changes
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

Example:
```
feat(auth): implement token blacklist repository

- Add Redis-based token blacklist repository
- Update JWT service to check blacklisted tokens
- Add tests for blacklist functionality
```

## HIPAA Development Guidelines

1. **No PHI in Logs**: Never log PHI directly; use identifiers or obfuscated values
2. **PHI Access Audit**: Always use audit decorators when accessing PHI
3. **Secure Error Handling**: Error responses must never include PHI
4. **Input Validation**: All user inputs must be validated with Pydantic
5. **Authorization Checks**: Always verify user permissions before PHI access

## Troubleshooting

### Common Issues

1. **Database Connection Errors**:
   - Verify database connection string in `.env`
   - Ensure database server is running
   - Check network connectivity

2. **Authentication Issues**:
   - Verify SECRET_KEY is properly set
   - Check token expiration settings
   - Ensure user has required permissions

3. **Test Failures**:
   - Run with `pytest -v` for detailed output
   - Check test database configuration
   - Verify test fixtures are properly isolated