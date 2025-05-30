# Clarity-AI Backend - Development Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help setup install clean test lint format check docker-up docker-down start stop build deploy health

# Default target
help: ## Show this help message
	@echo "Clarity-AI Backend - Available Make Commands"
	@echo "==========================================="
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup and Installation
setup: ## Full development environment setup (venv + install + services)
	@echo "🚀 Setting up Clarity-AI development environment..."
	python -m venv .venv
	@echo "✅ Virtual environment created"
	@echo "🔧 Activating venv and installing dependencies..."
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -e .[dev,test]
	@echo "✅ Dependencies installed"
	@echo "🐳 Starting Docker services..."
	docker compose -f docker-compose.test.yml up -d
	@echo "✅ Docker services started"
	@echo "📝 Copying environment template..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "✅ .env file created"; else echo "ℹ️  .env file already exists"; fi
	@echo ""
	@echo "🎉 Setup complete! Next steps:"
	@echo "   1. Activate virtual environment: source .venv/bin/activate"
	@echo "   2. Start the application: make start"
	@echo "   3. Visit: http://localhost:8000/docs"

install: ## Install dependencies only
	@echo "📦 Installing dependencies..."
	pip install -e .[dev,test]
	@echo "✅ Dependencies installed"

clean: ## Clean up generated files and caches
	@echo "🧹 Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -f pytest_output.log bandit-report.json lint_report.json typing_report.json report.json
	@echo "✅ Cleanup complete"

# Development Services
docker-up: ## Start Docker services (PostgreSQL, Redis)
	@echo "🐳 Starting Docker services..."
	docker compose -f docker-compose.test.yml up -d
	@echo "✅ Docker services started"

docker-down: ## Stop Docker services
	@echo "🐳 Stopping Docker services..."
	docker compose -f docker-compose.test.yml down
	@echo "✅ Docker services stopped"

start: ## Start the FastAPI application
	@echo "🚀 Starting Clarity-AI Backend..."
	@echo "📋 Running database migrations..."
	alembic upgrade head 2>/dev/null || echo "ℹ️  No migrations to run"
	@echo "🌐 Starting FastAPI server..."
	@echo "📖 API Documentation: http://localhost:8000/docs"
	@echo "🏥 Health Check: http://localhost:8000/api/v1/health"
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

stop: ## Stop the application (if running in background)
	@echo "🛑 Stopping application..."
	pkill -f "uvicorn app.main:app" 2>/dev/null || echo "ℹ️  No running application found"

# Testing and Quality Assurance
test: ## Run the test suite
	@echo "🧪 Running test suite..."
	pytest app/tests -v --tb=short

test-coverage: ## Run tests with coverage report
	@echo "🧪 Running tests with coverage..."
	pytest app/tests --cov=app --cov-report=term --cov-report=html

test-fast: ## Run tests without slow ML tests
	@echo "🧪 Running fast tests..."
	pytest app/tests -v --tb=short -m "not slow"

# Code Quality
lint: ## Run linting checks
	@echo "🔍 Running linting checks..."
	ruff check app
	@echo "✅ Linting complete"

format: ## Format code with ruff and black
	@echo "🎨 Formatting code..."
	ruff format app
	ruff check --fix app
	@echo "✅ Code formatting complete"

typecheck: ## Run type checking with mypy
	@echo "📝 Running type checks..."
	mypy app
	@echo "✅ Type checking complete"

security: ## Run security scanning
	@echo "🔒 Running security scan..."
	bandit -r app -f json -o bandit-report.json
	@echo "✅ Security scan complete (see bandit-report.json)"

check: lint typecheck ## Run all code quality checks
	@echo "✅ All code quality checks passed"

# Database Management
db-upgrade: ## Run database migrations
	@echo "📋 Running database migrations..."
	alembic upgrade head
	@echo "✅ Database migrations complete"

db-reset: ## Reset database (careful - destroys data!)
	@echo "⚠️  Resetting database..."
	@read -p "Are you sure? This will destroy all data [y/N]: " confirm && [ "$$confirm" = "y" ]
	alembic downgrade base
	alembic upgrade head
	@echo "✅ Database reset complete"

db-seed: ## Seed database with demo data
	@echo "🌱 Seeding database with demo data..."
	python scripts/seed_demo.py 2>/dev/null || echo "ℹ️  Demo seeding script not found"
	@echo "✅ Database seeded"

# Advanced Analysis & Security
security-scan: ## 🛡️  Run comprehensive security vulnerability scan
	@echo "🔍 Running security vulnerability scan..."
	@echo "🛡️  Scanning code for security issues with Bandit..."
	bandit -r app -f json -o bandit-report.json || echo "⚠️  Some security issues found - check bandit-report.json"
	@echo "🔒 Checking dependencies for known vulnerabilities..."
	safety check --json --output safety-report.json || echo "⚠️  Some dependency vulnerabilities found - check safety-report.json"
	@echo "📊 Security scan complete! Check reports: bandit-report.json, safety-report.json"

security-scan-detailed: ## 🔍 Detailed security scan with verbose output
	@echo "🔍 Running detailed security analysis..."
	bandit -r app -f screen --severity-level medium
	@echo "\n🔒 Dependency vulnerability check:"
	safety check --short-report

dead-code: ## 🧹 Find unused/dead code
	@echo "🧹 Scanning for dead code with Vulture..."
	vulture app --min-confidence 80 --sort-by-size || echo "📊 Dead code analysis complete"

benchmark: ## ⚡ Run performance benchmarks
	@echo "⚡ Running performance benchmarks..."
	pytest app/tests -k "benchmark" --benchmark-only --benchmark-sort=mean || echo "📈 Create benchmark tests with @pytest.mark.benchmark decorator"

benchmark-compare: ## 📊 Run benchmarks and compare with previous results
	@echo "📊 Running benchmark comparison..."
	pytest app/tests -k "benchmark" --benchmark-only --benchmark-compare --benchmark-sort=mean || echo "📈 Create benchmark tests to compare performance"

memory-profile: ## 🧠 Run memory profiling on key functions
	@echo "🧠 Running memory profiling..."
	@echo "💡 Add @profile decorator to functions you want to profile"
	python -m memory_profiler app/main.py || echo "ℹ️  Add memory profiling decorators to see detailed analysis"

load-test: ## 🔥 Run API load testing with Locust
	@echo "🔥 Starting Locust load testing..."
	@echo "🌐 Visit http://localhost:8089 to configure and run load tests"
	@echo "⚡ Target your API at http://localhost:8000"
	locust -f scripts/locustfile.py --host=http://localhost:8000 || echo "📝 Create scripts/locustfile.py for custom load tests"

coverage-html: ## 📊 Generate beautiful HTML coverage report
	@echo "📊 Generating detailed HTML coverage report..."
	pytest app/tests --cov=app --cov-report=html --cov-report=term-missing
	@echo "🌐 HTML report generated at: htmlcov/index.html"
	@echo "💡 Open htmlcov/index.html in your browser for detailed coverage visualization"

audit-full: ## 🔍 Complete security and code quality audit
	@echo "🔍 Running comprehensive audit..."
	@echo "1️⃣  Security vulnerabilities..."
	make security-scan-detailed
	@echo "\n2️⃣  Dead code analysis..."
	make dead-code
	@echo "\n3️⃣  Coverage analysis..."
	make coverage-html
	@echo "\n✅ Full audit complete! Check generated reports."

demo: ## 🎬 Showcase all the ultra cool development tools
	@echo "🎬 Starting ultra dank tools demonstration..."
	python scripts/demo_tools.py all

demo-security: ## 🛡️  Demo security scanning tools
	@echo "🛡️  Demonstrating security tools..."
	python scripts/demo_tools.py security

demo-performance: ## ⚡ Demo performance benchmarking
	@echo "⚡ Demonstrating performance tools..."
	python scripts/demo_tools.py benchmark

demo-dead-code: ## 🧹 Demo dead code detection
	@echo "🧹 Demonstrating dead code detection..."
	python scripts/demo_tools.py dead-code

demo-coverage: ## 📊 Demo coverage analysis
	@echo "📊 Demonstrating coverage analysis..."
	python scripts/demo_tools.py coverage

demo-load-test: ## 🔥 Demo load testing setup
	@echo "🔥 Demonstrating load testing..."
	python scripts/demo_tools.py load-test

# Docker and Deployment
build: ## Build Docker image
	@echo "🏗️  Building Docker image..."
	docker build -t clarity-ai-backend:latest .
	@echo "✅ Docker image built"

docker-test: ## Test the application in Docker
	@echo "🐳 Testing application in Docker..."
	docker build -t clarity-ai-backend:test .
	docker run --rm -p 8000:8000 --env-file .env clarity-ai-backend:test &
	@echo "⏳ Waiting for container to start..."
	sleep 10
	@echo "🏥 Testing health endpoint..."
	curl -f http://localhost:8000/api/v1/health || (echo "❌ Health check failed" && exit 1)
	@echo "✅ Docker test passed"
	docker stop $$(docker ps -q --filter ancestor=clarity-ai-backend:test) 2>/dev/null || true

# Monitoring and Health
health: ## Check application health
	@echo "🏥 Checking application health..."
	@curl -s http://localhost:8000/api/v1/health | python -m json.tool || echo "❌ Application not responding"

preflight: ## Run pre-installation system checks
	@echo "🚁 Running pre-flight checks..."
	python scripts/preflight_check.py

health-check: ## Run comprehensive health check
	@echo "🏥 Running comprehensive health check..."
	python scripts/simple_health.py

validate: ## Validate installation (alias for health-check)
	@echo "🔍 Validating installation..."
	python scripts/simple_health.py

logs: ## Show application logs (if running with Docker)
	@echo "📋 Showing recent logs..."
	docker compose -f docker-compose.test.yml logs --tail=50 -f

# Development Utilities
requirements: ## Update requirements.lock file
	@echo "📦 Updating requirements.lock..."
	pip-compile --all-extras -o requirements.lock pyproject.toml
	@echo "✅ Requirements updated"

dev-setup: setup ## Alias for setup (for compatibility)

quick-start: docker-up start ## Quick start for demos (services + app)

# Documentation
docs-serve: ## Serve documentation locally
	@echo "📚 Starting documentation server..."
	@echo "📖 Visit: http://localhost:8001"
	python -m http.server 8001 --directory docs &

# Environment Management
env-copy: ## Copy .env.example to .env
	@if [ ! -f .env ]; then cp .env.example .env; echo "✅ .env file created"; else echo "ℹ️  .env file already exists"; fi

env-check: ## Validate environment configuration
	@echo "🔧 Checking environment configuration..."
	@python -c "from app.core.config.settings import get_settings; s = get_settings(); print(f'✅ Environment: {s.ENVIRONMENT}'); print(f'✅ Database: {s.DATABASE_URL[:20]}...'); print(f'✅ Redis: {s.REDIS_URL or \"Not configured\"}')"

# All-in-one commands
full-setup: clean setup test ## Complete setup with testing
	@echo "🎉 Full setup complete and tested!"

ci-test: ## Run CI-style testing (no external dependencies)
	@echo "🤖 Running CI-style tests..."
	ruff check app
	mypy app --no-error-summary
	pytest app/tests -x --tb=short
	@echo "✅ CI tests passed"

# Help information
info: ## Show project information
	@echo "Clarity-AI Backend Development Environment"
	@echo "========================================"
	@echo "🐍 Python Version: $$(python --version)"
	@echo "📦 Pip Version: $$(pip --version)"
	@echo "🐳 Docker Version: $$(docker --version 2>/dev/null || echo 'Not installed')"
	@echo "🏗️  Make Version: $$(make --version | head -n1)"
	@echo ""
	@echo "📁 Project Structure:"
	@echo "   app/              - Application source code"
	@echo "   app/tests/        - Test suite"
	@echo "   docs/             - Documentation"
	@echo "   alembic/          - Database migrations"
	@echo "   .env.example      - Environment template"
	@echo ""
	@echo "🚀 Quick Start: make setup && make start"
	@echo "📖 Documentation: http://localhost:8000/docs"
	@echo "🆘 Help: make help"