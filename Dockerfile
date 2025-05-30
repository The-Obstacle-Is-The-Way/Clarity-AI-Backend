# Multi-stage Dockerfile for Clarity-AI Backend
# Optimized for both development and production use

# ==============================================================================
# Base Stage - Common dependencies and setup
# ==============================================================================
FROM python:3.12-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_NO_INTERACTION=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# ==============================================================================
# Dependencies Stage - Install Python dependencies
# ==============================================================================
FROM base as dependencies

# Copy dependency files
COPY pyproject.toml requirements.lock ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.lock

# ==============================================================================
# Development Stage - For local development with hot reload
# ==============================================================================
FROM dependencies as development

# Install development dependencies
RUN pip install -e .[dev,test]

# Copy application code
COPY . .

# Change ownership to appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Development command with hot reload
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ==============================================================================
# Production Stage - Optimized for production deployment
# ==============================================================================
FROM dependencies as production

# Copy application code
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini main.py ./

# Remove unnecessary files for production
RUN find . -type d -name "__pycache__" -exec rm -rf {} + && \
    find . -type f -name "*.pyc" -delete && \
    find . -type f -name "*.pyo" -delete

# Change ownership to appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Production command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# ==============================================================================
# Test Stage - For running tests in CI/CD
# ==============================================================================
FROM dependencies as test

# Install test dependencies
RUN pip install -e .[dev,test]

# Copy application code
COPY . .

# Change ownership to appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Run tests
CMD ["pytest", "app/tests", "-v", "--tb=short"]

# ==============================================================================
# Builder Stage - For creating minimal production images
# ==============================================================================
FROM python:3.12-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY pyproject.toml requirements.lock ./
RUN pip install --upgrade pip && \
    pip install --user -r requirements.lock

# ==============================================================================
# Runtime Stage - Minimal production runtime
# ==============================================================================
FROM python:3.12-slim as runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Set working directory
WORKDIR /app

# Copy application code
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini main.py ./

# Change ownership to appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Make sure scripts in .local are usable
ENV PATH=/home/appuser/.local/bin:$PATH

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Production command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ==============================================================================
# Build Arguments and Labels
# ==============================================================================
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL maintainer="Clarity-AI Team" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="clarity-ai-backend" \
      org.label-schema.description="HIPAA-compliant digital twin backend for psychiatric care" \
      org.label-schema.url="https://github.com/clarity-ai/backend" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/clarity-ai/backend" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"