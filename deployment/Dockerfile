FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY backend/requirements.txt ./requirements.txt
COPY backend/requirements-security.txt ./requirements-security.txt
COPY backend/requirements-analytics.txt ./requirements-analytics.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-security.txt
RUN pip install --no-cache-dir -r requirements-analytics.txt

# Copy backend application code
COPY backend/ ./backend/
COPY deployment/ ./deployment/
COPY reports/ ./reports/
COPY security-reports/ ./security-reports/
COPY tools/ ./tools/

# Set working directory to backend
WORKDIR /app/backend

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
