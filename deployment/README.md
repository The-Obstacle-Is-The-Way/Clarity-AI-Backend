# Novamind Digital Twin - Backend Deployment

This directory contains deployment configurations and scripts for the Novamind Digital Twin backend platform.

## Overview

The deployment system provides tools for deploying the Novamind backend to various environments, with a focus on security, performance, and HIPAA compliance.

## Files

- `Dockerfile` - Container definition for the backend
- `docker-compose.yml` - Service definitions for running the complete backend stack
- `deploy-novamind-backend.sh` - Main deployment script for the backend
- Various environment-specific configuration files

## Deployment Instructions

### Local Development

To run the backend locally for development:

```bash
docker-compose up
```

The API will be available at http://localhost:8000.

### Production Deployment

To deploy to production:

```bash
./deploy-novamind-backend.sh production
```

### Staging Deployment

To deploy to staging:

```bash
./deploy-novamind-backend.sh staging
```

## Environment Configuration

Environment-specific configurations are managed in the `environments/` directory. These settings are applied during deployment to ensure the appropriate configuration for each target environment.

## HIPAA Compliance

The deployment scripts ensure HIPAA compliance by:

1. Enforcing secure transport (HTTPS/TLS)
2. Configuring proper access controls
3. Setting up audit logging
4. Implementing security headers
5. Ensuring database encryption

## Infrastructure Components

The backend deployment includes:

- FastAPI application server
- PostgreSQL database
- Redis cache
- Secure service communication

## Troubleshooting

For deployment issues:

1. Check the deployment logs using `docker-compose logs backend`
2. Verify database connectivity with `docker-compose exec db pg_isready -U postgres`
3. Ensure Redis is functioning with `docker-compose exec redis redis-cli ping`
