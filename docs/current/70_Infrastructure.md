# Infrastructure and Deployment

This document describes the infrastructure architecture and deployment processes for the Novamind Digital Twin platform.

---

## 1. Infrastructure Overview

The Novamind Digital Twin platform uses a modern, cloud-native infrastructure designed for scalability, reliability, and security:

```
                                          ┌────────────────────────┐
                                          │   Client Applications  │
                                          └───────────┬────────────┘
                                                      │
                                                      ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                                   AWS Cloud                                   │
│  ┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐  │
│  │  Route 53 + WAF   │─────▶|  CloudFront       │──────▶  Application LB   │  │
│  └───────────────────┘      └───────────────────┘      └─────────┬─────────┘  │
│                                                                  │            │
│  ┌───────────────────┐      ┌───────────────────┐      ┌─────────▼─────────┐  │
│  │      S3 Bucket    │◀─────│    CloudWatch     │◀─────│    ECS Cluster    │  │
│  │  (Static Assets)  │      │  (Logs, Metrics)  │      │   (Application)   │  │
│  └───────────────────┘      └───────────────────┘      └─────────┬─────────┘  │
│                                                                  │            │
│  ┌───────────────────┐      ┌───────────────────┐      ┌─────────▼─────────┐  │
│  │  Secrets Manager  │      │      ElastiCache  │◀─────│      RDS Aurora   │  │
│  │   (Credentials)   │─────▶│       (Redis)     │      │    (PostgreSQL)   │  │
│  └───────────────────┘      └───────────────────┘      └───────────────────┘  │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 1.1. Key Components

- **Computing**: AWS ECS (Elastic Container Service) for container orchestration
- **Database**: AWS RDS Aurora (PostgreSQL) for primary data storage
- **Caching**: AWS ElastiCache (Redis) for caching and session management
- **Storage**: AWS S3 for static assets and data exports
- **CDN**: AWS CloudFront for content distribution
- **DNS**: AWS Route 53 for DNS management
- **Load Balancing**: AWS Application Load Balancer for traffic distribution
- **Monitoring**: AWS CloudWatch for logs, metrics, and alarms
- **Security**: AWS WAF for web application firewall, AWS Secrets Manager for secrets

### 1.2. Environment Strategy

The platform uses separate environments for different stages of the development lifecycle:

- **Development**: Local development environment for individual developers
- **Testing**: Shared environment for integration testing
- **Staging**: Production-like environment for final validation
- **Production**: Live environment serving real users

## 2. Containerization

### 2.1. Docker Container Strategy

The application is containerized using Docker:

- **Base Image**: Python 3.10+ Alpine for minimal size
- **Multi-stage Builds**: Separate build and runtime stages
- **Port Exposure**: Container exposes port 8000 for the API
- **Health Checks**: Docker health checks verify application functionality
- **Environment Variables**: Configuration via environment variables

### 2.2. Dockerfile

```dockerfile
# Build stage
FROM python:3.10-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev postgresql-dev

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip wheel --no-cache-dir --wheel-dir /app/wheels -r requirements.txt

# Final stage
FROM python:3.10-alpine

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache libpq

# Copy wheels from builder stage
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# Copy application code
COPY backend /app/backend
COPY alembic.ini .

# Set environment variables
ENV PYTHONPATH=/app
ENV API_ENV=production

# Create non-root user
RUN adduser -D appuser
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/api/v1/health || exit 1

# Run application
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 2.3. Docker Compose

For local development and testing, Docker Compose is used:

```yaml
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "8000:8000"
    volumes:
      - ./:/app
    env_file:
      - .env
    depends_on:
      - db
      - redis
    networks:
      - novamind-network

  db:
    image: postgres:14-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=${DB_NAME}
    ports:
      - "5432:5432"
    networks:
      - novamind-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - novamind-network

volumes:
  postgres_data:
  redis_data:

networks:
  novamind-network:
```

## 3. Infrastructure as Code

### 3.1. Terraform

The infrastructure is defined as code using Terraform:

```hcl
# main.tf
provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source = "./modules/vpc"
  environment = var.environment
}

module "ecs" {
  source = "./modules/ecs"
  environment = var.environment
  vpc_id = module.vpc.vpc_id
  subnets = module.vpc.private_subnets
  app_image = var.app_image
  app_count = var.app_count
  depends_on = [module.vpc]
}

module "rds" {
  source = "./modules/rds"
  environment = var.environment
  vpc_id = module.vpc.vpc_id
  subnets = module.vpc.database_subnets
  depends_on = [module.vpc]
}

module "elasticache" {
  source = "./modules/elasticache"
  environment = var.environment
  vpc_id = module.vpc.vpc_id
  subnets = module.vpc.elasticache_subnets
  depends_on = [module.vpc]
}

module "alb" {
  source = "./modules/alb"
  environment = var.environment
  vpc_id = module.vpc.vpc_id
  subnets = module.vpc.public_subnets
  ecs_service = module.ecs.ecs_service
  depends_on = [module.ecs]
}
```

### 3.2. CI/CD Configuration

Continuous Integration and Continuous Deployment are implemented using GitHub Actions:

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches:
      - main
      - develop

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Run tests
        run: |
          pytest --cov=app

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      - name: Build and push Docker image
        uses: docker/build-push-action@v3
        with:
          context: .
          push: true
          tags: ${{ steps.login-ecr.outputs.registry }}/novamind-backend:${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - name: Update ECS service
        run: |
          aws ecs update-service --cluster novamind-${{ github.ref == 'refs/heads/main' && 'production' || 'staging' }} --service novamind-backend --force-new-deployment
```

## 4. Networking

### 4.1. VPC Architecture

The application runs within a custom VPC with the following components:

- **Public Subnets**: For load balancers and NAT gateways
- **Private Subnets**: For application containers and services
- **Database Subnets**: Isolated subnets for database instances
- **NAT Gateways**: For outbound internet access from private subnets
- **Internet Gateway**: For inbound/outbound internet access

### 4.2. Security Groups

The following security groups are used:

- **ALB Security Group**: Allows HTTP/HTTPS from internet
- **Application Security Group**: Allows traffic from ALB
- **Database Security Group**: Allows traffic from application
- **Redis Security Group**: Allows traffic from application

### 4.3. Load Balancing

AWS Application Load Balancer is used for:

- **Traffic Distribution**: Distributing traffic across container instances
- **SSL Termination**: Handling HTTPS connections
- **Health Checks**: Monitoring application health
- **Path-based Routing**: Routing to different services based on URL paths

## 5. Data Storage

### 5.1. Database Architecture

The primary database is AWS RDS Aurora PostgreSQL with the following features:

- **High Availability**: Multi-AZ deployment for redundancy
- **Read Replicas**: For scaling read operations
- **Automated Backups**: Daily backups with 7-day retention
- **Point-in-time Recovery**: 5-minute recovery point objective (RPO)

### 5.2. Redis Configuration

AWS ElastiCache Redis is used for:

- **Caching**: Application data caching
- **Session Storage**: User session management
- **Rate Limiting**: API rate limit tracking
- **Pubsub**: Event distribution

### 5.3. S3 Storage

AWS S3 is used for:

- **Static Assets**: Images, documents, and other static files
- **Data Exports**: Secure exports of data for analysis
- **Logs**: Long-term storage of application logs
- **Backups**: Database and application backups

## 6. Monitoring and Logging

### 6.1. CloudWatch Configuration

AWS CloudWatch is used for:

- **Metrics Collection**: CPU, memory, disk, and custom metrics
- **Log Aggregation**: Centralized logging for all components
- **Alarms**: Alerting on threshold breaches
- **Dashboards**: Visualization of system health

### 6.2. Log Structure

Application logs follow a standardized JSON format:

```json
{
  "timestamp": "2025-04-20T12:34:56.789Z",
  "level": "INFO",
  "service": "novamind-backend",
  "environment": "production",
  "request_id": "abcd1234",
  "method": "GET",
  "path": "/api/v1/patients",
  "status_code": 200,
  "duration_ms": 123,
  "user_id": "user-1234",
  "message": "Request completed successfully"
}
```

### 6.3. Alerting Strategy

Alerts are configured for:

- **High Error Rates**: Unusual number of 4xx or 5xx responses
- **Latency Spikes**: Requests taking longer than expected
- **Resource Utilization**: High CPU, memory, or disk usage
- **Database Performance**: Slow queries or high connection counts
- **Security Events**: Unusual access patterns or authentication failures

## 7. Scaling Strategy

### 7.1. Horizontal Scaling

The application scales horizontally based on:

- **CPU Utilization**: Scale out when average CPU exceeds 70%
- **Memory Utilization**: Scale out when average memory exceeds 80%
- **Request Count**: Scale based on requests per target
- **Scheduled Scaling**: Scale based on known usage patterns

### 7.2. Database Scaling

Database scaling strategies include:

- **Read Replicas**: Scale read operations across multiple replicas
- **Vertical Scaling**: Increase instance size for more capacity
- **Connection Pooling**: Optimize database connection usage
- **Query Optimization**: Regular review and optimization of slow queries

### 7.3. Caching Strategy

Caching is implemented at multiple levels:

- **Application Caching**: In-memory caching for frequent calculations
- **Redis Caching**: Distributed caching for shared data
- **CDN Caching**: Edge caching for static assets
- **Database Caching**: Query result caching where appropriate

## 8. Security Infrastructure

### 8.1. Network Security

Network security measures include:

- **VPC Isolation**: Separation of public and private networks
- **Security Groups**: Restrictive access control between components
- **NACLs**: Additional network filtering
- **WAF**: Protection against common web exploits

### 8.2. Data Protection

Data protection measures include:

- **Encryption at Rest**: All databases and storage encrypted
- **Encryption in Transit**: TLS for all communications
- **Key Management**: AWS KMS for encryption key management
- **Secrets Management**: AWS Secrets Manager for credential storage

### 8.3. Identity and Access Management

IAM strategies include:

- **Least Privilege**: Minimum necessary permissions
- **Role-based Access**: Separation of roles and responsibilities
- **MFA**: Multi-factor authentication for console access
- **Service Roles**: Specific roles for services and automation

## 9. Deployment Process

### 9.1. Deployment Strategy

The platform uses a blue/green deployment strategy:

1. **Build**: Create and test a new container image
2. **Deploy**: Deploy the new version to a new target group
3. **Test**: Validate the new deployment
4. **Switch**: Redirect traffic to the new deployment
5. **Rollback**: If issues occur, revert to the previous version

### 9.2. Database Migrations

Database migrations follow these steps:

1. **Versioned Migrations**: Using Alembic for tracking changes
2. **Backward Compatibility**: Ensure migrations support rollback
3. **Deployment Timing**: Run migrations before application deployment
4. **Verification**: Validate migration success before proceeding

### 9.3. Release Checklist

Before each production release:

- [ ] All tests passing in CI/CD pipeline
- [ ] Security scan completed
- [ ] Performance tests executed
- [ ] Database migration tested
- [ ] Rollback plan documented
- [ ] Monitoring configured for new features
- [ ] Documentation updated

## 10. Disaster Recovery

### 10.1. Backup Strategy

Data backup strategies include:

- **Database Backups**: Automated daily backups with point-in-time recovery
- **Application State**: Event sourcing for state reconstruction
- **Configuration Backup**: Infrastructure as code for configuration rebuilding
- **Cross-region Replication**: For critical data

### 10.2. Recovery Plans

Recovery plans for different scenarios:

- **Application Failure**: Automatic container replacement
- **Database Failure**: Failover to standby instance
- **Availability Zone Failure**: Multi-AZ deployment
- **Region Failure**: Cross-region recovery (for critical components)

### 10.3. Recovery Testing

Regular testing of recovery procedures:

- **Chaos Engineering**: Controlled failure injection
- **DR Drills**: Regular recovery practice
- **Backup Restoration**: Validation of backup integrity

## 7. Database Migrations

The Novamind platform uses Alembic to manage database schema changes in a version-controlled manner.

### 7.1. Migration Structure

**Location**: `backend/alembic/`

**Key Components**:
- `alembic.ini`: Configuration file at project root
- `backend/alembic/env.py`: Migration environment configuration
- `backend/alembic/versions/`: Directory containing individual migration scripts
- `backend/alembic/script.py.mako`: Template for new migration files

### 7.2. Configuration

The migration system is configured through:
- Database connection settings from `backend/app/infrastructure/config/app_config.py`
- Environment variables for database credentials
- The `alembic.ini` file for Alembic-specific settings

### 7.3. Usage Instructions

```bash
# Create a new migration (auto-detecting model changes)
alembic revision --autogenerate -m "description of changes"

# Apply all pending migrations
alembic upgrade head

# Apply specific number of migrations
alembic upgrade +1

# Downgrade one migration
alembic downgrade -1

# View current version
alembic current

# View migration history
alembic history
```

### 7.4. Best Practices

- Always review auto-generated migrations before applying them
- Test migrations in development environments before production deployment
- Include both upgrade and downgrade logic in migrations
- Use transactional DDL when possible for safer migrations
- Document significant schema changes

### 7.5. Deployment Workflow

- Include `alembic upgrade head` in container startup scripts
- For critical production deployments, consider running migrations as a separate step
- Ensure database backup before applying migrations in production

### 7.6. Known Limitations

- Alembic auto-generation may miss certain schema changes (e.g., complex relationship alterations)
- Manual intervention may be required for certain types of migrations
- Consider adding explicit validation tests for migration paths

---

This infrastructure and deployment documentation provides a reference for the operational aspects of the Novamind Digital Twin platform. It should be updated as the infrastructure architecture evolves.

Last Updated: 2025-04-20
