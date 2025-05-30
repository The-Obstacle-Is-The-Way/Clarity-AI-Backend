# Clarity-AI Backend Documentation

Welcome to the Clarity-AI Backend documentation. This repository contains comprehensive documentation for the Clarity-AI Backend system, which provides a HIPAA-compliant platform for psychiatric care.

## Documentation Structure

The documentation is organized into the following sections:

```
docs/
├── content/                  # Main documentation content
│   ├── api/                  # API documentation
│   ├── architecture/         # Architecture documentation
│   ├── compliance/           # Compliance documentation
│   ├── development/          # Development guides
│   └── infrastructure/       # Infrastructure documentation
├── templates/                # Documentation templates
├── STYLE_GUIDE.md            # Documentation style guide
└── NAMING_CONVENTIONS.md     # Naming conventions
```

## Main Sections

### API Documentation

- [API Overview](./content/api/README.md) - Overview of the API endpoints
- API reference documentation for individual endpoints

### Architecture Documentation

- [Architecture Overview](./content/architecture/overview.md) - High-level architecture
- [Clean Architecture Diagram](./content/architecture/clean_architecture_diagram.md) - Visualization of architectural layers
- [Domain Model](./content/architecture/domain_model.md) - Core domain entities and relationships
- [ML Integration](./content/architecture/ml_integration.md) - Integration with machine learning services

### Compliance Documentation

- [HIPAA Compliance](./content/compliance/hipaa_compliance.md) - HIPAA compliance measures

### Development Documentation

- [Development Guide](./content/development/README.md) - Guide for developers
- [Project Structure](./content/development/project_structure.md) - Codebase structure and organization
- [Directory Tree](./content/development/directory_tree.md) - Visual representation of directory structure
- [Installation Guide](./content/development/installation_guide.md) - Installation instructions
- [Technical Status](./content/development/technical_status.md) - Current technical status
- [Test Status](./content/development/test_status.md) - Testing status and coverage
- [Dependency Analysis](./content/development/dependency_analysis.md) - Analysis of project dependencies
- [Technical Audit](./content/development/technical_audit.md) - Technical audit results
- [Tools Reference](./content/development/tools_reference.md) - Development tools
- [Development Roadmap](./content/development/roadmap.md) - Future development plans

### Infrastructure Documentation

- [Data Access](./content/infrastructure/data_access.md) - Data access patterns
- [Deployment Readiness](./content/infrastructure/deployment_readiness.md) - Deployment guidelines

## Documentation Standards

All documentation follows the standards defined in the [Style Guide](./STYLE_GUIDE.md) and adheres to the [Naming Conventions](./NAMING_CONVENTIONS.md). Contributors should familiarize themselves with these documents before making changes.

## Templates

Documentation templates are available in the [templates](./templates) directory for creating consistent documentation:

- [API Endpoint Template](./templates/API_ENDPOINT_TEMPLATE.md)
- [Architecture Component Template](./templates/ARCHITECTURE_COMPONENT_TEMPLATE.md)
- [README Template](./templates/README_TEMPLATE.md)
- [Domain Entity Template](./templates/DOMAIN_ENTITY_TEMPLATE.md)

## Documentation Tools

The project uses several tools to maintain documentation quality:

- **MkDocs with Material theme**: Static site generation for documentation
- **Vale**: Prose linting for style enforcement
- **Markdownlint**: Markdown syntax linting
- **Pre-commit hooks**: Automated checks before commits