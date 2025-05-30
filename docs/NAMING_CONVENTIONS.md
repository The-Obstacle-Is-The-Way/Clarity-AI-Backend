# Clarity-AI Documentation Naming Conventions

This document defines the naming conventions for all documentation assets in the Clarity-AI Backend project. Consistent naming enhances discoverability, clarifies document purpose, and improves overall documentation quality.

## File Naming Conventions

### General File Naming Rules

- Use lowercase letters for all filenames
- Use underscores (`_`) to separate words
- Be descriptive but concise
- Avoid abbreviations unless widely understood
- Include the file extension (`.md` for Markdown files)
- Omit articles (a, an, the) from filenames

### Standard Documentation Files

| Document Type | Naming Pattern | Example |
|---------------|----------------|---------|
| Main README | `README.md` | `README.md` |
| Architecture overview | `architecture_overview.md` | `architecture_overview.md` |
| API reference | `api_reference.md` | `api_reference.md` |
| Implementation guide | `implementation_guide.md` | `implementation_guide.md` |
| Installation guide | `installation_guide.md` | `installation_guide.md` |
| Domain model | `domain_model.md` | `domain_model.md` |
| Project structure | `project_structure.md` | `project_structure.md` |

### Component-Specific Documentation

| Component Type | Naming Pattern | Example |
|----------------|----------------|---------|
| API endpoint | `endpoint_[resource_name].md` | `endpoint_biometric_alerts.md` |
| Service | `service_[service_name].md` | `service_authentication.md` |
| Repository | `repository_[entity_name].md` | `repository_patient.md` |
| Entity | `entity_[entity_name].md` | `entity_digital_twin.md` |
| Use case | `usecase_[action_name].md` | `usecase_update_patient.md` |

### Image Files

- Use descriptive filenames indicating content
- Include image type in filename when relevant
- Follow the pattern: `[subject]_[type].[extension]`

Examples:
- `clean_architecture_diagram.png`
- `api_authentication_flow.svg`
- `database_schema.png`

### Diagram Files

- For source files (e.g., draw.io), use: `[subject]_diagram_source.[extension]`
- For exported image files, use: `[subject]_diagram.[extension]`

Examples:
- `authentication_flow_diagram_source.drawio`
- `authentication_flow_diagram.svg`

## Directory Naming Conventions

### Documentation Root Structure

The documentation is organized in a hierarchical structure with standardized directory names:

```
docs/
├── content/              # Core documentation content
│   ├── architecture/     # Architecture documentation
│   ├── api/              # API documentation
│   ├── implementation/   # Implementation details
│   ├── development/      # Development guides
│   └── reference/        # Reference materials
├── templates/            # Documentation templates
├── assets/               # Images, diagrams, etc.
└── audit/                # Documentation audit reports
```

### Subdirectory Naming Rules

- Use lowercase letters for all directory names
- Use descriptive singular nouns
- Avoid deeply nested directories (aim for max 3 levels)

## Document Structure Naming

### Section Headings

- Use title case for all headings in documentation
- Use sentence case for subsection headings (H3 and below)
- Follow a consistent numbering or hierarchy pattern
- Include descriptive section identifiers that reflect content

### Standard Section Names

For consistency, use these standard section names when applicable:

| Section Purpose | Standard Name |
|-----------------|---------------|
| Introduction | "Overview" or "Introduction" |
| Prerequisites | "Prerequisites" |
| Installation steps | "Installation" |
| Configuration | "Configuration" |
| API details | "API Reference" |
| Usage examples | "Examples" |
| Architecture | "Architecture" |
| Troubleshooting | "Troubleshooting" |
| Further reading | "Further Reading" |

## API Documentation Naming

### Endpoint Documentation Structure

For API endpoint documentation, use these standard section names:

1. "Endpoint Description"
2. "Request Parameters"
3. "Request Body"
4. "Response"
5. "Status Codes"
6. "Examples"
7. "Authentication"
8. "Implementation Status"

### Implementation Status Indicators

Use these standardized status indicators:

- ✅ **Fully Implemented**: Complete functionality
- 🚧 **Partially Implemented**: Some functionality is implemented
- 📝 **Route Defined**: Endpoint exists but minimal implementation
- 🔮 **Planned**: Not yet implemented

## Versioning Conventions

### Documentation Version Indicators

When indicating documentation versions, follow these patterns:

- For major versions: `v1`, `v2`, etc.
- For minor versions: `v1.1`, `v1.2`, etc.
- For documentation tied to software releases: `release-[version]`

Example:
```
api_reference_v1.md
architecture_overview_v2.md
```

### Deprecated Documentation

For deprecated documentation, add a prefix to clearly indicate status:

```
deprecated_authentication_v1.md
```

## MkDocs Navigation Structure

When defining navigation in `mkdocs.yml`, use these conventions:

- Use title case for navigation section names
- Use a hierarchical structure matching the filesystem
- Group related documents under logical sections
- Use descriptive link text, not filenames

Example:
```yaml
nav:
  - Home: index.md
  - Architecture:
    - Overview: architecture/overview.md
    - Clean Architecture: architecture/clean_architecture.md
    - Interfaces: architecture/interfaces.md
  - API Reference:
    - Overview: api/overview.md
    - Authentication: api/authentication.md
```

## File Linking Conventions

### Internal Document Links

When linking to other documentation files:

- Use relative paths
- Include the file extension
- Use descriptive link text

Example:
```markdown
See the [API Reference](../api/api_reference.md) for endpoint details.
```

### Anchor Links

For section links within documents:

- Use lowercase
- Replace spaces with hyphens
- Remove punctuation

Example:
```markdown
See the [Authentication section](#authentication) for more details.
```