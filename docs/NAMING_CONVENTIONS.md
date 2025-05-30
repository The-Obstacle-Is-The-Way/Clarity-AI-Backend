# Clarity-AI Documentation Naming Conventions

This document defines the naming conventions for all documentation assets in the Clarity-AI Backend project. 
Consistent naming enhances discoverability, clarifies document purpose, and improves overall documentation quality.

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
- For rendered images, use: `[subject]_diagram.[extension]`

Examples:
- `data_flow_diagram_source.drawio`
- `data_flow_diagram.png`

## Directory Structure Conventions

### Content Organization

Main documentation is organized in the following directory structure:

```
docs/
├── content/
│   ├── api/
│   ├── architecture/
│   ├── compliance/
│   ├── development/
│   └── infrastructure/
├── templates/
├── archive/
├── STYLE_GUIDE.md
└── NAMING_CONVENTIONS.md
```

### Directory Naming

- Use lowercase letters for all directory names
- Use simple, descriptive names
- Avoid compound words where possible
- Use singular form for category names
- Create subdirectories for logical groupings

## Document Structure Conventions

### Section Headings

- Use title case for section headings
- Follow a logical hierarchy (H1 → H2 → H3)
- Include only one H1 (title) per document
- Keep headings concise and descriptive

### Standard Document Sections

Standard documents should follow a consistent structure with these sections:

1. **Title**: Document title (H1)
2. **Overview**: Brief introduction
3. **Main Content**: Organized by sections
4. **References**: Links to related resources
5. **Change Log**: Document revision history (optional)

### API Documentation Structure

API endpoint documentation should include these sections:

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