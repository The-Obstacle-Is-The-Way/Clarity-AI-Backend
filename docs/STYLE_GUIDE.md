# Clarity-AI Documentation Style Guide

This style guide establishes consistent standards for all Clarity-AI Backend documentation. Following 
these guidelines ensures documentation is accurate, easy to understand, and maintainable.

## Core Principles

1. **Accuracy**: Documentation must reflect the actual code implementation
2. **Evidence-Based Claims**: Make only claims that can be substantiated
3. **Clarity**: Use clear, concise language
4. **Consistency**: Maintain consistent terminology and structure
5. **Maintainability**: Write documentation that is easy to update

## Voice and Tone

- **Voice**: Professional, straightforward, and technical
- **Person**: Use second person ("you") when addressing the reader
- **Tense**: Use present tense for current behavior
- **Active Voice**: Prefer active voice over passive voice
- **Technical Level**: Assume the reader has software development experience but may not be familiar
  with psychiatric domain concepts

## Accuracy Standards

### Capabilities and Claims

- **Never** include specific statistical claims (e.g., "43% improvement") without direct evidence or citations
- Use phrases like "aims to", "designed to", or "potential to" for aspirational capabilities
- Clearly distinguish between implemented features and planned functionality
- For implemented features, indicate the level of implementation (e.g., fully implemented, partially implemented)

### Code Examples

- All code examples must compile and execute correctly
- Examples should reflect the current codebase, not obsolete patterns
- Include imports in examples to show dependencies
- For longer examples, consider including comments

## Document Structure

### Headings

- Use sentence case for headings (capitalize only the first word and proper nouns)
- Use ATX-style headings with a space after the hash marks (`# Heading 1`)
- Structure documents hierarchically (H1 → H2 → H3)
- Include only one H1 heading per document
- Leave a blank line before and after headings

### Lists

- Use bullet lists for unordered items
- Use numbered lists for sequential steps or prioritized items
- Be consistent with punctuation (either use periods for all items or none)
- Leave a blank line before and after lists
- Indent nested lists correctly

### Code Blocks

- Use fenced code blocks with language specification
- Leave a blank line before and after code blocks
- For inline code, use backticks (`)
- For multi-line code samples, use triple backticks with language specification

Example:

```python
def calculate_risk_score(patient_id: UUID) -> float:
    """Calculate the risk score for a patient."""
    patient = get_patient_by_id(patient_id)
    return risk_assessment_service.calculate_score(patient)
```

### Tables

- Use tables for structured data
- Include a header row
- Align columns consistently
- Keep tables simple and readable
- Use a minimum of three hyphens per column in the separator row

Example:

| Component | Responsibility | Layer |
|-----------|----------------|-------|
| Entity | Core business object | Domain |
| Repository | Data access | Infrastructure |
| Service | Business logic | Application |
| Controller | Request handling | Presentation |

## Formatting

### Emphasis

- Use **bold** for emphasis of important concepts
- Use *italics* for new terms or parameters
- Use `code` formatting for code elements, file names, and paths
- Do not use underlining or all caps for emphasis

### Links

- Use descriptive link text that makes sense out of context
- Use relative links for internal documentation
- Use absolute links for external resources
- Check links regularly to ensure they are not broken

Example:

```markdown
See the [project structure](./content/development/project_structure.md) for more information.
```

### Images

- Include descriptive alt text for all images
- Keep image file sizes reasonable (< 200KB when possible)
- Prefer SVG for diagrams and PNG for screenshots
- Store images in the `/docs/content/assets/` directory
- Use descriptive filenames (e.g., `clean_architecture_diagram.png`)

Example:

```markdown
![Clean Architecture Diagram](../assets/clean_architecture_diagram.png)
```

## Special Content

### API Documentation

- Document each endpoint with:
  - HTTP method and path
  - Description of functionality
  - Request parameters and body
  - Response format
  - Status codes
  - Authentication requirements
  - Implementation status

### Architecture Documentation

- Include clear diagrams showing relationships
- Explain the purpose and responsibility of each component
- Document interfaces before implementations
- Include rationale for architectural decisions

### HIPAA Compliance Documentation

- Be precise about security measures without revealing vulnerabilities
- Cite relevant HIPAA regulations when appropriate
- Use accurate security terminology
- Avoid documenting specific PHI handling procedures in detail

## Technical Style

### File and Directory Names

- Use meaningful, descriptive names
- Use lowercase with underscores for file names (`project_structure.md`)
- Use title case for document titles ("Project Structure")

### Code Style in Documentation

- Follow the same code style as the main codebase
- Include type annotations in Python examples
- Use descriptive variable names
- For FastAPI examples, include the full decorator pattern

### Terminology

Always use consistent terminology:

| Use | Avoid |
|-----|-------|
| Digital twin | Virtual model, digital replica |
| API endpoint | API route, API URL |
| Repository | Data access layer, DAO |
| Entity | Model, object |
| Schema | DTO, data model |
| Biometric | Biosignal, biomarker |

## Review Process

All documentation should be reviewed for:

1. Technical accuracy
2. Adherence to this style guide
3. Clarity and readability
4. HIPAA compliance considerations
5. Consistency with other documentation