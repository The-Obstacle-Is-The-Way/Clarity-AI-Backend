# Clarity-AI Documentation Style Guide

This style guide establishes consistent standards for all Clarity-AI Backend documentation. Following these guidelines ensures documentation is accurate, easy to understand, and maintainable.

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
- **Technical Level**: Assume the reader has software development experience but may not be familiar with psychiatric domain concepts

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
- Use a hyphen (`-`) for bullet list markers
- Use `1.` for all numbered list items (Markdown will render correct numbers)
- Leave a blank line before and after lists

### Paragraphs

- Keep paragraphs concise (3-5 sentences)
- Use a blank line to separate paragraphs
- Group related paragraphs under descriptive headings

## Markdown Formatting

### Emphasis

- Use **bold** (`**bold**`) for UI elements, important terms, and emphasis
- Use *italics* (`*italics*`) for new terms and subtle emphasis
- Avoid using ALL CAPS for emphasis
- Use highlighting sparingly

### Code Formatting

- Use backticks (`` ` ``) for inline code references
- Use triple backticks (`` ``` ``) with language identifier for code blocks
- For terminal commands, use `bash` as the language identifier
- Include language identifier for syntax highlighting (e.g., `` ```python ``)

Example:
````
```python
async def get_patient(patient_id: UUID) -> Optional[Patient]:
    """Get a patient by ID."""
    return await repository.get_by_id(patient_id)
```
````

### Links and References

- Use descriptive link text, not "click here" or bare URLs
- For internal links, use relative paths
- For external links, use absolute URLs with HTTPS
- Reference other documents using their canonical names

Example:
```
[API Documentation](../api/overview.md)
```

### Images

- Use descriptive alt text for all images
- Keep image file sizes reasonable (< 200KB when possible)
- Prefer SVG for diagrams and PNG for screenshots
- Store images in the `/docs/content/assets/` directory
- Use descriptive filenames (e.g., `clean_architecture_diagram.png`)

Example:
```
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