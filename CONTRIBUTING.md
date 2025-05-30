# Contributing to Clarity-AI Backend

Thank you for your interest in contributing to the Clarity-AI Backend project. This document provides 
guidelines and workflows to help you contribute effectively.

## Code of Conduct

- Respect fellow contributors
- Provide constructive feedback
- Focus on problem-solving
- Maintain professionalism in all communications

## Development Setup

### Environment Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/The-Obstacle-Is-The-Way/Clarity-AI-Backend.git
   cd Clarity-AI-Backend
   ```

2. **Set up virtual environment with UV (recommended)**

   ```bash
   # Install UV if not already installed
   curl -LsSf https://astral.sh/UV/install.sh | sh
   
   # Create and activate virtual environment
   UV venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install dependencies
   UV sync
   ```

3. **Set up pre-commit hooks**

   ```bash
   pre-commit install
   ```

4. **Start services with Docker**

   ```bash
   Docker compose -f Docker-compose.test.yml up -d
   ```

5. **Run database migrations**

   ```bash
   alembic upgrade head
   ```

### Running Tests

Ensure all tests pass before submitting contributions:

```bash
# Run all tests
Pytest

# Run specific test file
Pytest app/tests/path/to/test_file.py

# Run with coverage report
Pytest --cov=app
```

## Contribution Workflow

### 1. Create a Feature Branch

Create a branch from `main` with a descriptive name:

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

Follow these principles when making changes:

- **Clean Architecture**: Maintain separation of concerns between layers
- **SOLID Principles**: Follow single responsibility, open/closed, etc.
- **Test Coverage**: Add/update tests for your changes
- **Documentation**: Update relevant documentation

### 3. Code Style and Quality

The project uses several tools to maintain code quality:

- **Ruff**: For Python linting and formatting
- **Mypy**: For static type checking
- **Black**: For code formatting (when not using Ruff)

Run these checks locally before submitting:

```bash
# Run ruff linting and formatting
ruff check app
ruff format app

# Run mypy type checking
mypy app

# Run all pre-commit hooks
pre-commit run --all-files
```

### 4. Commit Guidelines

Follow the conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types include:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:

```bash
feat(auth): add JWT refresh token support

Implement JWT refresh token mechanism to enhance security.
- Add refresh token generation
- Add token rotation on refresh
- Update tests for new flow

Closes #123
```

### 5. Submit a Pull Request

1. Push your branch to the repository
2. Create a pull request against the `main` branch
3. Fill out the PR template with details of your changes
4. Request review from maintainers
5. Address any feedback from reviewers

## Documentation Guidelines

When updating documentation:

1. **Accuracy**: Ensure all documentation accurately reflects the current code
2. **Evidence-Based Claims**: Only include claims that can be substantiated with evidence
3. **Clear Status**: Clearly indicate implementation status of features
4. **Code Examples**: Keep code examples up-to-date with the codebase
5. **Markdown Style**: Follow the project's [Style Guide](./docs/STYLE_GUIDE.md)

### Documentation Structure

Our documentation follows a specific structure:

- **API Documentation**: Details on endpoints, request/response formats
- **Architecture Documentation**: System design, components, and interactions
- **Development Guides**: How to develop specific features
- **Compliance Documentation**: HIPAA and security considerations

Use the templates in the [docs/templates](./docs/templates) directory when creating new documentation.

## Adding New Features

When proposing new features:

1. Start with an issue describing the feature and its use cases
2. Get feedback from maintainers before implementing
3. Follow the clean architecture principles
4. Implement the feature with comprehensive tests
5. Update documentation to reflect the new feature

## Reporting Bugs

When reporting bugs:

1. Check existing issues to avoid duplicates
2. Include steps to reproduce the bug
3. Describe expected vs. actual behavior
4. Include relevant logs or screenshots
5. Mention environment details (OS, Python version, etc.)

## Versioning and Releases

The project follows semantic versioning:

- **Major version**: Breaking changes
- **Minor version**: New features without breaking changes
- **Patch version**: Bug fixes and minor improvements

## Getting Help

If you need help with your contribution:

- Review the [Architecture Overview](./docs/content/architecture/README.md)
- Check the [Project Structure](./docs/content/development/project_structure.md)
- Ask questions in the issue you're working on
- Contact the maintainers via the project discussion forum

## Thank You

Your contributions help improve the Clarity-AI Backend project. We appreciate your efforts to make 
psychiatric care more data-informed while maintaining rigorous standards for code quality and accuracy 
in documentation.