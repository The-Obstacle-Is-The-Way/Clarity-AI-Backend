# Contributing to Clarity-AI Backend

Thank you for your interest in contributing to the Clarity-AI Backend project. This document provides guidelines and workflows to help you contribute effectively.

## Code of Conduct

- Respect fellow contributors
- Provide constructive feedback
- Focus on problem-solving
- Maintain professionalism in all communications

## Development Setup

### Environment Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Clarity-AI-Backend
   ```

2. **Set up virtual environment with UV (recommended)**
   ```bash
   # Install UV if not already installed
   curl -LsSf https://astral.sh/uv/install.sh | sh
   
   # Create and activate virtual environment
   uv venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   
   # Install dependencies
   uv sync
   ```

3. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

4. **Start services with Docker**
   ```bash
   docker compose -f docker-compose.test.yml up -d
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

### Running Tests

Ensure all tests pass before submitting contributions:

```bash
# Run all tests
pytest

# Run specific test file
pytest app/tests/path/to/test_file.py

# Run with coverage report
pytest --cov=app
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

Run these checks before committing:

```bash
# Ruff linting
ruff check .

# Mypy type checking
mypy app

# Fix formatting issues
ruff format .
```

### 4. Commit Your Changes

Use conventional commit messages:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types include:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting changes
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

Example:
```
feat(auth): implement JWT token refresh endpoint

- Add refresh token endpoint to auth router
- Add token refresh service method
- Update tests for token refresh flow

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
5. **Markdown Best Practices**: Use proper headings, lists, and code blocks

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

- Review the [Architecture Overview](./docs/Architecture_Overview.md)
- Check the [Project Structure](./docs/Project_Structure.md)
- Ask questions in the issue you're working on
- Contact the maintainers via email or discussion forum

## Thank You

Your contributions help improve the Clarity-AI Backend project. We appreciate your efforts to make psychiatric care more data-informed while maintaining rigorous standards for code quality and accuracy in documentation.