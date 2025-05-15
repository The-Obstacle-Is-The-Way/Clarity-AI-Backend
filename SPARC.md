# SPARC - AI Agent for Programming and Research Tasks

## Overview

SPARC (Superior Programming Assistant for Research and Coding) is a powerful CLI tool that provides AI-assisted capabilities for software development tasks. It functions as an autonomous agent that can analyze codebases, conduct research, implement features, fix bugs, and provide code explanations.

## Installation

SPARC is pre-installed in the project environment. No additional installation steps are required.

## Basic Usage

The general syntax for using SPARC is:

```bash
sparc -m "Your task description" [options]
```

### Core Command Options

| Option | Description |
|--------|-------------|
| `-m, --message` | The task or query to be executed by the agent |
| `--research-only` | Only perform research without implementation |
| `--non-interactive` | Run in non-interactive mode (for server deployments) |
| `--hil, -H` | Enable human-in-the-loop mode for additional prompting |
| `--chat` | Enable chat mode with direct human interaction |
| `--cowboy-mode` | Skip interactive approval for shell commands |

### Provider Configuration

| Option | Description |
|--------|-------------|
| `--provider` | The LLM provider to use |
| `--model` | The model name to use |
| `--expert-provider` | The LLM provider for expert knowledge queries |
| `--expert-model` | The model name for expert knowledge queries |

## Operation Modes

### Research Mode

Research mode analyzes the codebase without making changes, providing insights and understanding.

```bash
sparc -m "Analyze the JWT authentication implementation" --research-only
```

This is ideal for:
- Understanding complex codebases
- Diagnosing issues
- Planning refactoring
- Analyzing test failures
- Security reviews

### Implementation Mode

Implementation mode suggests and executes changes to fulfill the requested task.

```bash
sparc -m "Fix the JWT token expiration handling in the authentication service"
```

This is useful for:
- Implementing new features
- Fixing bugs
- Refactoring code
- Adding tests

### Human-in-the-Loop Mode

This mode allows SPARC to ask clarifying questions during execution.

```bash
sparc -m "Implement rate limiting for the API endpoints" --hil
```

Ideal for complex tasks where additional context might be needed during implementation.

### Chat Mode

Provides an interactive dialogue about the codebase.

```bash
sparc --chat
```

Perfect for exploration and Q&A sessions about the codebase.

## Workflow Integration

### With Cursor IDE

SPARC works excellently alongside Cursor IDE's built-in AI capabilities:

1. **Initial Research Phase**
   - Use SPARC for deep analysis: `sparc -m "Analyze [component]" --research-only`
   - Use Cursor IDE for file navigation and focused code understanding

2. **Planning Phase**
   - Use SPARC's research output to inform planning
   - Use Cursor IDE to implement the plan or make targeted changes

3. **Implementation Phase**
   - For complex implementations: `sparc -m "Implement [specific task]" --hil`
   - For simpler tasks: Direct implementation with Cursor IDE's assistance

4. **Testing and Validation**
   - Use `sparc -m "Test and review changes to [component]" --research-only` to validate changes
   - Use Cursor IDE for quick test running and debugging

## Best Practices

1. **Start with Research**
   Always begin with `--research-only` to understand the problem space before implementation.

2. **Be Specific**
   Provide detailed, focused tasks rather than broad ones:
   - Good: "Fix the token expiration handling in jwt_service.py"
   - Avoid: "Fix the authentication system"

3. **Use Human-in-the-Loop for Complex Tasks**
   The `--hil` flag enables SPARC to ask questions when it needs more information.

4. **Vertical Slices**
   Break down large tasks into smaller, focused requests that address a complete vertical slice of functionality.

5. **Verify Changes**
   Always review and test changes made by SPARC before committing.

6. **Security Considerations**
   Be cautious with `--cowboy-mode` as it skips command approval. Only use in trusted environments.

## Common Use Cases and Examples

### Code Analysis

```bash
sparc -m "Analyze the failing JWT tests in the codebase" --research-only
```

### Bug Fixing

```bash
sparc -m "Fix the token expiration handling in jwt_service.py"
```

### Feature Implementation

```bash
sparc -m "Implement rate limiting middleware for the API endpoints" --hil
```

### Refactoring

```bash
sparc -m "Refactor the user authentication flow to use the repository pattern" --hil
```

### Performance Optimization

```bash
sparc -m "Identify and optimize database query bottlenecks in the user service" --research-only
```

### Security Review

```bash
sparc -m "Review the JWT implementation for security vulnerabilities" --research-only
```

## Conclusion

SPARC is a powerful tool that enhances the development workflow when used correctly. It works best when:
- Tasks are specific and well-defined
- You start with research before implementation
- You maintain a balance between automation and human oversight
- You combine it with other tools in your development environment

For more complex operations or queries about the SPARC tool itself, you can always run:

```bash
sparc --help
```

---

*This documentation was created to facilitate efficient use of the SPARC tool within the Clarity AI Digital Twin project.*
