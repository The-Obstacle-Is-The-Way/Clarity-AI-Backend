# SPARC - AI Research Tool for Codebase Analysis

## Overview

SPARC (Superior Programming Assistant for Research and Coding) is a powerful CLI tool for codebase analysis and research. When used in **research-only mode**, it functions as a non-invasive diagnostic tool that can analyze code, identify issues, and provide insights without making any changes to your codebase.

## Recommended Workflow with Cursor IDE

The optimal way to use SPARC with Cursor IDE is through a combined approach:

1. **Use SPARC in research-only mode** to analyze issues and gain deep insights about the codebase
2. **Use Claude in Cursor IDE** to implement the solutions based on SPARC's analysis

This workflow combines SPARC's deep analytical capabilities with Claude's direct integration with the Cursor IDE for controlled, transparent code editing.

### Core Research Command

```bash
sparc -m "Your detailed question or analysis request" --research-only
```

The `--research-only` flag ensures SPARC only analyzes and reports findings without trying to modify files.

## Best Practices for Research Mode

1. **Be specific in your queries**: The more specific your question, the more focused and helpful the analysis.
   ```bash
   sparc -m "Analyze why the JWT token expiration tests are failing in test_security_boundary.py" --research-only
   ```

2. **Focus on one problem area at a time**: Target specific components or issues rather than asking for a full codebase analysis.
   ```bash
   sparc -m "Examine the token validation in jwt_service.py to identify inconsistencies in error handling" --research-only
   ```

3. **Request code path analysis**: Have SPARC trace execution paths through the code to understand complex issues.
   ```bash
   sparc -m "Trace the JWT token validation flow from middleware through service to identify where token validation fails" --research-only
   ```

4. **Ask for pattern identification**: SPARC can identify patterns and inconsistencies across multiple files.
   ```bash
   sparc -m "Identify inconsistent exception handling patterns across all JWT-related services" --research-only
   ```

## When to Use SPARC Research Mode

SPARC research mode is particularly useful for:

- Diagnosing failing tests by analyzing test code and implementation
- Understanding complex execution flows across multiple files
- Identifying inconsistent patterns in error handling or validation logic
- Exploring architectural issues before making changes
- Getting insights on code quality and potential improvements

## Implementation Options

While SPARC does offer implementation capabilities, using Claude in Cursor IDE for implementation provides several advantages:

1. **Greater visibility** into exactly what changes are being made
2. **More controlled editing** with the ability to review changes before they're applied
3. **Better integration** with Cursor IDE features
4. **More reliable** for complex changes that require careful coordination

For simpler projects or when working outside of Cursor, SPARC's full implementation mode can be used, but the research+Claude workflow is recommended for complex production codebases.

## Example Combined Workflow

1. Run failing tests to identify issues:
   ```bash
   python -m pytest app/tests/path/to/failing/test.py -v
   ```

2. Use SPARC to analyze the specific failing test:
   ```bash
   sparc -m "Analyze why test_token_validation is failing in test_jwt_auth.py" --research-only
   ```

3. Review SPARC's analysis in the terminal

4. Have Claude implement the fix in Cursor IDE based on SPARC's analysis

5. Run the tests again to verify the fix:
   ```bash
   python -m pytest app/tests/path/to/failing/test.py -v
   ```

This combined approach leverages the strengths of both tools while minimizing their limitations.
