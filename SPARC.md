# SPARC - AI Research Tool for Codebase Analysis

## Overview

SPARC (Superior Programming Assistant for Research and Coding) is a powerful CLI tool for codebase analysis and research. When used in **research-only mode**, it functions as a non-invasive diagnostic tool that can analyze code, identify issues, and provide insights without making any changes to your codebase.

## Effective Usage in Cursor IDE

SPARC works best in Cursor IDE when used exclusively in **research-only mode**, which provides detailed analysis without attempting to make changes to your code.

### Core Research Command

```bash
sparc -m "Your detailed question or analysis request" --research-only
```

The `--research-only` flag is critical - it ensures SPARC only analyzes and reports findings without trying to modify files.

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
- Exploring architectural issues without making changes
- Getting insights on code quality and potential improvements

## Implementation Mode Warning

⚠️ **Important**: The implementation mode of SPARC (without the `--research-only` flag) attempts to make changes to your code automatically. This mode has shown compatibility issues with Cursor IDE and may not work reliably. Stick to research-only mode when working with Cursor IDE.

## Example Workflow with Cursor IDE

1. Run failing tests to identify issues:
   ```bash
   python -m pytest app/tests/path/to/failing/test.py -v
   ```

2. Use SPARC to analyze the specific failing test:
   ```bash
   sparc -m "Analyze why test_token_validation is failing in test_jwt_auth.py with 'Invalid issuer' error" --research-only
   ```

3. Review SPARC's analysis in the terminal output

4. Based on SPARC's insights, manually implement fixes with Cursor IDE's assistance

5. Run tests again to verify your fix worked

This workflow combines SPARC's analytical capabilities with Cursor IDE's editing capabilities for an efficient problem-solving process.
