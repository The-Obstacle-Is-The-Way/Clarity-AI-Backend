# ESSENTIAL CODEBASE ANALYSIS TOOLS

## KEY TOOLS YOU MUST USE:

1. **SPARC** - AI Research Tool for deep analysis (research-only mode)
2. **MCP FILESYSTEM WITH ABSOLUTE PATHS** - Precise file access across project
3. **MCP MEMORY** - Knowledge graph for tracking relationships
4. **MCP SEQUENTIAL THINKING** - Structured problem solving

# SPARC - AI Research Tool for Codebase Analysis

## Overview

SPARC (Superior Programming Assistant for Research and Coding) is a powerful CLI tool for codebase analysis and research. When used in **research-only mode**, it functions as a non-invasive diagnostic tool that can analyze code, identify issues, and provide insights without making any changes to your codebase.

## Optimal Workflow with Cursor IDE

Based on our experience fixing JWT-related issues, the most effective workflow is:

1. **Use SPARC in research-only mode** to analyze issues and gain deep insights about the codebase
2. **Use Claude in Cursor IDE** to implement the solutions based on SPARC's analysis

This workflow leverages each tool's strengths:
- SPARC excels at deep code analysis and problem diagnosis
- Claude excels at implementing precise fixes with careful testing

### Core Research Command

```bash
sparc -m "Your detailed question or analysis request" --research-only
```

The `--research-only` flag is critical - it ensures SPARC only analyzes and reports findings without trying to modify files.

## Real-World Example: Fixing JWT Validation Issues

We used SPARC + Claude to fix all JWT-related tests by:

1. First identifying the core issues with SPARC:
```bash
sparc -m "Analyze the failing JWT tests in the codebase. Focus on understanding why 22 tests are failing, particularly those related to token validation, expiration, and error handling in jwt_service.py" --research-only
```

2. Using Claude to implement the fixes based on SPARC's insights
3. Verifying the fixes by running tests after each change

The combination proved extremely effective:
- SPARC provided comprehensive insights about complex authentication flows
- Claude implemented precise code changes with proper error handling
- All 22 previously failing tests now pass

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

⚠️ **Important**: While SPARC's implementation mode works, our experience suggests the SPARC (research) + Claude (implementation) workflow is more effective because:

1. Claude can implement the changes with more fine-grained control
2. Claude can test the changes incrementally
3. You maintain control over exactly what changes are being made

## Example Combined Workflow

1. Run failing tests to identify issues:
   ```bash
   python -m pytest app/tests/path/to/failing/test.py -v
   ```

2. Use SPARC to analyze the specific failing test:
   ```bash
   sparc -m "Analyze why test_token_validation is failing in test_jwt_auth.py" --research-only
   ```

3. Use Claude to implement the fix based on SPARC's analysis
   ```
   [Describe the issue to Claude based on SPARC's findings]
   ```

4. Verify the fix with another test run:
   ```bash
   python -m pytest app/tests/path/to/fixed/test.py -v
   ```

5. Repeat for other issues, using SPARC for research and Claude for implementation

------


