# SPARC - AI Research Tool for Codebase Analysis

## Overview

SPARC (Superior Programming Assistant for Research and Coding) is a powerful CLI tool for codebase analysis and research. When used in **research-only mode**, it functions as a non-invasive diagnostic tool that can analyze code, identify issues, and provide insights without making any changes to your codebase.

## Optimal Workflow with Cursor/Windsurf/AI-IDE

Based on our experience fixing JWT-related issues, the most effective workflow is:

1. **Use SPARC in research-only mode** to analyze issues and gain deep insights about the codebase
2. **Use Claude in Cursor/Windsurf/AI-IDE** to implement the solutions based on SPARC's analysis

This workflow leverages each tool's strengths:
- SPARC excels at deep code analysis and problem diagnosis
- Claude in Cursor/Windsurf/AI-IDE excels at implementing precise fixes with careful testing

### Core Research Command

```bash
sparc -m "Your detailed question or analysis request" --research-only
```

The `--research-only` flag is critical - it ensures SPARC only analyzes and reports findings without trying to modify files.

## Real-World Example: Fixing JWT Validation Issues

We used SPARC + Claude in Cursor/Windsurf/AI-IDE to fix all JWT-related tests by:

1. First identifying the core issues with SPARC:
```bash
sparc -m "Analyze the failing JWT tests in the codebase. Focus on understanding why 22 tests are failing, particularly those related to token validation, expiration, and error handling in jwt_service.py" --research-only
```

2. Using Claude in Cursor/Windsurf/AI-IDE to implement the fixes based on SPARC's insights
3. Verifying the fixes by running tests after each change

The combination proved extremely effective:
- SPARC provided comprehensive insights about complex authentication flows
- Claude in Cursor/Windsurf/AI-IDE implemented precise code changes with proper error handling
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

1. Claude in Cursor/Windsurf/AI-IDE can implement the changes with more fine-grained control
2. Claude in Cursor/Windsurf/AI-IDE can test the changes incrementally
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

3. Use Claude in Cursor/Windsurf/AI-IDE to implement the fix based on SPARC's analysis
   ```
   [Describe the issue to Claude based on SPARC's findings]
   ```

4. Verify the fix with another test run:
   ```bash
   python -m pytest app/tests/path/to/fixed/test.py -v
   ```

5. Repeat for other issues, using SPARC for research and Claude in Cursor/Windsurf/AI-IDE for implementation

------

# MCP Tools Integration

## Overview

In addition to SPARC and Claude, we have integrated several MCP (Model Control Protocol) tools to enhance our development workflow. These tools complement SPARC's analysis capabilities and Claude's implementation precision, providing a comprehensive toolkit for complex codebase management and problem solving.

## MCP Filesystem Tools

MCP Filesystem tools provide precise file manipulation with absolute path support, critical for maintaining consistency in a complex project structure.

### Key Features

- **Absolute Path Support**: Use exact file paths for precise targeting
- **Comprehensive File Operations**: Read, write, edit, and search with detailed control
- **Directory Structure Analysis**: Examine and understand project organization

### When to Use MCP Filesystem Tools

- When you need to examine files across different project directories
- When working with complex configurations spanning multiple files
- When tracing execution flows through deeply nested components
- When searching for specific patterns across the entire codebase

### Example Usage for JWT Issues

```python
# Reading a file with absolute path for precision
mcp_Filesystem_read_file(
    path="/Users/username/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Backend/app/factory.py"
)

# Examining middleware configuration
mcp_Filesystem_read_file(
    path="/Users/username/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Backend/app/presentation/middleware/authentication.py"
)

# Searching for JWT validation patterns
mcp_Filesystem_search_files(
    path="/Users/username/Desktop/CLARITY-DIGITAL-TWIN/Clarity-AI-Backend/app",
    pattern="jwt_service.*decode_token"
)
```

## MCP Memory Tools

MCP Memory tools enable building knowledge graphs to track relationships between components, dependencies, and code insights, creating a structured representation of codebase knowledge.

### Key Features

- **Knowledge Graph Construction**: Map relationships between components
- **Entity and Relation Management**: Track dependencies and hierarchies
- **Observation Storage**: Record insights about code patterns and issues

### When to Use MCP Memory Tools

- When analyzing complex authentication flows with multiple components
- When tracking dependencies between services, repositories, and models
- When collecting observations about code patterns across multiple files
- When building a comprehensive understanding of a feature implementation

### Example Usage for JWT Issues

```python
# Creating entities for JWT components
mcp_Memory_create_entities({
    "entities": [
        {
            "name": "JWTService",
            "entityType": "Service",
            "observations": ["Handles token generation and validation", "Implements JWTServiceInterface"]
        },
        {
            "name": "AuthenticationMiddleware",
            "entityType": "Middleware",
            "observations": ["Validates JWT tokens on requests", "Skippable with skip_auth_middleware flag"]
        }
    ]
})

# Creating relations between components
mcp_Memory_create_relations({
    "relations": [
        {
            "from": "AuthenticationMiddleware",
            "relationType": "depends on",
            "to": "JWTService"
        },
        {
            "from": "factory.py",
            "relationType": "configures",
            "to": "AuthenticationMiddleware"
        }
    ]
})
```

## MCP Sequential Thinking Tool

The Sequential Thinking tool facilitates structured problem-solving through explicit step-by-step reasoning, perfect for tackling complex implementation or debugging challenges.

### Key Features

- **Structured Thought Process**: Break down complex problems into manageable steps
- **Branching Exploration**: Consider alternative approaches when needed
- **Revision and Refinement**: Adjust thinking based on new insights

### When to Use Sequential Thinking

- When debugging complex authentication flows with multiple failure points
- When refactoring middleware with intricate dependencies
- When implementing SOLID principles in interdependent components
- When tracing execution paths through multiple layers of abstraction

### Example Usage for JWT Issues

```python
# Analyzing authentication middleware issues
mcp_sequential-thinking_sequentialthinking(
    thought="First, I need to understand how the AuthenticationMiddleware interacts with the JWT service",
    nextThoughtNeeded=True,
    thoughtNumber=1,
    totalThoughts=5
)

# Next thought in the sequence
mcp_sequential-thinking_sequentialthinking(
    thought="The middleware needs to check app.state.skip_auth_middleware flag which is set in factory.py",
    nextThoughtNeeded=True,
    thoughtNumber=2,
    totalThoughts=5
)
```

## Combined Workflow with All Tools

The most effective approach integrates all available tools in a structured workflow:

1. **Initial Research with SPARC**
   ```bash
   sparc -m "Analyze the JWT authentication flow and identify failure points in tests" --research-only
   ```

2. **Deep File Analysis with MCP Filesystem**
   ```python
   # Examine specific components identified by SPARC
   mcp_Filesystem_read_file(path="/path/to/authentication_middleware.py")
   ```

3. **Knowledge Mapping with MCP Memory**
   ```python
   # Create a knowledge graph of authentication components
   mcp_Memory_create_entities({...})
   mcp_Memory_create_relations({...})
   ```

4. **Structured Problem Solving with Sequential Thinking**
   ```python
   # Break down the solution approach step by step
   mcp_sequential-thinking_sequentialthinking({...})
   ```

5. **Implementation with Claude in Cursor/Windsurf/AI-IDE**
   ```
   # Implement the solution based on comprehensive analysis
   ```

6. **Verification with Tests**
   ```bash
   python -m pytest app/tests/unit/infrastructure/security/test_jwt_*.py -v
   ```

### Real-World Success: JWT Authentication Flow

This combined workflow allowed us to fix all 53 JWT-related tests by:

- Using SPARC to identify the high-level issues in the authentication flow
- Using MCP Filesystem to examine the specific implementation of token validation
- Using MCP Memory to map the relationships between middleware, services, and validators
- Using Sequential Thinking to develop a systematic approach to fixing each issue
- Using Claude in Cursor/Windsurf/AI-IDE to implement precise fixes with proper error handling
- Running targeted tests to verify each fix incrementally

The result was a robust, fully-tested authentication system that properly handles token validation, expiration, and error cases across all components.

## Additional MCP Tools

### MCP Context7 Library Documentation Tools

These tools provide access to up-to-date documentation for various libraries and frameworks used in the project.

#### Key Features

- **Library Resolution**: Find the correct documentation for any package
- **Documentation Retrieval**: Get latest documentation with specific topics
- **Direct Integration**: Use documentation directly in your workflow

#### Example Usage

```python
# First resolve the library ID
mcp_Context7-mcp_resolve-library-id(
    libraryName="fastapi"
)

# Then get the documentation
mcp_Context7-mcp_get-library-docs(
    context7CompatibleLibraryID="tiangolo/fastapi",
    topic="middleware",
    tokens=5000
)
```

### MCP GitHub Integration Tools

These tools provide direct GitHub integration for repository management and code analysis.

#### Key Features

- **Repository Management**: Create, fork, clone, and manage repositories
- **Issue Tracking**: Create, update, and manage issues
- **Pull Request Workflow**: Create, review, and merge pull requests
- **Code Search**: Search code across repositories

#### Example Usage

```python
# Get file contents from a GitHub repository
mcp_GITHUB_get_file_contents(
    owner="clarity-project",
    repo="Clarity-AI-Backend",
    path="app/factory.py"
)

# Search for specific code patterns
mcp_GITHUB_search_code(
    q="repo:clarity-project/Clarity-AI-Backend AuthenticationMiddleware"
)
```

### MCP Browser Tools

These tools provide browser-based debugging and analysis capabilities for web applications.

#### Key Features

- **Console Logs**: Access browser console logs and errors
- **Network Analysis**: Monitor network requests and responses
- **Screenshots**: Take screenshots of web application state
- **SEO and Performance**: Run audits for optimization

#### Example Usage

```python
# Get console logs
mcp_github_comAgentDeskAIbrowser-tools-mcp_getConsoleLogs(
    random_string=""
)

# Check for network errors
mcp_github_comAgentDeskAIbrowser-tools-mcp_getNetworkErrors(
    random_string=""
)

# Take a screenshot
mcp_github_comAgentDeskAIbrowser-tools-mcp_takeScreenshot(
    random_string=""
)
```

## Complete MCP Tool Reference

Below is a complete list of all available MCP tools categorized by function:

### Filesystem Tools
- `mcp_Filesystem_read_file`: Read a single file by path
- `mcp_Filesystem_read_multiple_files`: Read multiple files at once
- `mcp_Filesystem_write_file`: Create or overwrite a file
- `mcp_Filesystem_edit_file`: Make targeted edits to a file
- `mcp_Filesystem_create_directory`: Create a new directory
- `mcp_Filesystem_list_directory`: List contents of a directory
- `mcp_Filesystem_directory_tree`: Get recursive tree view of files/directories
- `mcp_Filesystem_move_file`: Move or rename files
- `mcp_Filesystem_search_files`: Find files matching a pattern
- `mcp_Filesystem_get_file_info`: Get metadata about a file
- `mcp_Filesystem_list_allowed_directories`: List accessible directories

### Memory Tools
- `mcp_Memory_create_entities`: Create entities in the knowledge graph
- `mcp_Memory_create_relations`: Create relations between entities
- `mcp_Memory_add_observations`: Add observations to existing entities
- `mcp_Memory_delete_entities`: Remove entities from the graph
- `mcp_Memory_delete_observations`: Remove specific observations
- `mcp_Memory_delete_relations`: Remove relations from the graph
- `mcp_Memory_read_graph`: Read the entire knowledge graph
- `mcp_Memory_search_nodes`: Search for nodes by query
- `mcp_Memory_open_nodes`: Open specific nodes by name

### Sequential Thinking Tool
- `mcp_sequential-thinking_sequentialthinking`: Structured problem-solving

### Library Documentation Tools
- `mcp_Context7-mcp_resolve-library-id`: Resolve library name to ID
- `mcp_Context7-mcp_get-library-docs`: Get documentation for a library

### Browser Tools
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_getConsoleLogs`: Get browser console logs
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_getConsoleErrors`: Get console errors
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_getNetworkErrors`: Get network errors
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_getNetworkLogs`: Get all network logs
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_takeScreenshot`: Take screenshot
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_wipeLogs`: Clear browser logs
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_runSEOAudit`: Run SEO audit
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_runNextJSAudit`: Run NextJS audit
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_runDebuggerMode`: Run debugger
- `mcp_github_comAgentDeskAIbrowser-tools-mcp_runAuditMode`: Run audit mode

### GitHub Tools
- `mcp_GITHUB_create_or_update_file`: Create or update file in repo
- `mcp_GITHUB_search_repositories`: Search for repositories
- `mcp_GITHUB_create_repository`: Create a new repository
- `mcp_GITHUB_get_file_contents`: Get file contents from repository
- `mcp_GITHUB_push_files`: Push multiple files in one commit
- `mcp_GITHUB_create_issue`: Create a new issue
- `mcp_GITHUB_create_pull_request`: Create a new pull request
- `mcp_GITHUB_fork_repository`: Fork a repository
- `mcp_GITHUB_create_branch`: Create a new branch
- `mcp_GITHUB_list_commits`: List commits in a branch
- `mcp_GITHUB_list_issues`: List repository issues
- `mcp_GITHUB_update_issue`: Update an existing issue
- `mcp_GITHUB_add_issue_comment`: Comment on an issue
- `mcp_GITHUB_search_code`: Search for code across repositories
- `mcp_GITHUB_search_issues`: Search for issues and PRs
- `mcp_GITHUB_search_users`: Search for GitHub users
- `mcp_GITHUB_get_issue`: Get details of an issue
- `mcp_GITHUB_get_pull_request`: Get PR details
- `mcp_GITHUB_list_pull_requests`: List repository PRs
- `mcp_GITHUB_create_pull_request_review`: Review a PR
- `mcp_GITHUB_merge_pull_request`: Merge a PR
- `mcp_GITHUB_get_pull_request_files`: Get files changed in a PR
- `mcp_GITHUB_get_pull_request_status`: Get PR status checks
- `mcp_GITHUB_update_pull_request_branch`: Update PR branch
- `mcp_GITHUB_get_pull_request_comments`: Get PR comments
- `mcp_GITHUB_get_pull_request_reviews`: Get PR reviews

### Utility Tools
- `mcp_github_comGarothecho-mcp_echo`: Echo back input message
