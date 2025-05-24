"""
PHI code analysis for HIPAA compliance.

This module provides analysis of code patterns to detect potential PHI leakage,
using the consolidated PHI sanitization components.
"""

import ast
import configparser
import json
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from app.infrastructure.security.phi.sanitizer import PHISanitizer, get_sanitized_logger

# Create a sanitized logger
logger = get_sanitized_logger(__name__)


class CodeSeverity(str, Enum):
    """Severity levels for PHI code findings."""

    CRITICAL = "critical"  # Definite PHI leak
    WARNING = "warning"  # Potential PHI leak
    INFO = "info"  # Informational finding


class PHIFinding:
    """Represents a potential PHI leak in code."""

    def __init__(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        message: str,
        severity: CodeSeverity,
    ):
        """
        Initialize a PHI finding.

        Args:
            file_path: Path to the file
            line_number: Line number of the finding
            code_snippet: Code snippet containing the finding
            message: Description of the finding
            severity: Severity level
        """
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.message = message
        self.severity = severity

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to dictionary representation.

        Returns:
            Dictionary representation of the finding
        """
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "message": self.message,
            "severity": self.severity.value,
        }

    def __str__(self) -> str:
        """Get string representation of the finding."""
        return (
            f"{self.severity.value.upper()}: {self.message}\n"
            f"  File: {self.file_path}, Line: {self.line_number}\n"
            f"  Code: {self.code_snippet}"
        )


class PHICodeAnalyzer:
    """
    Analyzer for detecting potential PHI leaks in code.

    This implementation uses the consolidated PHI sanitization system
    to identify potential PHI leaks in code files and directories.
    """

    # PHI patterns that should not appear in code
    PHI_PATTERNS = [
        # SSN patterns
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN format
        r'\bSSN\s*[:=]\s*["\']?\d{3}-\d{2}-\d{4}["\']?',  # SSN with label
        # Email patterns
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email address
        # Phone patterns
        r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",  # Phone number
        # Date of birth
        r"\b(0[1-9]|1[0-2])[/-](0[1-9]|[12][0-9]|3[01])[/-](19|20)\d{2}\b",  # MM/DD/YYYY
        r"\b(19|20)\d{2}[/-](0[1-9]|1[0-2])[/-](0[1-9]|[12][0-9]|3[01])\b",  # YYYY/MM/DD
        # Address patterns
        r"\b\d+\s+[A-Za-z0-9\s,]+(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Ln|Rd|Blvd|Dr|St)\.?\b",
        # Credit card patterns
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
    ]

    # Suspicious variable names that might contain PHI
    PHI_VARIABLE_NAMES = [
        "ssn",
        "social_security",
        "social",
        "dob",
        "birth_date",
        "birth",
        "address",
        "phone",
        "phone_number",
        "email",
        "patient_id",
        "medical_record_number",
        "mrn",
        "patient_name",
        "full_name",
        "first_name",
        "last_name",
        "credit_card",
        "cc_number",
        "credit",
        "license",
        "drivers_license",
        "dl_number",
        "passport",
    ]

    # Config keys and patterns that might contain sensitive data
    SENSITIVE_CONFIG_PATTERNS = [
        "password",
        "secret",
        "key",
        "token",
        "auth",
        "credential",
        "ssn",
        "social",
        "birth",
        "dob",
        "credit",
        "connection_string",
        "connection",
        "pw",
        "connect",
    ]

    def __init__(
        self,
        sanitizer: PHISanitizer | None = None,
    ):
        """
        Initialize the PHI code analyzer.

        Args:
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
        """
        self.sanitizer = sanitizer or PHISanitizer()
        # Patterns for code analysis
        self.patterns = [
            # Logging patterns
            (
                r"(?:logger|logging)\.(debug|info|warning|error|critical)\(.*?\)",
                "Potential PHI in log statement",
                CodeSeverity.WARNING,
            ),
            # Print statements
            (r"print\(.*?\)", "Potential PHI in print statement", CodeSeverity.INFO),
            # Exception patterns
            (
                r"(?:raise|except)\s+\w+\(.*?\)",
                "Potential PHI in exception message",
                CodeSeverity.WARNING,
            ),
            # Common PHI variable names
            (
                r"\b(?:ssn|social_security|dob|birth_date|address|phone|email|patient_id|medical_record_number|mrn)\b",
                "Variable name suggests PHI",
                CodeSeverity.INFO,
            ),
            # URL paths with potential identifiers
            (
                r"@(?:app|router)\.(?:get|post|put|delete)\(['\"]/?.*?/?\{.*?\}['\"]",
                "URL parameter may contain PHI",
                CodeSeverity.WARNING,
            ),
            # Database queries
            (
                r"(?:execute|query|cursor\.execute)\(.*?\)",
                "Database query might expose PHI",
                CodeSeverity.INFO,
            ),
        ]

        # Add the PHI patterns from the class constant
        for pattern in self.PHI_PATTERNS:
            self.patterns.append((pattern, "Direct PHI found in code", CodeSeverity.CRITICAL))

    def analyze_file(self, file_path: str) -> list[PHIFinding]:
        """
        Analyze a file for potential PHI leaks.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of PHI findings in the file
        """
        findings = []

        try:
            path_obj = Path(file_path)
            # Skip non-existent files
            if not path_obj.exists():
                return []

            # Skip directories
            if path_obj.is_dir():
                return []

            with path_obj.open(encoding="utf-8") as f:
                content = f.read()
                lines = content.splitlines()

            # Basic pattern matching on each line
            for i, line in enumerate(lines, 1):
                for pattern, message, severity in self.patterns:
                    if re.search(pattern, line):
                        findings.append(
                            PHIFinding(
                                file_path=file_path,
                                line_number=i,
                                code_snippet=line.strip(),
                                message=message,
                                severity=severity,
                            )
                        )

            # If it's a Python file, also do deeper AST analysis
            if path_obj.suffix.lower() == ".py":
                try:
                    ast_findings = self.analyze_ast(content, file_path)
                    # Add findings that aren't duplicates
                    existing_lines = {(f.file_path, f.line_number) for f in findings}
                    for finding in ast_findings:
                        if (
                            finding.file_path,
                            finding.line_number,
                        ) not in existing_lines:
                            findings.append(finding)
                except SyntaxError:
                    # If AST parsing fails, just continue with pattern-based findings
                    findings.append(
                        PHIFinding(
                            file_path=file_path,
                            line_number=0,
                            code_snippet="",
                            message="Failed to parse Python code for AST analysis",
                            severity=CodeSeverity.INFO,
                        )
                    )

            # If it's a config file, do special config analysis
            elif path_obj.suffix.lower() in (
                ".json",
                ".yaml",
                ".yml",
                ".ini",
                ".cfg",
                ".conf",
                ".config",
                ".env",
            ):
                try:
                    config_findings = self.analyze_config_file(file_path)
                    findings.extend(config_findings)
                except Exception as e:
                    findings.append(
                        PHIFinding(
                            file_path=file_path,
                            line_number=0,
                            code_snippet="",
                            message=f"Failed to parse config file: {e!s}",
                            severity=CodeSeverity.INFO,
                        )
                    )

        except Exception as e:
            # Add error finding
            findings.append(
                PHIFinding(
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    message=f"Error analyzing file: {e!s}",
                    severity=CodeSeverity.INFO,
                )
            )

        return findings

    def analyze_directory(
        self, directory_path: str, exclude_dirs: list[str] | None = None
    ) -> list[PHIFinding]:
        """
        Analyze all Python files in a directory for potential PHI leaks.

        Args:
            directory_path: Path to the directory to analyze
            exclude_dirs: List of directory names (not full paths) to
                          exclude from analysis.

        Returns:
            List of PHI findings in all analyzed files
        """
        all_findings: list[PHIFinding] = []
        base_dir = Path(directory_path)
        if not base_dir.is_dir():
            # Log warning or raise error?
            logger.warning(f"Directory not found: {directory_path}")
            return all_findings

        exclude_set = set(exclude_dirs) if exclude_dirs else set()

        for root, dirs, files in os.walk(base_dir, topdown=True):
            # Modify dirs in-place to exclude unwanted directories
            # Check if the directory name or any parent directory name is in exclude_set
            dirs[:] = [
                d
                for d in dirs
                if d not in exclude_set
                and not any(
                    excluded in Path(os.path.join(root, d)).parts for excluded in exclude_set
                )
            ]

            for file in files:
                if file.endswith(
                    (
                        ".py",
                        ".js",
                        ".ts",
                        ".jsx",
                        ".tsx",
                        ".json",
                        ".yaml",
                        ".yml",
                        ".ini",
                        ".cfg",
                        ".conf",
                    )
                ):
                    file_path = Path(root) / file

                    # Skip files in excluded directories
                    if any(excluded in file_path.parts for excluded in exclude_set):
                        continue

                    try:
                        file_findings = self.analyze_file(str(file_path))
                        all_findings.extend(file_findings)
                    except Exception as e:
                        # Add finding for file analysis error
                        all_findings.append(
                            PHIFinding(
                                file_path=str(file_path),
                                line_number=0,
                                code_snippet="",
                                message=f"Error analyzing file: {e!s}",
                                severity=CodeSeverity.INFO,
                            )
                        )

        return all_findings

    def analyze_code_string(self, code: str, file_path: str = "<string>") -> list[PHIFinding]:
        """
        Analyze a code string for potential PHI leaks.

        Args:
            code: Code string to analyze
            file_path: Virtual file path for reporting

        Returns:
            List of PHI findings in the code
        """
        findings = []
        lines = code.splitlines()

        for i, line in enumerate(lines, 1):
            for pattern, message, severity in self.patterns:
                if re.search(pattern, line):
                    findings.append(
                        PHIFinding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            message=message,
                            severity=severity,
                        )
                    )

        return findings

    def analyze_ast(self, code: str, file_path: str = "<string>") -> list[PHIFinding]:
        """
        Analyze abstract syntax tree for deeper PHI leak detection.

        Args:
            code: Python code to analyze
            file_path: File path for reporting

        Returns:
            List of PHI findings discovered through AST analysis
        """
        findings = []

        try:
            tree = ast.parse(code)

            class PHINodeVisitor(ast.NodeVisitor):
                """AST visitor to find PHI in Python code."""

                def __init__(self, file_path):
                    """Initialize visitor with file path."""
                    self.file_path = file_path
                    self.findings = []
                    self.current_line = 0

                def generic_visit(self, node) -> None:
                    """Visit a node and track line numbers."""
                    if hasattr(node, "lineno"):
                        self.current_line = node.lineno
                    ast.NodeVisitor.generic_visit(self, node)

                def visit_Constant(self, node) -> None:
                    """Visit string literals in modern Python (3.8+)."""
                    # Handle string constants which may contain PHI
                    if isinstance(node.value, str):
                        for pattern in PHICodeAnalyzer.PHI_PATTERNS:
                            if re.search(pattern, node.value):
                                # String literal contains PHI pattern
                                self.findings.append(
                                    PHIFinding(
                                        file_path=self.file_path,
                                        line_number=self.current_line,
                                        code_snippet=f'"{node.value[:20]}..."'
                                        if len(node.value) > 20
                                        else f'"{node.value}"',
                                        message="String literal contains PHI pattern",
                                        severity=CodeSeverity.CRITICAL,
                                    )
                                )
                                break
                    self.generic_visit(node)

                # For backward compatibility with older Python versions
                def visit_Str(self, node) -> None:
                    """Legacy method for string literals (Python < 3.8)."""
                    self.visit_Constant(
                        ast.Constant(value=node.s, lineno=node.lineno, col_offset=node.col_offset)
                    )

                def visit_Name(self, node) -> None:
                    """Visit variable names."""
                    for pattern in PHICodeAnalyzer.PHI_VARIABLE_NAMES:
                        if re.search(pattern, node.id, re.IGNORECASE):
                            self.findings.append(
                                PHIFinding(
                                    file_path=self.file_path,
                                    line_number=self.current_line,
                                    code_snippet=f"Variable name: {node.id}",
                                    message=f"Variable name suggests PHI: {node.id}",
                                    severity=CodeSeverity.WARNING,
                                )
                            )
                            break
                    self.generic_visit(node)

                def visit_ClassDef(self, node) -> None:
                    """Visit class definitions to check for PHI-related models."""
                    # Check for PHI-related class names
                    for pattern in PHICodeAnalyzer.PHI_MODEL_NAMES:
                        if re.search(pattern, node.name, re.IGNORECASE):
                            self.findings.append(
                                PHIFinding(
                                    file_path=self.file_path,
                                    line_number=self.current_line,
                                    code_snippet=f"class {node.name}:",
                                    message=f"Class name suggests PHI: {node.name}",
                                    severity=CodeSeverity.INFO,
                                )
                            )
                            break
                    self.generic_visit(node)

                def visit_Call(self, node) -> None:
                    """Visit function calls to check for logging and print statements."""
                    if hasattr(node, "lineno"):
                        self.current_line = node.lineno

                    # Check for logging calls
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in (
                            "debug",
                            "info",
                            "warning",
                            "error",
                            "critical",
                        ):
                            # This might be a logging call
                            self.findings.append(
                                PHIFinding(
                                    file_path=self.file_path,
                                    line_number=self.current_line,
                                    code_snippet="Logging call",
                                    message="Potential PHI in logging call",
                                    severity=CodeSeverity.WARNING,
                                )
                            )
                    elif isinstance(node.func, ast.Name) and node.func.id == "print":
                        # This is a print call
                        self.findings.append(
                            PHIFinding(
                                file_path=self.file_path,
                                line_number=self.current_line,
                                code_snippet="print statement",
                                message="Potential PHI in print statement",
                                severity=CodeSeverity.INFO,
                            )
                        )

                    # Continue visiting children
                    self.generic_visit(node)

            visitor = PHINodeVisitor(file_path)
            visitor.visit(tree)
            findings.extend(visitor.findings)

        except SyntaxError:
            # Code isn't valid Python, just skip AST analysis
            pass
        except Exception as e:
            # Log the error but continue
            logger.warning(f"AST analysis error in {file_path}: {e!s}")

        return findings

    def analyze_config_file(self, file_path: str) -> list[PHIFinding]:
        """
        Analyze configuration files for potential PHI or secrets.

        Args:
            file_path: Path to the configuration file

        Returns:
            List of PHI findings in the configuration
        """
        findings = []
        path = Path(file_path)

        try:
            # Choose parsing strategy based on file extension
            extension = path.suffix.lower()

            if extension in (".json"):
                with path.open("r", encoding="utf-8") as f:
                    config_data = json.load(f)
                self._check_config_dict(config_data, file_path, findings)

            elif extension in (".yaml", ".yml"):
                with path.open("r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f)
                self._check_config_dict(config_data, file_path, findings)

            elif extension in (".ini", ".cfg", ".conf"):
                config = configparser.ConfigParser()
                config.read(file_path)

                # Convert to dict for consistent processing
                config_dict = {}
                for section in config.sections():
                    config_dict[section] = dict(config[section])
                self._check_config_dict(config_dict, file_path, findings)

            else:
                # For unknown formats, just check line by line
                with path.open("r", encoding="utf-8") as f:
                    lines = f.readlines()

                for i, line in enumerate(lines, 1):
                    # Check for key-value patterns
                    kv_match = re.search(
                        r'([A-Za-z0-9_]+)\s*[=:]\s*["\'`]?(.*?)["\'`]?\s*(?:#|$)', line
                    )
                    if kv_match:
                        key, value = kv_match.groups()
                        if self._is_sensitive_key(key) and value.strip():
                            findings.append(
                                PHIFinding(
                                    file_path=file_path,
                                    line_number=i,
                                    code_snippet=line.strip(),
                                    message=f"Sensitive configuration key: {key}",
                                    severity=CodeSeverity.WARNING,
                                )
                            )

                    # Also check for PHI patterns
                    for pattern in self.PHI_PATTERNS:
                        if re.search(pattern, line):
                            findings.append(
                                PHIFinding(
                                    file_path=file_path,
                                    line_number=i,
                                    code_snippet=line.strip(),
                                    message="Configuration contains PHI pattern",
                                    severity=CodeSeverity.CRITICAL,
                                )
                            )
                            break

        except Exception as e:
            findings.append(
                PHIFinding(
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    message=f"Error analyzing config file: {e!s}",
                    severity=CodeSeverity.INFO,
                )
            )

        return findings

    def _check_config_dict(
        self,
        config: dict,
        file_path: str,
        findings: list[PHIFinding],
        path: str = "",
        line: int = 0,
    ) -> None:
        """Recursively check a configuration dictionary for sensitive data."""
        if isinstance(config, dict):
            for key, value in config.items():
                current_path = f"{path}.{key}" if path else key

                # Check if this key is sensitive
                if self._is_sensitive_key(key) and value:
                    findings.append(
                        PHIFinding(
                            file_path=file_path,
                            line_number=line,  # We don't know exact line in parsed configs
                            code_snippet=f"{current_path} = {value}",
                            message=f"Sensitive configuration key: {current_path}",
                            severity=CodeSeverity.WARNING,
                        )
                    )

                # Recurse into nested dictionaries
                if isinstance(value, dict | list):
                    self._check_config_dict(value, file_path, findings, current_path, line)

                # Check string values for PHI patterns
                elif isinstance(value, str):
                    for pattern in self.PHI_PATTERNS:
                        if re.search(pattern, value):
                            findings.append(
                                PHIFinding(
                                    file_path=file_path,
                                    line_number=line,
                                    code_snippet=f"{current_path} = {value[:20]}..."
                                    if len(value) > 20
                                    else f"{current_path} = {value}",
                                    message=f"Configuration value contains PHI pattern: {current_path}",
                                    severity=CodeSeverity.CRITICAL,
                                )
                            )
                            break

        elif isinstance(config, list):
            for i, item in enumerate(config):
                current_path = f"{path}[{i}]"
                if isinstance(item, dict | list):
                    self._check_config_dict(item, file_path, findings, current_path, line)
                elif isinstance(item, str):
                    for pattern in self.PHI_PATTERNS:
                        if re.search(pattern, item):
                            findings.append(
                                PHIFinding(
                                    file_path=file_path,
                                    line_number=line,
                                    code_snippet=f"{current_path} = {item[:20]}..."
                                    if len(item) > 20
                                    else f"{current_path} = {item}",
                                    message=f"Configuration array contains PHI pattern: {current_path}",
                                    severity=CodeSeverity.CRITICAL,
                                )
                            )
                            break

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a configuration key name suggests sensitive data."""
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in self.SENSITIVE_CONFIG_PATTERNS)

    def audit_api_endpoints(self, api_spec_file: str | None = None) -> list[PHIFinding]:
        """
        Audit API endpoints for potential PHI exposure.

        Args:
            api_spec_file: Path to OpenAPI specification file

        Returns:
            List of PHI findings in API endpoints
        """
        findings = []

        if not api_spec_file:
            return findings

        try:
            path = Path(api_spec_file)

            if not path.exists():
                # Return a specific finding about missing file instead of empty list
                findings.append(
                    PHIFinding(
                        file_path=api_spec_file,
                        line_number=0,
                        message="API specification file not found",
                        severity=CodeSeverity.WARNING,
                        code_snippet="File not found",
                    )
                )
                return findings

            # Load the file content directly first for a raw search
            with open(path, encoding="utf-8") as f:
                content = f.read()

            # Do an initial scan for PHI terms in the raw content
            # This is a fallback if the structured parsing fails
            for pattern in [
                "ssn",
                "social security",
                "dob",
                "date of birth",
                "name",
                "email",
                "phone",
                "address",
                "medical record",
                "mrn",
            ]:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append(
                        PHIFinding(
                            file_path=api_spec_file,
                            line_number=0,
                            message=f"API specification contains PHI term '{pattern}'",
                            severity=CodeSeverity.WARNING,
                            code_snippet=f"Content contains PHI pattern: {pattern}",
                        )
                    )

            # Now try to parse the file as YAML or JSON
            try:
                if path.suffix.lower() in (".yaml", ".yml"):
                    api_spec = yaml.safe_load(content)
                elif path.suffix.lower() == ".json":
                    api_spec = json.loads(content)
                else:
                    findings.append(
                        PHIFinding(
                            file_path=api_spec_file,
                            line_number=0,
                            message=f"Unsupported file format: {path.suffix}",
                            severity=CodeSeverity.WARNING,
                            code_snippet=f"File format {path.suffix} not supported",
                        )
                    )
                    return findings

                # If we have findings from the raw scan, we can return those
                if findings:
                    return findings

                # Check if the spec contains 'paths'
                if (
                    not isinstance(api_spec, dict)
                    or "paths" not in api_spec
                    or not isinstance(api_spec["paths"], dict)
                ):
                    findings.append(
                        PHIFinding(
                            file_path=api_spec_file,
                            line_number=0,
                            message="No API paths found in specification",
                            severity=CodeSeverity.INFO,
                            code_snippet="No 'paths' key or invalid paths structure",
                        )
                    )
                    return findings

                # Scan paths for PHI identifiers
                for path_key, path_item in api_spec["paths"].items():
                    # Check URL path for PHI parameter patterns
                    if re.search(
                        r"(ssn|social[\s_-]*security|name|email|phone|address|birth|dob)",
                        path_key,
                        re.IGNORECASE,
                    ):
                        findings.append(
                            PHIFinding(
                                file_path=api_spec_file,
                                line_number=0,
                                message=f"Path contains potential PHI identifier: {path_key}",
                                severity=CodeSeverity.WARNING,
                                code_snippet=f"Path: {path_key}",
                            )
                        )

                    if not isinstance(path_item, dict):
                        continue

                    # Check each operation (GET, POST, etc.)
                    for method, operation in path_item.items():
                        if method in (
                            "get",
                            "post",
                            "put",
                            "patch",
                            "delete",
                        ) and isinstance(operation, dict):
                            # Check for PHI in parameters
                            if "parameters" in operation and isinstance(
                                operation["parameters"], list
                            ):
                                for param in operation["parameters"]:
                                    if not isinstance(param, dict):
                                        continue

                                    param_name = param.get("name", "")
                                    param_in = param.get("in", "")

                                    # Check for PHI pattern in parameter name
                                    if re.search(
                                        r"(ssn|social[\s_-]*security|name|email|phone|address|birth|dob|mrn|medical[\s_-]*record)",
                                        param_name,
                                        re.IGNORECASE,
                                    ):
                                        findings.append(
                                            PHIFinding(
                                                file_path=api_spec_file,
                                                line_number=0,
                                                message=f"Parameter '{param_name}' (in {param_in}) may contain PHI",
                                                severity=CodeSeverity.WARNING
                                                if param_in == "path"
                                                else CodeSeverity.CRITICAL,
                                                code_snippet=f"Method: {method.upper()}, Path: {path_key}, Parameter: {param_name} (in {param_in})",
                                            )
                                        )

                            # Check for PHI in response schemas
                            if "responses" in operation and isinstance(
                                operation["responses"], dict
                            ):
                                for status_code, response in operation["responses"].items():
                                    if not isinstance(response, dict):
                                        continue

                                    # Check for content with schema
                                    content = response.get("content", {})
                                    if not isinstance(content, dict):
                                        continue

                                    for _media_type, media_content in content.items():
                                        if not isinstance(media_content, dict):
                                            continue

                                        schema = media_content.get("schema", {})
                                        if not isinstance(schema, dict):
                                            continue

                                        # Direct search for sensitive field names in the schema
                                        def search_for_phi_properties(obj, path_prefix="") -> None:
                                            """Recursively search for PHI properties in nested schema objects"""
                                            if not isinstance(obj, dict):
                                                return

                                            # Check properties directly
                                            if "properties" in obj and isinstance(
                                                obj["properties"], dict
                                            ):
                                                for prop_name, prop_schema in obj[
                                                    "properties"
                                                ].items():
                                                    full_path = (
                                                        f"{path_prefix}.{prop_name}"
                                                        if path_prefix
                                                        else prop_name
                                                    )
                                                    if re.search(
                                                        r"(ssn|social[\s_-]*security|name|email|phone|address|birth|dob|mrn|medical[\s_-]*record)",
                                                        prop_name,
                                                        re.IGNORECASE,
                                                    ):
                                                        findings.append(
                                                            PHIFinding(
                                                                file_path=api_spec_file,
                                                                line_number=0,
                                                                message=f"Response property '{full_path}' may contain PHI",
                                                                severity=CodeSeverity.CRITICAL,
                                                                code_snippet=f"Method: {method.upper()}, Path: {path_key}, Response: {status_code}, Property: {full_path}",
                                                            )
                                                        )

                                                    # Recurse into nested objects
                                                    if isinstance(prop_schema, dict):
                                                        search_for_phi_properties(
                                                            prop_schema, full_path
                                                        )

                                            # Check for items in arrays
                                            if "items" in obj and isinstance(obj["items"], dict):
                                                search_for_phi_properties(
                                                    obj["items"],
                                                    f"{path_prefix}[items]",
                                                )

                                        # Start the recursive search
                                        search_for_phi_properties(schema)

            except Exception as e:
                # If parsing fails, rely on our initial raw scan
                if not findings:
                    # Add an error finding only if we don't have any findings yet
                    findings.append(
                        PHIFinding(
                            file_path=api_spec_file,
                            line_number=0,
                            message=f"Error parsing API specification: {e!s}",
                            severity=CodeSeverity.WARNING,
                            code_snippet=f"Exception: {e!s}",
                        )
                    )

            return findings

        except Exception as e:
            # Return the error as a finding
            findings.append(
                PHIFinding(
                    file_path=api_spec_file if api_spec_file else "unknown",
                    line_number=0,
                    message=f"Error scanning API specification: {e!s}",
                    severity=CodeSeverity.WARNING,
                    code_snippet=f"Exception: {e!s}",
                )
            )
            return findings

    def audit_code(
        self, directory_path: str, exclude_dirs: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Perform a comprehensive PHI audit of code in a directory.

        Args:
            directory_path: Path to directory to audit
            exclude_dirs: List of directory names to exclude

        Returns:
            Audit results including findings and summary
        """
        exclude_dirs = exclude_dirs or []

        # Analyze all code in directory
        findings = self.analyze_directory(directory_path, exclude_dirs)

        # Organize findings by file and severity
        files_with_findings = set()
        findings_by_severity = {"critical": 0, "warning": 0, "info": 0}

        for finding in findings:
            files_with_findings.add(finding.file_path)
            findings_by_severity[finding.severity.value] += 1

        # Create summary
        summary = {
            "total_findings": len(findings),
            "files_with_phi": len(files_with_findings),
            "findings_by_severity": findings_by_severity,
        }

        # Return results
        return {
            "status": "completed",
            "findings": [finding.to_dict() for finding in findings],
            "summary": summary,
        }

    def audit_configuration(self, directory_path: str) -> dict[str, Any]:
        """
        Audit configuration files for sensitive information.

        Args:
            directory_path: Path to directory containing config files

        Returns:
            Audit results with findings and summary
        """
        dir_path = Path(directory_path)
        findings = []

        # Find all configuration files
        config_extensions = (".json", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".env")
        config_files = []

        for ext in config_extensions:
            config_files.extend(dir_path.glob(f"**/*{ext}"))

        # Analyze each config file
        for config_file in config_files:
            file_findings = self.analyze_config_file(str(config_file))
            findings.extend(file_findings)

        # Create summary
        files_with_findings = {finding.file_path for finding in findings}
        findings_by_severity = {"critical": 0, "warning": 0, "info": 0}

        for finding in findings:
            findings_by_severity[finding.severity.value] += 1

        summary = {
            "total_findings": len(findings),
            "files_with_issues": len(files_with_findings),
            "findings_by_severity": findings_by_severity,
        }

        # Return results
        return {
            "status": "completed",
            "findings": [finding.to_dict() for finding in findings],
            "summary": summary,
        }
