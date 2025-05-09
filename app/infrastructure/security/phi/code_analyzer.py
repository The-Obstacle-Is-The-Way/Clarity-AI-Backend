"""
PHI code analysis for HIPAA compliance.

This module provides analysis of code patterns to detect potential PHI leakage,
using the consolidated PHI sanitization components.
"""

import ast
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any

from app.infrastructure.security.phi.sanitizer import PHISanitizer, get_sanitized_logger

# Create a sanitized logger
logger = get_sanitized_logger(__name__)


class CodeSeverity(str, Enum):
    """Severity levels for PHI code findings."""
    CRITICAL = "critical"  # Definite PHI leak
    WARNING = "warning"    # Potential PHI leak
    INFO = "info"          # Informational finding


class PHIFinding:
    """Represents a potential PHI leak in code."""
    
    def __init__(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        message: str,
        severity: CodeSeverity
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
            "severity": self.severity.value
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
                CodeSeverity.WARNING
            ),
            # Print statements
            (r"print\(.*?\)", "Potential PHI in print statement", CodeSeverity.INFO),
            # Exception patterns
            (
                r"(?:raise|except)\s+\w+\(.*?\)", 
                "Potential PHI in exception message",
                CodeSeverity.WARNING
            ),
            # Common PHI variable names
            (
                r"\b(?:ssn|social_security|dob|birth_date|address|phone|email|patient_id|medical_record_number|mrn)\b", 
                "Variable name suggests PHI",
                CodeSeverity.INFO
            ),
            # URL paths with potential identifiers
            (
                r"@(?:app|router)\.(?:get|post|put|delete)\(['\"]/?.*?/?\{.*?\}['\"]", 
                "URL parameter may contain PHI",
                CodeSeverity.WARNING
            ),
            # Database queries
            (
                r"(?:execute|query|cursor\.execute)\(.*?\)", 
                "Database query might expose PHI",
                CodeSeverity.INFO
            ),
        ]
    
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
            with path_obj.open(encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            for i, line in enumerate(lines, 1):
                for pattern, message, severity in self.patterns:
                    if re.search(pattern, line):
                        findings.append(PHIFinding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            message=message,
                            severity=severity
                        ))
        except Exception as e:
            # Add error finding
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=0,
                code_snippet="",
                message=f"Error analyzing file: {e!s}",
                severity=CodeSeverity.INFO
            ))
        
        return findings
    
    def analyze_directory(
        self,
        directory_path: str,
        exclude_dirs: list[str] | None = None
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
            dirs[:] = [d for d in dirs if d not in exclude_set]
            
            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file
                    try:
                        file_findings = self.analyze_file(str(file_path))
                        all_findings.extend(file_findings)
                    except Exception as e:
                        # Add finding for file analysis error
                        all_findings.append(PHIFinding(
                            file_path=str(file_path),
                            line_number=0,
                            code_snippet="",
                            message=f"Error analyzing file: {e!s}",
                            severity=CodeSeverity.INFO
                        ))
        
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
                    findings.append(PHIFinding(
                        file_path=file_path,
                        line_number=i,
                        code_snippet=line.strip(),
                        message=message,
                        severity=severity
                    ))
        
        return findings
    
    def analyze_ast(self, code: str, file_path: str = "<string>") -> list[PHIFinding]:
        """
        Analyze abstract syntax tree for deeper PHI leak detection.
        
        Args:
            code: Code string to analyze
            file_path: Virtual file path for reporting
            
        Returns:
            List of PHI findings from AST analysis
        """
        findings: list[PHIFinding] = []
        try:
            tree = ast.parse(code, filename=file_path)
            
            # Implement AST visitor to find potential PHI leaks
            class PHIVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.findings = []
                    
                def visit_Call(self, node):
                    # Check function calls for logging and prints
                    if hasattr(node, 'func') and hasattr(node.func, 'attr'):
                        if node.func.attr in ('debug', 'info', 'warning', 'error', 'critical'):
                            # Check logging calls
                            self.findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=ast.unparse(node),
                                message="Potential PHI in log statement",
                                severity=CodeSeverity.WARNING
                            ))
                    self.generic_visit(node)
                    
                def visit_Name(self, node):
                    # Check variable names for potential PHI indicators
                    phi_indicators = ('ssn', 'dob', 'patient', 'address', 'phone', 'email', 'mrn')
                    if any(indicator in node.id.lower() for indicator in phi_indicators):
                        self.findings.append(PHIFinding(
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=node.id,
                            message="Variable name suggests PHI",
                            severity=CodeSeverity.INFO
                        ))
                    self.generic_visit(node)
            
            # Run the visitor
            visitor = PHIVisitor()
            visitor.visit(tree)
            findings.extend(visitor.findings)

        except SyntaxError as e:
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=e.lineno,
                code_snippet=e.text.strip() if e.text else "",
                message=f"Syntax error during AST parsing: {e.msg}",
                severity=CodeSeverity.WARNING
            ))
        except Exception as e:
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=0,
                code_snippet="",
                message=f"Unexpected error during AST analysis: {e!s}",
                severity=CodeSeverity.WARNING
            ))
            
        return findings

    def audit_api_endpoints(self, app=None) -> list[PHIFinding]:
        """
        Audits API endpoint definitions for potential PHI exposure.

        Args:
            app: Optional FastAPI application to analyze. If not provided,
                 this function will return an empty list.

        Returns:
            List of PHI findings in API endpoints.
        """
        findings = []
        
        if app is None:
            logger.warning("No FastAPI app provided for endpoint analysis")
            return []
            
        try:
            # Analyze FastAPI routes if available
            if hasattr(app, 'routes'):
                for route in app.routes:
                    if hasattr(route, 'path') and hasattr(route, 'endpoint'):
                        path = route.path
                        
                        # Check for PHI in URL parameters
                        if '{' in path and '}' in path:
                            param_match = re.search(r'\{([^}]+)\}', path)
                            if param_match:
                                param_name = param_match.group(1)
                                if any(phi in param_name.lower() for phi in ('id', 'patient', 'user', 'name')):
                                    findings.append(PHIFinding(
                                        file_path="API Routes",
                                        line_number=0,
                                        code_snippet=path,
                                        message=f"URL parameter '{param_name}' may contain PHI",
                                        severity=CodeSeverity.WARNING
                                    ))
        except Exception as e:
            logger.error(f"Error auditing API endpoints: {e}")
            
        return findings
