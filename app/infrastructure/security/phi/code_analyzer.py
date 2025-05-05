"""
PHI code analysis for HIPAA compliance (compatibility stub).

This module provides analysis of code patterns to detect potential PHI leakage,
delegating to consolidated PHI sanitization components where appropriate.
"""

import ast
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any

from app.infrastructure.security.phi.sanitizer import PHISanitizer


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
    
    This stub implementation provides backward compatibility with tests
    while delegating to the consolidated PHI sanitization system.
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
            print(f"Warning: Directory not found: {directory_path}")
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
            List of PHI findings from AST analysis (currently basic).
        """
        findings: list[PHIFinding] = []
        try:
            tree = ast.parse(code, filename=file_path)  # noqa: F841 - tree will be used when AST traversal is implemented
            
            # TODO: Implement AST traversal logic here
            # Example: Use ast.NodeVisitor to walk the tree and check nodes
            # - Check function calls (e.g., logging, print)
            # - Check assignments (e.g., sensitive variable names)
            # - Check string constants for PHI patterns
            
            # Placeholder: Add an info finding that AST analysis is pending
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=0, # AST nodes have line numbers, use them in real impl
                code_snippet="<AST Analysis Pending>",
                message="AST analysis implementation is pending.",
                severity=CodeSeverity.INFO
            ))

        except SyntaxError as e:
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=e.lineno,
                code_snippet=e.text.strip() if e.text else "",
                message=f"Syntax error during AST parsing: {e.msg}",
                severity=CodeSeverity.WARNING # Changed from INFO as syntax errors are more severe
            ))
        except Exception as e:
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=0,
                code_snippet="",
                message=f"Unexpected error during AST analysis: {e!s}",
                severity=CodeSeverity.WARNING # Changed from INFO
            ))
            
        return findings

    def audit_api_endpoints(self) -> list[PHIFinding]:
        """Audits API endpoint definitions for potential PHI exposure.

        Note: This is a stub. Direct analysis of FastAPI endpoints from this
        infrastructure component violates Clean Architecture. The actual logic
        should reside in a higher-level component with access to the API router.

        Returns:
            An empty list (stub implementation).
        """
        # TODO: Implement API endpoint analysis in a higher-level component.
        # This component would need access to the FastAPI app or router.
        # Potential checks:
        # - Analyze path parameters for sensitive names (e.g., /patients/{patient_id})
        # - Analyze request/response Pydantic models for PHI fields.
        # - Check for missing authentication/authorization on sensitive routes.
        return [] # Stub implementation
