"""
PHI code analysis for HIPAA compliance (compatibility stub).

This module provides analysis of code patterns to detect potential PHI leakage,
delegating to consolidated PHI sanitization components where appropriate.
"""

import re
from enum import Enum
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
    
    def __init__(self, sanitizer: PHISanitizer | None = None, phi_service=None):
        """
        Initialize the PHI code analyzer.
        
        Args:
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
            phi_service: Optional PHI service for backward compatibility (ignored in favor of sanitizer)
        """
        self.sanitizer = sanitizer or PHISanitizer()
        # Patterns for code analysis
        self.patterns = [
            # Logging patterns
            (r"(?:logger|logging)\.(debug|info|warning|error|critical)\(.*?\)", 
             "Potential PHI in log statement", CodeSeverity.WARNING),
            
            # Print statements
            (r"print\(.*?\)", 
             "Potential PHI in print statement", CodeSeverity.INFO),
            
            # Exception patterns
            (r"(?:raise|except)\s+\w+\(.*?\)", 
             "Potential PHI in exception message", CodeSeverity.WARNING),
            
            # Common PHI variable names
            (r"\b(?:ssn|social_security|dob|birth_date|address|phone|email|patient_id|medical_record_number|mrn)\b", 
             "Variable name suggests PHI", CodeSeverity.INFO),
            
            # URL paths with potential identifiers
            (r"@(?:app|router)\.(?:get|post|put|delete)\(['\"]/?.*?/?\{.*?\}['\"]", 
             "URL parameter may contain PHI", CodeSeverity.WARNING),
            
            # Database queries
            (r"(?:execute|query|cursor\.execute)\(.*?\)", 
             "Database query might expose PHI", CodeSeverity.INFO),
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
            with open(file_path, encoding='utf-8') as f:
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
    
    def analyze_directory(self, directory_path: str, exclude_dirs: list[str] | None = None) -> list[PHIFinding]:
        """
        Analyze all Python files in a directory for potential PHI leaks.
        
        Args:
            directory_path: Path to the directory to analyze
            exclude_dirs: Directories to exclude from analysis
            
        Returns:
            List of PHI findings in all files
        """
        # Stub implementation - in a real implementation, this would recursively
        # scan the directory and call analyze_file on each Python file
        return []
    
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
        # Stub implementation - in a real implementation, this would
        # parse the AST and look for patterns that might leak PHI
        return []
