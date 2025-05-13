"""
PHI code analysis for HIPAA compliance.

This module provides analysis of code patterns to detect potential PHI leakage,
using the consolidated PHI sanitization components.
"""

import ast
import os
import re
import yaml
import json
import configparser
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Set, Tuple

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
    
    # PHI patterns that should not appear in code
    PHI_PATTERNS = [
        # SSN patterns
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN format
        r'\bSSN\s*[:=]\s*["\']?\d{3}-\d{2}-\d{4}["\']?',  # SSN with label
        
        # Email patterns
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email address
        
        # Phone patterns
        r'\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Phone number
        
        # Date of birth
        r'\b(0[1-9]|1[0-2])[/-](0[1-9]|[12][0-9]|3[01])[/-](19|20)\d{2}\b',  # MM/DD/YYYY
        r'\b(19|20)\d{2}[/-](0[1-9]|1[0-2])[/-](0[1-9]|[12][0-9]|3[01])\b',  # YYYY/MM/DD
        
        # Address patterns
        r'\b\d+\s+[A-Za-z0-9\s,]+(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Ln|Rd|Blvd|Dr|St)\.?\b',
        
        # Credit card patterns 
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
    ]
    
    # Suspicious variable names that might contain PHI
    PHI_VARIABLE_NAMES = [
        'ssn', 'social_security', 'social', 'dob', 'birth_date', 'birth', 
        'address', 'phone', 'phone_number', 'email', 'patient_id', 
        'medical_record_number', 'mrn', 'patient_name', 'full_name',
        'first_name', 'last_name', 'credit_card', 'cc_number', 'credit',
        'license', 'drivers_license', 'dl_number', 'passport'
    ]
    
    # Config keys and patterns that might contain sensitive data
    SENSITIVE_CONFIG_PATTERNS = [
        'password', 'secret', 'key', 'token', 'auth', 'credential', 'ssn', 
        'social', 'birth', 'dob', 'credit', 'connection_string', 'connection', 
        'pw', 'connect'
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
        
        # Add the PHI patterns from the class constant
        for pattern in self.PHI_PATTERNS:
            self.patterns.append(
                (pattern, "Direct PHI found in code", CodeSeverity.CRITICAL)
            )
    
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
                
            with path_obj.open(encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            # Basic pattern matching on each line
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
            
            # If it's a Python file, also do deeper AST analysis
            if path_obj.suffix.lower() == '.py':
                try:
                    ast_findings = self.analyze_ast(content, file_path)
                    # Add findings that aren't duplicates
                    existing_lines = {(f.file_path, f.line_number) for f in findings}
                    for finding in ast_findings:
                        if (finding.file_path, finding.line_number) not in existing_lines:
                            findings.append(finding)
                except SyntaxError:
                    # If AST parsing fails, just continue with pattern-based findings
                    findings.append(PHIFinding(
                        file_path=file_path,
                        line_number=0,
                        code_snippet="",
                        message="Failed to parse Python code for AST analysis",
                        severity=CodeSeverity.INFO
                    ))
            
            # If it's a config file, do special config analysis
            elif path_obj.suffix.lower() in ('.json', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.config', '.env'):
                try:
                    config_findings = self.analyze_config_file(file_path)
                    findings.extend(config_findings)
                except Exception as e:
                    findings.append(PHIFinding(
                        file_path=file_path,
                        line_number=0,
                        code_snippet="",
                        message=f"Failed to parse config file: {e!s}",
                        severity=CodeSeverity.INFO
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
            # Check if the directory name or any parent directory name is in exclude_set
            dirs[:] = [d for d in dirs if d not in exclude_set and 
                      not any(excluded in Path(os.path.join(root, d)).parts 
                              for excluded in exclude_set)]
            
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".json", 
                                 ".yaml", ".yml", ".ini", ".cfg", ".conf")):
                    file_path = Path(root) / file
                    
                    # Skip files in excluded directories
                    if any(excluded in file_path.parts for excluded in exclude_set):
                        continue
                        
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
            code: Python code to analyze
            file_path: File path for reporting
            
        Returns:
            List of PHI findings discovered through AST analysis
        """
        findings = []
        
        try:
            tree = ast.parse(code)
            
            class PHIVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.findings = []
                    self.current_line = 0
                
                def visit_Call(self, node):
                    # Check function calls for logging and prints
                    self.current_line = node.lineno
                    
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ('debug', 'info', 'warning', 'error', 'critical'):
                            # This might be a logging call
                            self.findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=ast.get_source_segment(code, node),
                                message="Potential PHI in logging call",
                                severity=CodeSeverity.WARNING
                            ))
                    elif isinstance(node.func, ast.Name) and node.func.id == 'print':
                        # This is a print call
                        self.findings.append(PHIFinding(
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=ast.get_source_segment(code, node),
                            message="Potential PHI in print statement",
                            severity=CodeSeverity.INFO
                        ))
                    
                    # Continue visiting children
                    self.generic_visit(node)
                
                def visit_Name(self, node):
                    # Check variable names for potential PHI indicators
                    self.current_line = getattr(node, 'lineno', self.current_line)
                    var_name = node.id.lower()
                    
                    for phi_var in PHICodeAnalyzer.PHI_VARIABLE_NAMES:
                        if phi_var in var_name:
                            # Variable name suggests PHI
                            self.findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=self.current_line,
                                code_snippet=var_name,
                                message=f"Variable name suggests PHI: {var_name}",
                                severity=CodeSeverity.INFO
                            ))
                            break
                    
                    # Continue visiting children
                    self.generic_visit(node)
                
                def visit_Str(self, node):
                    # Check string literals for PHI patterns
                    self.current_line = getattr(node, 'lineno', self.current_line)
                    
                    for pattern in PHICodeAnalyzer.PHI_PATTERNS:
                        if re.search(pattern, node.s):
                            # String literal contains PHI pattern
                            self.findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=self.current_line,
                                code_snippet=f'"{node.s[:20]}..."' if len(node.s) > 20 else f'"{node.s}"',
                                message="String literal contains PHI pattern",
                                severity=CodeSeverity.CRITICAL
                            ))
                            break
                    
                    # Continue visiting children
                    self.generic_visit(node)
            
            visitor = PHIVisitor()
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
            
            if extension in ('.json'):
                with path.open('r', encoding='utf-8') as f:
                    config_data = json.load(f)
                self._check_config_dict(config_data, file_path, findings)
                
            elif extension in ('.yaml', '.yml'):
                with path.open('r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)
                self._check_config_dict(config_data, file_path, findings)
                
            elif extension in ('.ini', '.cfg', '.conf'):
                config = configparser.ConfigParser()
                config.read(file_path)
                
                # Convert to dict for consistent processing
                config_dict = {}
                for section in config.sections():
                    config_dict[section] = dict(config[section])
                self._check_config_dict(config_dict, file_path, findings)
                
            else:
                # For unknown formats, just check line by line
                with path.open('r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for i, line in enumerate(lines, 1):
                    # Check for key-value patterns
                    kv_match = re.search(r'([A-Za-z0-9_]+)\s*[=:]\s*["\'`]?(.*?)["\'`]?\s*(?:#|$)', line)
                    if kv_match:
                        key, value = kv_match.groups()
                        if self._is_sensitive_key(key) and value.strip():
                            findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=i,
                                code_snippet=line.strip(),
                                message=f"Sensitive configuration key: {key}",
                                severity=CodeSeverity.WARNING
                            ))
                        
                    # Also check for PHI patterns
                    for pattern in self.PHI_PATTERNS:
                        if re.search(pattern, line):
                            findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=i,
                                code_snippet=line.strip(),
                                message="Configuration contains PHI pattern",
                                severity=CodeSeverity.CRITICAL
                            ))
                            break
        
        except Exception as e:
            findings.append(PHIFinding(
                file_path=file_path,
                line_number=0,
                code_snippet="",
                message=f"Error analyzing config file: {e!s}",
                severity=CodeSeverity.INFO
            ))
        
        return findings
    
    def _check_config_dict(self, config: Dict, file_path: str, findings: List[PHIFinding], path: str = "", line: int = 0):
        """Recursively check a configuration dictionary for sensitive data."""
        if isinstance(config, dict):
            for key, value in config.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if this key is sensitive
                if self._is_sensitive_key(key) and value:
                    findings.append(PHIFinding(
                        file_path=file_path,
                        line_number=line,  # We don't know exact line in parsed configs
                        code_snippet=f"{current_path} = {value}",
                        message=f"Sensitive configuration key: {current_path}",
                        severity=CodeSeverity.WARNING
                    ))
                
                # Recurse into nested dictionaries
                if isinstance(value, (dict, list)):
                    self._check_config_dict(value, file_path, findings, current_path, line)
                    
                # Check string values for PHI patterns
                elif isinstance(value, str):
                    for pattern in self.PHI_PATTERNS:
                        if re.search(pattern, value):
                            findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=line,
                                code_snippet=f"{current_path} = {value[:20]}..." if len(value) > 20 else f"{current_path} = {value}",
                                message=f"Configuration value contains PHI pattern: {current_path}",
                                severity=CodeSeverity.CRITICAL
                            ))
                            break
        
        elif isinstance(config, list):
            for i, item in enumerate(config):
                current_path = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    self._check_config_dict(item, file_path, findings, current_path, line)
                elif isinstance(item, str):
                    for pattern in self.PHI_PATTERNS:
                        if re.search(pattern, item):
                            findings.append(PHIFinding(
                                file_path=file_path,
                                line_number=line,
                                code_snippet=f"{current_path} = {item[:20]}..." if len(item) > 20 else f"{current_path} = {item}",
                                message=f"Configuration array contains PHI pattern: {current_path}",
                                severity=CodeSeverity.CRITICAL
                            ))
                            break
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a configuration key name suggests sensitive data."""
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in self.SENSITIVE_CONFIG_PATTERNS)
    
    def audit_api_endpoints(self, api_spec_file: Optional[str] = None) -> list[PHIFinding]:
        """
        Audit API endpoints for potential PHI exposure.
        
        Args:
            api_spec_file: Optional path to OpenAPI specification file
            
        Returns:
            List of PHI findings in API endpoints
        """
        findings = []
        
        if not api_spec_file:
            return findings
            
        try:
            path = Path(api_spec_file)
            
            if not path.exists():
                return findings
                
            # Parse OpenAPI spec based on file extension
            if path.suffix.lower() in ('.yaml', '.yml'):
                with path.open('r', encoding='utf-8') as f:
                    spec = yaml.safe_load(f)
            elif path.suffix.lower() == '.json':
                with path.open('r', encoding='utf-8') as f:
                    spec = json.load(f)
            else:
                findings.append(PHIFinding(
                    file_path=api_spec_file,
                    line_number=0,
                    code_snippet="",
                    message="Unsupported API spec format. Expected YAML or JSON.",
                    severity=CodeSeverity.INFO
                ))
                return findings
            
            # Check paths and schemas for PHI
            if 'paths' in spec:
                for path, path_item in spec['paths'].items():
                    # Check if path contains PHI indicators
                    for phi_var in self.PHI_VARIABLE_NAMES:
                        if phi_var in path.lower():
                            findings.append(PHIFinding(
                                file_path=api_spec_file,
                                line_number=0,  # Line number unknown from parsed spec
                                code_snippet=path,
                                message=f"API path contains PHI identifier: {phi_var}",
                                severity=CodeSeverity.WARNING
                            ))
                    
                    # Check operations (GET, POST, etc.)
                    for op_name, operation in path_item.items():
                        if op_name in ('get', 'post', 'put', 'delete', 'patch'):
                            # Check if operation returns PHI in response
                            if 'responses' in operation:
                                for status, response in operation['responses'].items():
                                    if 'content' in response:
                                        for content_type, content_schema in response['content'].items():
                                            if 'schema' in content_schema:
                                                self._check_schema_for_phi(
                                                    content_schema['schema'], 
                                                    api_spec_file, 
                                                    findings, 
                                                    f"{path} - {op_name} response"
                                                )
            
            # Check components/schemas for PHI
            if 'components' in spec and 'schemas' in spec['components']:
                for schema_name, schema in spec['components']['schemas'].items():
                    self._check_schema_for_phi(
                        schema, 
                        api_spec_file, 
                        findings, 
                        f"components/schemas/{schema_name}"
                    )
            
        except Exception as e:
            findings.append(PHIFinding(
                file_path=api_spec_file,
                line_number=0,
                code_snippet="",
                message=f"Error analyzing API spec: {e!s}",
                severity=CodeSeverity.INFO
            ))
        
        return findings
    
    def _check_schema_for_phi(self, schema: Dict, file_path: str, findings: List[PHIFinding], context: str):
        """Check OpenAPI schema for PHI indicators."""
        if 'properties' in schema:
            for prop_name, prop_schema in schema['properties'].items():
                # Check property name for PHI indicators
                for phi_var in self.PHI_VARIABLE_NAMES:
                    if phi_var in prop_name.lower():
                        severity = CodeSeverity.HIGH if phi_var in ('ssn', 'social_security', 'medical_record_number') else CodeSeverity.WARNING
                        findings.append(PHIFinding(
                            file_path=file_path,
                            line_number=0,  # Line number unknown from parsed spec
                            code_snippet=f"{context}.{prop_name}",
                            message=f"API schema property suggests PHI: {prop_name}",
                            severity=severity
                        ))
                
                # Recurse into nested objects
                if 'properties' in prop_schema:
                    self._check_schema_for_phi(
                        prop_schema, 
                        file_path, 
                        findings, 
                        f"{context}.{prop_name}"
                    )
                elif prop_schema.get('type') == 'array' and 'items' in prop_schema:
                    if 'properties' in prop_schema['items']:
                        self._check_schema_for_phi(
                            prop_schema['items'], 
                            file_path, 
                            findings, 
                            f"{context}.{prop_name}[]"
                        )
    
    def audit_code(self, directory_path: str, exclude_dirs: Optional[List[str]] = None) -> Dict[str, Any]:
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
        findings_by_severity = {
            "critical": 0,
            "warning": 0,
            "info": 0
        }
        
        for finding in findings:
            files_with_findings.add(finding.file_path)
            findings_by_severity[finding.severity.value] += 1
        
        # Create summary
        summary = {
            "total_findings": len(findings),
            "files_with_phi": len(files_with_findings),
            "findings_by_severity": findings_by_severity
        }
        
        # Return results
        return {
            "status": "completed",
            "findings": [finding.to_dict() for finding in findings],
            "summary": summary
        }
    
    def audit_configuration(self, directory_path: str) -> Dict[str, Any]:
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
        config_extensions = ('.json', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.env')
        config_files = []
        
        for ext in config_extensions:
            config_files.extend(dir_path.glob(f"**/*{ext}"))
        
        # Analyze each config file
        for config_file in config_files:
            file_findings = self.analyze_config_file(str(config_file))
            findings.extend(file_findings)
        
        # Create summary
        files_with_findings = set(finding.file_path for finding in findings)
        findings_by_severity = {
            "critical": 0,
            "warning": 0,
            "info": 0
        }
        
        for finding in findings:
            findings_by_severity[finding.severity.value] += 1
        
        summary = {
            "total_findings": len(findings),
            "files_with_issues": len(files_with_findings),
            "findings_by_severity": findings_by_severity
        }
        
        # Return results
        return {
            "status": "completed",
            "findings": [finding.to_dict() for finding in findings],
            "summary": summary
        }
