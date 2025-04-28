"""
HIPAA-compliant source code analyzer to prevent PHI from being stored in source code.

This module provides utilities to scan source code files for potential PHI
and enforce policies to maintain HIPAA compliance across the codebase.
"""

import os
import re
import json
import logging
import pathlib
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Union

from .phi_service import PHIService, PHIType
from .patterns import PHI_PATTERNS

# Create a logger
logger = logging.getLogger(__name__)


class CodeSeverity(str, Enum):
    """Severity levels for PHI detected in code."""
    CRITICAL = "critical"  # Definite PHI that must be removed immediately
    HIGH = "high"          # Highly likely to be PHI, should be removed
    MEDIUM = "medium"      # May be PHI, should be reviewed
    LOW = "low"            # Low probability of being PHI, but flagged
    INFO = "info"          # Informational only


class PHICodeAnalyzer:
    """
    Analyzer to detect PHI in source code.
    
    This class provides methods to scan code files for PHI patterns and
    generate reports of potential PHI violations.
    """
    
    def __init__(self, phi_service: Optional[PHIService] = None):
        """
        Initialize the PHI code analyzer.
        
        Args:
            phi_service: Optional PHIService for PHI detection
        """
        self.phi_service = phi_service or PHIService()
        
        # File extensions to check, grouped by type
        self.code_extensions = {
            "python": [".py"],
            "javascript": [".js", ".jsx", ".ts", ".tsx"],
            "api": [".graphql", ".json", ".yaml", ".yml"],
            "config": [".ini", ".env", ".conf", ".cfg", ".config", ".toml"],
            "docs": [".md", ".txt", ".rst"],
            "templates": [".html", ".jinja", ".jinja2"],
            "data": [".csv", ".json", ".jsonl", ".xml"]
        }
        
        # Specific patterns for code files
        # These are in addition to regular PHI patterns
        self.code_patterns = {
            # Password/credentials in code (high severity)
            "hardcoded_password": (
                r"(?:password|passwd|pwd)\s*=\s*['\"]([^'\"]{8,})['\"]",
                CodeSeverity.HIGH
            ),
            # API keys in code (high severity)
            "api_key": (
                r"(?:api_?key|auth_?token|access_?token|secret)\s*=\s*['\"]([A-Za-z0-9_\-\.=]{8,})['\"]",
                CodeSeverity.HIGH
            ),
            # Database connection strings (high severity)
            "connection_string": (
                r"(?:(?:mongodb|postgresql|mysql|redis|jdbc|sqlalchemy|odbc|oracle|sql_server):(?:\\/\\/|@)(?:[^:]+:[^@]+@)?[\\w\\.-]+(?::[0-9]+)?(?:\\/[\\w\\.-]+)?)",
                CodeSeverity.HIGH
            ),
            # IP addresses (medium severity)
            "ip_address": (
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                CodeSeverity.MEDIUM
            ),
            # Patient identifiers in tests (medium severity)
            "test_patient_id": (
                r"(?i)(?:test_patient_id|patient_id|patient_uuid|patient-id|patientid)\\s*[=:]\\s*['\"]([^'\"]+)['\"]",
                CodeSeverity.MEDIUM
            ),
            # URLs with credentials (high severity)
            "url_with_credentials": (
                r"https?://[^:]+:[^@]+@[^/]+",
                CodeSeverity.HIGH
            ),
            # AWS access keys (high severity)
            "aws_access_key": (
                r"(?:AKIA[0-9A-Z]{16})",
                CodeSeverity.HIGH
            ),
            # Comments that may indicate PHI (medium severity)
            "phi_comment": (
                r"(?i)(?:#|\/\/|\/\*|--)\s*(?:TODO|FIXME|HACK|NOTE|WARNING).*?(?:phi|hipaa|patient|pii|ssn|social security|record)",
                CodeSeverity.MEDIUM
            )
        }
        
        # Paths to exclude from scanning
        self.default_exclude_paths = [
            "venv", ".venv", ".git", "node_modules", "__pycache__",
            "dist", "build", "*.egg-info", ".pytest_cache", ".coverage",
            "htmlcov", ".DS_Store"
        ]
        
        # Initialize patterns for code analysis
        self._initialize_patterns()
        
    def _initialize_patterns(self) -> None:
        """Initialize and compile regex patterns for code analysis."""
        # Compile standard PHI patterns
        self.compiled_phi_patterns = {}
        for phi_type, pattern in PHI_PATTERNS.items():
            self.compiled_phi_patterns[phi_type] = re.compile(pattern, re.IGNORECASE)
            
        # Compile code-specific patterns
        self.compiled_code_patterns = {}
        for pattern_name, (pattern, _) in self.code_patterns.items():
            self.compiled_code_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE)
            
    def is_excluded(self, path: str, exclude_paths: Optional[List[str]] = None) -> bool:
        """
        Check if a path should be excluded from analysis.
        
        Args:
            path: Path to check
            exclude_paths: Optional list of paths to exclude
            
        Returns:
            True if path should be excluded, False otherwise
        """
        exclude_paths = exclude_paths or self.default_exclude_paths
        
        # Convert path to absolute and normalize
        abs_path = os.path.abspath(path)
        
        # Check if path is in excluded paths
        for exclude in exclude_paths:
            # Handle glob patterns
            if "*" in exclude:
                if pathlib.Path(abs_path).match(exclude):
                    return True
            # Handle directory/file name matches
            elif exclude in abs_path.split(os.sep):
                return True
                
        return False
        
    def get_file_type(self, file_path: str) -> Optional[str]:
        """
        Get the type of a file based on its extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File type or None if not recognized
        """
        ext = os.path.splitext(file_path)[1].lower()
        for file_type, extensions in self.code_extensions.items():
            if ext in extensions:
                return file_type
        return None
        
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file for PHI patterns.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with scan results
        """
        if not os.path.exists(file_path) or self.is_excluded(file_path):
            return {
                "file_path": file_path,
                "status": "skipped",
                "reason": "File excluded or does not exist",
                "findings": []
            }
            
        file_type = self.get_file_type(file_path)
        if not file_type:
            return {
                "file_path": file_path,
                "status": "skipped",
                "reason": "Unsupported file type",
                "findings": []
            }
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return {
                "file_path": file_path,
                "status": "error",
                "reason": f"Error reading file: {str(e)}",
                "findings": []
            }
            
        findings = []
        
        # Check for standard PHI patterns
        for phi_type, pattern in self.compiled_phi_patterns.items():
            for match in pattern.finditer(content):
                findings.append({
                    "pattern_type": "phi",
                    "pattern_name": phi_type,
                    "severity": CodeSeverity.CRITICAL,
                    "line_content": self._get_line_content(content, match.start()),
                    "line_number": content.count('\n', 0, match.start()) + 1,
                    "match": match.group(0)
                })
                
        # Check for code-specific patterns
        for pattern_name, pattern in self.compiled_code_patterns.items():
            severity = self.code_patterns[pattern_name][1]
            for match in pattern.finditer(content):
                findings.append({
                    "pattern_type": "code",
                    "pattern_name": pattern_name,
                    "severity": severity,
                    "line_content": self._get_line_content(content, match.start()),
                    "line_number": content.count('\n', 0, match.start()) + 1,
                    "match": match.group(0)
                })
                
        return {
            "file_path": file_path,
            "file_type": file_type,
            "status": "scanned",
            "findings": findings,
            "has_phi": len(findings) > 0
        }
        
    def _get_line_content(self, content: str, match_pos: int) -> str:
        """
        Get the line content for a match position.
        
        Args:
            content: File content
            match_pos: Position of the match
            
        Returns:
            Line content containing the match
        """
        line_start = content.rfind('\n', 0, match_pos) + 1
        line_end = content.find('\n', match_pos)
        if line_end == -1:
            line_end = len(content)
            
        line_content = content[line_start:line_end]
        # Truncate line if too long
        if len(line_content) > 150:
            match_relative_pos = match_pos - line_start
            start_pos = max(0, match_relative_pos - 50)
            end_pos = min(len(line_content), match_relative_pos + 50)
            line_content = f"...{line_content[start_pos:end_pos]}..."
            
        return line_content
    
    def scan_directory(
        self, 
        directory_path: str, 
        exclude_paths: Optional[List[str]] = None, 
        recursive: bool = True,
        file_extensions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Scan a directory for PHI patterns.
        
        Args:
            directory_path: Path to the directory to scan
            exclude_paths: Optional list of paths to exclude
            recursive: Whether to scan subdirectories
            file_extensions: Optional list of file extensions to scan
            
        Returns:
            Dictionary with scan results
        """
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            return {
                "directory_path": directory_path,
                "status": "error",
                "reason": "Directory does not exist or is not a directory",
                "files_scanned": 0,
                "results": []
            }
            
        exclude_paths = exclude_paths or self.default_exclude_paths
        
        if file_extensions:
            extensions_to_scan = file_extensions
        else:
            # Flatten list of extensions
            extensions_to_scan = []
            for ext_list in self.code_extensions.values():
                extensions_to_scan.extend(ext_list)
                
        results = []
        files_scanned = 0
        
        for root, dirs, files in os.walk(directory_path):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not self.is_excluded(os.path.join(root, d), exclude_paths)]
            
            # If not recursive, clear dirs list to prevent descending into subdirectories
            if not recursive:
                dirs.clear()
                
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip excluded files
                if self.is_excluded(file_path, exclude_paths):
                    continue
                    
                # Check file extension
                ext = os.path.splitext(file)[1].lower()
                if ext not in extensions_to_scan:
                    continue
                    
                result = self.scan_file(file_path)
                files_scanned += 1
                
                # Only include files with findings to reduce result size
                if result["status"] == "scanned" and result["has_phi"]:
                    results.append(result)
                    
        return {
            "directory_path": directory_path,
            "status": "completed",
            "files_scanned": files_scanned,
            "files_with_phi": len(results),
            "results": results
        }
        
    def audit_code_for_phi(
        self,
        target_path: str,
        exclude_paths: Optional[List[str]] = None,
        recursive: bool = True,
        file_extensions: Optional[List[str]] = None,
        include_all_files: bool = False,
        output_format: str = "dict"
    ) -> Union[Dict[str, Any], str]:
        """
        Audit code for PHI patterns.
        
        Args:
            target_path: Path to scan (file or directory)
            exclude_paths: Optional list of paths to exclude
            recursive: Whether to scan subdirectories
            file_extensions: Optional list of file extensions to scan
            include_all_files: Whether to include files without findings
            output_format: Format for the output ('dict' or 'json')
            
        Returns:
            Dictionary with audit results or JSON string
        """
        if os.path.isdir(target_path):
            results = self.scan_directory(
                target_path,
                exclude_paths=exclude_paths,
                recursive=recursive,
                file_extensions=file_extensions
            )
        else:
            # If it's a file, just scan it
            results = self.scan_file(target_path)
            
        # Add summary for directories
        if "results" in results:
            total_findings = sum(len(r["findings"]) for r in results["results"])
            findings_by_severity = {sev.value: 0 for sev in CodeSeverity}
            
            for result in results["results"]:
                for finding in result["findings"]:
                    severity = finding["severity"]
                    if isinstance(severity, CodeSeverity):
                        sev_value = severity.value
                    else:
                        sev_value = severity
                    findings_by_severity[sev_value] = findings_by_severity.get(sev_value, 0) + 1
                    
            results["summary"] = {
                "total_findings": total_findings,
                "by_severity": findings_by_severity
            }
            
        if output_format == "json":
            return json.dumps(results, indent=2, default=str)
        return results
        
    def audit_api_endpoints(
        self,
        app_directory: str,
        exclude_paths: Optional[List[str]] = None,
        file_patterns: Optional[List[str]] = None,
        output_format: str = "dict"
    ) -> Union[Dict[str, Any], str]:
        """
        Audit API endpoints for potential PHI exposure.
        
        Args:
            app_directory: Path to the application directory
            exclude_paths: Optional list of paths to exclude
            file_patterns: Optional list of file patterns to match endpoint files
            output_format: Format for the output ('dict' or 'json')
            
        Returns:
            Dictionary with audit results or JSON string
        """
        exclude_paths = exclude_paths or self.default_exclude_paths
        file_patterns = file_patterns or ["routes.py", "endpoints.py", "api.py", "views.py"]
        
        # Find all API endpoint files
        api_files = []
        for root, _, files in os.walk(app_directory):
            # Skip excluded paths
            if self.is_excluded(root, exclude_paths):
                continue
                
            for file in files:
                if file.endswith(".py") and any(pattern in file for pattern in file_patterns):
                    api_files.append(os.path.join(root, file))
                    
        results = {
            "app_directory": app_directory,
            "api_files_found": len(api_files),
            "api_files": [],
            "phi_exposure_risks": []
        }
        
        for api_file in api_files:
            file_result = self.scan_file(api_file)
            
            # Look for patterns specific to API endpoints
            try:
                with open(api_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                endpoint_patterns = [
                    # Path parameters that might contain PHI
                    (r"@(?:app|router)\.(?:get|post|put|delete|patch)\([\'\"](?:[^\'\"]*\/\{([^}]+)\}[^\'\"]*)+[\'\"]", "path_parameter"),
                    # Query parameters that might contain PHI
                    (r"(?:Query|QueryParam)\([\'\"]([^\'\"]+)[\'\"]\)", "query_parameter"),
                    # Response fields that might contain PHI
                    (r"return\s+(?:jsonify|JSONResponse)\((?:\{[^\}]*\}|[^\)]*)\)", "response"),
                    # Database queries with potential PIDs
                    (r"(?:select|SELECT).*?(?:from|FROM).*?(?:where|WHERE).*?(?:id|patient|user|customer|client|record)", "database_query")
                ]
                
                for pattern, pattern_type in endpoint_patterns:
                    for match in re.finditer(pattern, content):
                        parameter_name = match.group(1) if match.lastindex else match.group(0)
                        if self._is_potential_phi_parameter(parameter_name):
                            results["phi_exposure_risks"].append({
                                "file_path": api_file,
                                "line_number": content.count('\n', 0, match.start()) + 1,
                                "pattern_type": pattern_type,
                                "parameter": parameter_name,
                                "line_content": self._get_line_content(content, match.start()),
                                "recommendation": self._get_recommendation_for_pattern(pattern_type)
                            })
            except Exception as e:
                logger.warning(f"Error analyzing API endpoints in {api_file}: {str(e)}")
                
            results["api_files"].append({
                "file_path": api_file,
                "findings": file_result.get("findings", [])
            })
            
        if output_format == "json":
            return json.dumps(results, indent=2, default=str)
        return results
        
    def _is_potential_phi_parameter(self, parameter_name: str) -> bool:
        """
        Check if a parameter name could potentially contain PHI.
        
        Args:
            parameter_name: Parameter name to check
            
        Returns:
            True if parameter might contain PHI, False otherwise
        """
        phi_related_terms = [
            "patient", "user", "name", "email", "phone", "address", "dob", "birth", 
            "ssn", "record", "id", "identifier", "mrn", "encounter", "visit", 
            "admission", "medical", "health", "diagnosis", "treatment"
        ]
        
        parameter_lower = parameter_name.lower()
        return any(term in parameter_lower for term in phi_related_terms)
        
    def _get_recommendation_for_pattern(self, pattern_type: str) -> str:
        """
        Get a recommendation for a pattern type.
        
        Args:
            pattern_type: Type of pattern
            
        Returns:
            Recommendation for how to fix the issue
        """
        recommendations = {
            "path_parameter": "Avoid using PHI in URL paths. Use opaque identifiers instead.",
            "query_parameter": "Ensure query parameters never contain PHI. Consider using POST instead of GET for sensitive data.",
            "response": "Audit response payloads to ensure PHI is properly sanitized before returning to clients.",
            "database_query": "Review query to ensure it doesn't expose PHI. Consider using parameterized queries."
        }
        
        return recommendations.get(pattern_type, "Review this code for potential PHI exposure.")
        
    def audit_configuration(
        self,
        app_directory: str,
        exclude_paths: Optional[List[str]] = None,
        config_file_patterns: Optional[List[str]] = None,
        output_format: str = "dict"
    ) -> Union[Dict[str, Any], str]:
        """
        Audit configuration files for potential PHI and security issues.
        
        Args:
            app_directory: Path to the application directory
            exclude_paths: Optional list of paths to exclude
            config_file_patterns: Optional list of file patterns to match config files
            output_format: Format for the output ('dict' or 'json')
            
        Returns:
            Dictionary with audit results or JSON string
        """
        exclude_paths = exclude_paths or self.default_exclude_paths
        config_file_patterns = config_file_patterns or [
            ".env", "config.py", "settings.py", ".ini", ".yaml", ".yml", 
            ".json", ".toml", ".conf", ".cfg", "config.js", "config.ts"
        ]
        
        # Find all configuration files
        config_files = []
        for root, _, files in os.walk(app_directory):
            # Skip excluded paths
            if self.is_excluded(root, exclude_paths):
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                is_config = any(file.endswith(pattern) for pattern in config_file_patterns if not pattern.startswith(".")) or \
                           any(pattern in file for pattern in config_file_patterns if pattern.startswith("."))
                           
                if is_config:
                    config_files.append(file_path)
                    
        results = {
            "app_directory": app_directory,
            "config_files_found": len(config_files),
            "config_files": [],
            "security_classifications": {}
        }
        
        security_findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for config_file in config_files:
            file_result = self.scan_file(config_file)
            
            # Analyze security settings
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check for specific security settings
                security_settings = [
                    # Critical security settings
                    (r"(?i)(?:DEBUG|DEVELOPMENT|DEV_MODE|TESTING)\s*=\s*(?:True|TRUE|1|yes|Y)", "debug_enabled", CodeSeverity.HIGH),
                    (r"(?i)(?:ALLOW_ALL_ORIGINS|CORS_ALLOW_ALL|CORS_ORIGIN_ALLOW_ALL)\s*=\s*(?:True|TRUE|1|yes|Y)", "cors_all_allowed", CodeSeverity.HIGH),
                    # Insecure settings
                    (r"(?i)(?:SECURE_SSL|REQUIRE_SSL|SSL_REQUIRED|HTTPS_ONLY)\s*=\s*(?:False|FALSE|0|no|N)", "ssl_disabled", CodeSeverity.CRITICAL),
                    (r"(?i)(?:ALLOWED_HOSTS|CORS_ORIGIN_WHITELIST|CORS_ALLOWED_ORIGINS).*?[\"\']\*[\"\']", "wildcard_origin", CodeSeverity.HIGH),
                    # Session security
                    (r"(?i)(?:SESSION_EXPIRE|SESSION_TIMEOUT|EXPIRY|TIMEOUT).*?(?:0|none|never|False|disabled)", "no_session_timeout", CodeSeverity.HIGH),
                    # Encryption keys
                    (r"(?i)(?:ENCRYPTION_KEY|SECRET_KEY|DJANGO_SECRET|FLASK_SECRET).*?[\"\']((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)[\"\']", "hardcoded_secret", CodeSeverity.CRITICAL),
                    # Database credentials
                    (r"(?i)(?:DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD).*?[\"\']([^\"\']+)[\"\']", "db_password", CodeSeverity.CRITICAL),
                    # API keys/tokens
                    (r"(?i)(?:API_KEY|TOKEN|AUTH_KEY|ACCESS_KEY).*?[\"\']([^\"\']+)[\"\']", "api_credential", CodeSeverity.HIGH),
                    # Audit logging
                    (r"(?i)(?:AUDIT_LOG|AUDIT_LOGGING|ENABLE_AUDIT|HIPAA_LOGGING)\s*=\s*(?:False|FALSE|0|no|N|disabled)", "audit_disabled", CodeSeverity.HIGH),
                    # PHI protection
                    (r"(?i)(?:SANITIZE_PHI|REDACT_PHI|PROTECT_PHI|ENCRYPT_PHI)\s*=\s*(?:False|FALSE|0|no|N|disabled)", "phi_protection_disabled", CodeSeverity.CRITICAL)
                ]
                
                for pattern, setting_type, severity in security_settings:
                    for match in re.finditer(pattern, content):
                        setting_value = match.group(1) if match.lastindex else match.group(0)
                        finding = {
                            "file_path": config_file,
                            "line_number": content.count('\n', 0, match.start()) + 1,
                            "setting_type": setting_type,
                            "setting_value": setting_value,
                            "line_content": self._get_line_content(content, match.start()),
                            "recommendation": self._get_security_recommendation(setting_type)
                        }
                        
                        if severity == CodeSeverity.CRITICAL:
                            security_findings["critical"].append(finding)
                        elif severity == CodeSeverity.HIGH:
                            security_findings["high"].append(finding)
                        elif severity == CodeSeverity.MEDIUM:
                            security_findings["medium"].append(finding)
                        else:
                            security_findings["low"].append(finding)
                
            except Exception as e:
                logger.warning(f"Error analyzing configuration in {config_file}: {str(e)}")
                
            results["config_files"].append({
                "file_path": config_file,
                "findings": file_result.get("findings", [])
            })
            
        results["security_classifications"] = security_findings
        
        if output_format == "json":
            return json.dumps(results, indent=2, default=str)
        return results
        
    def _get_security_recommendation(self, setting_type: str) -> str:
        """
        Get a security recommendation for a setting type.
        
        Args:
            setting_type: Type of security setting
            
        Returns:
            Recommendation for how to fix the issue
        """
        recommendations = {
            "debug_enabled": "Disable DEBUG mode in production. Debug mode can leak sensitive information.",
            "cors_all_allowed": "Restrict CORS to specific origins instead of allowing all origins.",
            "ssl_disabled": "Enable SSL/HTTPS for all traffic to ensure data in transit is encrypted.",
            "wildcard_origin": "Specify exact allowed origins instead of using wildcards.",
            "no_session_timeout": "Implement session timeouts to reduce risk from unattended sessions.",
            "hardcoded_secret": "Move secrets to environment variables or secure storage, not in code.",
            "db_password": "Store database credentials in environment variables or secure storage, not in code.",
            "api_credential": "Store API keys in environment variables or secure storage, not in code.",
            "audit_disabled": "Enable audit logging for HIPAA compliance.",
            "phi_protection_disabled": "Enable PHI protection features like sanitization and encryption."
        }
        
        return recommendations.get(setting_type, "Review this security setting for potential issues.")