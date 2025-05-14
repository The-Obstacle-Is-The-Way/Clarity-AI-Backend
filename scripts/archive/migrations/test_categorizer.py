#!/usr/bin/env python3
"""
Test Categorizer for Novamind Backend

This script analyzes test files to determine their dependency level:
- standalone: Tests requiring no external dependencies
- venv_only: Tests requiring Python packages but no external services
- db_required: Tests requiring database or other external services

It can automatically detect dependencies based on imports and code patterns,
and optionally update test files with the appropriate pytest markers.
"""

import argparse
import ast
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# Dependency categories
STANDALONE = "standalone"
VENV_ONLY = "venv_only"
DB_REQUIRED = "db_required"

# Import patterns to identify dependencies
DB_IMPORTS = [
    "sqlalchemy", "asyncpg", "databases", "alembic", "redis", "aiomysql",
    "motor", "odmantic", "beanie", "tortoise", "prisma", "psycopg", 
    "app.infrastructure.persistence.sqlalchemy", "app.core.dependencies.database", "app.db",
    "database", "repository", "unit_of_work", "datastore", "transaction"
]

EXTERNAL_SERVICE_IMPORTS = [
    "http", "aiohttp", "requests", "urllib", "boto", "aws", "s3", "sns", "sqs",
    "google", "firebase", "openai", "azure", "sendgrid", 
    "twilio", "stripe", "paypal", "cloudflare", "fastapi.testclient"
]

# Patterns to match in code (not just imports)
DB_PATTERNS = [
    r"session", r"connection", r"query", r"cursor",
    r"execute", r"commit", r"rollback", r"transaction", r"database"
]

EXTERNAL_SERVICE_PATTERNS = [
    r"request[s]?\.get", r"request[s]?\.post", r"http", r"url", r"endpoint",
    r"api", r"client", r"mock_response", r"patch\(.*\)", r"aws", r"s3", 
    r"dynamodb", r"async with .* as client", r"TestClient"
]


class TestDependencyAnalyzer:
    """Analyzes test files to determine their dependency requirements."""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
    
    def log(self, message: str) -> None:
        """Log a message if debug mode is enabled."""
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def analyze_imports(self, file_path: Path) -> Tuple[Set[str], Dict[str, List[str]]]:
        """
        Analyze imports in a Python file to determine dependency categories.
        
        Returns:
            Tuple of (dependency_categories, import_details)
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            tree = ast.parse(content)
            imports = set()
            from_imports = {}
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imports.add(name.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if module not in from_imports:
                        from_imports[module] = []
                    for name in node.names:
                        from_imports[module].append(name.name)
            
            categories = set()
            
            # Check regular imports
            for imp in imports:
                if any(db_import in imp.lower() for db_import in DB_IMPORTS):
                    categories.add(DB_REQUIRED)
                elif any(ext in imp.lower() for ext in EXTERNAL_SERVICE_IMPORTS):
                    categories.add(DB_REQUIRED)
            
            # Check from imports
            for module, names in from_imports.items():
                if any(db_import in module.lower() for db_import in DB_IMPORTS):
                    categories.add(DB_REQUIRED)
                elif any(ext in module.lower() for ext in EXTERNAL_SERVICE_IMPORTS):
                    categories.add(DB_REQUIRED)
            
            # If content contains specific patterns
            for pattern in DB_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    categories.add(DB_REQUIRED)
                    break
            
            for pattern in EXTERNAL_SERVICE_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    categories.add(DB_REQUIRED)
                    break
            
            # If no specific dependencies found, it's at least VENV_ONLY
            if not categories:
                categories.add(VENV_ONLY)
            
            # Now check if it could be standalone
            # If it only imports pytest, unittest, mock, or standard lib
            std_lib_patterns = [
                "pytest", "unittest", "mock", "json", "datetime", 
                "os", "sys", "time", "re", "math", "random",
                "app.domain.entities", "app.domain.value_objects", "app.domain.enums",
                "app.core.exceptions"
            ]
            
            only_std_lib = True
            
            for imp in imports:
                if not any(std in imp.lower() for std in std_lib_patterns):
                    only_std_lib = False
                    break
            
            for module, _ in from_imports.items():
                if not any(std in module.lower() for std in std_lib_patterns):
                    only_std_lib = False
                    break
            
            if only_std_lib and "app.tests.standalone" in str(file_path):
                categories = {STANDALONE}
            
            import_details = {"imports": list(imports), "from_imports": from_imports}
            return categories, import_details
        
        except Exception as e:
            print(f"Error analyzing {file_path}: {str(e)}")
            return {VENV_ONLY}, {}
    
    def get_existing_markers(self, file_path: Path) -> Set[str]:
        """Extract existing pytest markers from a file."""
        markers = set()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Look for @pytest.mark.* patterns
            marker_pattern = r"@pytest\.mark\.(\w+)"
            for match in re.finditer(marker_pattern, content):
                markers.add(match.group(1))
            
            return markers
        except Exception as e:
            print(f"Error getting markers from {file_path}: {str(e)}")
            return set()
    
    def update_test_file(self, file_path: Path, category: str) -> bool:
        """
        Update a test file with the appropriate pytest marker.
        
        Args:
            file_path: Path to the test file
            category: The dependency category to add
            
        Returns:
            bool: True if the file was updated, False otherwise
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Check for existing markers
            existing_markers = self.get_existing_markers(file_path)
            if category in existing_markers:
                self.log(f"Marker @pytest.mark.{category} already exists in {file_path}")
                return False
            
            # Find the appropriate import
            import_line = "import pytest"
            if "import pytest" not in content:
                # Add pytest import at the top
                content = f"{import_line}\n{content}"
            
            # Find the first class or function definition
            class_match = re.search(r"class\s+(\w+)", content)
            func_match = re.search(r"def\s+test_(\w+)", content)
            
            if class_match and (not func_match or class_match.start() < func_match.start()):
                # Insert marker before the class definition
                pos = class_match.start()
                marker_line = f"@pytest.mark.{category}\n"
                content = content[:pos] + marker_line + content[pos:]
            elif func_match:
                # Insert marker before the function definition
                pos = func_match.start()
                marker_line = f"@pytest.mark.{category}\n"
                content = content[:pos] + marker_line + content[pos:]
            else:
                self.log(f"Could not find a test class or function in {file_path}")
                return False
            
            # Write the updated content back to the file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            
            return True
        
        except Exception as e:
            print(f"Error updating {file_path}: {str(e)}")
            return False
    
    def analyze_test_file(self, file_path: Path, update: bool = False) -> Optional[str]:
        """
        Analyze a single test file to determine its dependency category.
        
        Args:
            file_path: Path to the test file
            update: Whether to update the file with markers
            
        Returns:
            The determined dependency category or None if failed
        """
        if not file_path.exists():
            print(f"File not found: {file_path}")
            return None
        
        if not file_path.name.startswith("test_") and not file_path.name.endswith("_test.py"):
            self.log(f"Skipping non-test file: {file_path}")
            return None
        
        self.log(f"Analyzing {file_path}")
        
        # First check if the file already has dependency markers
        existing_markers = self.get_existing_markers(file_path)
        for marker in [STANDALONE, VENV_ONLY, DB_REQUIRED]:
            if marker in existing_markers:
                self.log(f"Found existing marker: {marker} in {file_path}")
                return marker
        
        # If not, analyze imports and code patterns
        categories, import_details = self.analyze_imports(file_path)
        
        # Determine the appropriate category
        category = None
        
        # Hard-coded specific paths
        if "app/tests/standalone/" in str(file_path):
            category = STANDALONE
        elif "app/tests/integration/" in str(file_path) or "app/tests/e2e/" in str(file_path):
            category = DB_REQUIRED
        else:
            # Otherwise use import and pattern analysis
            if DB_REQUIRED in categories:
                category = DB_REQUIRED
            elif VENV_ONLY in categories:
                category = VENV_ONLY
            else:
                category = STANDALONE
        
        self.log(f"Determined category: {category} for {file_path}")
        
        # Update the file if requested
        if update:
            updated = self.update_test_file(file_path, category)
            if updated:
                print(f"Updated {file_path} with @pytest.mark.{category}")
            else:
                self.log(f"No updates needed for {file_path}")
        
        return category
    
    def analyze_directory(self, directory: Path, update: bool = False) -> Dict[str, List[Path]]:
        """
        Recursively analyze test files in a directory.
        
        Args:
            directory: Path to the directory to analyze
            update: Whether to update files with markers
            
        Returns:
            Dictionary mapping categories to lists of file paths
        """
        if not directory.exists():
            print(f"Directory not found: {directory}")
            return {}
        
        results = {STANDALONE: [], VENV_ONLY: [], DB_REQUIRED: []}
        
        for root, _, files in os.walk(directory):
            root_path = Path(root)
            for file in files:
                if file.endswith(".py") and (file.startswith("test_") or file.endswith("_test.py")):
                    file_path = root_path / file
                    category = self.analyze_test_file(file_path, update)
                    if category:
                        results[category].append(file_path)
        
        return results


def main() -> None:
    """Main function to run the test categorizer."""
    parser = argparse.ArgumentParser(description="Analyze and categorize tests by dependency level")
    parser.add_argument("--base-dir", type=str, default=".", help="Base directory of the project")
    parser.add_argument("--tests-dir", type=str, default="app/tests", help="Directory containing tests")
    parser.add_argument("--update", action="store_true", help="Update test files with pytest markers")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--output", type=str, help="Output file for results (JSON format)")
    parser.add_argument("--file", type=str, help="Analyze a single file instead of a directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir)
    
    analyzer = TestDependencyAnalyzer(debug=args.debug)
    
    if args.file:
        file_path = base_dir / args.file
        category = analyzer.analyze_test_file(file_path, args.update)
        print(f"File: {file_path}")
        print(f"Category: {category}")
    else:
        tests_dir = base_dir / args.tests_dir
        results = analyzer.analyze_directory(tests_dir, args.update)
        
        # Print summary
        total = sum(len(files) for files in results.values())
        print("\n=== Test Dependency Analysis Summary ===")
        print(f"Total test files: {total}")
        print(f"Standalone tests: {len(results[STANDALONE])}")
        print(f"VENV-only tests: {len(results[VENV_ONLY])}")
        print(f"DB-required tests: {len(results[DB_REQUIRED])}")
        
        # Print details if debug is enabled
        if args.debug:
            print("\n=== Details ===")
            for category, files in results.items():
                print(f"\n{category.upper()} TESTS:")
                for file in sorted(files):
                    print(f"  - {file.relative_to(base_dir)}")


if __name__ == "__main__":
    main()