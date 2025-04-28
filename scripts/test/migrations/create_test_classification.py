#!/usr/bin/env python3
"""
Test Classification Report Generator

This script analyzes the test suite and generates a comprehensive report of 
test classifications based on directory structure, test requirements, and test types.
"""

import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple
import json
import datetime
import argparse

# Config constants
TEST_DIRS = ["standalone", "venv", "integration"]
TEST_DIR_DESCRIPTIONS = {
    "standalone": "Tests that have no external dependencies (no DB, no network, no files)",
    "venv": "Tests that require the virtual environment but no external services",
    "integration": "Tests that require external services (DB, network, etc.)"
}

class TestClassifier:
    """Analyzes and classifies tests based on their structure and dependencies."""
    
    def __init__(self, base_dir: Path):
        """Initialize the test classifier with the base directory path."""
        self.base_dir = base_dir
        self.test_dir = base_dir / "app" / "tests"
        self.report_data: Dict[str, Any] = {
            "metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "version": "1.0",
            },
            "summary": {},
            "categories": {},
            "files": {}
        }

    def scan_tests(self) -> None:
        """Scan test files and collect data about them."""
        if not self.test_dir.exists():
            print(f"ERROR: Test directory not found at {self.test_dir}")
            sys.exit(1)
        
        # Initialize counters for summary
        total_tests = 0
        total_files = 0
        tests_by_category: Dict[str, int] = {}
        
        # Scan each test directory
        for category in TEST_DIRS:
            category_dir = self.test_dir / category
            if not category_dir.exists():
                continue
                
            tests_by_category[category] = 0
            self.report_data["categories"][category] = {
                "description": TEST_DIR_DESCRIPTIONS.get(category, ""),
                "files": [],
                "test_count": 0,
            }
            
            # Scan Python files in this category
            for root, _, files in os.walk(category_dir):
                for file in files:
                    if not file.endswith(".py") or file == "__init__.py":
                        continue
                    
                    total_files += 1
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(self.base_dir)
                    
                    # Analyze this test file
                    file_data = self._analyze_test_file(file_path, rel_path, category)
                    
                    # Update counters
                    test_count = file_data["test_count"]
                    total_tests += test_count
                    tests_by_category[category] += test_count
                    
                    # Add to category listing
                    self.report_data["categories"][category]["files"].append(str(rel_path))
                    self.report_data["categories"][category]["test_count"] += test_count
        
        # Update summary
        self.report_data["summary"] = {
            "total_test_files": total_files,
            "total_tests": total_tests,
            "tests_by_category": tests_by_category,
        }

    def _analyze_test_file(self, file_path: Path, rel_path: Path, category: str) -> Dict[str, Any]:
        """Analyze a single test file and extract metadata."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
        except Exception as e:
            print(f"WARNING: Failed to read {file_path}: {e}")
            return {"test_count": 0, "dependencies": []}
        
        # Count test functions and classes
        test_classes = re.findall(r'class\s+Test\w+\s*\(', content)
        test_funcs = re.findall(r'def\s+test_\w+\s*\(', content)
        
        # Extract test dependencies
        dependencies = self._extract_dependencies(content)
        
        # Extract fixtures used
        fixtures = self._extract_fixtures(content)
        
        # Look for mocks used
        mocks = self._extract_mocks(content)
        
        # Extract test requirements from docstrings
        requirements = self._extract_requirements(content)
        
        # Store the data
        file_data = {
            "path": str(rel_path),
            "category": category,
            "test_count": len(test_funcs) + self._estimate_test_methods(test_classes, content),
            "classes": len(test_classes),
            "dependencies": dependencies,
            "fixtures": fixtures,
            "mocks": mocks,
            "requirements": requirements,
        }
        
        self.report_data["files"][str(rel_path)] = file_data
        return file_data

    def _extract_dependencies(self, content: str) -> List[str]:
        """Extract dependencies from import statements."""
        # Look for import statements
        imports = re.findall(r'(?:from|import)\s+([\w.]+)', content)
        
        # Filter to relevant dependencies
        app_imports = [imp for imp in imports if imp.startswith('app.')]
        
        # Organize by module
        modules = set()
        for imp in app_imports:
            parts = imp.split('.')
            if len(parts) >= 2:
                modules.add(f"{parts[0]}.{parts[1]}")
        
        return sorted(list(modules))

    def _extract_fixtures(self, content: str) -> List[str]:
        """Extract fixtures used in the tests."""
        # Match function parameters that look like fixtures
        fixtures = set()
        
        # Find all function parameters
        func_params = re.findall(r'def\s+\w+\s*\((.*?)\):', content, re.DOTALL)
        for params in func_params:
            # Split parameters and clean them
            param_list = [p.strip().split(':')[0].split('=')[0].strip() 
                         for p in params.split(',') if p.strip()]
            
            # Filter out self and cls
            param_list = [p for p in param_list if p not in ('self', 'cls')]
            
            fixtures.update(param_list)
        
        return sorted(list(fixtures))

    def _extract_mocks(self, content: str) -> List[str]:
        """Extract mock objects created in the tests."""
        # Look for common mocking patterns
        mock_patterns = [
            r'@patch\s*\(\s*[\'"]([^\'"]+)[\'"]',  # @patch decorator
            r'patch\s*\(\s*[\'"]([^\'"]+)[\'"]',   # patch() function
            r'MagicMock\s*\(\s*spec\s*=\s*([^)]+)\)',  # MagicMock with spec
            r'Mock\s*\(\s*spec\s*=\s*([^)]+)\)',   # Mock with spec
            r'create_autospec\s*\(\s*([^,)]+)',    # create_autospec
        ]
        
        mocks = set()
        for pattern in mock_patterns:
            matches = re.findall(pattern, content)
            mocks.update(matches)
        
        return sorted(list(mocks))

    def _extract_requirements(self, content: str) -> List[str]:
        """Extract special requirements from test docstrings."""
        requirements = set()
        
        # Look for docstrings with specific requirements
        req_keywords = ['requires', 'requirement', 'dependency', 'dependencies', 'needs']
        
        # Find docstrings
        docstrings = re.findall(r'"""(.*?)"""', content, re.DOTALL)
        for docstring in docstrings:
            for keyword in req_keywords:
                if keyword in docstring.lower():
                    # Extract the line containing the keyword
                    lines = docstring.split('\n')
                    for line in lines:
                        if keyword in line.lower():
                            requirements.add(line.strip())
        
        return sorted(list(requirements))

    def _estimate_test_methods(self, test_classes: List[str], content: str) -> int:
        """Estimate the number of test methods in test classes."""
        # This is a rough estimation, as we're using regex for parsing
        if not test_classes:
            return 0
        
        # Find test methods in the content
        test_methods = re.findall(r'def\s+test_\w+\s*\(\s*self', content)
        return len(test_methods)

    def generate_report(self, output_format: str = "md") -> str:
        """Generate a report in the specified format."""
        if output_format == "json":
            return json.dumps(self.report_data, indent=2)
        elif output_format == "md":
            return self._generate_markdown_report()
        else:
            print(f"ERROR: Unsupported output format: {output_format}")
            sys.exit(1)

    def _generate_markdown_report(self) -> str:
        """Generate a Markdown report from the collected data."""
        lines = []
        
        # Header
        lines.append("# Novamind Backend Test Classification Report")
        lines.append("")
        lines.append(f"*Generated on: {self.report_data['metadata']['generated_at']}*")
        lines.append("")
        
        # Summary
        lines.append("## Test Summary")
        lines.append("")
        summary = self.report_data["summary"]
        lines.append(f"- **Total Test Files:** {summary['total_test_files']}")
        lines.append(f"- **Total Tests:** {summary['total_tests']}")
        lines.append("")
        
        lines.append("### Tests by Category")
        lines.append("")
        for category, count in summary.get("tests_by_category", {}).items():
            description = TEST_DIR_DESCRIPTIONS.get(category, "")
            lines.append(f"- **{category}:** {count} tests - {description}")
        lines.append("")
        
        # Categories detail
        lines.append("## Test Categories")
        lines.append("")
        
        for category, data in self.report_data["categories"].items():
            lines.append(f"### {category.capitalize()} Tests")
            lines.append("")
            lines.append(f"{data['description']}")
            lines.append("")
            lines.append(f"**Total Tests:** {data['test_count']}")
            lines.append("")
            
            if data["files"]:
                lines.append("#### Files")
                lines.append("")
                for file_path in sorted(data["files"]):
                    file_data = self.report_data["files"].get(file_path, {})
                    test_count = file_data.get("test_count", 0)
                    lines.append(f"- `{file_path}` ({test_count} tests)")
                lines.append("")
        
        # Detailed file analysis
        lines.append("## Detailed File Analysis")
        lines.append("")
        
        for file_path, data in sorted(self.report_data["files"].items()):
            lines.append(f"### {file_path}")
            lines.append("")
            lines.append(f"- **Category:** {data['category']}")
            lines.append(f"- **Test Count:** {data['test_count']}")
            lines.append(f"- **Test Classes:** {data['classes']}")
            lines.append("")
            
            if data.get("dependencies"):
                lines.append("#### Dependencies")
                lines.append("")
                for dep in data["dependencies"]:
                    lines.append(f"- `{dep}`")
                lines.append("")
            
            if data.get("fixtures"):
                lines.append("#### Fixtures Used")
                lines.append("")
                for fixture in data["fixtures"]:
                    lines.append(f"- `{fixture}`")
                lines.append("")
            
            if data.get("mocks"):
                lines.append("#### Mocks")
                lines.append("")
                for mock in data["mocks"]:
                    lines.append(f"- `{mock}`")
                lines.append("")
            
            if data.get("requirements"):
                lines.append("#### Special Requirements")
                lines.append("")
                for req in data["requirements"]:
                    lines.append(f"- {req}")
                lines.append("")
        
        return "\n".join(lines)

    def save_report(self, output_path: Path, output_format: str = "md") -> None:
        """Save the report to a file."""
        report = self.generate_report(output_format)
        
        try:
            with open(output_path, 'w') as f:
                f.write(report)
            print(f"Report saved to {output_path}")
        except Exception as e:
            print(f"ERROR: Failed to save report to {output_path}: {e}")
            sys.exit(1)

def main():
    """Main function to run the test classifier."""
    parser = argparse.ArgumentParser(description="Generate a test classification report.")
    
    parser.add_argument(
        "--format", 
        choices=["md", "json"],
        default="md",
        help="Output format (default: md)"
    )
    
    parser.add_argument(
        "--output", 
        type=str,
        default="test-classification-report",
        help="Output file name (without extension)"
    )
    
    args = parser.parse_args()
    
    # Get the base directory
    base_dir = Path(__file__).resolve().parent.parent
    
    # Initialize the classifier
    classifier = TestClassifier(base_dir)
    
    # Scan tests
    print("Scanning tests...")
    classifier.scan_tests()
    
    # Save the report
    output_path = base_dir / f"{args.output}.{args.format}"
    print(f"Generating {args.format} report...")
    classifier.save_report(output_path, args.format)

if __name__ == "__main__":
    main()