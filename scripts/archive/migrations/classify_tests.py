#!/usr/bin/env python3
"""
Test Classification Script

This script analyzes test files and classifies them as:
1. Standalone - No external dependencies
2. VENV - Requires virtualenv but not a database
3. Integration - Requires a full database or external services

It helps maintain the directory-based test organization by suggesting where tests 
should be located based on their dependencies.
"""

import os
import re
import ast
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

# Define dependency patterns to search for
STANDALONE_SAFE_IMPORTS = {
    'pytest', 'unittest', 're', 'json', 'datetime', 'typing', 
    'enum', 'mock', 'patch', 'MagicMock', 'copy', 'random', 'math',
    'functools', 'itertools', 'app.domain', 'app.core', 'dataclasses',
    'abc', 'collections', 'contextlib', 'hashlib', 'uuid'
}

DB_DEPENDENCY_PATTERNS = [
    r'session', r'database', r'models\.', r'db\.',
    r'repository', r'sqlalchemy', r'transaction',
    r'commit', r'rollback', r'query', r'execute', r'SELECT',
    r'PostgreSQL', r'alembic'
]

EXTERNAL_SERVICE_PATTERNS = [
    r'requests\.', r'http', r'boto3', r'aws', r's3', 
    r'sqs', r'sns', r'redis', r'kafka', r'smtp', 
    r'email\.', r'sms', r'twilio', r'openai', r'api\.'
]


class TestAnalyzer:
    """Analyzes test files to determine their classification."""
    
    def __init__(self, base_dir: str = 'app/tests'):
        """Initialize with the base directory for tests."""
        self.base_dir = Path(base_dir)
        
        # Define test directories
        self.standalone_dir = self.base_dir / 'standalone'
        self.venv_dir = self.base_dir / 'venv' 
        self.integration_dir = self.base_dir / 'integration'
        
        # Create directories if they don't exist
        for directory in [self.standalone_dir, self.venv_dir, self.integration_dir]:
            directory.mkdir(exist_ok=True, parents=True)
    
    def analyze_file(self, file_path: Path) -> Tuple[str, List[str]]:
        """
        Analyze a test file to determine its classification.
        
        Returns:
            Tuple[str, List[str]]: The classification and the reasons for it
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for imports and dependencies
        has_db_dependencies = any(re.search(pattern, content, re.IGNORECASE) for pattern in DB_DEPENDENCY_PATTERNS)
        has_external_dependencies = any(re.search(pattern, content, re.IGNORECASE) for pattern in EXTERNAL_SERVICE_PATTERNS)
        
        # Look for imported modules
        try:
            tree = ast.parse(content)
            imports = self._extract_imports(tree)
        except SyntaxError:
            imports = set()  # If there's a syntax error, we can't parse imports
        
        # Analyze decorators and fixtures
        has_integration_fixtures = re.search(r'@pytest\.fixture\(.*(scope=[\"\']session[\"\']|autouse=True)', content) is not None
        has_db_fixtures = re.search(r'@pytest\.fixture.*db|database|session', content) is not None
        
        # Classify the test
        reasons = []
        
        if has_db_dependencies:
            reasons.append("Uses database dependencies")
        
        if has_external_dependencies:
            reasons.append("Uses external service dependencies")
        
        if has_integration_fixtures:
            reasons.append("Uses session-scoped or autouse fixtures")
        
        if has_db_fixtures:
            reasons.append("Uses database fixtures")
        
        # Non-safe imports
        non_safe_imports = imports - STANDALONE_SAFE_IMPORTS
        if non_safe_imports:
            reasons.append(f"Uses non-standalone imports: {', '.join(non_safe_imports)}")
        
        # Make classification decision
        if has_db_dependencies or has_external_dependencies or has_integration_fixtures or has_db_fixtures:
            if has_db_dependencies or has_db_fixtures:
                return "integration", reasons
            else:
                return "venv", reasons
        elif non_safe_imports:
            return "venv", reasons
        else:
            return "standalone", reasons
    
    def _extract_imports(self, tree: ast.Module) -> Set[str]:
        """Extract all imported modules from an AST."""
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
        
        return imports
    
    def get_existing_classification(self, file_path: Path) -> Optional[str]:
        """Determine the current classification based on directory."""
        rel_path = file_path.relative_to(self.base_dir.parent.parent)  # Relative to repo root
        
        if 'standalone' in str(rel_path):
            return "standalone"
        elif 'venv' in str(rel_path):
            return "venv"
        elif 'integration' in str(rel_path):
            return "integration"
        return None
    
    def analyze_all_tests(self) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
        """
        Analyze all test files in the project.
        
        Returns:
            Dict with statistics and misclassified tests
        """
        results = {
            'counts': {'standalone': 0, 'venv': 0, 'integration': 0},
            'misclassified': {'standalone': [], 'venv': [], 'integration': []},
            'correctly_classified': {'standalone': [], 'venv': [], 'integration': []}
        }
        
        # Find all test files
        for root, _, files in os.walk(self.base_dir):
            for file in files:
                if file.startswith('test_') and file.endswith('.py'):
                    file_path = Path(root) / file
                    classification, reasons = self.analyze_file(file_path)
                    current = self.get_existing_classification(file_path)
                    
                    # Update counts
                    results['counts'][classification] += 1
                    
                    # Check if correctly classified
                    rel_path = str(file_path.relative_to(self.base_dir.parent.parent))
                    if current and current != classification:
                        results['misclassified'][classification].append({
                            'file': rel_path,
                            'current': current,
                            'should_be': classification,
                            'reasons': reasons
                        })
                    elif current and current == classification:
                        results['correctly_classified'][classification].append({
                            'file': rel_path
                        })
        
        return results

    def generate_report(self) -> str:
        """Generate a report of the test classification analysis."""
        results = self.analyze_all_tests()
        
        report = []
        report.append("# Test Classification Report")
        report.append("\n## Summary")
        report.append(f"- Standalone Tests: {results['counts']['standalone']}")
        report.append(f"- VENV Tests: {results['counts']['venv']}")
        report.append(f"- Integration Tests: {results['counts']['integration']}")
        
        total = sum(results['counts'].values())
        report.append(f"\nTotal Tests: {total}")
        
        # Misclassified tests
        misclassified_count = sum(len(tests) for tests in results['misclassified'].values())
        if misclassified_count > 0:
            report.append("\n## Misclassified Tests")
            report.append(f"\n{misclassified_count} tests are in the wrong directory:")
            
            for category, tests in results['misclassified'].items():
                if tests:
                    report.append(f"\n### Should be {category.upper()} tests:")
                    for test in tests:
                        reasons = "\n   - " + "\n   - ".join(test['reasons'])
                        report.append(f"- {test['file']} (currently in {test['current']}){reasons}")
        
        # Correctly classified
        report.append("\n## Correctly Classified Tests")
        for category, tests in results['correctly_classified'].items():
            if tests:
                report.append(f"\n### {category.upper()} tests:")
                for test in tests[:5]:  # Show only first 5 examples
                    report.append(f"- {test['file']}")
                if len(tests) > 5:
                    report.append(f"- ... and {len(tests) - 5} more")
        
        return "\n".join(report)


def move_test(file_path: str, target_category: str, dry_run: bool = True) -> None:
    """Move a test file to the correct directory."""
    base_dir = Path('app/tests')
    source = Path(file_path)
    if not source.exists():
        print(f"Error: File {file_path} not found")
        return
    
    # Extract the filename
    filename = source.name
    
    # Construct the target path
    target_dir = base_dir / target_category
    target_dir.mkdir(exist_ok=True, parents=True)
    target = target_dir / filename
    
    # Move the file
    if dry_run:
        print(f"Would move {source} to {target}")
    else:
        # Create any intermediate directories
        target.parent.mkdir(parents=True, exist_ok=True)
        # Move the file
        source.rename(target)
        print(f"Moved {source} to {target}")


def main():
    """Main function to parse arguments and run the test classifier."""
    parser = argparse.ArgumentParser(description="Classify tests based on their dependencies")
    parser.add_argument('--report', action='store_true', help='Generate a report of test classifications')
    parser.add_argument('--move', action='store_true', help='Move misclassified tests to the correct directory')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be moved without actually moving files')
    
    args = parser.parse_args()
    
    analyzer = TestAnalyzer()
    
    if args.report:
        report = analyzer.generate_report()
        print(report)
        # Also write to a file
        with open('test-classification-report.md', 'w') as f:
            f.write(report)
        print("\nReport written to test-classification-report.md")
    
    if args.move:
        results = analyzer.analyze_all_tests()
        for category, tests in results['misclassified'].items():
            for test in tests:
                move_test(test['file'], category, dry_run=args.dry_run)


if __name__ == "__main__":
    main()