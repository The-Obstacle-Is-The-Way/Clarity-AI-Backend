#!/usr/bin/env python3
"""
Test Organization Script for Novamind Digital Twin

This script organizes tests into the directory-based SSOT structure:
- standalone/ - Tests with no external dependencies
- venv/ - Tests requiring Python packages but no external services
- integration/ - Tests requiring external services (DB, Redis, etc.)

Usage:
    python scripts/organize_tests.py --analyze  # Analyze test dependencies
    python scripts/organize_tests.py --execute  # Move tests to correct directories
"""

import os
import re
import sys
import shutil
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("test-organizer")


class TestOrganizer:
    """Organizes tests into directory-based SSOT structure."""
    
    def __init__(self):
        """Initialize the test organizer."""
        self.project_root = Path.cwd()
        self.tests_dir = self.project_root / 'app' / 'tests'
        
        # Create directory structure if it doesn't exist
        for directory in ['standalone', 'venv', 'integration']:
            (self.tests_dir / directory).mkdir(exist_ok=True, parents=True)
            
            # Create __init__.py files
            init_file = self.tests_dir / directory / "__init__.py"
            if not init_file.exists():
                init_file.touch()
                logger.info(f"Created {init_file}")
        
        # Define dependency patterns to look for
        self.db_patterns = [
            r'from\s+sqlalchemy', r'import\s+sqlalchemy', 
            r'\.session', r'\.query', r'\.commit\(',
            r'from\s+app\.infrastructure\.persistence',
            r'import\s+app\.infrastructure\.persistence',
            r'database', r'repository'
        ]
        
        self.external_service_patterns = [
            r'import\s+requests', r'from\s+requests', 
            r'import\s+redis', r'from\s+redis',
            r'import\s+boto3', r'from\s+boto3',
            r'import\s+flask', r'from\s+flask',
            r'http[s]?://', r'localhost', r'integration',
            r'from\s+app\.infrastructure\.external',
            r'import\s+app\.infrastructure\.external'
        ]
        
        self.framework_patterns = [
            r'import\s+fastapi', r'from\s+fastapi',
            r'import\s+pydantic', r'from\s+pydantic',
            r'import\s+numpy', r'from\s+numpy',
            r'import\s+pandas', r'from\s+pandas',
            r'import\s+pytest_mock', r'from\s+pytest_mock',
            r'from\s+app\.api', r'import\s+app\.api'
        ]
        
        # Track test files by category
        self.test_files = {
            'standalone': [],
            'venv': [],
            'integration': []
        }
    
    def scan_tests(self) -> Dict[str, List[Path]]:
        """Scan all test files and categorize them."""
        logger.info("Scanning test files...")
        
        # Clear existing data
        for category in self.test_files:
            self.test_files[category] = []
        
        # Find all test files
        for item in self.tests_dir.glob("**/*.py"):
            if item.name.startswith("test_") and item.is_file():
                # Skip files already in target directories
                if any(d in str(item) for d in ['/standalone/', '/venv/', '/integration/']):
                    continue
                
                # Categorize the test file
                category = self.categorize_test_file(item)
                self.test_files[category].append(item)
        
        return self.test_files
    
    def categorize_test_file(self, file_path: Path) -> str:
        """Determine the appropriate category for a test file."""
        try:
            content = file_path.read_text()
            
            # Check for pytest markers
            markers = self._extract_markers(content)
            if "integration" in markers or "db_required" in markers:
                return "integration"
            elif "venv_only" in markers:
                return "venv"
            elif "standalone" in markers:
                return "standalone"
            
            # Check for integration dependencies
            for pattern in self.db_patterns + self.external_service_patterns:
                if re.search(pattern, content):
                    return "integration"
            
            # Check for framework dependencies
            for pattern in self.framework_patterns:
                if re.search(pattern, content):
                    return "venv"
            
            # Default to standalone if no dependencies found
            return "standalone"
        except Exception as e:
            logger.error(f"Error categorizing {file_path}: {e}")
            return "venv"  # Default to venv if there's an error
    
    def _extract_markers(self, content: str) -> List[str]:
        """Extract pytest markers from test content."""
        markers = []
        
        # Look for marker decorators
        marker_pattern = r'@pytest\.mark\.(\w+)'
        matches = re.findall(marker_pattern, content)
        markers.extend(matches)
        
        return markers
    
    def analyze_results(self) -> str:
        """Generate a Markdown analysis of test categorization."""
        self.scan_tests()
        
        lines = [
            "# Test Organization Analysis",
            "",
            "## Summary",
            "",
            f"- Standalone Tests: {len(self.test_files['standalone'])} files",
            f"- VENV Tests: {len(self.test_files['venv'])} files",
            f"- Integration Tests: {len(self.test_files['integration'])} files",
            "",
            "## Details",
            ""
        ]
        
        for category in ['standalone', 'venv', 'integration']:
            lines.append(f"### {category.capitalize()} Tests")
            lines.append("")
            
            for file_path in sorted(self.test_files[category]):
                rel_path = file_path.relative_to(self.project_root)
                lines.append(f"- {rel_path}")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def execute_organization(self, dry_run: bool = False) -> Dict[str, int]:
        """Move test files to their appropriate directories."""
        self.scan_tests()
        results = {'standalone': 0, 'venv': 0, 'integration': 0}
        
        for category, files in self.test_files.items():
            target_dir = self.tests_dir / category
            
            for source_path in files:
                # Get the filename
                filename = source_path.name
                
                # Create target path
                target_path = target_dir / filename
                
                if dry_run:
                    logger.info(f"Would move {source_path} to {target_path}")
                    results[category] += 1
                else:
                    try:
                        # Copy the file to the new location
                        shutil.copy2(source_path, target_path)
                        logger.info(f"Moved {source_path} to {target_path}")
                        
                        # Optionally remove old test markers and update references
                        self._update_test_file(target_path)
                        
                        results[category] += 1
                    except Exception as e:
                        logger.error(f"Error moving {source_path}: {e}")
        
        return results
    
    def _update_test_file(self, file_path: Path) -> None:
        """Update test file by removing old markers and fixing imports."""
        try:
            content = file_path.read_text()
            
            # Replace legacy markers
            markers_to_remove = [
                r'@pytest\.mark\.standalone\s*\n',
                r'@pytest\.mark\.venv_only\s*\n',
                r'@pytest\.mark\.db_required\s*\n',
                r'@pytest\.mark\.integration\s*\n'
            ]
            
            modified_content = content
            for pattern in markers_to_remove:
                modified_content = re.sub(pattern, '', modified_content)
            
            if modified_content != content:
                file_path.write_text(modified_content)
                logger.info(f"Updated markers in {file_path}")
        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")


def main():
    """Parse arguments and run the test organizer."""
    parser = argparse.ArgumentParser(description="Organize Novamind tests into directory-based SSOT")
    parser.add_argument('--analyze', action='store_true', help='Analyze test files without moving')
    parser.add_argument('--execute', action='store_true', help='Execute test organization')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--report', action='store_true', help='Generate a detailed report')
    
    args = parser.parse_args()
    
    # Default to analyze if no specific action
    if not (args.analyze or args.execute or args.report):
        args.analyze = True
    
    organizer = TestOrganizer()
    
    if args.analyze or args.report:
        analysis = organizer.analyze_results()
        
        if args.report:
            report_path = Path('test-organization-report.md')
            report_path.write_text(analysis)
            logger.info(f"Report generated: {report_path}")
        else:
            print(analysis)
    
    if args.execute:
        results = organizer.execute_organization(args.dry_run)
        
        action = "Would move" if args.dry_run else "Moved"
        logger.info(f"{action} test files:")
        for category, count in results.items():
            logger.info(f"  {category.capitalize()}: {count} files")


if __name__ == "__main__":
    main()