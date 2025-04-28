#!/usr/bin/env python3
"""
Test Migration to Directory SSOT

This script migrates tests from marker-based organization to directory-based Single Source of Truth.
It identifies tests using pytest markers and moves them to the appropriate directories.

Usage:
    python scripts/migrate_to_directory_ssot.py [--analyze] [--execute] [--report]
"""

import os
import re
import shutil
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("test-migration")


class TestMigrator:
    """Handles migration of tests from markers to directory structure."""
    
    def __init__(self):
        """Initialize the migrator with project paths."""
        self.project_root = Path.cwd()
        self.app_dir = self.project_root / 'app'
        self.tests_dir = self.app_dir / 'tests'
        
        # Ensure directory structure exists
        for directory in ['standalone', 'venv', 'integration']:
            (self.tests_dir / directory).mkdir(exist_ok=True, parents=True)
            
        # Create __init__.py files
        self._ensure_init_files()
    
    def _ensure_init_files(self):
        """Ensure __init__.py files exist in all test directories."""
        for root, dirs, _ in os.walk(self.tests_dir):
            root_path = Path(root)
            # Create __init__.py in the current directory
            init_file = root_path / "__init__.py"
            if not init_file.exists():
                init_file.touch()
                logger.info(f"Created {init_file}")
    
    def scan_test_files(self) -> List[Dict[str, Any]]:
        """Scan all test files and extract their markers."""
        test_files = []
        
        # Find all test files
        for root, _, files in os.walk(self.tests_dir):
            for file in files:
                if file.startswith('test_') and file.endswith('.py'):
                    file_path = Path(root) / file
                    
                    # Skip files already in the correct structure
                    if any(d in str(file_path) for d in ['standalone/', 'venv/', 'integration/']):
                        continue
                    
                    markers = self._extract_markers(file_path)
                    dependencies = self._analyze_dependencies(file_path)
                    
                    test_files.append({
                        'path': file_path,
                        'markers': markers,
                        'dependencies': dependencies,
                        'target_dir': self._determine_target_directory(markers, dependencies)
                    })
        
        return test_files
    
    def _extract_markers(self, file_path: Path) -> List[str]:
        """Extract pytest markers from a test file."""
        markers = []
        
        try:
            content = file_path.read_text()
            
            # Look for marker decorators
            marker_patterns = [
                r'@pytest\.mark\.(\w+)',              # @pytest.mark.marker
                r'pytest\.mark\.(\w+)',               # pytest.mark.marker
                r'@pytest\.fixture\(.*scope=[\"\'](\w+)[\"\'].*\)', # fixture scope
            ]
            
            for pattern in marker_patterns:
                matches = re.findall(pattern, content)
                markers.extend(matches)
            
            return list(set(markers))
        except Exception as e:
            logger.error(f"Error extracting markers from {file_path}: {e}")
            return []
    
    def _analyze_dependencies(self, file_path: Path) -> Dict[str, bool]:
        """Analyze a test file for dependencies."""
        dependencies = {
            'has_db': False,
            'has_network': False,
            'has_external_libs': False
        }
        
        try:
            content = file_path.read_text()
            
            # Check for database dependencies
            db_patterns = [
                r'from\s+sqlalchemy', r'import\s+sqlalchemy', 
                r'\.session', r'\.query', r'\.commit\('
            ]
            for pattern in db_patterns:
                if re.search(pattern, content):
                    dependencies['has_db'] = True
                    break
            
            # Check for network dependencies
            network_patterns = [
                r'import\s+requests', r'from\s+requests', 
                r'import\s+flask', r'from\s+flask',
                r'http[s]?://', r'localhost'
            ]
            for pattern in network_patterns:
                if re.search(pattern, content):
                    dependencies['has_network'] = True
                    break
            
            # Check for external library dependencies
            external_lib_patterns = [
                r'import\s+numpy', r'from\s+numpy', 
                r'import\s+pandas', r'from\s+pandas',
                r'import\s+fastapi', r'from\s+fastapi',
                r'import\s+boto3', r'from\s+boto3',
                r'import\s+redis', r'from\s+redis'
            ]
            for pattern in external_lib_patterns:
                if re.search(pattern, content):
                    dependencies['has_external_libs'] = True
                    break
                
            return dependencies
        except Exception as e:
            logger.error(f"Error analyzing dependencies in {file_path}: {e}")
            return dependencies
    
    def _determine_target_directory(self, markers: List[str], dependencies: Dict[str, bool]) -> str:
        """Determine the target directory for a test file based on markers and dependencies."""
        # Check markers first
        if 'standalone' in markers:
            return 'standalone'
        elif 'venv_only' in markers:
            return 'venv'
        elif 'db_required' in markers or 'integration' in markers:
            return 'integration'
        
        # Check dependencies
        if dependencies['has_db'] or dependencies['has_network']:
            return 'integration'
        elif dependencies['has_external_libs']:
            return 'venv'
        else:
            return 'standalone'
    
    def plan_migration(self, test_files: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Plan the migration of test files to their target directories."""
        migration_plan = {
            'standalone': [],
            'venv': [],
            'integration': []
        }
        
        for test_file in test_files:
            target_dir = test_file['target_dir']
            migration_plan[target_dir].append(test_file)
        
        return migration_plan
    
    def execute_migration(self, migration_plan: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
        """Execute the migration plan."""
        results = {
            'standalone': 0,
            'venv': 0,
            'integration': 0
        }
        
        for target_dir, files in migration_plan.items():
            for file_info in files:
                source_path = file_info['path']
                file_name = source_path.name
                target_path = self.tests_dir / target_dir / file_name
                
                # Create the target directory if it doesn't exist
                target_path.parent.mkdir(exist_ok=True, parents=True)
                
                try:
                    # Copy the file to the new location
                    shutil.copy2(source_path, target_path)
                    logger.info(f"Migrated {source_path} to {target_path}")
                    
                    # Optionally remove legacy markers from the file
                    self._remove_legacy_markers(target_path)
                    
                    results[target_dir] += 1
                except Exception as e:
                    logger.error(f"Error migrating {source_path}: {e}")
        
        return results
    
    def _remove_legacy_markers(self, file_path: Path) -> None:
        """Remove legacy dependency markers from a test file."""
        try:
            content = file_path.read_text()
            
            # Replace these marker patterns
            legacy_markers = [
                r'@pytest\.mark\.standalone', 
                r'@pytest\.mark\.venv_only',
                r'@pytest\.mark\.db_required',
            ]
            
            modified_content = content
            for pattern in legacy_markers:
                modified_content = re.sub(pattern, '# Migrated to directory SSOT', modified_content)
            
            if modified_content != content:
                file_path.write_text(modified_content)
                logger.info(f"Removed legacy markers from {file_path}")
        except Exception as e:
            logger.error(f"Error removing markers from {file_path}: {e}")
    
    def generate_report(self, migration_plan: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate a report of the migration plan."""
        total_files = sum(len(files) for files in migration_plan.values())
        
        lines = [
            "# Test Migration to Directory SSOT Report",
            "",
            f"Total files to migrate: {total_files}",
            "",
            "## Migration Plan",
            ""
        ]
        
        for target_dir, files in migration_plan.items():
            lines.append(f"### {target_dir.capitalize()} Tests ({len(files)})")
            lines.append("")
            
            for file_info in sorted(files, key=lambda x: str(x['path'])):
                markers_str = ", ".join(file_info['markers']) if file_info['markers'] else "none"
                dependencies = file_info['dependencies']
                dep_list = []
                if dependencies['has_db']:
                    dep_list.append("database")
                if dependencies['has_network']:
                    dep_list.append("network")
                if dependencies['has_external_libs']:
                    dep_list.append("external libraries")
                dependencies_str = ", ".join(dep_list) if dep_list else "none"
                
                lines.append(f"- {file_info['path'].relative_to(self.project_root)}")
                lines.append(f"  - Markers: {markers_str}")
                lines.append(f"  - Dependencies: {dependencies_str}")
                lines.append("")
        
        lines.extend([
            "## Next Steps",
            "",
            "1. Review the migration plan",
            "2. Execute the migration with `--execute`",
            "3. Run tests to ensure everything works correctly",
            "4. Update CI/CD pipelines to use the new directory structure",
            ""
        ])
        
        return "\n".join(lines)


def main():
    """Main function to parse arguments and run the migrator."""
    parser = argparse.ArgumentParser(
        description="Migrate tests from markers to directory-based organization"
    )
    parser.add_argument('--analyze', action='store_true', help='Analyze test files without migrating')
    parser.add_argument('--execute', action='store_true', help='Execute the migration')
    parser.add_argument('--report', action='store_true', help='Generate a migration report')
    
    args = parser.parse_args()
    
    # Default to analyze if no args provided
    if not (args.analyze or args.execute or args.report):
        args.analyze = True
    
    migrator = TestMigrator()
    test_files = migrator.scan_test_files()
    migration_plan = migrator.plan_migration(test_files)
    
    if args.analyze:
        logger.info("Analysis of test files:")
        for target_dir, files in migration_plan.items():
            logger.info(f"{target_dir.capitalize()} tests: {len(files)}")
    
    if args.report:
        report = migrator.generate_report(migration_plan)
        report_path = Path('test-migration-report.md')
        report_path.write_text(report)
        logger.info(f"Migration report generated: {report_path}")
    
    if args.execute:
        logger.info("Executing migration plan...")
        results = migrator.execute_migration(migration_plan)
        logger.info("Migration complete:")
        for target_dir, count in results.items():
            logger.info(f"{target_dir.capitalize()} tests: {count}")


if __name__ == "__main__":
    main()