#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HIPAA Compliance Summary Generator
=================================

Generates a comprehensive compliance summary report from various security
test results. This provides an executive summary of the platform's
HIPAA compliance status with actionable recommendations.

Usage:
    python generate_compliance_summary.py --reports-dir reports
"""

import os
import sys
import json
import argparse
import datetime
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple

# Rich library provides beautiful formatting for terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ComplianceSummaryGenerator:
    """Generate comprehensive HIPAA compliance summary from test reports."""
    
    def __init__(self, reports_dir: str):
        """Initialize with reports directory path."""
        self.reports_dir = reports_dir
        self.report_data = {
            "security_score": 0.0,
            "tests_passed": 0,
            "tests_failed": 0,
            "total_tests": 0,
            "pass_rate": 0.0,
            "vulnerabilities": [],
            "coverage": 0.0,
            "timestamp": datetime.datetime.now().isoformat(),
            "compliance_status": "UNKNOWN",
            "category_scores": {},
            "recommendations": []
        }
    
    def collect_data(self) -> None:
        """Collect data from all available reports."""
        self._read_compliance_score()
        self._read_pytest_results()
        self._read_bandit_results()
        self._read_safety_results()
        self._calculate_category_scores()
        self._generate_recommendations()
    
    def _read_compliance_score(self) -> None:
        """Read the overall compliance score."""
        try:
            score_path = os.path.join(self.reports_dir, "compliance_score.json")
            if os.path.exists(score_path):
                with open(score_path, 'r') as f:
                    score_data = json.load(f)
                    
                self.report_data["security_score"] = score_data.get("overall_score", 0.0)
                self.report_data["compliance_status"] = score_data.get("status", "UNKNOWN")
                self.report_data["category_scores"] = score_data.get("tool_scores", {})
        except Exception as e:
            print(f"Error reading compliance score: {str(e)}")
    
    def _read_pytest_results(self) -> None:
        """Read pytest test results from XML reports."""
        try:
            # Try to read PHI middleware test results
            phi_tests_path = os.path.join(self.reports_dir, "phi_middleware_tests.xml")
            if os.path.exists(phi_tests_path):
                tree = ET.parse(phi_tests_path)
                root = tree.getroot()
                
                tests = int(root.attrib.get("tests", "0"))
                failures = int(root.attrib.get("failures", "0"))
                errors = int(root.attrib.get("errors", "0"))
                skipped = int(root.attrib.get("skipped", "0"))
                
                self.report_data["total_tests"] += tests
                self.report_data["tests_failed"] += (failures + errors)
                self.report_data["tests_passed"] += (tests - failures - errors - skipped)
            
            # Try to read auth middleware test results
            auth_tests_path = os.path.join(self.reports_dir, "auth_middleware_tests.xml")
            if os.path.exists(auth_tests_path):
                tree = ET.parse(auth_tests_path)
                root = tree.getroot()
                
                tests = int(root.attrib.get("tests", "0"))
                failures = int(root.attrib.get("failures", "0"))
                errors = int(root.attrib.get("errors", "0"))
                skipped = int(root.attrib.get("skipped", "0"))
                
                self.report_data["total_tests"] += tests
                self.report_data["tests_failed"] += (failures + errors)
                self.report_data["tests_passed"] += (tests - failures - errors - skipped)
            
            # Calculate pass rate
            if self.report_data["total_tests"] > 0:
                self.report_data["pass_rate"] = (
                    self.report_data["tests_passed"] / self.report_data["total_tests"] * 100.0
                )
            
            # Try to read coverage data
            coverage_path = os.path.join(self.reports_dir, "coverage.xml")
            if os.path.exists(coverage_path):
                tree = ET.parse(coverage_path)
                root = tree.getroot()
                
                # Find the overall coverage
                coverage = root.attrib.get("line-rate", "0.0")
                try:
                    self.report_data["coverage"] = float(coverage) * 100.0
                except ValueError:
                    self.report_data["coverage"] = 0.0
        
        except Exception as e:
            print(f"Error reading pytest results: {str(e)}")
    
    def _read_bandit_results(self) -> None:
        """Read bandit security analysis results."""
        try:
            bandit_path = os.path.join(self.reports_dir, "bandit_results.json")
            if os.path.exists(bandit_path):
                with open(bandit_path, 'r') as f:
                    bandit_data = json.load(f)
                
                results = bandit_data.get("results", [])
                for result in results:
                    severity = result.get("issue_severity", "UNKNOWN").upper()
                    if severity in ["HIGH", "MEDIUM"]:  # Only include high and medium severity issues
                        self.report_data["vulnerabilities"].append({
                            "type": "Security Issue",
                            "severity": severity,
                            "description": result.get("issue_text", "Unknown issue"),
                            "location": f"{result.get('filename', 'Unknown')}: {result.get('line_number', 0)}",
                            "recommendation": "Fix according to bandit recommendation"
                        })
        except Exception as e:
            print(f"Error reading bandit results: {str(e)}")
    
    def _read_safety_results(self) -> None:
        """Read safety dependency check results."""
        try:
            safety_path = os.path.join(self.reports_dir, "vulnerabilities.json")
            if os.path.exists(safety_path):
                with open(safety_path, 'r') as f:
                    vulnerabilities = json.load(f)
                
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "UNKNOWN").upper()
                    if severity in ["HIGH", "MEDIUM", "CRITICAL"]:  # Only include serious issues
                        package = vuln.get("package_name", "Unknown")
                        version = vuln.get("affected_versions", "Unknown")
                        
                        self.report_data["vulnerabilities"].append({
                            "type": "Dependency Vulnerability",
                            "severity": severity,
                            "description": vuln.get("description", "Unknown vulnerability"),
                            "location": f"Package: {package} {version}",
                            "recommendation": f"Upgrade {package} to a patched version"
                        })
        except Exception as e:
            print(f"Error reading safety results: {str(e)}")
    
    def _calculate_category_scores(self) -> None:
        """Calculate scores for different compliance categories."""
        # HIPAA compliance categories
        categories = {
            "Administrative Safeguards": 0.0,
            "Physical Safeguards": 0.0,
            "Technical Safeguards": 0.0,
            "Organizational Requirements": 0.0,
            "Policies and Procedures": 0.0
        }
        
        # Map our tests to HIPAA categories for scoring
        category_mappings = {
            "Administrative Safeguards": ["pytest", "hipaa_scanner"],
            "Technical Safeguards": ["safety", "bandit", "hipaa_scanner"],
            "Policies and Procedures": ["hipaa_scanner"]
        }
        
        # Calculate scores based on our test results
        for category, tools in category_mappings.items():
            scores = []
            for tool in tools:
                if tool in self.report_data["category_scores"]:
                    scores.append(self.report_data["category_scores"][tool])
            
            if scores:
                categories[category] = sum(scores) / len(scores)
        
        # Add to report data
        self.report_data["hipaa_categories"] = categories
    
    def _generate_recommendations(self) -> None:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        # Add recommendations based on security score
        if self.report_data["security_score"] < 80.0:
            recommendations.append({
                "category": "Overall Security",
                "description": "Improve overall security posture to meet HIPAA requirements",
                "priority": "HIGH",
                "actions": [
                    "Address all high severity vulnerabilities",
                    "Increase test coverage to at least 80%",
                    "Implement missing security controls"
                ]
            })
        
        # Add recommendations based on vulnerabilities
        high_vulns = [v for v in self.report_data["vulnerabilities"] if v["severity"] == "HIGH"]
        if high_vulns:
            recommendations.append({
                "category": "Vulnerabilities",
                "description": f"Fix {len(high_vulns)} high severity vulnerabilities",
                "priority": "CRITICAL",
                "actions": [
                    f"Address {v['description']} in {v['location']}" for v in high_vulns[:3]
                ] + (["...and more"] if len(high_vulns) > 3 else [])
            })
        
        # Add recommendations based on test coverage
        if self.report_data["coverage"] < 80.0:
            recommendations.append({
                "category": "Test Coverage",
                "description": "Increase security test coverage",
                "priority": "MEDIUM",
                "actions": [
                    "Add tests for authentication flows",
                    "Add tests for authorization controls",
                    "Add tests for PHI handling in all layers"
                ]
            })
        
        # Add recommendations based on HIPAA categories
        for category, score in self.report_data.get("hipaa_categories", {}).items():
            if score < 80.0:
                recommendations.append({
                    "category": category,
                    "description": f"Improve compliance in {category}",
                    "priority": "HIGH",
                    "actions": [
                        f"Review and implement missing {category} controls",
                        "Document implementation details",
                        "Create automated tests for verification"
                    ]
                })
        
        # If we have no recommendations but aren't compliant, add a generic one
        if not recommendations and self.report_data["compliance_status"] != "COMPLIANT":
            recommendations.append({
                "category": "General",
                "description": "Perform comprehensive HIPAA gap analysis",
                "priority": "HIGH",
                "actions": [
                    "Identify specific compliance gaps",
                    "Create remediation plan",
                    "Implement missing controls"
                ]
            })
        
        # If we are compliant, add a maintenance recommendation
        if self.report_data["compliance_status"] == "COMPLIANT":
            recommendations.append({
                "category": "Maintenance",
                "description": "Maintain current HIPAA compliance posture",
                "priority": "MEDIUM",
                "actions": [
                    "Continue regular security testing",
                    "Update dependencies regularly",
                    "Perform quarterly compliance reviews"
                ]
            })
        
        self.report_data["recommendations"] = recommendations
    
    def generate_text_report(self) -> None:
        """Generate a plain text report."""
        report_path = os.path.join(self.reports_dir, "compliance_summary.txt")
        
        with open(report_path, 'w') as f:
            f.write("===================================================================\n")
            f.write("           HIPAA COMPLIANCE SUMMARY REPORT                        \n")
            f.write("           Luxury Concierge Psychiatry Platform                   \n")
            f.write("===================================================================\n\n")
            
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Overall compliance status
            f.write("COMPLIANCE STATUS\n")
            f.write("-----------------\n")
            status = self.report_data["compliance_status"]
            f.write(f"Overall Status: {status}\n")
            f.write(f"Security Score: {self.report_data['security_score']:.1f}%\n\n")
            
            # Test Results
            f.write("TEST RESULTS\n")
            f.write("-----------\n")
            f.write(f"Total Tests: {self.report_data['total_tests']}\n")
            f.write(f"Passed: {self.report_data['tests_passed']}\n")
            f.write(f"Failed: {self.report_data['tests_failed']}\n")
            f.write(f"Pass Rate: {self.report_data['pass_rate']:.1f}%\n")
            f.write(f"Coverage: {self.report_data['coverage']:.1f}%\n\n")
            
            # HIPAA Categories
            f.write("HIPAA CATEGORY SCORES\n")
            f.write("--------------------\n")
            for category, score in self.report_data.get("hipaa_categories", {}).items():
                f.write(f"{category}: {score:.1f}%\n")
            f.write("\n")
            
            # Vulnerabilities
            f.write("SECURITY VULNERABILITIES\n")
            f.write("-----------------------\n")
            vulns = self.report_data["vulnerabilities"]
            if vulns:
                for i, vuln in enumerate(vulns, 1):
                    f.write(f"{i}. [{vuln['severity']}] {vuln['description']}\n")
                    f.write(f"   Location: {vuln['location']}\n")
                    f.write(f"   Recommendation: {vuln['recommendation']}\n\n")
            else:
                f.write("No major vulnerabilities detected.\n\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("---------------\n")
            recs = self.report_data["recommendations"]
            if recs:
                for i, rec in enumerate(recs, 1):
                    f.write(f"{i}. [{rec['priority']}] {rec['description']}\n")
                    f.write(f"   Category: {rec['category']}\n")
                    f.write("   Actions:\n")
                    for action in rec['actions']:
                        f.write(f"     - {action}\n")
                    f.write("\n")
            else:
                f.write("No specific recommendations.\n\n")
            
            # Footer
            f.write("===================================================================\n")
            if status == "COMPLIANT":
                f.write("This platform meets HIPAA security and compliance requirements.\n")
            else:
                f.write("This platform requires remediation to meet HIPAA requirements.\n")
            f.write("===================================================================\n")
    
    def generate_markdown_report(self) -> None:
        """Generate a Markdown report."""
        report_path = os.path.join(self.reports_dir, "compliance_summary.md")
        
        with open(report_path, 'w') as f:
            f.write("# HIPAA Compliance Summary Report\n\n")
            f.write("## Luxury Concierge Psychiatry Platform\n\n")
            
            f.write(f"*Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Overall compliance status
            f.write("## Compliance Status\n\n")
            status = self.report_data["compliance_status"]
            status_color = "green" if status == "COMPLIANT" else "red"
            f.write(f"**Overall Status:** <span style='color:{status_color}'>{status}</span>\n\n")
            f.write(f"**Security Score:** {self.report_data['security_score']:.1f}%\n\n")
            
            # Test Results
            f.write("## Test Results\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Total Tests | {self.report_data['total_tests']} |\n")
            f.write(f"| Passed | {self.report_data['tests_passed']} |\n")
            f.write(f"| Failed | {self.report_data['tests_failed']} |\n")
            f.write(f"| Pass Rate | {self.report_data['pass_rate']:.1f}% |\n")
            f.write(f"| Coverage | {self.report_data['coverage']:.1f}% |\n\n")
            
            # HIPAA Categories
            f.write("## HIPAA Category Scores\n\n")
            f.write("| Category | Score |\n")
            f.write("|----------|-------|\n")
            for category, score in self.report_data.get("hipaa_categories", {}).items():
                score_color = "green" if score >= 80.0 else "red"
                f.write(f"| {category} | <span style='color:{score_color}'>{score:.1f}%</span> |\n")
            f.write("\n")
            
            # Vulnerabilities
            f.write("## Security Vulnerabilities\n\n")
            vulns = self.report_data["vulnerabilities"]
            if vulns:
                f.write("| Severity | Description | Location | Recommendation |\n")
                f.write("|----------|-------------|----------|----------------|\n")
                for vuln in vulns:
                    f.write(f"| **{vuln['severity']}** | {vuln['description']} | {vuln['location']} | {vuln['recommendation']} |\n")
            else:
                f.write("No major vulnerabilities detected.\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            recs = self.report_data["recommendations"]
            if recs:
                for i, rec in enumerate(recs, 1):
                    f.write(f"### {i}. {rec['description']} ({rec['priority']})\n\n")
                    f.write(f"**Category:** {rec['category']}\n\n")
                    f.write("**Actions:**\n\n")
                    for action in rec['actions']:
                        f.write(f"* {action}\n")
                    f.write("\n")
            else:
                f.write("No specific recommendations.\n\n")
            
            # Footer
            f.write("---\n\n")
            if status == "COMPLIANT":
                f.write("**This platform meets HIPAA security and compliance requirements.**\n")
            else:
                f.write("**This platform requires remediation to meet HIPAA requirements.**\n")
    
    def generate_json_report(self) -> None:
        """Generate a JSON report."""
        report_path = os.path.join(self.reports_dir, "compliance_summary.json")
        
        with open(report_path, 'w') as f:
            json.dump(self.report_data, f, indent=2)
    
    def display_console_report(self) -> None:
        """Display a formatted report in the console."""
        if not RICH_AVAILABLE:
            print("Rich library not available. Install with 'pip install rich' for better formatting.")
            return
        
        console = Console()
        
        console.print("\n")
        console.print("[bold blue]===================================================================")
        console.print("[bold blue]           HIPAA COMPLIANCE SUMMARY REPORT                        ")
        console.print("[bold blue]           Luxury Concierge Psychiatry Platform                   ")
        console.print("[bold blue]===================================================================")
        console.print("\n")
        
        # Overall compliance status
        status = self.report_data["compliance_status"]
        status_color = "green" if status == "COMPLIANT" else "red"
        console.print(f"[bold]Overall Status:[/bold] [{status_color}]{status}[/{status_color}]")
        console.print(f"[bold]Security Score:[/bold] {self.report_data['security_score']:.1f}%")
        console.print("\n")
        
        # Test Results
        console.print("[bold]Test Results:[/bold]")
        test_table = Table(show_header=True)
        test_table.add_column("Metric")
        test_table.add_column("Value")
        
        test_table.add_row("Total Tests", str(self.report_data['total_tests']))
        test_table.add_row("Passed", str(self.report_data['tests_passed']))
        test_table.add_row("Failed", str(self.report_data['tests_failed']))
        test_table.add_row("Pass Rate", f"{self.report_data['pass_rate']:.1f}%")
        test_table.add_row("Coverage", f"{self.report_data['coverage']:.1f}%")
        
        console.print(test_table)
        console.print("\n")
        
        # HIPAA Categories
        console.print("[bold]HIPAA Category Scores:[/bold]")
        hipaa_table = Table(show_header=True)
        hipaa_table.add_column("Category")
        hipaa_table.add_column("Score")
        
        for category, score in self.report_data.get("hipaa_categories", {}).items():
            score_str = f"{score:.1f}%"
            score_color = "green" if score >= 80.0 else "red"
            hipaa_table.add_row(category, f"[{score_color}]{score_str}[/{score_color}]")
        
        console.print(hipaa_table)
        console.print("\n")
        
        # Vulnerabilities
        console.print("[bold]Security Vulnerabilities:[/bold]")
        vulns = self.report_data["vulnerabilities"]
        if vulns:
            vuln_table = Table(show_header=True)
            vuln_table.add_column("Severity")
            vuln_table.add_column("Description")
            vuln_table.add_column("Location")
            
            for vuln in vulns:
                severity = vuln['severity']
                severity_color = "red" if severity == "HIGH" else "yellow" if severity == "MEDIUM" else "blue"
                vuln_table.add_row(
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    vuln['description'],
                    vuln['location']
                )
            
            console.print(vuln_table)
        else:
            console.print("[green]No major vulnerabilities detected.[/green]")
        console.print("\n")
        
        # Recommendations
        console.print("[bold]Recommendations:[/bold]")
        recs = self.report_data["recommendations"]
        if recs:
            for i, rec in enumerate(recs, 1):
                priority = rec['priority']
                priority_color = "red" if priority == "HIGH" else "yellow" if priority == "MEDIUM" else "blue"
                
                console.print(f"{i}. [bold]{rec['description']}[/bold] ([{priority_color}]{priority}[/{priority_color}])")
                console.print(f"   Category: {rec['category']}")
                console.print("   Actions:")
                for action in rec['actions']:
                    console.print(f"     - {action}")
                console.print("")
        else:
            console.print("[green]No specific recommendations.[/green]")
        
        # Footer
        console.print("[bold blue]===================================================================")
        if status == "COMPLIANT":
            console.print("[bold green]This platform meets HIPAA security and compliance requirements.[/bold green]")
        else:
            console.print("[bold red]This platform requires remediation to meet HIPAA requirements.[/bold red]")
        console.print("[bold blue]===================================================================")
    
    def generate_all_reports(self) -> None:
        """Generate all report formats."""
        self.collect_data()
        self.generate_text_report()
        self.generate_markdown_report()
        self.generate_json_report()
        self.display_console_report()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="HIPAA Compliance Summary Generator")
    parser.add_argument("--reports-dir", default="reports", help="Directory containing security reports")
    
    return parser.parse_args()


def main():
    """Main entry point for the script."""
    args = parse_args()
    
    print("Generating HIPAA compliance summary...")
    generator = ComplianceSummaryGenerator(args.reports_dir)
    generator.generate_all_reports()
    
    print(f"Reports generated in the '{args.reports_dir}' directory")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())