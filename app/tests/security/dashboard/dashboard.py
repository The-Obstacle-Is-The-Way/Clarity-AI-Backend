#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
NovaMind Digital Twin Security Dashboard Generator

This module generates a comprehensive visualization dashboard for the
security test results, highlighting HIPAA compliance metrics and
quantum-level encryption effectiveness across all components.
"""

import os
import json
from datetime import datetime
from typing import Dict, Any, List
import unittest
from unittest.mock import Mock

class MockDatabase:
    def clear_data(self):
        pass

class MockUser:
    def __init__(self, id: int, username: str, password: str, role: str):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

class MockAuthService:
    def __init__(self, users: Dict[str, MockUser]):
        self.users = users

class MockAuthorizationService:
    pass

def create_app():
    # Create a mock app for testing purposes
    class MockApp:
        def __init__(self):
            self.config = {}

        def test_client(self):
            # Create a mock test client
            class MockTestClient:
                def post(self, url, data, follow_redirects):
                    # Mock login response
                    if url == '/login':
                        return MockResponse(200, b'Login successful')

                def get(self, url, follow_redirects):
                    # Mock dashboard response
                    if url == '/admin/dashboard':
                        return MockResponse(200, b'Admin Dashboard')

            return MockTestClient()

    return MockApp()

class MockResponse:
    def __init__(self, status_code: int, data: bytes):
        self.status_code = status_code
        self.data = data

class DashboardSecurityTest(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.app = create_app()
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.config['DEBUG'] = False
        
        # Set up test database or mock database connection
        self.db = MockDatabase()
        self.app.config['DATABASE'] = self.db
        
        # Initialize test users and roles
        self.admin_user = MockUser(id=1, username='admin', password='adminpass', role='admin')
        self.provider_user = MockUser(id=2, username='provider', password='providerpass', role='provider')
        self.patient_user = MockUser(id=3, username='patient', password='patientpass', role='patient')
        
        self.users = {
            'admin': self.admin_user,
            'provider': self.provider_user,
            'patient': self.patient_user
        }
        
        # Setup mock authentication service
        self.auth_service = MockAuthService(self.users)
        self.app.config['AUTH_SERVICE'] = self.auth_service
        
        # Setup mock authorization service
        self.authz_service = MockAuthorizationService()
        self.app.config['AUTHZ_SERVICE'] = self.authz_service

    def tearDown(self):
        """Clean up after each test method."""
        # Clean up test data if necessary
        self.db.clear_data()

    def login(self, username, password):
        """Helper method to login a user."""
        response = self.client.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)
        return response

    def logout(self):
        """Helper method to logout the current user."""
        return self.client.get('/logout', follow_redirects=True)

    def assertAccessDenied(self, response):
        """Assert that the response indicates access denied."""
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'Access Denied', response.data)

    def assertUnauthorized(self, response):
        """Assert that the response indicates unauthorized access."""
        self.assertEqual(response.status_code, 401)
        self.assertIn(b'Unauthorized', response.data)

    def assertSuccessfulLogin(self, response, username):
        """Assert that login was successful."""
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'Welcome {username}'.encode(), response.data)

    def assertSuccessfulLogout(self, response):
        """Assert that logout was successful."""
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'You have been logged out', response.data)

    def test_admin_dashboard_access(self):
        """Test admin dashboard access for different roles."""
        # Test admin access (should succeed)
        self.login(self.admin_user.username, self.admin_user.password)
        response = self.client.get('/admin/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Admin Dashboard', response.data)
        self.logout()
        
        # Test provider access (should be denied)
        self.login(self.provider_user.username, self.provider_user.password)
        response = self.client.get('/admin/dashboard')
        self.assertAccessDenied(response)
        self.logout()
        
        # Test patient access (should be denied)
        self.login(self.patient_user.username, self.patient_user.password)
        response = self.client.get('/admin/dashboard')
        self.assertAccessDenied(response)
        self.logout()
        
        # Test unauthenticated access (should be unauthorized)
        response = self.client.get('/admin/dashboard')
        self.assertUnauthorized(response)

def generate_dashboard(results: Dict[str, Any], output_path: str) -> None:
    """Generate HTML dashboard for security test results.

    Args:
        results: Dictionary with test results
        output_path: Path to save the dashboard HTML
    """
    # Calculate overall metrics
    total_tests = results['summary']['total']
    passed_tests = results['summary']['passed']
    failed_tests = results['summary']['failed']
    error_tests = results['summary']['errors']
    skipped_tests = results['summary']['skipped']

    # Calculate success rate
    if total_tests > 0:
        success_rate = 100 * passed_tests / total_tests
    else:
        success_rate = 0

    # Generate timestamp
    timestamp = datetime.fromisoformat(results['timestamp'])
    formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')

    # Generate category summaries
    category_rows = []
    for name, category in results['categories'].items():
        cat_total = category['tests']['total']
        cat_passed = category['tests']['passed']
        cat_success_rate = 100 * cat_passed / cat_total if cat_total > 0 else 0

        # Set color based on success rate
        if cat_success_rate >= 95:
            color_class = "success"
        elif cat_success_rate >= 75:
            color_class = "warning"
        else:
            color_class = "danger"

        category_rows.append(f"""
        <tr class="{color_class}">
        <td>{name}</td>
        <td>{cat_passed}/{cat_total}</td>
        <td>{category['tests']['failed']}</td>
        <td>{category['tests']['errors']}</td>
        <td>{category['tests']['skipped']}</td>
        <td>{cat_success_rate:.2f}%</td>
        </tr>
        """)

    # Generate detailed test file results
    file_sections = []
    for name, category in results['categories'].items():
        file_rows = []

        for file_result in category.get('files', []):
            file_name = file_result.get('file', 'Unknown')
            file_path = file_result.get('path', 'Unknown')
            file_summary = file_result.get('summary', {})

            file_total = file_summary.get('total', 0)
            file_passed = file_summary.get('passed', 0)
            file_success_rate = 100 * file_passed / file_total if file_total > 0 else 0

            # Set color based on success rate
            if file_success_rate >= 95:
                color_class = "success"
            elif file_success_rate >= 75:
                color_class = "warning"
            else:
                color_class = "danger"

            file_rows.append(f"""
            <tr class="{color_class}">
            <td>{file_name}</td>
            <td>{file_passed}/{file_total}</td>
            <td>{file_summary.get('failed', 0)}</td>
            <td>{file_summary.get('errors', 0)}</td>
            <td>{file_summary.get('skipped', 0)}</td>
            <td>{file_success_rate:.2f}%</td>
            </tr>
            """)

            # Add detailed test results
            test_rows = []
            for test in file_result.get('tests', []):
                test_name = test.get('name', 'Unknown')
                test_outcome = test.get('outcome', 'unknown')
                test_duration = test.get('duration', 0)
                test_message = test.get('message', '')

                # Set color based on outcome
                if test_outcome == 'passed':
                    row_class = "success"
                elif test_outcome == 'skipped':
                    row_class = "warning"
                else:
                    row_class = "danger"

                test_rows.append(f"""
                <tr class="{row_class}">
                <td>{test_name}</td>
                <td>{test_outcome}</td>
                <td>{test_duration:.3f}s</td>
                <td><pre class="message">{test_message}</pre></td>
                </tr>
                """)

                # Add test details if available
                if test_rows:
                    file_rows.append(f"""
                    <tr>
                    <td colspan="6">
                    <div class="test-details">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Test</th>
                                <th>Outcome</th>
                                <th>Duration</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(test_rows)}
                        </tbody>
                    </table>
                    </div>
                    </td>
                    </tr>
                    """)

            # Add file section
            if file_rows:
                file_sections.append(f"""
                <div class="card mb-4">
                <div class="card-header">
                <h3>{name}</h3>
                </div>
                <div class="card-body">
                <table class="table table-bordered">
                <thead>
                <thead>
                <tr>
                    <th>File</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Errors</th>
                    <th>Skipped</th>
                    <th>Success Rate</th>
                </tr>
                </thead>
                <tbody>
                {"".join(file_rows)}
                </tbody>
                </table>
                </div>
                </div>
                """)

    # Determine overall status color
    if success_rate >= 95:
        status_class = "success"
        status_text = "COMPLIANT"
    elif success_rate >= 75:
        status_class = "warning"
        status_text = "PARTIALLY COMPLIANT"
    else:
        status_class = "danger"
        status_text = "NON-COMPLIANT"

    # Generate the HTML
    html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NovaMind Digital Twin Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
    .dashboard-header {{background-color: #343a40; color: white; padding: 20px 0; margin-bottom: 30px;}}
    .status-indicator {{font-size: 24px; font-weight: bold; padding: 10px 20px; border-radius: 5px; display: inline-block;}}
    .success {{background-color: #d4edda; color: #155724;}}
    .warning {{background-color: #fff3cd; color: #856404;}}
    .danger {{background-color: #f8d7da; color: #721c24;}}
    .metrics-card {{text-align: center; margin-bottom: 20px;}}
    .metric-value {{font-size: 36px; font-weight: bold;}}
    .metric-label {{font-size: 14px; text-transform: uppercase;}}
    .test-details {{margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-radius: 5px;}}
    .message {{font-size: 12px; max-height: 200px; overflow-y: auto; white-space: pre-wrap;}}
    footer {{margin-top: 50px; padding: 20px 0; background-color: #f8f9fa; text-align: center;}}
    </style>
    </head>
    <body>
    <div class="dashboard-header">
    <div class="container">
    <div class="row align-items-center">
    <div class="col-md-8">
        <h1>NovaMind Digital Twin</h1>
        <h2>HIPAA Security Compliance Dashboard</h2>
        <p class="mb-0">Generated: {{formatted_timestamp}}</p>
    </div>
    <div class="col-md-4 text-end">
        <div class="status-indicator {{status_class}}">
            {{status_text}}
        </div>
    </div>
    </div>
    </div>
    </div>

    <div class="container">
    <div class="row">
    <div class="col-md-3">
    <div class="card metrics-card">
        <div class="card-body">
            <div class="metric-value">{{total_tests}}</div>
            <div class="metric-label">Total Tests</div>
        </div>
    </div>
    </div>
    <div class="col-md-3">
    <div class="card metrics-card">
        <div class="card-body">
            <div class="metric-value text-success">{{passed_tests}}</div>
            <div class="metric-label">Passed</div>
        </div>
    </div>
    </div>
    <div class="col-md-3">
    <div class="card metrics-card">
        <div class="card-body">
            <div class="metric-value text-danger">{{failed_tests + error_tests}}</div>
            <div class="metric-label">Failed/Errors</div>
        </div>
    </div>
    </div>
    <div class="col-md-3">
    <div class="card metrics-card">
        <div class="card-body">
            <div class="metric-value {{status_class}}">{{success_rate:.2f}}%</div>
            <div class="metric-label">Success Rate</div>
        </div>
    </div>
    </div>
    </div>
"""

    html += f"""
    <div class="row mt-4">
    <div class="col-12">
    <div class="card mb-4">
        <div class="card-header">
            <h3>Category Summary</h3>
        </div>
        <div class="card-body">
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Passed</th>
                        <th>Failed</th>
                        <th>Errors</th>
                        <th>Skipped</th>
                        <th>Success Rate</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(category_rows)}
                </tbody>
            </table>
        </div>
    </div>
    </div>
    </div>

    <div class="row">
    <div class="col-12">
    <h2>Detailed Results</h2>
    {"".join(file_sections)}
    </div>
    </div>
    </div>

    <footer>
    <div class="container">
    <p>&copy; 2025 NovaMind Digital Twin Platform</p>
    <p>HIPAA Security Compliance Report</p>
    </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Toggle test details on file row click
    document.addEventListener('DOMContentLoaded', function() {{
    const testDetails = document.querySelectorAll('.test-details');
    testDetails.forEach(function(detail) {{
        detail.style.display = 'none';
    }});

    const fileRows = document.querySelectorAll('tr:not(:has(td[colspan]))');
    fileRows.forEach(function(row) {{
        row.addEventListener('click', function() {{
            const nextRow = this.nextElementSibling;
            if (nextRow && nextRow.querySelector('.test-details')) {{
                const details = nextRow.querySelector('.test-details');
                details.style.display = details.style.display === 'none' ? 'block' : 'none';
            }}
        }});
    }});
}});
</script>
</body>
</html>
"""

    # Write the HTML to the output file
    with open(output_path, 'w') as f:
        f.write(html.format(
            formatted_timestamp=formatted_timestamp,
            status_class=status_class,
            status_text=status_text,
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            error_tests=error_tests,
            success_rate=success_rate,
        ))

def parse_test_results(results_path: str) -> Dict[str, Any]:
    """Parse a test results JSON file.

    Args:
        results_path: Path to the results JSON file

    Returns:
        Parsed results dictionary
    """
    with open(results_path, 'r') as f:
        return json.load(f)

if __name__ == "__main__":
    # Get the most recent results file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, 'test_results')

    if not os.path.exists(results_dir):
        print(f"Results directory not found: {results_dir}")
        exit(1)

    # Find the most recent results file
    results_files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
    if not results_files:
        print("No results files found")
        exit(1)

    # Sort by modification time (most recent first)
    results_files.sort(key=lambda f: os.path.getmtime(os.path.join(results_dir, f)), reverse=True)
    latest_file = os.path.join(results_dir, results_files[0])

    # Generate dashboard
    results = parse_test_results(latest_file)
    dashboard_path = os.path.join(results_dir, f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    generate_dashboard(results, dashboard_path)

    print(f"Dashboard generated at: {dashboard_path}")
