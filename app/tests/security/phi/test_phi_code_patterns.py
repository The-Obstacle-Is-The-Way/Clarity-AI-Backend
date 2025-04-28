"""
Tests for the PHI code pattern detection mechanisms.

These tests verify that the PHI code analyzer can properly detect PHI 
in various types of source code files.
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from app.infrastructure.security.phi.code_analyzer import PHICodeAnalyzer, CodeSeverity
from app.infrastructure.security.phi.phi_service import PHIService


class TestPHIInSourceFiles:
    """Test suite for PHI detection in source code files."""
    
    @pytest.fixture
    def phi_analyzer(self):
        """Create a PHI code analyzer instance for testing."""
        phi_service = PHIService()
        return PHICodeAnalyzer(phi_service=phi_service)
    
    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        fd, temp_path = tempfile.mkstemp()
        try:
            yield temp_path
        finally:
            os.close(fd)
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    def write_temp_file(self, file_path, content):
        """Write content to a temporary file."""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def test_python_file_with_phi(self, phi_analyzer, temp_file):
        """Test that PHI is detected in Python files."""
        # Python file with PHI
        python_content = '''
        # Patient information module
        def get_patient_data(patient_id):
            """Retrieve patient data from the database."""
            # This is just a mock implementation
            if patient_id == "12345":
                return {
                    "name": "John Smith",
                    "ssn": "123-45-6789",
                    "dob": "1980-01-01",
                    "email": "john.smith@example.com",
                    "phone": "(555) 123-4567"
                }
            return None
        '''
        
        self.write_temp_file(temp_file, python_content)
        
        # Scan the file
        result = phi_analyzer.scan_file(temp_file)
        
        # Verify results
        assert result["status"] == "scanned"
        assert result["has_phi"] is True
        assert len(result["findings"]) >= 3  # At least SSN, email, and phone
        
        # Check that we found the SSN
        ssn_findings = [f for f in result["findings"] if "123-45-6789" in f["match"]]
        assert len(ssn_findings) > 0
        assert ssn_findings[0]["severity"] == CodeSeverity.CRITICAL
        
        # Check that we found the phone number
        phone_findings = [f for f in result["findings"] if "(555) 123-4567" in f["match"]]
        assert len(phone_findings) > 0
    
    def test_js_file_with_phi(self, phi_analyzer, temp_file):
        """Test that PHI is detected in JavaScript files."""
        # JavaScript file with PHI
        js_content = '''
        // Patient record component
        function PatientRecord(props) {
            const [patient, setPatient] = useState({
                id: "PT12345",
                name: "Jane Doe",
                ssn: "987-65-4321",
                contact: {
                    email: "jane.doe@example.com",
                    phone: "(555) 987-6543"
                }
            });
            
            return (
                <div className="patient-record">
                    <h2>{patient.name}</h2>
                    <p>SSN: {patient.ssn}</p>
                    <p>Email: {patient.contact.email}</p>
                    <p>Phone: {patient.contact.phone}</p>
                </div>
            );
        }
        '''
        
        self.write_temp_file(temp_file, js_content)
        
        # Scan the file
        result = phi_analyzer.scan_file(temp_file)
        
        # Verify results
        assert result["status"] == "scanned"
        assert result["has_phi"] is True
        assert len(result["findings"]) >= 3  # At least SSN, email, and phone
        
        # Check that we found the SSN
        ssn_findings = [f for f in result["findings"] if "987-65-4321" in f["match"]]
        assert len(ssn_findings) > 0
        assert ssn_findings[0]["severity"] == CodeSeverity.CRITICAL
    
    def test_config_file_with_phi(self, phi_analyzer, temp_file):
        """Test that PHI is detected in configuration files."""
        # Config file with sensitive information
        config_content = '''
        [database]
        host = localhost
        port = 5432
        name = patient_records
        user = admin
        password = s3cr3tP@ssw0rd
        
        [api]
        endpoint = https://api.example.com/v1
        api_key = abcdef123456789
        
        [test_data]
        # Test patient for integration tests
        test_patient_ssn = 123-45-6789
        test_patient_email = test.patient@example.com
        '''
        
        self.write_temp_file(temp_file, config_content)
        
        # Scan the file
        result = phi_analyzer.scan_file(temp_file)
        
        # Verify results
        assert result["status"] == "scanned"
        assert result["has_phi"] is True
        
        # Check that we found the hardcoded password
        password_findings = [f for f in result["findings"] if "password" in f["match"].lower()]
        assert len(password_findings) > 0
        
        # Check that we found the API key
        api_key_findings = [f for f in result["findings"] if "api_key" in f["match"].lower()]
        assert len(api_key_findings) > 0
        
        # Check that we found the SSN
        ssn_findings = [f for f in result["findings"] if "123-45-6789" in f["match"]]
        assert len(ssn_findings) > 0
    
    def test_clean_file(self, phi_analyzer, temp_file):
        """Test that clean files don't trigger false positives."""
        # Clean file without PHI
        clean_content = '''
        def calculate_stats(data_points):
            """Calculate statistical measures for a list of data points."""
            if not data_points:
                return {"mean": 0, "median": 0, "std_dev": 0}
                
            mean = sum(data_points) / len(data_points)
            sorted_points = sorted(data_points)
            
            # Calculate median
            n = len(sorted_points)
            if n % 2 == 0:
                median = (sorted_points[n//2 - 1] + sorted_points[n//2]) / 2
            else:
                median = sorted_points[n//2]
                
            # Calculate standard deviation
            variance = sum((x - mean) ** 2 for x in data_points) / len(data_points)
            std_dev = variance ** 0.5
            
            return {
                "mean": mean,
                "median": median,
                "std_dev": std_dev
            }
        '''
        
        self.write_temp_file(temp_file, clean_content)
        
        # Scan the file
        result = phi_analyzer.scan_file(temp_file)
        
        # Verify results
        assert result["status"] == "scanned"
        assert result["has_phi"] is False
        assert len(result["findings"]) == 0
    
    def test_directory_scan(self, phi_analyzer, temp_dir):
        """Test scanning a directory for PHI in multiple files."""
        # Create multiple files with and without PHI
        py_file = os.path.join(temp_dir, "patient.py")
        self.write_temp_file(py_file, '''
        # Patient module
        def get_patient(id):
            return {
                "name": "John Smith",
                "ssn": "123-45-6789"
            }
        ''')
        
        js_file = os.path.join(temp_dir, "app.js")
        self.write_temp_file(js_file, '''
        // Clean JavaScript file
        function calculateTotal(items) {
            return items.reduce((sum, item) => sum + item.price, 0);
        }
        ''')
        
        config_file = os.path.join(temp_dir, "config.ini")
        self.write_temp_file(config_file, '''
        [api]
        secret_key = abcdef123456
        ''')
        
        # Create a subdirectory with files
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir, exist_ok=True)
        
        subdir_file = os.path.join(subdir, "user.py")
        self.write_temp_file(subdir_file, '''
        def get_user(email):
            if email == "john.doe@example.com":
                return {"name": "John Doe"}
            return None
        ''')
        
        # Scan the directory
        result = phi_analyzer.scan_directory(temp_dir)
        
        # Verify results
        assert result["status"] == "completed"
        assert result["files_scanned"] == 4
        assert result["files_with_phi"] >= 2  # At least patient.py and config.ini
        
        # Check findings
        phi_files = [r["file_path"] for r in result["results"]]
        assert py_file in phi_files  # patient.py should have PHI
        assert config_file in phi_files  # config.ini should have PHI
    
    def test_excluded_files(self, phi_analyzer, temp_dir):
        """Test that excluded files are skipped."""
        # Create files in excluded paths
        node_modules = os.path.join(temp_dir, "node_modules")
        os.makedirs(node_modules, exist_ok=True)
        
        excluded_file = os.path.join(node_modules, "module.js")
        self.write_temp_file(excluded_file, '''
        // This file has PHI but should be excluded
        const patient = {
            name: "John Smith",
            ssn: "123-45-6789"
        };
        ''')
        
        # Create a regular file with PHI
        regular_file = os.path.join(temp_dir, "data.py")
        self.write_temp_file(regular_file, '''
        # This file has PHI and should be included
        patient_ssn = "987-65-4321"
        ''')
        
        # Scan the directory
        result = phi_analyzer.scan_directory(temp_dir)
        
        # Verify excluded file was skipped
        scanned_files = [r["file_path"] for r in result["results"]]
        assert excluded_file not in scanned_files
        assert regular_file in scanned_files
    
    def test_audit_code_for_phi(self, phi_analyzer, temp_dir):
        """Test the comprehensive audit function."""
        # Create files for testing
        py_file = os.path.join(temp_dir, "patient.py")
        self.write_temp_file(py_file, '''
        patient_records = {
            "123": {
                "name": "John Smith",
                "ssn": "123-45-6789"
            }
        }
        ''')
        
        # Scan the directory
        result = phi_analyzer.audit_code_for_phi(temp_dir)
        
        # Verify results
        assert "summary" in result
        assert result["summary"]["total_findings"] > 0
        assert "critical" in result["summary"]["by_severity"]
        
        # Test JSON output
        json_result = phi_analyzer.audit_code_for_phi(temp_dir, output_format="json")
        assert isinstance(json_result, str)
        assert "summary" in json_result
    
    def test_audit_api_endpoints(self, phi_analyzer, temp_dir):
        """Test auditing API endpoints for PHI exposure risks."""
        # Create mock API file
        api_file = os.path.join(temp_dir, "routes.py")
        self.write_temp_file(api_file, '''
        @app.route('/patients/<patient_id>')
        def get_patient(patient_id):
            patient = db.get_patient(patient_id)
            return jsonify({
                "id": patient.id,
                "name": patient.name,
                "ssn": patient.ssn,
                "email": patient.email
            })
        
        @app.route('/search')
        def search_patients():
            ssn = request.args.get('ssn')
            return jsonify(db.search_by_ssn(ssn))
        ''')
        
        # Audit API endpoints
        result = phi_analyzer.audit_api_endpoints(temp_dir)
        
        # Verify results
        assert "api_files_found" in result
        assert result["api_files_found"] == 1
        assert len(result["phi_exposure_risks"]) > 0
        
        # Check for path parameter risks
        path_risks = [r for r in result["phi_exposure_risks"] if r["pattern_type"] == "path_parameter"]
        assert len(path_risks) > 0
        assert "patient_id" in path_risks[0]["parameter"]
        
        # Check for response risks
        response_risks = [r for r in result["phi_exposure_risks"] if r["pattern_type"] == "response"]
        assert len(response_risks) > 0
    
    def test_audit_configuration(self, phi_analyzer, temp_dir):
        """Test auditing configuration files for security issues."""
        # Create mock config file
        config_file = os.path.join(temp_dir, "config.py")
        self.write_temp_file(config_file, '''
        # Development configuration
        DEBUG = True
        
        # Database configuration
        DB_PASSWORD = "super_secret_password"
        
        # Security settings
        SECRET_KEY = "hardcoded_secret_key_12345"
        SESSION_TIMEOUT = 0  # No timeout
        
        # CORS settings
        CORS_ALLOW_ALL = True
        
        # PHI protection
        SANITIZE_PHI = False  # Disabled for dev
        ''')
        
        # Audit configuration
        result = phi_analyzer.audit_configuration(temp_dir)
        
        # Verify results
        assert "config_files_found" in result
        assert result["config_files_found"] == 1
        
        # Check security classifications
        security = result["security_classifications"]
        assert len(security["critical"]) > 0
        assert len(security["high"]) > 0
        
        # Check specific security issues
        critical_issues = [issue["setting_type"] for issue in security["critical"]]
        assert "phi_protection_disabled" in critical_issues
        
        high_issues = [issue["setting_type"] for issue in security["high"]]
        assert "debug_enabled" in high_issues