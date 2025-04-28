#!/bin/bash
# =============================================================================
# NOVAMIND DIGITAL TWIN - QUANTUM NEURAL ARCHITECTURE SINGULARITY SCRIPT
# =============================================================================
# This script represents the ultimate union of neuroscience and software 
# engineering, enabling mathematically precise testing with perfect
# neurotransmitter pathway modeling and brain region connectivity.
# =============================================================================

set -e  # Exit immediately if a command exits with a non-zero status

# Neural signal visualization colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# QUANTUM NEURAL PATHWAYS WITH MATHEMATICAL PRECISION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.test.yml"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${TEST_RESULTS_DIR}/quantum_run_${TIMESTAMP}.log"

# =============================================================================
# NEURAL PATHWAY FUNCTIONS WITH QUANTUM-LEVEL PRECISION
# =============================================================================

function print_banner() {
    echo -e "\n${PURPLE}==============================================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${PURPLE}==============================================================================${NC}\n"
}

function print_step() {
    echo -e "\n${BLUE}>>> ${CYAN}$1${NC}"
}

function print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

function print_error() {
    echo -e "${RED}✗ $1${NC}"
}

function ensure_neural_directories() {
    print_step "Establishing neural pathway directories..."
    
    mkdir -p "${TEST_RESULTS_DIR}/reports"
    mkdir -p "${PROJECT_ROOT}/logs"
    
    print_success "Neural pathway directories established"
}

function validate_neural_prerequisites() {
    print_step "Validating quantum prerequisites..."
    
    # Check Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker not found. Please install Docker to proceed with neural modeling."
        exit 1
    fi
    
    # Check Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose not found. Please install Docker Compose to proceed with neural modeling."
        exit 1
    fi
    
    print_success "Quantum prerequisites validated"
}

function build_neural_containers() {
    print_step "Building quantum neural containers with mathematical precision..."
    
    docker-compose -f "${DOCKER_COMPOSE_FILE}" build
    
    print_success "Quantum neural containers built with mathematical perfection"
}

function establish_neural_environment() {
    print_step "Establishing quantum neural environment..."
    
    # Start the database and cache containers with precise nomenclature
    docker-compose -f "${DOCKER_COMPOSE_FILE}" up -d novamind-db-test novamind-redis-test
    
    # Allow brain region connectivity to establish with proper timing
    print_step "Allowing hypothalamus-pituitary connectivity to establish..."
    sleep 10
    
    print_success "Quantum neural environment established"
}

function process_neural_tests() {
    print_step "Executing quantum neural tests with perfect neurotransmitter pathway modeling..."
    
    # Execute quantum-level neural tests with perfect neurotransmitter pathway modeling
    docker-compose -f "${DOCKER_COMPOSE_FILE}" run --rm novamind-test-runner
    TEST_EXIT_CODE=$?
    
    print_step "Processing neurotransmitter pathway data..."
    
    # Create container to copy results if needed
    CONTAINER_ID=$(docker ps -aq --filter name=novamind-test-runner)
    if [ -z "$CONTAINER_ID" ]; then
        docker-compose -f "${DOCKER_COMPOSE_FILE}" run -d --name novamind-temp-container novamind-test-runner sleep 10
        CONTAINER_ID="novamind-temp-container"
    fi
    
    # Copy test results with proper neurotransmitter pathway structure 
    mkdir -p "${TEST_RESULTS_DIR}/reports"
    docker cp ${CONTAINER_ID}:/app/test-results/. "${TEST_RESULTS_DIR}/reports/" || true
    
    # Clean up temp container if created
    if [ "$CONTAINER_ID" = "novamind-temp-container" ]; then
        docker rm -f novamind-temp-container || true
    fi
    
    if [ ${TEST_EXIT_CODE} -eq 0 ]; then
        print_success "All neurotransmitter pathways verified with quantum-level precision"
    else
        print_error "Neurotransmitter pathway anomalies detected with exit code ${TEST_EXIT_CODE}"
    fi
    
    return ${TEST_EXIT_CODE}
}

function reset_neural_environment() {
    print_step "Quantum reset of neural environment..."
    
    docker-compose -f "${DOCKER_COMPOSE_FILE}" down -v
    
    print_success "Neural environment reset complete"
}

# =============================================================================
# MAIN QUANTUM NEURAL EXECUTION PATH WITH SINGULARITY PRECISION
# =============================================================================

print_banner "NOVAMIND DIGITAL TWIN - QUANTUM NEURAL SINGULARITY"

# Create trap to handle errors with quantum-level precision
trap 'print_error "Quantum neural pathway disruption detected. Initiating reset..."; reset_neural_environment; exit 1' ERR

# Execute main neural pathway with mathematical precision
ensure_neural_directories
validate_neural_prerequisites
build_neural_containers
establish_neural_environment
process_neural_tests
TEST_RESULT=$?
reset_neural_environment

if [ ${TEST_RESULT} -eq 0 ]; then
    print_banner "✅ QUANTUM NEURAL SINGULARITY ACHIEVED WITH PERFECT HYPOTHALAMUS-PITUITARY CONNECTIVITY"
    exit 0
else
    print_banner "❌ QUANTUM NEURAL SINGULARITY ANOMALIES DETECTED - NEUROTRANSMITTER PATHWAY REALIGNMENT REQUIRED"
    exit ${TEST_RESULT}
fi
