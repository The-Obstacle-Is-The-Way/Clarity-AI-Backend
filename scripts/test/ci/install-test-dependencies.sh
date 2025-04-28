#!/bin/bash
# Script to install test dependencies for Novamind Digital Twin Backend

set -e  # Exit on error

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}  Installing Test Dependencies for Novamind      ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Check if pip is available
if ! command -v pip &> /dev/null; then
    echo -e "${RED}ERROR: pip is not installed or not in PATH${NC}"
    echo "Please install pip and try again"
    exit 1
fi

# Check if we're in a virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}WARNING: Not running in a virtual environment${NC}"
    echo -e "It's recommended to use a virtual environment for installing dependencies"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Installation aborted${NC}"
        exit 0
    fi
fi

# Check if requirements-test.txt exists
if [ ! -f "requirements-test.txt" ]; then
    echo -e "${RED}ERROR: requirements-test.txt not found${NC}"
    echo "Please run this script from the backend directory"
    exit 1
fi

echo -e "${YELLOW}Installing primary test dependencies...${NC}"
pip install -r requirements-test.txt

# Check for and install async database drivers
echo -e "${YELLOW}Installing async database drivers...${NC}"

# Check if asyncpg is installed
if ! pip list | grep -q asyncpg; then
    echo "Installing asyncpg (PostgreSQL async driver)..."
    pip install asyncpg>=0.28.0
else
    echo "asyncpg already installed."
fi

# Check if aiosqlite is installed
if ! pip list | grep -q aiosqlite; then
    echo "Installing aiosqlite (SQLite async driver)..."
    pip install aiosqlite>=0.19.0
else
    echo "aiosqlite already installed."
fi

# Add Python path to include the current directory
echo -e "${YELLOW}Setting up environment...${NC}"
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Create a .env.test file if it doesn't exist
if [ ! -f ".env.test" ]; then
    echo -e "${YELLOW}Creating .env.test file...${NC}"
    cat > .env.test << EOF
# Test Environment Configuration
TESTING=1
ENVIRONMENT=testing
POSTGRES_SERVER=localhost
POSTGRES_USER=test_user
POSTGRES_PASSWORD=test_password
POSTGRES_DB=novamind_test
SECRET_KEY=test_secret_key_do_not_use_in_production
EOF
    echo ".env.test file created."
else
    echo ".env.test file already exists."
fi

echo -e "${GREEN}Installation complete!${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}To run tests, use: ${NC}"
echo -e "  TESTING=1 python -m pytest"
echo -e "  # Or for standalone tests:"
echo -e "  python -m backend.app.tests.standalone.test_ml_exceptions_self_contained"
echo -e "${BLUE}==================================================${NC}"