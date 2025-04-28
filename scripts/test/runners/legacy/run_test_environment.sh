#!/bin/bash
# Novamind Test Environment Management Script
# This script handles setting up and tearing down the test environment

set -e

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Determine the script directory and backend directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"

# Print a header
echo -e "${BLUE}${BOLD}=====================================================================${NC}"
echo -e "${BLUE}${BOLD}               Novamind Test Environment Management                  ${NC}"
echo -e "${BLUE}${BOLD}=====================================================================${NC}"

# Function to check if Docker is running
check_docker() {
  echo -e "${YELLOW}Checking if Docker is running...${NC}"
  if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Docker is not running. Please start Docker and try again.${NC}"
    exit 1
  fi
  echo -e "${GREEN}Docker is running.${NC}"
}

# Function to start the test environment
start_test_environment() {
  echo -e "${YELLOW}Starting test environment...${NC}"
  cd "$BACKEND_DIR" || exit 1
  
  # Check if containers are already running
  if docker ps --format '{{.Names}}' | grep -q "novamind-db-test"; then
    echo -e "${YELLOW}Test environment is already running. Stopping and removing containers...${NC}"
    docker-compose -f docker-compose.test.yml down
  fi
  
  # Start containers in detached mode
  docker-compose -f docker-compose.test.yml up -d novamind-db-test novamind-redis-test novamind-pgadmin-test
  
  # Wait for database to be ready
  echo -e "${YELLOW}Waiting for database to be ready...${NC}"
  for i in {1..30}; do
    if docker exec novamind-db-test pg_isready -U postgres > /dev/null 2>&1; then
      echo -e "${GREEN}Database is ready.${NC}"
      break
    fi
    echo -n "."
    sleep 1
    if [ $i -eq 30 ]; then
      echo -e "\n${RED}Database did not become ready in time. Please check the logs.${NC}"
      exit 1
    fi
  done
  
  # Run database migrations if needed
  if [ "$1" = "--with-migrations" ]; then
    echo -e "${YELLOW}Running database migrations...${NC}"
    cd "$BACKEND_DIR" || exit 1
    
    # Set environment variables for alembic
    export DB_USER=postgres
    export DB_PASSWORD=postgres
    export DB_HOST=localhost
    export DB_PORT=15432
    export DB_NAME=novamind_test
    
    # Run migrations
    alembic upgrade head
    
    echo -e "${GREEN}Database migrations completed.${NC}"
  fi
  
  echo -e "${GREEN}Test environment is up and running.${NC}"
  echo -e "${YELLOW}PostgreSQL is available at localhost:15432${NC}"
  echo -e "${YELLOW}PgAdmin is available at http://localhost:15050${NC}"
  echo -e "${YELLOW}Redis is available at localhost:16379${NC}"
}

# Function to clean up the test environment
cleanup() {
  echo -e "${YELLOW}Cleaning up test environment...${NC}"
  cd "$BACKEND_DIR" || exit 1
  docker-compose -f docker-compose.test.yml down
  echo -e "${GREEN}Test environment has been stopped and removed.${NC}"
}

# Function to show test environment status
status() {
  echo -e "${YELLOW}Test environment status:${NC}"
  
  # Check if containers are running
  if docker ps --format '{{.Names}}' | grep -q "novamind-db-test"; then
    echo -e "${GREEN}Database container is running.${NC}"
    
    # Check database connectivity
    if docker exec novamind-db-test pg_isready -U postgres > /dev/null 2>&1; then
      echo -e "${GREEN}Database is accepting connections.${NC}"
    else
      echo -e "${RED}Database is not accepting connections.${NC}"
    fi
  else
    echo -e "${RED}Database container is not running.${NC}"
  fi
  
  # Check Redis
  if docker ps --format '{{.Names}}' | grep -q "novamind-redis-test"; then
    echo -e "${GREEN}Redis container is running.${NC}"
    
    # Check Redis connectivity
    if docker exec novamind-redis-test redis-cli ping > /dev/null 2>&1; then
      echo -e "${GREEN}Redis is accepting connections.${NC}"
    else
      echo -e "${RED}Redis is not accepting connections.${NC}"
    fi
  else
    echo -e "${RED}Redis container is not running.${NC}"
  fi
  
  # Check PgAdmin
  if docker ps --format '{{.Names}}' | grep -q "novamind-pgadmin-test"; then
    echo -e "${GREEN}PgAdmin container is running.${NC}"
  else
    echo -e "${RED}PgAdmin container is not running.${NC}"
  fi
}

# Main execution
case "$1" in
  start)
    check_docker
    start_test_environment "$2"
    ;;
  stop|clean)
    cleanup
    ;;
  status)
    status
    ;;
  restart)
    cleanup
    check_docker
    start_test_environment "$2"
    ;;
  *)
    echo -e "Usage: $0 {start|stop|status|restart} [--with-migrations]"
    echo -e ""
    echo -e "Commands:"
    echo -e "  start             Start the test environment"
    echo -e "  stop, clean       Stop and remove the test environment"
    echo -e "  status            Check the status of the test environment"
    echo -e "  restart           Restart the test environment"
    echo -e ""
    echo -e "Options:"
    echo -e "  --with-migrations Run database migrations after startup"
    echo -e ""
    echo -e "Example:"
    echo -e "  $0 start --with-migrations"
    ;;
esac

exit 0