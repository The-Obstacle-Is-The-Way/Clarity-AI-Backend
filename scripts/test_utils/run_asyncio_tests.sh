#!/bin/bash
# run_asyncio_tests.sh - Script to verify asyncio event loop fixes

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}===== Testing Event Loop Fixes =====${NC}"
echo

# First, run the tests we just fixed
echo -e "${YELLOW}Testing redis cache tests...${NC}"
python -m pytest app/tests/unit/infrastructure/cache/test_redis_cache.py -v

echo
echo -e "${YELLOW}Testing redis service tests...${NC}"
python -m pytest app/tests/unit/infrastructure/services/test_redis_cache_service.py -v

echo
echo -e "${YELLOW}Testing JWT service tests...${NC}"
python -m pytest app/tests/unit/infrastructure/security/test_jwt_service_enhanced.py -v

echo
echo -e "${YELLOW}Testing messaging service tests...${NC}"
python -m pytest app/tests/unit/infrastructure/messaging/test_secure_messaging_service.py -v

echo
echo -e "${YELLOW}Testing digital twin integration tests...${NC}"
python -m pytest app/tests/unit/infrastructure/ml/test_digital_twin_integration_service.py -v

echo
echo -e "${YELLOW}Testing rate limiter dependency tests...${NC}"
python -m pytest app/tests/unit/presentation/api/dependencies/test_rate_limiter_deps.py -v

echo
echo -e "${GREEN}===== Testing Completed =====${NC}"
echo -e "${YELLOW}If all tests pass, the event loop issue has been fixed.${NC}"
echo -e "${YELLOW}To run all tests: python -m pytest${NC}"
echo 