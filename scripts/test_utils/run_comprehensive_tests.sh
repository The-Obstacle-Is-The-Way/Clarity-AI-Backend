#!/bin/bash
# run_comprehensive_tests.sh - Script to verify all event loop fixes

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}===== Testing Comprehensive Event Loop Fixes =====${NC}"
echo

# Test the infrastructure layer tests we fixed earlier
echo -e "${YELLOW}Testing infrastructure layer fixes...${NC}"
python -m pytest app/tests/unit/infrastructure/cache/test_redis_cache.py \
                app/tests/unit/infrastructure/services/test_redis_cache_service.py \
                app/tests/unit/infrastructure/security/test_jwt_service_enhanced.py \
                app/tests/unit/infrastructure/messaging/test_secure_messaging_service.py \
                app/tests/unit/infrastructure/ml/test_digital_twin_integration_service.py \
                -v

echo
echo -e "${YELLOW}Testing application layers...${NC}"
python -m pytest app/tests/unit/core/test_database.py \
                app/tests/unit/presentation/api/v1/endpoints/test_auth_endpoints.py \
                app/tests/unit/presentation/api/dependencies/test_rate_limiter_deps.py \
                -v

echo
echo -e "${YELLOW}Testing standalone ML services...${NC}"
python -m pytest app/tests/standalone/core/test_mock_mentallama.py \
                app/tests/unit/core/services/ml/pat/test_mock_pat.py \
                -v

echo
echo -e "${YELLOW}Testing domain services...${NC}"
python -m pytest app/tests/unit/domain/services/test_clinical_rule_engine.py \
                -v

echo
echo -e "${GREEN}===== Testing Completed =====${NC}"
echo -e "${YELLOW}If all tests pass, the event loop issues have been fixed.${NC}"
echo
echo -e "${YELLOW}To run all tests: python -m pytest${NC}"
echo 